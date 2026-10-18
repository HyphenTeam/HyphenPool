# Hyphen Pool

Hyphen Pool is the independent mining-pool server for Hyphen block version 5
(PoUW v3). It connects to the node's template protocol, serves signed Protocol v6
jobs to miners, verifies single-use Cunningham witness chains itself, keeps
durable accounting, and drives payouts through Hyphen Wallet's payout agent.

Consensus types, hashing, the wire profile, and the node protocol are not copied
here. `hyphen-core`, `hyphen-crypto`, `hyphen-pow`, `hyphen-neural`, and
`hyphen-transport` are consumed from the public Hyphen revision
`c57f908464df6634eba829e8267f9c5330b3a4b4` pinned in `Cargo.toml` and
`Cargo.lock`. There is no path dependency on a base-chain checkout: CI builds
this repository from a clean clone. A protocol change is a coordinated revision
bump followed by the compatibility checks below.

## Share semantics

A share is a witness list, not a nonce. For every submission the pool:

1. Rejects a chain length that differs from the job's.
2. Rejects a witness another miner has already claimed on this pool.
3. Runs the node's own predicate (`verify_witnesses`) over the list.
4. Recomputes `witness_commitment(parent_commitment, height, witnesses)` and
   compares it with the commitment the miner submitted.

A list of `difficulty` witnesses is a block candidate: the pool reconstructs the
exact header the miner signed, verifies the miner authorization inside it,
assembles the block with `pow_witnesses`, and submits it. A shorter list with at
least `share_difficulty` witnesses earns credit.

The claim set records *who* claimed each witness. The miner's documented flow is
to submit a credit share and then extend the same list to `difficulty`, so a
miner must be allowed to reuse its own credited witnesses; that is the only way
a block candidate can exist while `share_difficulty` is below the block
difficulty. Another miner submitting the same list is refused, and a credit
submission that contains no new witness is refused outright instead of earning
credit. Credit is granted per witness the pool has not paid for before, so a
replayed list earns nothing. The node enforces single use chain-wide with its
own sparse Merkle set; the pool mirrors the rule so a replay is refused before
the node ever sees it.

`share_difficulty` is therefore a witness count, not an iteration count. The
persisted ledger field keeps its old name for compatibility.

The pool also re-derives the credit threshold from the miner's reported compute
rate and the analytic witness density `(1 / ln 2^63)^chain_length`, then clamps
it to the job's own difficulty. Estimating beats guessing, and the job's
difficulty always wins.

## Stratum

The legacy Stratum V1 adapter was removed. Stratum submits a nonce and a hash;
that cannot carry a witness list or a miner block authorization, so a Stratum
miner can never produce a block on this chain. Keeping the adapter would have
been a compatibility claim the code could not honor.

## Payout modes

SOLO, PROP, PPS, PPLNS, PPS+ and FPPS remain available. For a submission with
`k` credited witnesses against a block requirement of `D` and a reward basis of
`R`, the credited amount is `R * k / D` before the pool fee.

## Build and run

```bash
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings

# One-time pool identity. Refuses to overwrite; --force rotates the key.
./target/release/hyphen-pool-server keygen --output pool.key

./target/release/hyphen-pool-server \
    --network devnet \
    --node 127.0.0.1:3350 \
    --bind 0.0.0.0:3340 \
    --api-bind 0.0.0.0:8081 \
    --payout-mode solo \
    --share-difficulty 10 \
    --key-file pool.key \
    --pool-state-dir pool_state
```

On Windows use `.\target\release\hyphen-pool-server.exe` and a backtick for line
continuation.

`--key-file` must exist and contain exactly 32 bytes. `keygen` creates missing
parent directories and writes the key with mode 0600 on Unix; the server warns
if an existing key is readable by group or other. Omitting `--key-file` makes
the server generate an ephemeral key, so the pool identity changes on every
restart — that is only acceptable for a throwaway devnet.

`--payout-mode solo` needs no payout agent: each miner's authorized address
receives the coinbase. `--pool-wallet` is optional and defaults to the pool
key's public key in solo mode. `pool_state` is created automatically and holds
the accounting ledger. The node must expose its Template Provider on `--node`
(`127.0.0.1:3350` by default).

## Accounting API

The pool serves its ledger over HTTP. The explorer reads it from another origin,
so the grant is permissive while the data is not secret — it is already on chain
or derivable from it:

```text
GET /healthz                                    liveness for supervisors
GET /api/pool/info                              mode, pool fee, pool wallet
GET /api/pool/wallet/{wallet}/balance?limit=16  one wallet's ledger
```

`--api-bind` sets the listener (`0.0.0.0:8081` by default) and `--no-api`
disables it. `--api-tls-cert` plus `--api-tls-key` take a PEM certificate chain
and its private key and serve the same routes over HTTPS with HTTP/2; giving only
one of the two is a startup error, never a silent downgrade to plaintext.

Requests are bounded: 8 KiB of body, 32 KiB of headers, a 15-second deadline for
the complete request head, 512 concurrent connections. Balances answer with
`cache-control: no-store`, and the listener is closed — joined, not merely
signalled — before the process exits, so a restarted pool never finds its port
still held.

The API is served by Courierust's HTTP/1.1 + HTTP/2 stack. There is no router
framework and no service-layer stack in the pool's dependency graph.

## Payout link

The pool speaks to `hyphen-payout-agent` over loopback HTTP, also Courierust on
both ends: `POST /v1/health`, `POST /v1/submit`, `POST /v1/status`, with the
shared `--payout-token-file` secret in an `authorization: Bearer` header,
compared in constant time by the agent. Status codes carry the transport
outcome; the agent's own decision — including why a payment was refused — comes
back in the body with `ok` and `error`, and a protocol-version mismatch is
refused rather than misread.

## Protocol

- Block version: 5
- PoUW protocol: 3
- Template protocol: 5 (node to pool)
- Pool protocol: 6 (pool to miner)

## Limits

Not independently audited. Chain-wide single use is enforced by the node; the
pool's claim set is a stricter local view that protects its own ledger. If a
block is rejected after the pool credited it, the pool stays stricter than the
chain, which costs liveness, never soundness.