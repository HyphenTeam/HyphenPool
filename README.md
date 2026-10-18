# Hyphen Pool

Hyphen Pool is the independent mining-pool server for Hyphen block version 5
(PoUW v3). It connects to the node's template protocol, serves signed Protocol v6
jobs to miners, verifies single-use Cunningham witness chains itself, keeps
durable accounting, and drives payouts through Hyphen Wallet's payout agent.

Consensus types, hashing, the wire profile, and the node protocol are not copied
here. `hyphen-core`, `hyphen-crypto`, `hyphen-pow`, and `hyphen-transport` are
consumed from the public Hyphen revision
`576bc67d972d1156fbabb1ddf579104d5ff2ff88` pinned in `Cargo.toml` and
`Cargo.lock`, and the pool derives the chain identity from its configuration
instead of pinning literals. There is no path dependency on a base-chain
checkout: CI builds this repository from a clean clone. A protocol change is a
coordinated revision bump followed by the compatibility checks below.

## Share semantics

A share is a witness list, not a nonce. For every submission the pool:

1. Rejects a chain length that differs from the job's.
2. Rejects any witness already claimed on this pool.
3. Runs the node's own predicate (`verify_witnesses`) over the list.
4. Recomputes `witness_commitment(parent_commitment, height, witnesses)` and
   compares it with the commitment the miner submitted.

A list of `difficulty` witnesses is a block candidate: the pool reconstructs the
exact header the miner signed, verifies the miner authorization inside it,
assembles the block with `pow_witnesses`, and submits it. A shorter list with at
least `share_difficulty` witnesses earns credit.

Credit is granted per witness the pool has not paid for before, so submitting a
prefix and then the full list cannot be double counted, and a replayed list earns
nothing. The node enforces single use chain-wide with its own sparse Merkle set;
the pool mirrors the rule so a replay is refused before the node ever sees it.

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

```powershell
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings

.\target\release\hyphen-pool-server.exe --network devnet --node 127.0.0.1:3350 `
    --bind 0.0.0.0:3340 --pool-state-dir pool_state
```

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