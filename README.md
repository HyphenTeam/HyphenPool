# Hyphen Pool

[中文说明](README_CN.md)

Hyphen Pool is the independent pool server for the Hyphen base chain. It
connects to the node template protocol, serves signed Pool Protocol v3 jobs,
validates shares, keeps durable accounting, and coordinates automatic shared
payouts through the separately operated `hyphen-payout-agent`.

## What is implemented

- SOLO, PROP, PPS, PPLNS, PPS+, and FPPS accounting.
- Signed miner and pool messages, chain-identity checks, miner-authorized full
  blocks, VarDiff, and hash-chained share receipts.
- Durable accounting with legacy-state migration and backup recovery.
- Automatic payout lifecycle: `Reserved -> Submitted -> Confirmed`.
- Loopback-only payout-agent connection, token authentication, wallet identity
  verification, idempotent intent IDs, rebroadcast, and confirmation tracking.

The pool is not trustless. It can still choose or omit transactions before
issuing a v3 job, can refuse service, and controls the shared reward wallet.
Receipt integrity is not proof of solvency. Useful-Work is disabled.

## Build and start

```bash
cargo build --release --locked
./target/release/hyphen-pool-server keygen --output ./pool.key
```

SOLO devnet:

```bash
./target/release/hyphen-pool-server \
  --network devnet \
  --node 127.0.0.1:3350 \
  --key-file ./pool.key \
  --bind 127.0.0.1:3340 \
  --api-bind 127.0.0.1:8081 \
  --share-difficulty 100 \
  --payout-mode solo \
  --pool-state-dir ./pool_state
```

Shared modes additionally require a network-correct `--pool-wallet`, a
loopback `--payout-agent`, and `--payout-token-file`. The payout agent binary is
released by Hyphen Wallet because it owns transaction construction and signing.

```bash
./target/release/hyphen-pool-server \
  --network devnet \
  --node 127.0.0.1:3350 \
  --key-file ./pool.key \
  --payout-mode pplns \
  --pool-wallet '<pool-hy1-address>' \
  --payout-agent 127.0.0.1:38401 \
  --payout-token-file ./payout.token \
  --minimum-payout-atomic 1000000 \
  --payout-confirmations 20
```

Keep the node RPC and payout agent on a trusted host. The accounting API is
operational data and should not be exposed without an authenticated reverse
proxy.

## Accounting mathematics

For one share with difficulty `d`, network difficulty `D`, reward basis `R`,
and fee `b` basis points, PPS/FPPS credit is integer arithmetic:

```text
gross = floor(R d / D)
net   = floor(gross (10000-b) / 10000).
```

PPS uses block subsidy as `R`; FPPS uses subsidy plus declared fees. PPS+ pays
the subsidy component per share and allocates actually found transaction fees
over the PPLNS window. Integer truncation stays in the pool ledger; it must be
included in economic audits.

For PROP/PPLNS settlement, let eligible weights be `w_i` and distributable
reward be `A`. The intended proportional allocation is

```text
a_i = floor(A w_i / sum_j w_j),
```

with deterministic remainder handling in the accounting implementation. PPLNS
uses the newest trailing share weights until their sum reaches the configured
multiple of current block difficulty; old work outside that window receives
zero for that block.

For each wallet, the payout state maintains

```text
L = pending + reserved + paid.
```

Reservation moves `x` from pending to reserved, submission changes only the
record status, and confirmation moves the same `x` from reserved to paid.
Therefore each valid transition preserves `L`. The implementation persists the
new state before returning success and binds one `intent_id` to one transaction
hash. Repeating submit or confirm with the same binding is idempotent; changing
the hash is rejected. This prevents ordinary crash retries from double-counting
payment, but it does not eliminate chain reorg risk, wallet compromise, or an
insolvent operator.

Share receipts use a signed hash chain. Under collision resistance and
signature unforgeability, editing an accepted historical share is detectable
from the later chain head. A miner still needs the receipt data; there is no
public receipt data-availability layer yet.

## Operations

Back up `pool.key`, the pool accounting directory, payout-agent state, and the
pool wallet seed separately. Never copy a live state directory as if it were an
atomic backup. Monitor pending, reserved, and paid amounts independently; an
increasing reserved balance means broadcasts or confirmations are stalled.

Use `hyphen-pool-server --help` for the complete current CLI and `/healthz` for
local health. A share count does not prove that a block or payout occurred.

## CI and releases

CI runs formatting, strict Clippy, tests, and a locked release build. Successful
CI on `main` triggers Linux, Windows, and macOS packaging with build/debug
metadata and SHA-256 files, followed by a commit-bound GitHub prerelease.

This software is AGPL-3.0 licensed. Protect `pool.key`, the payout token, wallet
seed, and state backups.
