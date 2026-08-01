# Hyphen Pool

[中文](README_CN.md)

Hyphen Pool is the independent scientific-work pool server for Hyphen block version 3. It connects to node template protocol v3, serves signed Pool Protocol v5 jobs, independently recomputes scientific checkpoints and full block work, maintains durable accounting, and coordinates payouts through Hyphen Wallet's payout agent.

## Scientific-work verification

Pool v5 does not accept low hashes. For each miner submission the pool reconstructs the miner-bound header and recomputes the deterministic 64x64 Q12 diffusion PDE.

- A checkpoint uses fewer iterations than the block requirement and carries no block authorization.
- A full result uses exactly the block difficulty, updates pow_commitment, and must include a miner signature binding the complete header and reward keys.
- The pool submits a block only after commitment, authorization, chain identity, job freshness, and transaction binding all pass.
- Legacy Stratum cannot carry these commitments and frozen-v3 authorization, so it is rejected for PoUW submissions.

BLAKE3 remains in message, receipt, transaction and commitment integrity paths. It is not used as the work acceptance target.

The protocol identifier is PoUW v1, but checkpoints prove only the specified deterministic PDE. They are not proofs of a user-funded AetherCompute task, external scientific utility, or succinct verification. Pool compute-rate accounting uses seven specified arithmetic operations per cell update and caps every checkpoint at the consensus maximum of 4096 iterations.

## Accounting

SOLO, PROP, PPS, PPLNS, PPS+ and FPPS modes remain available. The persisted field name share_difficulty is retained for ledger compatibility, but in Pool v5 its value is a verified checkpoint iteration count.

For checkpoint iterations d, block iterations D, reward basis R, and fee b basis points:

```text
gross = floor(R * d / D)
net   = floor(gross * (10000 - b) / 10000)
```

The pool signs a chained receipt over the miner, sequence, previous receipt, submission commitment and result. This provides tamper evidence, not proof of solvency or public data availability.

## Build and run

```powershell
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
.\target\release\hyphen-pool-server.exe keygen --output .\pool.key
```

SOLO devnet:

```powershell
.\target\release\hyphen-pool-server.exe `
  --network devnet `
  --node 127.0.0.1:3350 `
  --key-file .\pool.key `
  --bind 127.0.0.1:3340 `
  --api-bind 127.0.0.1:8081 `
  --share-difficulty 32 `
  --payout-mode solo `
  --pool-state-dir .\pool_state
```

Shared payout modes additionally require a network-correct pool wallet, a loopback payout agent, an authentication token file, minimum payout and confirmation policy. Keep node RPC and payout services on a trusted host.

## Compatibility

- Node template protocol: 3
- Pool protocol: 5
- Block version: 3
- PoUW protocol: 1
- Fixed scientific vector: 25078c250c5b44211bbf0fea60e90ac7024df6ff94d154161852fdd72684e524

Miner and pool reject mismatched consensus parameter hashes and genesis hashes. RustBinary uses bounded fixed-width little-endian encoding and rejects trailing bytes. Existing accounting ledgers use an explicit versioned migration and refuse unreadable state instead of silently replacing it.

The pool is not trustless. It can omit transactions before creating a job, refuse service, and control a shared reward wallet. This software has not received an independent economic, consensus or payout audit.

## License

Hyphen Pool is licensed under the PolyForm Strict License 1.0.0. See [LICENSE](LICENSE).
