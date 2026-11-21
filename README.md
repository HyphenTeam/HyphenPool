# Hyphen Pool

[简体中文](README_CN.md) · [Mining pool documentation](https://github.com/HyphenTeam/HyphenPool/wiki)

Hyphen Pool serves neural mining jobs, verifies the nonce and persists the candidate before submitting it. The node pays the winning miner’s authorized address directly.

## Start a local pool

Start a devnet node with its Template Provider listening on `127.0.0.1:3350`. Generate the pool identity once and keep the same key and ledger directory across restarts.

```sh
cargo run --release --locked --bin hyphen-pool-server -- keygen --output pool.key
cargo run --release --locked --bin hyphen-pool-server -- --network neural-devnet --node 127.0.0.1:3350 --bind 127.0.0.1:3340 --api-bind 127.0.0.1:8081 --key-file pool.key --pool-state-dir pool_state/neural-v3 --payout-mode solo
```

[Accounting, payouts and recovery](wiki/Operations.md) · [Hyphen node](https://github.com/HyphenTeam/Hyphen)

## License

[PolyForm Strict License 1.0.0](LICENSE)
