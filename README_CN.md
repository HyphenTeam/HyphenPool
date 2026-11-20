# Hyphen Pool

[English](README.md)

Hyphen Pool 将矿工连接到 Hyphen 节点，验证提交的工作量，并将奖励记入持久化账本。SOLO 模式直接通过区块奖励向矿工支付；共享模式通过单独运行的 Hyphen Wallet 付款代理完成支付。

## 启动本地矿池

先启动开发网节点，使模板服务监听 `127.0.0.1:3350`。首次运行时生成矿池身份密钥，重启时复用该密钥和账本目录。

```sh
cargo run --release --locked --bin hyphen-pool-server -- keygen --output pool.key
cargo run --release --locked --bin hyphen-pool-server -- --network devnet --node 127.0.0.1:3350 --bind 127.0.0.1:3340 --api-bind 127.0.0.1:8081 --key-file pool.key --pool-state-dir pool_state --payout-mode solo
```

[记账、付款与重启恢复](wiki/Operations.md) · [Hyphen 节点](https://github.com/HyphenTeam/Hyphen)

## 许可证

[PolyForm Strict License 1.0.0](LICENSE)
