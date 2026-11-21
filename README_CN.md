# Hyphen Pool

[English](README.md) · [矿池运行指南](https://github.com/HyphenTeam/HyphenPool/wiki/Operations#中文说明)

Hyphen Pool 向矿工分发神经挖矿任务，复算 nonce 的两阶段工作量，持久化候选区块后提交给节点。奖励直接支付给矿工授权的地址。

## 启动本地矿池

先启动开发网节点，使模板服务监听 `127.0.0.1:3350`。首次运行时生成矿池身份密钥，重启时复用该密钥和账本目录。

```sh
cargo run --release --locked --bin hyphen-pool-server -- keygen --output pool.key
cargo run --release --locked --bin hyphen-pool-server -- --network neural-devnet --node 127.0.0.1:3350 --bind 127.0.0.1:3340 --api-bind 127.0.0.1:8081 --key-file pool.key --pool-state-dir pool_state/neural-v3 --payout-mode solo
```

[记账、付款与重启恢复](wiki/Operations.md) · [Hyphen 节点](https://github.com/HyphenTeam/Hyphen)

## 许可证

[PolyForm Strict License 1.0.0](LICENSE)
