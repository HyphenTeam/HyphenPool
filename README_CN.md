# Hyphen Pool

[English](README.md)

Hyphen Pool 是 Hyphen 区块版本 3 的独立科学计算矿池。它连接节点模板协议 v3，向矿工提供签名的 Pool Protocol v5 job，独立复算科学检查点和完整区块工作，持久化结算账本，并通过 Hyphen Wallet 的 payout agent 执行付款。

## 科学工作验证

Pool v5 不接受低哈希。每次提交都会重建绑定矿工身份的区块头，并复算确定性的 64x64 Q12 二维扩散 PDE。

- 检查点的迭代数低于区块要求，不携带区块授权。
- 完整结果必须执行等于区块难度的迭代数，写入 pow_commitment，并包含绑定完整区块头和奖励公钥的矿工签名。
- 只有承诺、授权、链身份、job 新鲜度和交易绑定全部通过后才向节点提交区块。
- 旧 Stratum 无法携带科学承诺和 frozen-v3 授权，因此明确拒绝 PoUW 提交。

BLAKE3 仍用于消息、回执、交易和承诺的完整性，不作为工作接受目标。

协议标识为 PoUW v1，但检查点只证明指定的确定性 PDE，不证明用户出资的 AetherCompute 任务、外部科学价值或简洁验证。Pool 的计算速率按每个单元更新 7 次规范算术操作计量，所有检查点都限制在共识最大 4096 次迭代以内。

## 结算

SOLO、PROP、PPS、PPLNS、PPS+ 和 FPPS 模式仍可用。为了兼容已有账本，持久化字段仍名为 share_difficulty；Pool v5 中该值实际表示已验证的检查点迭代数。

检查点迭代数为 d、区块迭代数为 D、奖励基数为 R、费率为 b 个 basis points 时：

```text
gross = floor(R * d / D)
net   = floor(gross * (10000 - b) / 10000)
```

Pool 对矿工、序号、前一回执、提交承诺和结果签署链式回执。它只能提供防篡改证据，不能证明 Pool 偿付能力或公共数据可用性。

## 构建与运行

```powershell
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
.\target\release\hyphen-pool-server.exe keygen --output .\pool.key
```

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

共享付款模式还必须配置正确网络的钱包、loopback payout agent、认证 token、最小付款额和确认策略。节点 RPC 和付款服务应只位于可信主机。

## 兼容性

- 节点模板协议：3
- Pool 协议：5
- 区块版本：3
- PoUW 协议：1
- 科学计算固定向量：25078c250c5b44211bbf0fea60e90ac7024df6ff94d154161852fdd72684e524

Miner 和 Pool 会拒绝共识参数哈希或 genesis hash 不匹配的连接。RustBinary 使用有限长度、固定宽度、小端并拒绝尾随字节的编码。已有账本通过显式版本迁移读取；不可读状态会报错，不会静默覆盖。

Pool 不是无信任系统：它可在创建 job 前省略交易、拒绝服务，并控制共享奖励钱包。本软件尚未经过独立经济、共识或付款审计。

## 许可证

Hyphen Pool 使用 PolyForm Strict License 1.0.0，完整条款见 [LICENSE](LICENSE)。
