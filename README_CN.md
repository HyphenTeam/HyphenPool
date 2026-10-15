# Hyphen Pool

Hyphen Pool 是 Hyphen 区块版本 5（PoUW v3）的独立矿池服务。它连接节点的模板协议，向
矿工下发签名的 Protocol v6 job，自行校验单次使用的 Cunningham 见证链，维护持久化结算
账本，并通过 Hyphen Wallet 的 payout agent 执行付款。

共识类型、哈希、wire 编码与节点协议在这里不再复制。hyphen-core、hyphen-crypto、
hyphen-pow、hyphen-transport 以路径依赖引入，且矿池从配置派生链身份，而不是钉死字面量。

## 份额语义

份额是一份见证列表，不是一个 nonce。对每次提交，矿池会：

1. 拒绝与 job 不一致的链长。
2. 拒绝本矿池已经认领过的任何见证。
3. 用节点自己的谓词（verify_witnesses）校验整份列表。
4. 复算 witness_commitment(parent_commitment, height, witnesses) 并与矿工提交的承诺比对。

达到 difficulty 个见证的列表就是区块候选：矿池重建矿工签名过的那个区块头，验证其中的矿工
授权，把 pow_witnesses 装进区块并提交。见证数较少但不少于 share_difficulty 的列表只能获得
credit。

credit 只按矿池此前未付过的见证计数，因此先提交前缀、再提交完整列表无法重复记账，重放列表
也拿不到任何收益。链级别的单次使用由节点用自己的稀疏 Merkle 集合强制执行；矿池镜像该规则，
让重放在节点看到之前就被拒绝。

因此 share_difficulty 表示见证数量，而非迭代次数。持久化账本字段保留旧名只为兼容。

矿池还会根据矿工上报的算力与解析式见证密度 (1 / ln 2^63)^chain_length 推导 credit 门槛，
再按 job 自身的难度做上限收敛。会估算是比猜更好，且 job 难度永远优先。

## Stratum

旧 Stratum V1 适配器已移除。Stratum 的提交模型是 nonce 加哈希，无法携带见证列表或矿工区块
授权，因此 Stratum 矿工在本链上永远无法产出区块。留着它等于给出一个代码无法兑现的兼容承诺。

## 结算模式

SOLO、PROP、PPS、PPLNS、PPS+、FPPS 均保留。对某次提交，credited 见证数为 k、区块需求为 D、
奖励基数为 R 时，扣矿池费前的记账额为 R * k / D。

## 构建与运行

```powershell
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings

.\target\release\hyphen-pool-server.exe --network devnet --node 127.0.0.1:3350 `
    --bind 0.0.0.0:3340 --pool-state-dir pool_state
```

## 协议

- 区块版本：5
- PoUW 协议：3
- 模板协议：5（节点到矿池）
- 矿池协议：6（矿池到矿工）

## 局限

尚未经过独立审计。链级别的单次使用由节点保证；矿池的认领集合是更严格的本地视图，用于保护
自己的账本。若区块在矿池记账后被节点拒绝，矿池只会比链更严格——损失的是时效性，不是安全性。