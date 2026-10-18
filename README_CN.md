# Hyphen Pool

Hyphen Pool 是 Hyphen 区块版本 5（PoUW v3）的独立矿池服务。它连接节点的模板协议，向
矿工下发签名的 Protocol v6 job，自行校验单次使用的 Cunningham 见证链，维护持久化结算
账本，并通过 Hyphen Wallet 的 payout agent 执行付款。

共识类型、哈希、wire 编码与节点协议在这里不再复制：hyphen-core、hyphen-crypto、
hyphen-pow、hyphen-transport 来自 `HyphenTeam/Hyphen` 的同级 `crates/` 目录。CI 与发布
工作流会先物化 `../Cargo.toml`、`../crates` 和 `../LICENSE`，再开始构建。矿池从配置派生
链身份，而不是钉死字面量。协议变更在同一个检出中同时验证两棵树，发布元数据记录基础链
commit。

## 份额语义

份额是一份见证列表，不是一个 nonce。对每次提交，矿池会：

1. 拒绝与 job 不一致的链长。
2. 拒绝其他矿工已在本矿池认领过的见证。
3. 用节点自己的谓词（verify_witnesses）校验整份列表。
4. 复算 witness_commitment(parent_commitment, height, witnesses) 并与矿工提交的承诺比对。

达到 difficulty 个见证的列表就是区块候选：矿池重建矿工签名过的那个区块头，验证其中的矿工
授权，把 pow_witnesses 装进区块并提交。见证数较少但不少于 share_difficulty 的列表只能获得
credit。

认领集合记录每个见证是*哪个矿工*认领的。矿工的标准流程是先交 credit 份额，再把同一份列表
扩展到 difficulty，所以必须允许矿工复用自己已记账的见证——否则当 share_difficulty 低于区块
难度时，区块候选永远无法成立。其他矿工提交同一份列表会被拒绝；credit 提交若不含任何新见证
则直接拒绝，不进入账本。credit 只按矿池此前未付过的见证计数，因此重放列表拿不到任何收益。
链级别的单次使用由节点用自己的稀疏 Merkle 集合强制执行；矿池镜像该规则，让重放在节点看到
之前就被拒绝。

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

## 结算 API

矿池通过 HTTP 提供账本查询。Explorer 从另一个 origin 读取，因此授权是宽松的，但这里的数据
并非机密——它们已经在链上，或可由链上数据推导：

```text
GET /healthz                                    给监管进程的存活探测
GET /api/pool/info                              模式、矿池费率、矿池钱包
GET /api/pool/wallet/{wallet}/balance?limit=16  单个钱包的账本
```

`--api-bind` 指定监听地址（默认 `0.0.0.0:8081`），`--no-api` 完全关闭。`--api-tls-cert` 与
`--api-tls-key` 接收 PEM 证书链及其私钥，用 HTTPS + HTTP/2 提供同样的路由；只给其中一个是
启动错误，绝不会静默降级为明文。

请求有明确上限：请求体 8 KiB、头部 32 KiB、完整请求头 15 秒绝对期限、512 个并发连接。余额
响应带 `cache-control: no-store`；进程退出前监听器会被关闭并 join（而不是只发信号），因此
重启的矿池不会发现端口仍被占用。

API 由 Courierust 的 HTTP/1.1 + HTTP/2 栈提供，依赖图中没有路由框架，也没有 service layer。

## 付款链路

矿池通过 loopback HTTP 与 `hyphen-payout-agent` 通信，两端都是 Courierust：
`POST /v1/health`、`POST /v1/submit`、`POST /v1/status`，共享密钥来自 `--payout-token-file`，
放在 `authorization: Bearer` 头中，由 agent 在恒定时间内比较。状态码承载传输层结果；agent
自身的判定（包括拒绝付款的原因）通过响应体的 `ok` 与 `error` 返回；协议版本不一致会直接
拒绝，而不是被误读。

## 协议

- 区块版本：5
- PoUW 协议：3
- 模板协议：5（节点到矿池）
- 矿池协议：6（矿池到矿工）

## 局限

尚未经过独立审计。链级别的单次使用由节点保证；矿池的认领集合是更严格的本地视图，用于保护
自己的账本。若区块在矿池记账后被节点拒绝，矿池只会比链更严格——损失的是时效性，不是安全性。