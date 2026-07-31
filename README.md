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

## Protocol compatibility and fail-closed startup

Consensus-facing local types must remain synchronized with the main chain.
Binary encoding uses RustBinary 0.1.2 with the same bounded, fixed-width,
little-endian, trailing-byte-rejecting profile as Hyphen. The legacy
`--standalone` embedded chain is disabled and returns an error. Production
startup requires a real main-chain Template Provider. If both the primary and
backup ledgers fail strict decoding, startup stops instead of silently replacing
balances with an empty ledger. Format fallback is never accepted in a hash or
signature path.

## CI and releases

CI runs formatting, strict Clippy, tests, and a locked release build. Successful
CI on `main` triggers Linux, Windows, and macOS packaging with build/debug
metadata and SHA-256 files, followed by a commit-bound GitHub prerelease.

This software is AGPL-3.0 licensed. Protect `pool.key`, the payout token, wallet
seed, and state backups.

---

<!-- hyphen-bilingual-chinese -->

# 中文版

# Hyphen Pool

[English](README.md)

Hyphen Pool 是独立矿池服务器。它从主链节点获取模板，向矿工发送签名的 Pool Protocol v3 job，验证 share，持久化结算账本，并通过单独运行的 `hyphen-payout-agent` 自动完成共享收益付款。

## 当前实现和信任边界

已经实现 SOLO、PROP、PPS、PPLNS、PPS+、FPPS；签名协议、链身份检查、矿工完整区块授权、VarDiff、share 回执链；账本损坏备份恢复和旧格式迁移；以及 `Reserved -> Submitted -> Confirmed` 自动付款状态机。

共享模式强制配置 loopback payout agent 和 token，Pool 会校验 agent 使用的池钱包地址。Agent 将 `intent_id` 固定到已签名交易，可在崩溃后重发，并等待规定确认数以后才让 Pool 增加 `total_paid`。

它仍不是无信任矿池。Pool v3 目前可以在发 job 前选择或遗漏交易，可以拒绝矿工，也控制共享奖励钱包。签名回执不能证明偿付能力；Useful-Work 仍然关闭。

## 构建和 SOLO 启动

```powershell
cargo build --release --locked
.\target\release\hyphen-pool-server.exe keygen --output .\pool.key
```

```powershell
.\target\release\hyphen-pool-server.exe `
  --network devnet `
  --node 127.0.0.1:3350 `
  --key-file .\pool.key `
  --bind 127.0.0.1:3340 `
  --api-bind 127.0.0.1:8081 `
  --share-difficulty 100 `
  --payout-mode solo `
  --pool-state-dir .\pool_state
```

共享模式还必须提供 `--pool-wallet`、`--payout-agent 127.0.0.1:38401`、`--payout-token-file`、最小付款额和确认数。签名交易属于钱包职责，所以 agent 可执行文件由 Hyphen Wallet 仓库发布。

## 收益公式与付款不变量

一份 share 的难度为 `d`，区块难度为 `D`，计价奖励为 `R`，费率为 `b` 个 basis points，则 PPS/FPPS 使用确定性整数公式：

```text
gross=floor(Rd/D)
net=floor(gross(10000-b)/10000).
```

PPS 的 `R` 是基础区块奖励；FPPS 的 `R` 包含奖励与声明手续费。PPS+ 按 share 支付基础奖励，再把实际找到区块的手续费按 PPLNS 窗口分配。整数除法截断会形成 dust，经济审计必须把它计入，不能用浮点近似替代账本结果。

PROP/PPLNS 中，合格 share 权重为 `w_i`，可分配金额为 `A`：

```text
a_i=floor(Aw_i/sum_j w_j).
```

PPLNS 从最新 share 反向取权重，直到总权重达到“当前区块难度乘窗口因子”；窗口外旧 share 对这个区块分配为零。

对一个收款钱包，记：

```text
L=pending+reserved+paid.
```

Reserve 把同一个 `x` 从 pending 移到 reserved；Submitted 只改变状态和绑定 tx hash；达到确认数后 Confirmed 把同一个 `x` 从 reserved 移到 paid。所以每个合法转换都保持 `L` 不变。重复提交相同 `intent_id -> tx_hash` 是幂等的，试图替换 hash 会被拒绝。这解决了常规崩溃重试导致的重复记账，不解决链深度 reorg、钱包被盗或运营者资不抵债。

Share 回执链把池公钥、矿工公钥、序号、前一回执、submission hash 和 result hash 一起哈希并由池签名。改动历史需要制造哈希碰撞或签名伪造；但矿工仍需保存回执，目前没有公共数据可用性层。

## 运维要点

分别备份 `pool.key`、Pool 账本目录、payout-agent 状态和池钱包 seed。不要把运行中的目录复制品当成原子备份。监控 pending、reserved、paid 三类余额；reserved 持续增长表示广播、节点连接或确认跟踪发生故障。

完整参数以 `hyphen-pool-server --help` 为准。`/healthz` 只说明进程健康；share 增长不证明已找到区块或已经付款。Accounting API 不应直接暴露公网。

## 协议兼容性与启动失败关闭

面向共识的本地类型必须与 Hyphen 主链保持同步。二进制编码使用 RustBinary 0.1.2，
配置与主链相同：有界、固定宽度、小端并拒绝尾随字节。旧 `--standalone` 内置链已
禁用并返回错误，生产启动必须连接真实主链 Template Provider。主账本和备份均无法
严格解码时，启动会停止，不会以空账本静默替换余额。格式回退绝不能进入哈希或签名路径。

## CI 和 Release

CI 执行格式检查、严格 Clippy、全部测试和锁定依赖的 release build。只有 `main` 的 CI 成功后才自动构建 Linux、Windows、macOS 包，附提交号、工具链、调试信息和 SHA-256，并创建 commit-bound prerelease。

本仓库使用 PolyForm Strict License 1.0.0。`pool.key`、payout token、钱包 seed 和状态备份都属于敏感数据。
