# Accounting and payouts · 矿池记账与支付

## Choose a settlement mode

| Mode | Basis for settlement |
| --- | --- |
| SOLO | The winning miner authorizes a coinbase to its own reward address. |
| PROP | The pool divides the block reward by credited work in the round. |
| PPLNS | The pool divides a block reward among the most recent weighted shares in the configured window. |
| PPS, PPS+, FPPS | The pool credits shares under its selected reward and fee policy and funds the payout wallet. |

On the standard devnet, `--share-difficulty` counts witnesses. The pool verifies them, tracks ownership and credits each new witness once. The miner may extend its own credited work to a full block. On `neural-devnet` run SOLO. A candidate and its payout information are persisted before submission to the node. Settlement and candidate cleanup share a ledger transaction so a restart can reconcile the outstanding candidate.

## Run shared payouts

Bind the wallet agent to a loopback address. Configure a dedicated pool seed, a bearer token shared with the pool and a persistent directory for the agent’s state. Supply the matching `--pool-wallet`, `--payout-agent`, `--payout-token-file` and `--payout-mode` options to the pool. Each miner must authorize the shared reward address. Set `--minimum-payout-atomic`, `--maximum-payout-atomic`, `--payout-confirmations` and `--payout-interval-secs` according to the pool’s settlement policy. Use `--pplns-window-factor` to configure the PPLNS window. [Wallet agent configuration](https://github.com/HyphenTeam/HyphenWallet/wiki/Operations#shared-pool-payout-agent)

The pool reserves credit for a payout intent. The agent signs, saves the transaction and returns its hash. The pool marks the reserved amount paid after the configured canonical confirmations. Preserve the ledger, identity key, agent state and seed across restarts. Stop the services before making a file-level backup. Legacy ledgers retain recorded balances on migration. Earlier formats omitted historical witness IDs, so ownership of those older claims cannot be reconstructed.

| Accounting endpoint | Contents |
| --- | --- |
| `GET /healthz` | Service liveness |
| `GET /api/pool/info` | Mode, fee and advertised wallet |
| `GET /api/pool/wallet/{wallet}/balance?limit=16` | Credited shares, rewards, reserved and paid amounts, recent payouts |

Bind the API with `--api-bind`. For HTTPS provide both `--api-tls-cert` and `--api-tls-key`. The node template and miner protocols use binary frames. The miner port accepts the Hyphen protocol.

The worker checks one previously confirmed intent per payout interval. When the agent reports fewer than the required confirmations, the original amount moves from paid back to reserved. The agent can resubmit its saved bytes. Confirmation restores the paid amount once. Newly confirmed intents remain in the reconciliation index after the visible history is trimmed. Migration indexes the confirmed records still present in the previous ledger. In a local contract-devnet fork, the same 1,000,000,000-unit payout confirmed at heights 16 and 22 on successive canonical branches, with a pool restart between confirmations.

Each newly settled block now stores its original fee, reward recipient and exact increases in pending credit by miner in the same database transaction. Inspect a stopped ledger copy with `hyphen-pool-server block-credits --state-dir COPY BLOCK_HASH`. Opening the copy allows redb to recover an interrupted write. `pending_by_miner` lists the amounts credited at settlement. SOLO credits appear in `settlement` as a direct coinbase. A block record describes the original distribution even if the block later leaves the chain. Compare its hash and height with the canonical node. Historical databases can contain multiple miners paid to one wallet and lack the individual split for those blocks.

Upgrade the node before the pool. The pool requests canonical hashes from the node's Template Provider in batches under one chain view. Each page checks the scan's tip hash. Replacing a settled block reverses the finder count, direct SOLO reward or shared miner credits and pool fee. Reattaching the block restores its original distribution. PROP rounds close when a block is first settled. A replacement uses the work in its own round. PPS credits remain earned for accepted shares.

Existing reservations and signed payments retain their intent. If the detached credit exceeds a miner's remaining balance, the wallet API reports the shortfall in `reward_deficit_atomic`. New credit for that miner offsets the shortfall before it becomes available for another payment. A historical shared block whose exact allocation is missing requires operator reconciliation if it detaches. The worker defers new reservations while that discrepancy or a node lookup error persists.

When the node accepts a pool candidate at an already settled height, reversal of the previous settlement, credit of the replacement and removal of the pending candidate share one database commit. A failure leaves the candidate available for recovery. Processing the node's acceptance invalidates the previous scan before writing the settlement. New reservations wait for a successful canonical-hash scan after that settlement attempt, including when it fails.

In a local two-fork PPLNS run, the original block at height 16 left the chain and later returned. The three miners recovered exactly `41520054991664`, `12145322208445` and `45333121266406` atomic units. The pool recovered a fee of `999984832995`. Both restarted nodes agreed at height 26 and located the original payout at height 16. The record is `target/payment-fork-86459itt/result.json` in the node workspace.

## 中文说明

先升级节点，再升级矿池。矿池从模板服务分批读取规范块哈希，逐页核对同一链顶。出块奖励脱链时撤销出块计数、SOLO 直付或共享分配及矿池费用。原块重新接入时恢复原分配。PROP 在首次结算时关闭该轮，替换块按自身轮次计算。PPS 按已接受份额计酬。已有付款意图继续跟踪；如矿工待付不足以冲抵脱链奖励，API 的 `reward_deficit_atomic` 显示差额，后续收入优先填补。发现旧共享奖励脱链且缺少分配明细时，矿池暂停新预留，需根据外部账目核查。

每个付款周期另查一笔历史确认记录。确认数降至阈值以下时，原付款从已付退回预留，代理可重新广播原签名交易。合约开发网实测中，原付款在高度 16 脱链，矿池重启后保留预留状态，同一哈希在高度 22 再确认。迁移只能为旧账本仍保存的确认记录建立索引。

节点接受同高度替换块时，矿池在同一数据库事务中冲销旧块、入账替换块并清除候选。事务失败后可重启并重试该候选。矿池在写入结算前使旧对账结果失效。即使入账发生错误，新预留也须等待受影响高度重新核验通过。

本地三矿工 PPLNS 连续两次换链后，原高度 16 奖励重新接入。三人原分配合计 `98998498466515` 原子单位，矿池费用 `999984832995`，均逐项恢复。两端分别重启后链顶同为高度 26，原付款在高度 16 确认。

新版按块哈希保存原始结算和逐矿工的待付增加额，可在停机副本上用 `block-credits` 查看。`settlement` 记录 SOLO 直接奖励及矿池费用，`pending_by_miner` 给出共享分配明细。多个矿工共用一个收款地址时，旧版钱包级汇总可能缺少重建个人份额所需的数据。

SOLO 将区块奖励直接付给胜出矿工。PROP 按本轮计入的工作量分配，PPLNS 按最近窗口内的工作量分配。PPS、PPS+、FPPS 根据各自的奖励与手续费政策给份额记账，由矿池钱包承担兑付。标准开发网的份额难度按见证数量计量，每个新增见证只计一次；神经工作量开发网使用 SOLO。

共享模式先在回环地址运行钱包付款代理，再给矿池传入对应的 `--pool-wallet`、`--payout-agent`、`--payout-token-file` 和模式。设置付款上下限、确认数和检查间隔；PPLNS 窗口由 `--pplns-window-factor` 控制。矿工需显式授权共享结算地址。

矿池先预留余额，代理签名并持久化付款，达到确认数后矿池将预留金额转为已付。重启时复用矿池密钥、账本、代理状态和种子。文件级备份应在停止服务后执行。旧账本可以迁移已记录的余额，但无法还原旧格式未保存的历史见证归属。通过上表的 HTTP 接口核对付款状态。
