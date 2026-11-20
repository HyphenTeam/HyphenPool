# HyphenPool

HyphenPool distributes mining jobs, verifies shares and records rewards. The settlement mode determines whether the winning miner receives the block reward directly or the pool credits miners and pays them from a shared wallet.

- [Settlement modes](Operations.md#choose-a-settlement-mode) describes SOLO, PROP, PPLNS, PPS, PPS+ and FPPS accounting.
- [Shared payouts](Operations.md#run-shared-payouts) covers wallet-agent configuration, confirmation depth, ledger recovery and reconciliation after a chain reorganization.

## 中文指南

矿池负责分发挖矿任务、验证矿工提交的份额并记录收益。SOLO 模式将区块奖励直接支付至获胜矿工的地址。共享结算模式由矿池记账，再通过钱包代理付款。[矿池记账与支付指南](Operations.md#中文说明)介绍结算方式、付款配置，以及链重组后的账目核对。
