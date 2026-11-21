# Pool operation and reward recovery

## SOLO settlement

The miner checks both payout public keys before connecting. The pool performs the same Ristretto checks on the signed login and on text addresses. Its accounting ledger indexes payouts by spend key. Registrations using an existing spend key must supply the same view key. A ledger with conflicting historical pairs needs reconciliation against the original payout addresses before it can reopen.

Start `hyphen-pool-server --network neural-devnet --payout-mode solo` with a HYN3 node serving the Template Provider. Give the ledger its own directory (`--pool-state-dir pool_state/neural-v3`). Set `--key-file` to a persistent pool key. Each signed nonce is verified against the challenge, and a full candidate is saved before submission. A successful block pays the miner’s authorized receiving keys directly.

| Accounting endpoint | Contents |
| --- | --- |
| `GET /healthz` | Service liveness |
| `GET /api/pool/info` | Mode, fee and advertised wallet |
| `GET /api/pool/wallet/{wallet}/balance?limit=16` | Credited shares, rewards, reserved and paid amounts, recent payouts |

Bind the API with `--api-bind`. For HTTPS provide both `--api-tls-cert` and `--api-tls-key`. The node template and miner protocols use binary frames. The miner port accepts the Hyphen protocol.

Stop the pool before copying its ledger. Inspect a copy with `hyphen-pool-server block-credits --state-dir COPY BLOCK_HASH`. The pool checks canonical block hashes after startup and reconciles a pending submission with the node. Compare `settlement` with the current canonical hash and the receiving wallet’s scan.

## 中文说明

神经开发网采用 SOLO 模式。矿工在候选区块中签名授权收款地址，矿池复算神经分数和内存门槛，节点验块后直接支付奖励。重启时使用原密钥与 HYN3 账本目录，用钱包扫描和节点的规范区块哈希核对奖励。
