use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::accounting::{AccountingError, PayoutRecord, PayoutStatus, PoolAccounting};
use crate::primitives::hex_decode;

const PROTOCOL_VERSION: u32 = 1;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct PayoutWorkerConfig {
    pub minimum_payout_atomic: u64,
    pub maximum_payout_atomic: u64,
    pub required_confirmations: u64,
    pub interval: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum AgentTransactionStatus {
    Unknown,
    Mempool,
    Confirmed {
        block_hash_hex: String,
        block_height: u64,
        confirmations: u64,
    },
}

#[derive(Debug, Deserialize)]
struct AgentResponse {
    version: u32,
    ok: bool,
    error: String,
    wallet_address: String,
    fee_atomic: u64,
    intent_id: String,
    tx_hash: String,
    status: Option<AgentTransactionStatus>,
}

#[derive(Debug, Serialize)]
struct HealthRequest<'a> {
    version: u32,
    token: &'a str,
    method: &'static str,
}

#[derive(Debug, Serialize)]
struct SubmitRequest<'a> {
    version: u32,
    token: &'a str,
    method: &'static str,
    intent_id: &'a str,
    recipient_address: &'a str,
    amount_atomic: u64,
}

#[derive(Debug, Error)]
pub enum PayoutError {
    #[error("payout agent endpoint must use a loopback address")]
    NonLoopbackEndpoint,
    #[error("payout token must contain between 32 and 256 characters")]
    InvalidToken,
    #[error("payout configuration is invalid: {0}")]
    InvalidConfig(String),
    #[error("payout agent I/O failed: {0}")]
    Io(String),
    #[error("payout agent protocol failed: {0}")]
    Protocol(String),
    #[error(transparent)]
    Accounting(#[from] AccountingError),
}

pub struct PayoutAgentClient {
    endpoint: SocketAddr,
    token: Zeroizing<String>,
    expected_wallet_address: String,
}

impl PayoutAgentClient {
    pub fn new(
        endpoint: SocketAddr,
        token: String,
        expected_wallet_address: String,
    ) -> Result<Self, PayoutError> {
        if !is_loopback(endpoint.ip()) {
            return Err(PayoutError::NonLoopbackEndpoint);
        }
        if token.len() < 32 || token.len() > 256 {
            return Err(PayoutError::InvalidToken);
        }
        Ok(Self {
            endpoint,
            token: Zeroizing::new(token),
            expected_wallet_address,
        })
    }

    pub async fn health(&self) -> Result<u64, PayoutError> {
        let request = HealthRequest {
            version: PROTOCOL_VERSION,
            token: self.token.as_str(),
            method: "health",
        };
        let response = self.call(&request).await?;
        self.validate_response(&response)?;
        Ok(response.fee_atomic)
    }

    async fn submit(
        &self,
        payout: &PayoutRecord,
        recipient_address: &str,
    ) -> Result<AgentResponse, PayoutError> {
        let request = SubmitRequest {
            version: PROTOCOL_VERSION,
            token: self.token.as_str(),
            method: "submit",
            intent_id: &payout.intent_id,
            recipient_address,
            amount_atomic: payout.amount_atomic,
        };
        let response = self.call(&request).await?;
        self.validate_response(&response)?;
        if response.intent_id != payout.intent_id {
            return Err(PayoutError::Protocol(
                "agent returned a different payout intent".into(),
            ));
        }
        if hex_decode(&response.tx_hash).map_or(true, |hash| hash.len() != 32) {
            return Err(PayoutError::Protocol(
                "agent returned an invalid transaction hash".into(),
            ));
        }
        Ok(response)
    }

    async fn call<T: Serialize>(&self, request: &T) -> Result<AgentResponse, PayoutError> {
        let bytes = serde_json::to_vec(request)
            .map_err(|error| PayoutError::Protocol(error.to_string()))?;
        let operation = async {
            let mut stream = TcpStream::connect(self.endpoint)
                .await
                .map_err(|error| PayoutError::Io(error.to_string()))?;
            stream
                .write_all(&bytes)
                .await
                .map_err(|error| PayoutError::Io(error.to_string()))?;
            stream
                .shutdown()
                .await
                .map_err(|error| PayoutError::Io(error.to_string()))?;

            let mut response_bytes = Vec::new();
            stream
                .take((MAX_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut response_bytes)
                .await
                .map_err(|error| PayoutError::Io(error.to_string()))?;
            if response_bytes.len() > MAX_RESPONSE_BYTES {
                return Err(PayoutError::Protocol(
                    "payout-agent response exceeds 64 KiB".into(),
                ));
            }
            serde_json::from_slice(&response_bytes)
                .map_err(|error| PayoutError::Protocol(error.to_string()))
        };
        tokio::time::timeout(Duration::from_secs(90), operation)
            .await
            .map_err(|_| PayoutError::Io("payout-agent request timed out".into()))?
    }

    fn validate_response(&self, response: &AgentResponse) -> Result<(), PayoutError> {
        if response.version != PROTOCOL_VERSION {
            return Err(PayoutError::Protocol(
                "agent returned an unsupported protocol version".into(),
            ));
        }
        if !response.ok {
            return Err(PayoutError::Protocol(response.error.clone()));
        }
        if response.wallet_address != self.expected_wallet_address {
            return Err(PayoutError::Protocol(
                "agent wallet does not match the configured pool wallet".into(),
            ));
        }
        Ok(())
    }
}

pub struct PayoutWorker {
    accounting: Arc<PoolAccounting>,
    client: PayoutAgentClient,
    config: PayoutWorkerConfig,
}

impl PayoutWorker {
    pub fn new(
        accounting: Arc<PoolAccounting>,
        client: PayoutAgentClient,
        config: PayoutWorkerConfig,
    ) -> Result<Self, PayoutError> {
        if config.minimum_payout_atomic == 0
            || config.maximum_payout_atomic < config.minimum_payout_atomic
            || config.required_confirmations == 0
            || config.interval.is_zero()
        {
            return Err(PayoutError::InvalidConfig(
                "minimum, maximum, confirmations and interval must be nonzero and ordered".into(),
            ));
        }
        Ok(Self {
            accounting,
            client,
            config,
        })
    }

    pub async fn verify_agent(&self) -> Result<(), PayoutError> {
        let fee = self.client.health().await?;
        info!("Automatic payout agent verified; transaction fee={fee}");
        Ok(())
    }

    pub async fn run(self) {
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(error) = self.process_once().await {
                warn!("Automatic payout attempt failed without releasing reserved funds: {error}");
            }
        }
    }

    pub async fn process_once(&self) -> Result<(), PayoutError> {
        let payout = match self.accounting.active_payout() {
            Some(payout) => payout,
            None => match self.accounting.reserve_next_payout(
                self.config.minimum_payout_atomic,
                self.config.maximum_payout_atomic,
            )? {
                Some(payout) => payout,
                None => return Ok(()),
            },
        };
        let recipient = payout.recipient_address(self.accounting.network_magic())?;
        let response = self.client.submit(&payout, &recipient).await?;

        if let PayoutStatus::Submitted { tx_hash, .. } | PayoutStatus::Confirmed { tx_hash, .. } =
            &payout.status
        {
            if tx_hash != &response.tx_hash {
                return Err(PayoutError::Protocol(
                    "agent changed the transaction bound to an existing payout".into(),
                ));
            }
        }
        self.accounting
            .mark_payout_submitted(&payout.intent_id, &response.tx_hash)?;

        let status = response
            .status
            .ok_or_else(|| PayoutError::Protocol("agent omitted transaction status".into()))?;
        if let AgentTransactionStatus::Confirmed {
            block_height,
            confirmations,
            ..
        } = status
        {
            if confirmations >= self.config.required_confirmations {
                self.accounting.mark_payout_confirmed(
                    &payout.intent_id,
                    &response.tx_hash,
                    block_height,
                    confirmations,
                )?;
                info!(
                    "Automatic payout {} confirmed in transaction {} with {} confirmations",
                    payout.intent_id, response.tx_hash, confirmations
                );
            }
        }
        Ok(())
    }
}

pub fn load_token_file(path: &Path) -> Result<String, PayoutError> {
    let token = std::fs::read_to_string(path)
        .map_err(|error| PayoutError::Io(error.to_string()))?
        .trim()
        .to_owned();
    if token.len() < 32 || token.len() > 256 {
        return Err(PayoutError::InvalidToken);
    }
    Ok(token)
}

fn is_loopback(ip: IpAddr) -> bool {
    ip.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn client_rejects_non_loopback_agent() {
        let endpoint = "192.0.2.1:4000".parse().unwrap();
        assert!(matches!(
            PayoutAgentClient::new(endpoint, "x".repeat(32), "hy1test".into()),
            Err(PayoutError::NonLoopbackEndpoint)
        ));
    }

    #[test]
    fn worker_rejects_zero_confirmation_policy() {
        let endpoint = "127.0.0.1:4000".parse().unwrap();
        let client = PayoutAgentClient::new(endpoint, "x".repeat(32), "hy1test".into()).unwrap();
        let accounting = Arc::new(PoolAccounting::new(
            crate::accounting::PoolAccountingConfig {
                mode: crate::accounting::PoolMode::Solo,
                pool_fee_bps: 0,
                pool_wallet: [1; 32],
                pool_view_public: [2; 32],
                network_magic: [0x48, 0x59, 0x44, 0x56],
                pplns_window_factor: 1,
                state_dir: None,
            },
        ));
        assert!(PayoutWorker::new(
            accounting,
            client,
            PayoutWorkerConfig {
                minimum_payout_atomic: 1,
                maximum_payout_atomic: 1,
                required_confirmations: 0,
                interval: Duration::from_secs(1),
            },
        )
        .is_err());
    }

    #[tokio::test]
    async fn worker_reserves_submits_and_confirms_through_agent_protocol() {
        let directory = std::env::temp_dir().join(format!(
            "hyphen_pool_worker_test_{}_{}",
            std::process::id(),
            crate::random_u64()
        ));
        let accounting = Arc::new(PoolAccounting::new(
            crate::accounting::PoolAccountingConfig {
                mode: crate::accounting::PoolMode::Pps,
                pool_fee_bps: 100,
                pool_wallet: [9; 32],
                pool_view_public: [6; 32],
                network_magic: [0x48, 0x59, 0x44, 0x56],
                pplns_window_factor: 1,
                state_dir: Some(directory.clone()),
            },
        ));
        let miner = [7; 32];
        let recipient = [8; 32];
        accounting.register_view_key(recipient, [5; 32]);
        accounting.register_miner(miner, recipient);
        accounting.record_valid_share(miner, recipient, 1, 1, 100, 0);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let pool_wallet = accounting.pool_wallet_address().unwrap();
        let expected_wallet = pool_wallet.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
            assert_eq!(request["method"], "submit");
            assert_eq!(request["amount_atomic"], 90);
            let response = serde_json::json!({
                "version": 1,
                "ok": true,
                "error": "",
                "wallet_address": expected_wallet,
                "fee_atomic": 1,
                "intent_id": request["intent_id"],
                "tx_hash": "ab".repeat(32),
                "status": {
                    "state": "confirmed",
                    "block_hash_hex": "cd".repeat(32),
                    "block_height": 10,
                    "confirmations": 20
                }
            });
            stream
                .write_all(&serde_json::to_vec(&response).unwrap())
                .await
                .unwrap();
        });

        let client = PayoutAgentClient::new(endpoint, "x".repeat(32), pool_wallet).unwrap();
        let worker = PayoutWorker::new(
            Arc::clone(&accounting),
            client,
            PayoutWorkerConfig {
                minimum_payout_atomic: 50,
                maximum_payout_atomic: 90,
                required_confirmations: 20,
                interval: Duration::from_secs(1),
            },
        )
        .unwrap();
        worker.process_once().await.unwrap();
        server.await.unwrap();

        let ledger = accounting.miner_ledger(&miner).unwrap();
        assert_eq!(ledger.pending_payout_atomic, 9);
        assert_eq!(ledger.reserved_payout_atomic, 0);
        assert_eq!(ledger.total_paid_atomic, 90);
        let _ = std::fs::remove_dir_all(directory);
    }
}
