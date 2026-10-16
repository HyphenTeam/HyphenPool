use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use courierust::courierust_client::{Client, ClientConfig};
use courierust::courierust_http::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::task::spawn_blocking;
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::accounting::{AccountingError, PayoutRecord, PayoutStatus, PoolAccounting};
use crate::primitives::hex_decode;

const PROTOCOL_VERSION: u32 = 2;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Reachable-or-not deadline for the loopback agent. Paying a wallet is the
/// pool's slowest operation, and the agent waits on the chain to sign and
/// submit, so the read budget is the long one.
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AGENT_READ_TIMEOUT: Duration = Duration::from_secs(90);

const HEALTH_PATH: &str = "/v1/health";
const SUBMIT_PATH: &str = "/v1/submit";

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
struct HealthRequest {
    version: u32,
}

#[derive(Debug, Serialize)]
struct SubmitRequest<'a> {
    version: u32,
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

/// The payout link to `hyphen-payout-agent`.
///
/// The agent serves HTTP on loopback and this is the client: Courierust is on
/// both ends of the link, so the two halves are one implementation of HTTP
/// rather than two hand-rolled codecs. The shared token travels in the
/// `authorization` header — never in the payload, so a body can be logged or
/// echoed without leaking it — and the version field still guards a pool that
/// was upgraded without its agent.
///
/// Courierust's client is blocking. [`PayoutWorker`] calls it from the blocking
/// pool, which keeps the reactor free for shares and the accounting API.
pub struct PayoutAgentClient {
    endpoint: SocketAddr,
    client: Client,
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

        // The header value is the client's to keep for the life of the link; the
        // working copy here is zeroized as soon as it has been handed over.
        let credential = Zeroizing::new(format!("Bearer {token}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_lowercase("authorization"),
            HeaderValue::from(credential.as_str()),
        );
        let config = ClientConfig {
            connect_timeout: Some(AGENT_CONNECT_TIMEOUT),
            read_timeout: Some(AGENT_READ_TIMEOUT),
            max_body: MAX_RESPONSE_BYTES,
            max_header_list: 16 * 1024,
            default_headers: headers,
            ..ClientConfig::default()
        };

        Ok(Self {
            endpoint,
            client: Client::with_config(config),
            expected_wallet_address,
        })
    }

    pub fn health(&self) -> Result<u64, PayoutError> {
        let response = self.call(
            HEALTH_PATH,
            &HealthRequest {
                version: PROTOCOL_VERSION,
            },
        )?;
        Ok(response.fee_atomic)
    }

    fn submit(
        &self,
        payout: &PayoutRecord,
        recipient_address: &str,
    ) -> Result<AgentResponse, PayoutError> {
        let response = self.call(
            SUBMIT_PATH,
            &SubmitRequest {
                version: PROTOCOL_VERSION,
                intent_id: &payout.intent_id,
                recipient_address,
                amount_atomic: payout.amount_atomic,
            },
        )?;
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

    fn call<T: Serialize>(&self, path: &str, request: &T) -> Result<AgentResponse, PayoutError> {
        let payload = serde_json::to_vec(request)
            .map_err(|error| PayoutError::Protocol(error.to_string()))?;
        let url = format!("http://{}{path}", self.endpoint);
        let response = self
            .client
            .post(&url, payload)
            .map_err(|error| PayoutError::Io(error.to_string()))?;
        let status = response.status;

        // The agent answers with its own JSON in both directions, so its message
        // is preferred over a bare status code: an operator reading the pool log
        // should see "authentication failed", not "HTTP 401".
        let body = response
            .text()
            .map_err(|error| PayoutError::Protocol(format!("payout agent body: {error}")))?;
        let response: AgentResponse = serde_json::from_str(&body)
            .map_err(|error| PayoutError::Protocol(format!("payout agent body: {error}")))?;

        if status.as_u16() != 200 {
            return Err(PayoutError::Protocol(if response.error.is_empty() {
                format!("payout agent answered HTTP {}", status.as_u16())
            } else {
                response.error.clone()
            }));
        }
        self.validate_response(&response)?;
        Ok(response)
    }

    fn validate_response(&self, response: &AgentResponse) -> Result<(), PayoutError> {
        if response.version != PROTOCOL_VERSION {
            return Err(PayoutError::Protocol(format!(
                "agent speaks payout protocol {} but this pool speaks {PROTOCOL_VERSION}",
                response.version
            )));
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
    client: Arc<PayoutAgentClient>,
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
            client: Arc::new(client),
            config,
        })
    }

    pub async fn verify_agent(&self) -> Result<(), PayoutError> {
        let fee = self.call_agent(|client| client.health()).await?;
        info!("Automatic payout agent verified; transaction fee={fee}");
        Ok(())
    }

    /// Runs one client call on the blocking pool.
    ///
    /// Courierust's client is a blocking HTTP client; a payout reconciliation
    /// must not stall the reactor that is serving shares and the accounting API.
    async fn call_agent<T, F>(&self, call: F) -> Result<T, PayoutError>
    where
        T: Send + 'static,
        F: FnOnce(&PayoutAgentClient) -> Result<T, PayoutError> + Send + 'static,
    {
        let client = Arc::clone(&self.client);
        spawn_blocking(move || call(&client))
            .await
            .map_err(|error| PayoutError::Io(format!("payout agent task failed: {error}")))?
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
        let submission = payout.clone();
        let response = self
            .call_agent(move |client| client.submit(&submission, &recipient))
            .await?;

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
    use courierust::courierust_body::Body as AgentBody;
    use courierust::courierust_http::request::Request as AgentRequestWire;
    use courierust::courierust_http::response::Response as AgentResponseWire;
    use courierust::courierust_http::StatusCode;
    use courierust::courierust_server::{Server, ServerConfig};

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

        let server = Server::bind_with_config(
            "127.0.0.1:0",
            ServerConfig {
                http2: false,
                max_body: MAX_RESPONSE_BYTES,
                ..ServerConfig::default()
            },
        )
        .unwrap();
        let endpoint = server.local_addr().unwrap();
        let pool_wallet = accounting.pool_wallet_address().unwrap();
        let expected_wallet = pool_wallet.clone();
        let token = Zeroizing::new("x".repeat(32));
        let expected_token = token.clone();
        let agent = server
            .serve_background(move |request: AgentRequestWire<AgentBody>| {
                let mut response = AgentResponseWire::<AgentBody>::with_status(StatusCode::OK);
                response
                    .headers
                    .insert("content-type".into(), "application/json".into());

                // The agent is authenticated by header, never by payload.
                let authorized = request
                    .headers
                    .get("authorization")
                    .and_then(|value| value.to_str().ok())
                    .map(|value| value == format!("Bearer {}", expected_token.as_str()))
                    .unwrap_or(false);
                if !authorized || request.uri.path() != SUBMIT_PATH {
                    response.status = StatusCode::UNAUTHORIZED;
                    response.body = AgentBody::from("{\"error\":\"authentication failed\"}");
                    return response;
                }

                let request: serde_json::Value =
                    serde_json::from_slice(&request.body.collect().unwrap_or_default()).unwrap();
                assert_eq!(request["version"], 2);
                assert_eq!(request["amount_atomic"], 90);

                let body = serde_json::json!({
                    "version": 2,
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
                response.body = AgentBody::from(serde_json::to_vec(&body).unwrap());
                response
            })
            .unwrap();

        let client = PayoutAgentClient::new(endpoint, token.as_str().to_string(), pool_wallet)
            .expect("the loopback agent client is valid");
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
        agent.stop();

        let ledger = accounting.miner_ledger(&miner).unwrap();
        assert_eq!(ledger.pending_payout_atomic, 9);
        assert_eq!(ledger.reserved_payout_atomic, 0);
        assert_eq!(ledger.total_paid_atomic, 90);
        let _ = std::fs::remove_dir_all(directory);
    }
}
