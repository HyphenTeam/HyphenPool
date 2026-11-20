use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tracing::warn;
mod canonical;

use crate::primitives::ChainIdentity;
use crate::primitives::{ChainConfig, SecretKey};
use crate::tp::{
    BlockTemplate, DeclareJobRequest, DeclareJobResult, SignedEnvelope, SubmitBlockRequest,
    SubmitBlockResult, TP_DECLARE_JOB, TP_DECLARE_JOB_RESULT, TP_GET_TEMPLATE, TP_SUBMIT_BLOCK,
    TP_SUBMIT_RESULT, TP_SUBSCRIBE, TP_TEMPLATE, TPError, TemplateProvider, TemplateRequest,
    read_envelope, write_envelope,
};

pub struct TemplateProviderClient {
    addr: String,
    sk: SecretKey,
    request_stream: Mutex<Option<TcpStream>>,
    template_rx: Arc<Mutex<Option<mpsc::Receiver<SignedEnvelope>>>>,
    cfg: ChainConfig,
    reward_anchor: Mutex<Option<(u64, Vec<u8>)>>,
}

impl TemplateProviderClient {
    pub async fn connect(addr: &str, sk: &SecretKey, cfg: &ChainConfig) -> Result<Self, TPError> {
        let request_stream = Self::connect_stream(addr).await?;

        Ok(Self {
            addr: addr.to_string(),
            sk: sk.clone(),
            request_stream: Mutex::new(Some(request_stream)),
            template_rx: Arc::new(Mutex::new(None)),
            cfg: cfg.clone(),
            reward_anchor: Mutex::new(None),
        })
    }

    async fn connect_stream(addr: &str) -> Result<TcpStream, TPError> {
        tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| TPError::Protocol("template provider connection timed out".into()))?
            .map_err(TPError::from)
    }

    async fn request_response(
        &self,
        request: SignedEnvelope,
        expected_type: u32,
    ) -> Result<SignedEnvelope, TPError> {
        let mut slot = self.request_stream.lock().await;
        for attempt in 0..2 {
            // Taking ownership also discards a partially consumed frame on cancellation.
            let mut stream = match slot.take() {
                Some(stream) => stream,
                None => Self::connect_stream(&self.addr).await?,
            };
            let response = tokio::time::timeout(Duration::from_secs(25), async {
                write_envelope(&mut stream, &request).await?;
                read_envelope(&mut stream).await
            })
            .await
            .unwrap_or_else(|_| {
                Err(TPError::Protocol(
                    "template provider request timed out".into(),
                ))
            });
            match response {
                Ok(response) => {
                    if !response.verify() {
                        return Err(TPError::Protocol("invalid envelope signature".into()));
                    }
                    if response.msg_type != expected_type {
                        return Err(TPError::Protocol(format!(
                            "expected response type {expected_type}, got {}",
                            response.msg_type,
                        )));
                    }
                    *slot = Some(stream);
                    return Ok(response);
                }
                Err(e) => {
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }

        unreachable!("the second attempt returns its result");
    }

    fn identity_request(&self) -> TemplateRequest {
        TemplateRequest {
            requester_pubkey: self.sk.public_key().as_bytes().to_vec(),
            network_magic: self.cfg.network_magic.to_vec(),
            protocol_version: hyphen_transport::POOL_PROTOCOL_VERSION,
            consensus_params_hash: self.cfg.consensus_params_hash().to_vec(),
            genesis_hash: ChainIdentity::of(&self.cfg)
                .genesis_hash
                .as_bytes()
                .to_vec(),
        }
    }

    async fn spawn_subscription_reader(&self) -> Result<(), TPError> {
        let mut stream = Self::connect_stream(&self.addr).await?;
        let req = self.identity_request();
        let env = SignedEnvelope::sign(TP_SUBSCRIBE, req.encode_to_vec(), &self.sk);
        write_envelope(&mut stream, &env).await?;

        let (template_tx, template_rx) = mpsc::channel::<SignedEnvelope>(1);

        {
            let mut rx_slot = self.template_rx.lock().await;
            *rx_slot = Some(template_rx);
        }

        tokio::spawn(async move {
            let mut stream = stream;
            loop {
                match read_envelope(&mut stream).await {
                    Ok(env) if env.msg_type == TP_TEMPLATE => {
                        if !env.verify() {
                            warn!("Rejected template envelope with an invalid signature");
                            continue;
                        }
                        if template_tx.send(env).await.is_err() {
                            break;
                        }
                    }
                    Ok(env) => {
                        warn!(
                            "Subscription connection received unexpected msg_type {}",
                            env.msg_type
                        );
                    }
                    Err(e) => {
                        warn!("Subscription reader stopped: {e}");
                        break;
                    }
                }
            }
        });

        Ok(())
    }
}

#[async_trait::async_trait]
impl TemplateProvider for TemplateProviderClient {
    async fn get_template(&self) -> Result<BlockTemplate, TPError> {
        let req = self.identity_request();
        let env = SignedEnvelope::sign(TP_GET_TEMPLATE, req.encode_to_vec(), &self.sk);
        let resp = self.request_response(env, TP_TEMPLATE).await?;
        BlockTemplate::decode(&resp.payload[..]).map_err(TPError::from)
    }

    async fn submit_block(&self, block_data: Vec<u8>) -> Result<SubmitBlockResult, TPError> {
        let req = SubmitBlockRequest { block_data };
        let env = SignedEnvelope::sign(TP_SUBMIT_BLOCK, req.encode_to_vec(), &self.sk);
        let resp = self.request_response(env, TP_SUBMIT_RESULT).await?;
        SubmitBlockResult::decode(&resp.payload[..]).map_err(TPError::from)
    }

    async fn declare_job(
        &self,
        template_id: Vec<u8>,
        custom_transactions: Vec<Vec<u8>>,
        coinbase_script: Vec<u8>,
    ) -> Result<DeclareJobResult, TPError> {
        let req = DeclareJobRequest {
            template_id,
            custom_transactions,
            coinbase_script,
        };
        let env = SignedEnvelope::sign(TP_DECLARE_JOB, req.encode_to_vec(), &self.sk);
        let resp = self.request_response(env, TP_DECLARE_JOB_RESULT).await?;
        DeclareJobResult::decode(&resp.payload[..]).map_err(TPError::from)
    }

    async fn subscribe(&self) -> Result<(), TPError> {
        self.spawn_subscription_reader().await
    }

    async fn read_next(&self) -> Result<SignedEnvelope, TPError> {
        let mut rx_slot = self.template_rx.lock().await;
        let rx = rx_slot
            .as_mut()
            .ok_or_else(|| TPError::Protocol("subscription not active".into()))?;
        rx.recv()
            .await
            .ok_or_else(|| TPError::Protocol("template subscription channel closed".into()))
    }
}
