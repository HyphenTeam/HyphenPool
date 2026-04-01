use prost::Message;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::warn;

use crate::primitives::SecretKey;
use crate::tp::{
    read_envelope, write_envelope, BlockTemplate, DeclareJobRequest, DeclareJobResult,
    SignedEnvelope, SubmitBlockRequest, SubmitBlockResult, TPError, TemplateProvider,
    TemplateRequest, TP_DECLARE_JOB, TP_DECLARE_JOB_RESULT, TP_GET_TEMPLATE, TP_SUBMIT_BLOCK,
    TP_SUBMIT_RESULT, TP_SUBSCRIBE, TP_TEMPLATE,
};

pub struct TemplateProviderClient {
    addr: String,
    sk: SecretKey,
    request_stream: Arc<Mutex<TcpStream>>,
    template_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<SignedEnvelope>>>>,
}

impl TemplateProviderClient {
    pub async fn connect(addr: &str, sk: &SecretKey) -> Result<Self, TPError> {
        let request_stream = TcpStream::connect(addr).await?;

        Ok(Self {
            addr: addr.to_string(),
            sk: sk.clone(),
            request_stream: Arc::new(Mutex::new(request_stream)),
            template_rx: Arc::new(Mutex::new(None)),
        })
    }

    async fn request_response(
        &self,
        request: SignedEnvelope,
        expected_type: u32,
    ) -> Result<SignedEnvelope, TPError> {
        let mut last_error = None;

        for attempt in 0..2 {
            let mut stream = self.request_stream.lock().await;
            let response = match write_envelope(&mut *stream, &request).await {
                Ok(()) => read_envelope(&mut *stream).await,
                Err(e) => Err(e),
            };

            match response {
                Ok(response) => {
                    if response.msg_type != expected_type {
                        return Err(TPError::Protocol(format!(
                            "expected response type {expected_type}, got {}",
                            response.msg_type,
                        )));
                    }
                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt == 0 {
                        *stream = TcpStream::connect(&self.addr).await?;
                        continue;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| TPError::Protocol("request failed".into())))
    }

    async fn spawn_subscription_reader(&self) -> Result<(), TPError> {
        let mut stream = TcpStream::connect(&self.addr).await?;
        let req = TemplateRequest {
            requester_pubkey: self.sk.public_key().as_bytes().to_vec(),
        };
        let env = SignedEnvelope::sign(TP_SUBSCRIBE, req.encode_to_vec(), &self.sk);
        write_envelope(&mut stream, &env).await?;

        let (template_tx, template_rx) = mpsc::unbounded_channel::<SignedEnvelope>();

        {
            let mut rx_slot = self.template_rx.lock().await;
            *rx_slot = Some(template_rx);
        }

        tokio::spawn(async move {
            let mut stream = stream;
            loop {
                match read_envelope(&mut stream).await {
                    Ok(env) if env.msg_type == TP_TEMPLATE => {
                        if template_tx.send(env).is_err() {
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
        let req = TemplateRequest {
            requester_pubkey: self.sk.public_key().as_bytes().to_vec(),
        };
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
