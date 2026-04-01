use async_trait::async_trait;
use prost::Message;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::primitives::{PublicKey, SecretKey, Signature};

pub const TP_GET_TEMPLATE: u32 = 100;
pub const TP_TEMPLATE: u32 = 101;
pub const TP_SUBMIT_BLOCK: u32 = 102;
pub const TP_SUBMIT_RESULT: u32 = 103;
pub const TP_SUBSCRIBE: u32 = 104;
pub const TP_UNSUBSCRIBE: u32 = 105;
pub const TP_DECLARE_JOB: u32 = 110;
pub const TP_DECLARE_JOB_RESULT: u32 = 111;
pub const TP_TEMPLATE_INVALIDATED: u32 = 120;

#[derive(Debug, Error)]
pub enum TPError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("decode: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("signature verification failed")]
    SignatureFailed,
    #[error("protocol: {0}")]
    Protocol(String),
}

#[derive(Clone, prost::Message)]
pub struct SignedEnvelope {
    #[prost(uint32, tag = "1")]
    pub msg_type: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub sender_pubkey: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signature: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub timestamp: u64,
    #[prost(uint64, tag = "6")]
    pub nonce: u64,
}

impl SignedEnvelope {
    pub fn sign(msg_type: u32, payload: Vec<u8>, sk: &SecretKey) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_millis() as u64;
        let nonce = rand::random::<u64>();
        let to_sign = Self::sign_payload(msg_type, &payload, timestamp, nonce);
        let signature = sk.sign(&to_sign).as_bytes().to_vec();
        Self {
            msg_type,
            payload,
            sender_pubkey: sk.public_key().as_bytes().to_vec(),
            signature,
            timestamp,
            nonce,
        }
    }

    pub fn verify(&self) -> Result<(), TPError> {
        let pk_bytes: [u8; 32] = self
            .sender_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| TPError::SignatureFailed)?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| TPError::SignatureFailed)?;
        let pk = PublicKey(pk_bytes);
        let sig = Signature(sig_bytes);
        let to_sign = Self::sign_payload(self.msg_type, &self.payload, self.timestamp, self.nonce);
        pk.verify(&to_sign, &sig)
            .map_err(|_| TPError::SignatureFailed)
    }

    fn sign_payload(msg_type: u32, payload: &[u8], timestamp: u64, nonce: u64) -> Vec<u8> {
        let mut data = Vec::with_capacity(20 + payload.len());
        data.extend_from_slice(&msg_type.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(payload);
        data
    }
}

#[derive(Clone, prost::Message)]
pub struct TemplateRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub requester_pubkey: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct BlockTemplate {
    #[prost(bytes = "vec", tag = "1")]
    pub template_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub header_data: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub transactions: Vec<Vec<u8>>,
    #[prost(uint64, tag = "4")]
    pub height: u64,
    #[prost(uint64, tag = "5")]
    pub difficulty: u64,
    #[prost(uint64, tag = "6")]
    pub reward: u64,
    #[prost(uint64, tag = "7")]
    pub total_fee: u64,
    #[prost(bytes = "vec", tag = "8")]
    pub epoch_seed: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub prev_hash: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub arena_size: u64,
    #[prost(uint64, tag = "11")]
    pub page_size: u64,
    #[prost(bool, tag = "12")]
    pub clean: bool,
}

#[derive(Clone, prost::Message)]
pub struct SubmitBlockRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub block_data: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct SubmitBlockResult {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub error: String,
    #[prost(bytes = "vec", tag = "3")]
    pub block_hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct DeclareJobRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub template_id: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "2")]
    pub custom_transactions: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "3")]
    pub coinbase_script: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct DeclareJobResult {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(bytes = "vec", tag = "2")]
    pub job_id: Vec<u8>,
    #[prost(string, tag = "3")]
    pub error: String,
    #[prost(bytes = "vec", tag = "4")]
    pub updated_header: Vec<u8>,
}

pub async fn read_envelope<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<SignedEnvelope, TPError> {
    let len = reader.read_u32().await?;
    if len > 64 * 1024 * 1024 {
        return Err(TPError::Protocol(format!("envelope too large: {len}")));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    SignedEnvelope::decode(&buf[..]).map_err(TPError::from)
}

pub async fn write_envelope<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    env: &SignedEnvelope,
) -> Result<(), TPError> {
    let data = env.encode_to_vec();
    writer.write_u32(data.len() as u32).await?;
    writer.write_all(&data).await?;
    Ok(())
}

#[async_trait]
pub trait TemplateProvider: Send + Sync {
    async fn get_template(&self) -> Result<BlockTemplate, TPError>;
    async fn submit_block(&self, block_data: Vec<u8>) -> Result<SubmitBlockResult, TPError>;
    async fn declare_job(
        &self,
        template_id: Vec<u8>,
        custom_transactions: Vec<Vec<u8>>,
        coinbase_script: Vec<u8>,
    ) -> Result<DeclareJobResult, TPError>;
    async fn subscribe(&self) -> Result<(), TPError>;
    async fn read_next(&self) -> Result<SignedEnvelope, TPError>;
}
