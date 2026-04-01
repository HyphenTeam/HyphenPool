use prost::Message;

use crate::primitives::{PublicKey, SecretKey, Signature};

#[derive(Clone, prost::Message)]
pub struct PoolEnvelope {
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

impl PoolEnvelope {
    pub fn sign(msg_type: u32, payload: Vec<u8>, sk: &SecretKey) -> Self {
        let pk = sk.public_key();
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let nonce: u64 = rand::random();

        let sign_data = Self::sign_payload(msg_type, &payload, pk.as_bytes(), timestamp, nonce);
        let sig = sk.sign(&sign_data);

        Self {
            msg_type,
            payload,
            sender_pubkey: pk.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            timestamp,
            nonce,
        }
    }

    pub fn verify(&self) -> Result<(), PoolError> {
        if self.sender_pubkey.len() != 32 {
            return Err(PoolError::InvalidPublicKey);
        }
        if self.signature.len() != 64 {
            return Err(PoolError::InvalidSignature);
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&self.sender_pubkey);
        let pk = PublicKey(pk_bytes);

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(&self.signature);
        let sig = Signature(sig_bytes);

        let sign_data = Self::sign_payload(
            self.msg_type,
            &self.payload,
            &pk_bytes,
            self.timestamp,
            self.nonce,
        );

        pk.verify(&sign_data, &sig)
            .map_err(|_| PoolError::SignatureVerificationFailed)?;

        let now = chrono::Utc::now().timestamp() as u64;
        if self.timestamp > now + 30 {
            return Err(PoolError::MessageFromFuture);
        }
        if now > self.timestamp + 120 {
            return Err(PoolError::MessageExpired);
        }

        Ok(())
    }

    fn sign_payload(
        msg_type: u32,
        payload: &[u8],
        pubkey: &[u8; 32],
        timestamp: u64,
        nonce: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + payload.len() + 32 + 8 + 8);
        data.extend_from_slice(&msg_type.to_le_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data
    }
}

pub const MSG_LOGIN: u32 = 1;
pub const MSG_LOGIN_ACK: u32 = 2;
pub const MSG_JOB: u32 = 3;
pub const MSG_SUBMIT: u32 = 4;
pub const MSG_SUBMIT_RESULT: u32 = 5;
pub const MSG_KEEPALIVE: u32 = 6;
pub const MSG_BLOCK_FOUND: u32 = 7;
pub const MSG_SET_DIFFICULTY: u32 = 8;
pub const MSG_HASHRATE_REPORT: u32 = 9;
pub const MSG_CHAIN_STATE: u32 = 10;

#[derive(Clone, prost::Message)]
pub struct LoginRequest {
    #[prost(string, tag = "1")]
    pub miner_id: String,
    #[prost(string, tag = "2")]
    pub user_agent: String,
    #[prost(bytes = "vec", tag = "3")]
    pub payout_pubkey: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub estimated_hashrate: u64,
    #[prost(uint32, tag = "5")]
    pub thread_count: u32,
}

#[derive(Clone, prost::Message)]
pub struct LoginAck {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub pool_id: String,
    #[prost(string, tag = "3")]
    pub error: String,
    #[prost(uint64, tag = "4")]
    pub share_difficulty: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub chain_tip_hash: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub chain_height: u64,
    #[prost(uint64, tag = "7")]
    pub block_difficulty: u64,
    #[prost(uint64, tag = "8")]
    pub block_time_target_ms: u64,
    #[prost(string, tag = "9")]
    pub network_name: String,
}

#[derive(Clone, prost::Message)]
pub struct HashrateReport {
    #[prost(uint64, tag = "1")]
    pub hashrate: u64,
    #[prost(uint64, tag = "2")]
    pub total_hashes: u64,
    #[prost(uint64, tag = "3")]
    pub uptime_secs: u64,
}

#[derive(Clone, prost::Message)]
pub struct ChainStateInfo {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(uint64, tag = "2")]
    pub difficulty: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub tip_hash: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub block_time_target_ms: u64,
    #[prost(uint64, tag = "5")]
    pub epoch_seed_height: u64,
}

#[derive(Clone, prost::Message)]
pub struct JobTemplate {
    #[prost(bytes = "vec", tag = "1")]
    pub job_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub header_data: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub height: u64,
    #[prost(uint64, tag = "4")]
    pub block_difficulty: u64,
    #[prost(uint64, tag = "5")]
    pub share_difficulty: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub epoch_seed: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub prev_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub arena_params: Vec<u8>,
    #[prost(bool, tag = "9")]
    pub clean_jobs: bool,
}

#[derive(Clone, prost::Message)]
pub struct ShareSubmission {
    #[prost(bytes = "vec", tag = "1")]
    pub job_id: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub nonce: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub extra_nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub pow_hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct SubmitResult {
    #[prost(bool, tag = "1")]
    pub accepted: bool,
    #[prost(string, tag = "2")]
    pub error: String,
    #[prost(bool, tag = "3")]
    pub block_found: bool,
    #[prost(bytes = "vec", tag = "4")]
    pub block_hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct BlockFoundNotify {
    #[prost(uint64, tag = "1")]
    pub height: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub block_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub finder_pubkey: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct SetDifficulty {
    #[prost(uint64, tag = "1")]
    pub share_difficulty: u64,
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(u32),
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    SignatureVerificationFailed,
    #[error("message timestamp from future")]
    MessageFromFuture,
    #[error("message expired")]
    MessageExpired,
    #[error("decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("internal: {0}")]
    Internal(String),
}

pub struct PoolCodec;

impl PoolCodec {
    pub async fn read_envelope(
        stream: &mut tokio::net::TcpStream,
    ) -> Result<PoolEnvelope, PoolError> {
        use tokio::io::AsyncReadExt;
        let len = stream.read_u32().await?;
        if len > 64 * 1024 * 1024 {
            return Err(PoolError::FrameTooLarge(len));
        }
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let envelope = PoolEnvelope::decode(&buf[..])?;
        Ok(envelope)
    }

    pub async fn write_envelope(
        stream: &mut tokio::net::TcpStream,
        envelope: &PoolEnvelope,
    ) -> Result<(), PoolError> {
        use tokio::io::AsyncWriteExt;
        let data = envelope.encode_to_vec();
        stream.write_u32(data.len() as u32).await?;
        stream.write_all(&data).await?;
        Ok(())
    }
}

pub type PoolMessage = PoolEnvelope;
