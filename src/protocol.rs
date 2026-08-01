use prost::Message;

use crate::primitives::{blake3_hash_many, PublicKey, SecretKey, Signature};

const SHARE_RECEIPT_DOMAIN: &[u8] = b"Hyphen/NCAP/share-receipt/v1";

pub fn share_receipt_hash(
    pool_pubkey: &[u8; 32],
    miner_pubkey: &[u8; 32],
    sequence: u64,
    previous_receipt_hash: &[u8; 32],
    submission_hash: &[u8; 32],
    result_hash: &[u8; 32],
) -> [u8; 32] {
    *blake3_hash_many(&[
        SHARE_RECEIPT_DOMAIN,
        pool_pubkey,
        miner_pubkey,
        &sequence.to_le_bytes(),
        previous_receipt_hash,
        submission_hash,
        result_hash,
    ])
    .as_bytes()
}

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
    #[prost(uint64, tag = "7")]
    pub receipt_sequence: u64,
    #[prost(bytes = "vec", tag = "8")]
    pub previous_receipt_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub receipt_hash: Vec<u8>,
}

impl PoolEnvelope {
    pub fn sign(msg_type: u32, payload: Vec<u8>, sk: &SecretKey) -> Self {
        Self::sign_with_receipt(msg_type, payload, sk, 0, Vec::new(), Vec::new())
    }

    pub fn sign_with_receipt(
        msg_type: u32,
        payload: Vec<u8>,
        sk: &SecretKey,
        receipt_sequence: u64,
        previous_receipt_hash: Vec<u8>,
        receipt_hash: Vec<u8>,
    ) -> Self {
        let pk = sk.public_key();
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let nonce: u64 = rand::random();

        let sign_data = Self::sign_payload(
            msg_type,
            &payload,
            pk.as_bytes(),
            timestamp,
            nonce,
            receipt_sequence,
            &previous_receipt_hash,
            &receipt_hash,
        );
        let sig = sk.sign(&sign_data);

        Self {
            msg_type,
            payload,
            sender_pubkey: pk.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            timestamp,
            nonce,
            receipt_sequence,
            previous_receipt_hash,
            receipt_hash,
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
            self.receipt_sequence,
            &self.previous_receipt_hash,
            &self.receipt_hash,
        );

        pk.verify(&sign_data, &sig)
            .map_err(|_| PoolError::SignatureVerificationFailed)?;

        let now = chrono::Utc::now().timestamp() as u64;
        if self.timestamp > now.saturating_add(30) {
            return Err(PoolError::MessageFromFuture);
        }
        if now > self.timestamp.saturating_add(120) {
            return Err(PoolError::MessageExpired);
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_payload(
        msg_type: u32,
        payload: &[u8],
        pubkey: &[u8; 32],
        timestamp: u64,
        nonce: u64,
        receipt_sequence: u64,
        previous_receipt_hash: &[u8],
        receipt_hash: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + payload.len() + 32 + 8 + 8);
        data.extend_from_slice(&msg_type.to_le_bytes());
        data.extend_from_slice(payload);
        data.extend_from_slice(pubkey);
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&nonce.to_le_bytes());
        data.extend_from_slice(&receipt_sequence.to_le_bytes());
        data.extend_from_slice(previous_receipt_hash);
        data.extend_from_slice(receipt_hash);
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
pub const MSG_COMPUTE_RATE_REPORT: u32 = 9;
pub const MSG_CHAIN_STATE: u32 = 10;
pub const POOL_PROTOCOL_VERSION: u32 = 5;

#[derive(Clone, prost::Message)]
pub struct LoginRequest {
    #[prost(string, tag = "1")]
    pub miner_id: String,
    #[prost(string, tag = "2")]
    pub user_agent: String,
    #[prost(bytes = "vec", tag = "3")]
    pub payout_pubkey: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub estimated_operations_per_second: u64,
    #[prost(uint32, tag = "5")]
    pub thread_count: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub network_magic: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub consensus_params_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub genesis_hash: Vec<u8>,
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
    #[prost(bytes = "vec", tag = "10")]
    pub network_magic: Vec<u8>,
    #[prost(uint32, tag = "11")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "12")]
    pub consensus_params_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub genesis_hash: Vec<u8>,
}

#[derive(Clone, prost::Message)]
pub struct ComputeRateReport {
    #[prost(uint64, tag = "1")]
    pub operations_per_second: u64,
    #[prost(uint64, tag = "2")]
    pub total_operations: u64,
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
    #[prost(bytes = "vec", tag = "10")]
    pub consensus_params_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub genesis_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub reward_view_public: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub reward_spend_public: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "14")]
    pub transactions: Vec<Vec<u8>>,
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
    pub work_commitment: Vec<u8>,
    /// Present only for a full block solution. Encodes BlockAuthorization.
    #[prost(bytes = "vec", tag = "5")]
    pub block_authorization: Vec<u8>,
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
        if len > 1024 * 1024 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_envelope_rejects_payload_tampering() {
        let secret = SecretKey([17u8; 32]);
        let mut envelope = PoolEnvelope::sign(MSG_SUBMIT, vec![1, 2, 3], &secret);
        envelope.payload[0] ^= 0x80;
        assert!(matches!(
            envelope.verify(),
            Err(PoolError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn signed_envelope_rejects_share_stealing_identity_substitution() {
        let victim = SecretKey([18u8; 32]);
        let attacker = SecretKey([19u8; 32]);
        let mut envelope = PoolEnvelope::sign(MSG_SUBMIT, vec![4, 5, 6], &victim);
        envelope.sender_pubkey = attacker.public_key().as_bytes().to_vec();
        assert!(matches!(
            envelope.verify(),
            Err(PoolError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn share_receipt_commits_submission_result_and_chain_position() {
        let pool = [1u8; 32];
        let miner = [2u8; 32];
        let previous = [3u8; 32];
        let submission = [4u8; 32];
        let result = [5u8; 32];
        let receipt = share_receipt_hash(&pool, &miner, 7, &previous, &submission, &result);

        assert_ne!(
            receipt,
            share_receipt_hash(&pool, &miner, 8, &previous, &submission, &result)
        );
        let mut changed_submission = submission;
        changed_submission[0] ^= 1;
        assert_ne!(
            receipt,
            share_receipt_hash(&pool, &miner, 7, &previous, &changed_submission, &result)
        );
        let mut changed_result = result;
        changed_result[0] ^= 1;
        assert_ne!(
            receipt,
            share_receipt_hash(&pool, &miner, 7, &previous, &submission, &changed_result)
        );
    }

    #[test]
    fn signed_envelope_handles_max_timestamp_without_overflow() {
        let secret = SecretKey([20u8; 32]);
        let public = *secret.public_key().as_bytes();
        let payload = vec![7u8];
        let timestamp = u64::MAX;
        let nonce = 9;
        let sign_data = PoolEnvelope::sign_payload(
            MSG_KEEPALIVE,
            &payload,
            &public,
            timestamp,
            nonce,
            0,
            &[],
            &[],
        );
        let envelope = PoolEnvelope {
            msg_type: MSG_KEEPALIVE,
            payload,
            sender_pubkey: public.to_vec(),
            signature: secret.sign(&sign_data).as_bytes().to_vec(),
            timestamp,
            nonce,
            receipt_sequence: 0,
            previous_receipt_hash: Vec::new(),
            receipt_hash: Vec::new(),
        };
        assert!(matches!(
            envelope.verify(),
            Err(PoolError::MessageFromFuture)
        ));
    }

    #[test]
    fn deterministic_malformed_pool_corpus_never_panics() {
        let mut state = 0xa54f_f53a_5f1d_36f1u64;
        for len in 0..=4096usize {
            let mut bytes = vec![0u8; len];
            for byte in &mut bytes {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            let result = std::panic::catch_unwind(|| PoolEnvelope::decode(bytes.as_slice()));
            assert!(
                result.is_ok(),
                "pool decoder panicked for corpus length {len}"
            );
        }
    }
}
