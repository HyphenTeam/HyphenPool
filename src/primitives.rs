use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroize;

pub const FROZEN_BLOCK_VERSION: u32 = 2;
pub const BLOCK_AUTHORIZATION_VERSION: u16 = 1;
const AUTHORIZATION_DOMAIN: &[u8] = b"Hyphen/NCAP/block-authorization/v1";

pub const MAINNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0xeb, 0x77, 0x36, 0x0a, 0x33, 0xbd, 0x56, 0x09, 0x45, 0x19, 0x65, 0x90, 0xb9, 0xfe, 0x4d, 0x9a,
    0xef, 0x88, 0x89, 0x72, 0xd9, 0xa6, 0xa9, 0x47, 0x5e, 0x0b, 0xc4, 0xdb, 0x52, 0x0f, 0x95, 0x57,
];
pub const MAINNET_GENESIS_HASH: [u8; 32] = [
    0xfc, 0xc9, 0x1f, 0x7a, 0x75, 0x37, 0xb8, 0x4f, 0x8e, 0xf1, 0x75, 0x7d, 0x56, 0xba, 0xc7, 0x5d,
    0x1f, 0xc0, 0xd1, 0x8a, 0xa1, 0x54, 0x07, 0x26, 0xc6, 0x1d, 0xb4, 0x9a, 0xc8, 0x99, 0x1c, 0x9e,
];
pub const TESTNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0x9b, 0x5a, 0x78, 0x1f, 0x5e, 0xe6, 0x47, 0xbc, 0xef, 0x6b, 0x14, 0x81, 0xb6, 0x84, 0xbb, 0xd3,
    0xdf, 0x27, 0x71, 0x18, 0xd7, 0x88, 0x7e, 0x9a, 0xe4, 0x9d, 0xb1, 0x8d, 0x50, 0x7c, 0x2b, 0xda,
];
pub const TESTNET_GENESIS_HASH: [u8; 32] = [
    0xd5, 0x14, 0x38, 0xcd, 0xc8, 0x36, 0x4e, 0x9d, 0x0a, 0x13, 0x9f, 0x73, 0x12, 0x96, 0xd3, 0xa3,
    0x38, 0x45, 0xc1, 0xbb, 0x5f, 0x4b, 0x0a, 0x7c, 0xd1, 0xfa, 0x13, 0xeb, 0xce, 0x2a, 0xe7, 0x8f,
];
pub const DEVNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0xe9, 0x59, 0x14, 0x68, 0xe6, 0xb5, 0x3e, 0x92, 0x2b, 0x67, 0xf6, 0xdb, 0xec, 0xd0, 0xdc, 0xce,
    0xc4, 0x21, 0x7e, 0x95, 0xf0, 0xf0, 0x9a, 0x21, 0xbc, 0xe7, 0x24, 0x4f, 0xbe, 0x8e, 0x83, 0x22,
];
pub const DEVNET_GENESIS_HASH: [u8; 32] = [
    0x4e, 0xe1, 0x46, 0xf6, 0x3e, 0xc5, 0x4d, 0xed, 0x2e, 0xd7, 0x43, 0xe8, 0x8e, 0xe4, 0xff, 0x09,
    0x81, 0x59, 0x8a, 0xfc, 0x04, 0x12, 0xd4, 0x26, 0x1e, 0x17, 0xe4, 0x3a, 0x73, 0x1a, 0x1b, 0x92,
];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

pub fn blake3_hash(data: &[u8]) -> Hash256 {
    Hash256(blake3::hash(data).into())
}

pub fn blake3_hash_many(parts: &[&[u8]]) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(part);
    }
    Hash256(hasher.finalize().into())
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    VerificationFailed,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), KeyError> {
        let vk = VerifyingKey::from_bytes(&self.0).map_err(|_| KeyError::InvalidPublicKey)?;
        let signature = Ed25519Signature::from_bytes(&sig.0);
        vk.verify(msg, &signature)
            .map_err(|_| KeyError::VerificationFailed)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PK({})", hex::encode(self.0))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn generate() -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        Self(sk.to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sk = SigningKey::from_bytes(&self.0);
        Signature(sk.sign(msg).to_bytes())
    }

    pub fn public_key(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.0);
        PublicKey(sk.verifying_key().to_bytes())
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SK(**redacted**)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Self(array))
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({}…)", hex::encode(&self.0[..8]))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainConfig {
    pub network_name: String,
    pub network_magic: [u8; 4],
    pub block_time: Duration,
    pub epoch_length: u64,
    pub arena_size: usize,
    pub scratchpad_size: usize,
    pub page_size: usize,
    pub pow_rounds: u32,
    pub writeback_interval: u32,
    pub kernel_count: u8,
    pub merkle_depth: usize,
    pub ring_size: usize,
    pub difficulty_window: u64,
    pub genesis_difficulty: u64,
    pub max_block_size: usize,
    pub initial_reward: u64,
    pub tail_emission: u64,
    pub fee_burn_bps: u16,
    pub tail_emission_height: u64,
    pub emission_half_life: u64,
    pub max_uncles: usize,
    pub max_uncle_depth: u64,
    pub uncle_reward_numerator: u64,
    pub uncle_reward_denominator: u64,
    pub nephew_reward_numerator: u64,
    pub nephew_reward_denominator: u64,
    pub difficulty_clamp_up: u64,
    pub difficulty_clamp_down: u64,
    pub timestamp_future_limit_ms: u64,
    pub min_ring_span: u64,
}

impl ChainConfig {
    pub fn block_time_ms(&self) -> u64 {
        self.block_time.as_millis() as u64
    }

    pub fn consensus_params_hash(&self) -> [u8; 32] {
        match self.network_magic {
            [0x48, 0x59, 0x50, 0x4e] => MAINNET_CONSENSUS_PARAMS_HASH,
            [0x48, 0x59, 0x54, 0x53] => TESTNET_CONSENSUS_PARAMS_HASH,
            [0x48, 0x59, 0x44, 0x56] => DEVNET_CONSENSUS_PARAMS_HASH,
            _ => [0u8; 32],
        }
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        match self.network_magic {
            [0x48, 0x59, 0x50, 0x4e] => MAINNET_GENESIS_HASH,
            [0x48, 0x59, 0x54, 0x53] => TESTNET_GENESIS_HASH,
            [0x48, 0x59, 0x44, 0x56] => DEVNET_GENESIS_HASH,
            _ => [0u8; 32],
        }
    }

    pub fn mainnet() -> Self {
        Self {
            network_name: "hyphen-mainnet".into(),
            network_magic: [0x48, 0x59, 0x50, 0x4E],
            block_time: Duration::from_secs(60),
            epoch_length: 2048,
            arena_size: 2 * 1024 * 1024 * 1024,
            scratchpad_size: 8 * 1024 * 1024,
            page_size: 4096,
            pow_rounds: 1024,
            writeback_interval: 32,
            kernel_count: 12,
            merkle_depth: 32,
            ring_size: 16,
            difficulty_window: 60,
            genesis_difficulty: 1_000_000,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 100_000_000_000_000,
            tail_emission: 600_000_000_000,
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_half_life: 1_048_576,
            max_uncles: 2,
            max_uncle_depth: 7,
            uncle_reward_numerator: 7,
            uncle_reward_denominator: 8,
            nephew_reward_numerator: 1,
            nephew_reward_denominator: 32,
            difficulty_clamp_up: 3,
            difficulty_clamp_down: 3,
            timestamp_future_limit_ms: 120_000,
            min_ring_span: 100,
        }
    }

    pub fn testnet() -> Self {
        Self {
            network_name: "hyphen-testnet".into(),
            network_magic: [0x48, 0x59, 0x54, 0x53],
            block_time: Duration::from_secs(30),
            epoch_length: 128,
            arena_size: 64 * 1024 * 1024,
            scratchpad_size: 256 * 1024,
            page_size: 4096,
            pow_rounds: 64,
            writeback_interval: 8,
            kernel_count: 12,
            merkle_depth: 32,
            ring_size: 4,
            difficulty_window: 30,
            genesis_difficulty: 1000,
            max_block_size: 2 * 1024 * 1024,
            initial_reward: 100_000_000_000_000,
            tail_emission: 600_000_000_000,
            fee_burn_bps: 5000,
            tail_emission_height: 0,
            emission_half_life: 4_096,
            max_uncles: 2,
            max_uncle_depth: 7,
            uncle_reward_numerator: 7,
            uncle_reward_denominator: 8,
            nephew_reward_numerator: 1,
            nephew_reward_denominator: 32,
            difficulty_clamp_up: 3,
            difficulty_clamp_down: 3,
            timestamp_future_limit_ms: 60_000,
            min_ring_span: 20,
        }
    }

    pub fn devnet() -> Self {
        let mut cfg = Self::testnet();
        cfg.network_name = "hyphen-devnet-v1".into();
        cfg.network_magic = [0x48, 0x59, 0x44, 0x56];
        cfg.max_uncles = 0;
        cfg.max_uncle_depth = 0;
        cfg.uncle_reward_numerator = 0;
        cfg.uncle_reward_denominator = 1;
        cfg.nephew_reward_numerator = 0;
        cfg.nephew_reward_denominator = 1;
        cfg.min_ring_span = 0;
        cfg
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub timestamp: u64,
    pub prev_hash: Hash256,
    pub tx_root: Hash256,
    pub commitment_root: Hash256,
    pub nullifier_root: Hash256,
    pub state_root: Hash256,
    pub receipt_root: Hash256,
    pub uncle_root: Hash256,
    pub pow_commitment: Hash256,
    pub epoch_seed: Hash256,
    pub difficulty: u64,
    pub nonce: u64,
    pub extra_nonce: [u8; 32],
    pub miner_pubkey: [u8; 32],
    pub total_fee: u64,
    pub reward: u64,
    pub view_tag: u8,
    pub block_size: u32,
}

impl BlockHeader {
    pub fn serialise_for_hash(&self) -> Vec<u8> {
        bincode::serialize(self).expect("header serialisation infallible")
    }

    pub fn hash(&self) -> Hash256 {
        blake3_hash(&self.serialise_for_hash())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Vec<u8>>,
    pub uncle_headers: Vec<BlockHeader>,
    pub block_authorization: Vec<u8>,
}

impl Block {
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockAuthorization {
    pub version: u16,
    pub reward_view_public: [u8; 32],
    pub reward_spend_public: [u8; 32],
    pub miner_signature: Vec<u8>,
}

impl BlockAuthorization {
    pub fn verify(&self, header: &BlockHeader, cfg: &ChainConfig) -> Result<(), String> {
        if header.version != FROZEN_BLOCK_VERSION {
            return Err(format!("unsupported block version {}", header.version));
        }
        if self.version != BLOCK_AUTHORIZATION_VERSION {
            return Err(format!(
                "unsupported block authorization version {}",
                self.version
            ));
        }
        if header.miner_pubkey == [0u8; 32]
            || self.reward_view_public == [0u8; 32]
            || self.reward_spend_public == [0u8; 32]
        {
            return Err("authorization contains a zero public key".into());
        }
        let signature: [u8; 64] = self
            .miner_signature
            .as_slice()
            .try_into()
            .map_err(|_| "miner signature must be exactly 64 bytes")?;
        let digest = authorization_digest(
            header,
            cfg.network_magic,
            cfg.consensus_params_hash(),
            cfg.genesis_hash(),
            self.reward_view_public,
            self.reward_spend_public,
        );
        PublicKey(header.miner_pubkey)
            .verify(digest.as_bytes(), &Signature(signature))
            .map_err(|_| "miner block authorization signature is invalid".into())
    }
}

pub fn authorization_digest(
    header: &BlockHeader,
    network_magic: [u8; 4],
    consensus_params_hash: [u8; 32],
    genesis_hash: [u8; 32],
    reward_view_public: [u8; 32],
    reward_spend_public: [u8; 32],
) -> Hash256 {
    blake3_hash_many(&[
        AUTHORIZATION_DOMAIN,
        &BLOCK_AUTHORIZATION_VERSION.to_le_bytes(),
        &network_magic,
        &consensus_params_hash,
        &genesis_hash,
        header.hash().as_bytes(),
        &reward_view_public,
        &reward_spend_public,
    ])
}
