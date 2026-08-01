use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;
use zeroize::Zeroize;

pub const FROZEN_BLOCK_VERSION: u32 = 3;
pub const BLOCK_AUTHORIZATION_VERSION: u16 = 1;
const AUTHORIZATION_DOMAIN: &[u8] = b"Hyphen/NCAP/block-authorization/v1";

pub const MAINNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0x92, 0x31, 0xdc, 0xb5, 0xfa, 0x6e, 0xaf, 0x9d, 0xc2, 0xe0, 0x6f, 0xe9, 0x5c, 0x02, 0x61, 0x41,
    0xd8, 0x6e, 0xed, 0xc4, 0xfd, 0x71, 0x19, 0xa4, 0x04, 0xed, 0xa0, 0xc3, 0x46, 0xdd, 0x88, 0xdc,
];
pub const MAINNET_GENESIS_HASH: [u8; 32] = [
    0x6b, 0x31, 0x1c, 0xb4, 0xf6, 0x58, 0x7f, 0xf7, 0xaa, 0xf6, 0x32, 0xc1, 0xc4, 0xc0, 0x06, 0xa2,
    0x3c, 0x5b, 0xbc, 0x41, 0x67, 0x9a, 0x66, 0xe1, 0xc1, 0x60, 0x4a, 0xb8, 0x05, 0x62, 0xc8, 0xd1,
];
pub const TESTNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0xcf, 0xb4, 0xd6, 0x33, 0xa7, 0xa2, 0x32, 0x66, 0x70, 0xed, 0x97, 0x03, 0x35, 0xa2, 0x64, 0x54,
    0xe5, 0x2a, 0xd1, 0x66, 0xe9, 0x7f, 0x30, 0x4d, 0x3e, 0xf9, 0x6d, 0xbe, 0x4e, 0x26, 0x93, 0x58,
];
pub const TESTNET_GENESIS_HASH: [u8; 32] = [
    0x36, 0x6d, 0x32, 0xb3, 0xef, 0x3f, 0xb2, 0x06, 0x36, 0x6f, 0x1d, 0x0e, 0x54, 0x69, 0x33, 0x40,
    0x68, 0x9d, 0x49, 0xf3, 0xf9, 0xa4, 0xd1, 0xba, 0xd2, 0xcf, 0x35, 0x3b, 0x05, 0x39, 0xa6, 0x43,
];
pub const DEVNET_CONSENSUS_PARAMS_HASH: [u8; 32] = [
    0x54, 0xbf, 0x97, 0xe4, 0xe2, 0x8d, 0x4f, 0xcf, 0x96, 0x3d, 0x88, 0x4a, 0x55, 0x5a, 0x84, 0x25,
    0xbb, 0xfe, 0x7c, 0x84, 0xd2, 0x75, 0x30, 0x01, 0xbc, 0xab, 0xba, 0xf1, 0x16, 0x23, 0x2f, 0xda,
];
pub const DEVNET_GENESIS_HASH: [u8; 32] = [
    0x47, 0xd5, 0x30, 0x16, 0x0c, 0xfe, 0xf9, 0x14, 0x1f, 0xe3, 0xb3, 0x7b, 0x88, 0x6e, 0x09, 0xb9,
    0xf9, 0x6e, 0xc4, 0xdc, 0x93, 0xd6, 0xc0, 0x50, 0x05, 0xb9, 0xc6, 0xdb, 0xf3, 0x5b, 0x19, 0x72,
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
        let sk = SigningKey::generate(&mut rand::rng());
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
            genesis_difficulty: 384,
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
            genesis_difficulty: 192,
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
        cfg.network_name = "hyphen-devnet-v2".into();
        cfg.network_magic = [0x48, 0x59, 0x44, 0x56];
        cfg.genesis_difficulty = 64;
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
        crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(self)
            .expect("header serialisation infallible")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct CodecFixture {
        tag: u8,
        count: u64,
        bytes: Vec<u8>,
        optional: Option<u32>,
    }

    #[test]
    fn canonical_codec_matches_main_chain_fixed_vector() {
        let fixture = CodecFixture {
            tag: 7,
            count: 0x0102,
            bytes: vec![3, 4],
            optional: Some(9),
        };
        let expected = vec![
            7, 2, 1, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3, 4, 1, 9, 0, 0, 0,
        ];
        assert_eq!(
            crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&fixture)
                .unwrap(),
            expected
        );
        assert_eq!(
            crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .deserialize::<CodecFixture>(&expected)
                .unwrap(),
            fixture
        );
        let mut trailing = expected;
        trailing.push(0);
        assert!(crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .deserialize::<CodecFixture>(&trailing)
            .is_err());
    }

    #[test]
    fn chain_identity_matches_main_chain_vectors() {
        let cases = [
            (
                ChainConfig::mainnet(),
                "9231dcb5fa6eaf9dc2e06fe95c026141d86eedc4fd7119a404eda0c346dd88dc",
                "6b311cb4f6587ff7aaf632c1c4c006a23c5bbc41679a66e1c1604ab80562c8d1",
            ),
            (
                ChainConfig::testnet(),
                "cfb4d633a7a2326670ed970335a26454e52ad166e97f304d3ef96dbe4e269358",
                "366d32b3ef3fb206366f1d0e54693340689d49f3f9a4d1bad2cf353b0539a643",
            ),
            (
                ChainConfig::devnet(),
                "54bf97e4e28d4fcf963d884a555a8425bbfe7c84d2753001bcabbaf116232fda",
                "47d530160cfef9141fe3b37b886e09b9f96ec4dc93d6c05005b9c6dbf35b1972",
            ),
        ];
        for (config, params, genesis) in cases {
            assert_eq!(hex::encode(config.consensus_params_hash()), params);
            assert_eq!(hex::encode(config.genesis_hash()), genesis);
        }
        assert_eq!(ChainConfig::devnet().network_name, "hyphen-devnet-v2");
    }
}
