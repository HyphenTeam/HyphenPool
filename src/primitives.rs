//! Canonical re-exports. The pool owns policy, not consensus: every item below
//! is the exact definition the node executes, reached through the pinned
//! consensus revision.
#![allow(unused_imports)]

pub use hyphen_core::{
    AuthorizationError, Block, BlockAuthorization, BlockHeader, ChainConfig, ChainIdentity,
    FROZEN_BLOCK_VERSION, authorization_digest, build_genesis_block, wire_config,
};
pub use hyphen_crypto::{
    Hash256, PublicKey, SecretKey, Signature, base58, blake3_hash, blake3_hash_many,
    fill_system_random, hex_decode, hex_encode,
};
pub use hyphen_pow::{POUW_PROTOCOL_VERSION, vms};

pub const FEATURE_ASSET_RULES_V1: u32 = 1 << 9;

pub fn bind_reward(cfg: &ChainConfig, header: &mut BlockHeader, view: &[u8; 32], spend: &[u8; 32]) {
    if cfg.feature_enabled(FEATURE_ASSET_RULES_V1) {
        header.extra_nonce =
            *blake3_hash_many(&[b"Hyphen/reward-recipient/v1", view, spend]).as_bytes();
    }
}
