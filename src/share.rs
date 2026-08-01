use crate::pow::{evaluate_scientific_work_at, EpochArena};
use crate::primitives::{BlockHeader, ChainConfig, Hash256};

#[derive(Debug)]
pub enum ShareVerdict {
    ValidShare { hash: Hash256 },
    BlockFound { hash: Hash256 },
    Invalid(String),
}

pub fn verify_share(
    header: &BlockHeader,
    nonce: u64,
    extra_nonce: &[u8; 32],
    _arena: &EpochArena,
    _cfg: &ChainConfig,
    share_difficulty: u64,
) -> ShareVerdict {
    let mut candidate = header.clone();
    candidate.nonce = nonce;
    candidate.extra_nonce = *extra_nonce;
    candidate.pow_commitment = Hash256::ZERO;

    let iterations = match u32::try_from(share_difficulty) {
        Ok(iterations) => iterations,
        Err(_) => {
            return ShareVerdict::Invalid(
                "scientific checkpoint iteration count exceeds u32".into(),
            )
        }
    };
    match evaluate_scientific_work_at(&candidate, iterations) {
        Some(commitment) if share_difficulty == header.difficulty => {
            ShareVerdict::BlockFound { hash: commitment }
        }
        Some(commitment) => ShareVerdict::ValidShare { hash: commitment },
        None => ShareVerdict::Invalid(
            "scientific PoUW iteration count is outside the consensus range".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_independently_recomputes_scientific_work() {
        let cfg = ChainConfig::testnet();
        let epoch_seed = crate::primitives::blake3_hash(b"Hyphen_genesis_epoch_seed");
        let arena = EpochArena::generate(epoch_seed, cfg.arena_size, cfg.page_size);
        let header = BlockHeader {
            version: crate::primitives::FROZEN_BLOCK_VERSION,
            height: 1,
            timestamp: 1_750_000_012,
            prev_hash: Hash256::ZERO,
            tx_root: Hash256::ZERO,
            commitment_root: Hash256::ZERO,
            nullifier_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: Hash256::ZERO,
            epoch_seed,
            difficulty: 8,
            nonce: 0,
            extra_nonce: [0u8; 32],
            miner_pubkey: [0u8; 32],
            total_fee: 0,
            reward: 0,
            view_tag: 0,
            block_size: 0,
        };

        assert!(matches!(
            verify_share(&header, 7, &[9; 32], &arena, &cfg, 8),
            ShareVerdict::BlockFound { .. }
        ));
    }
}
