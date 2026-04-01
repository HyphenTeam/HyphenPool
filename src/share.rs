use crate::pow::{difficulty_to_target, evaluate_pow, EpochArena};
use crate::primitives::{BlockHeader, ChainConfig, Hash256};

#[derive(Debug)]
pub enum ShareVerdict {
    ValidShare,
    BlockFound { hash: Hash256 },
    Invalid(String),
}

pub fn verify_share(
    header: &BlockHeader,
    nonce: u64,
    extra_nonce: &[u8; 32],
    arena: &EpochArena,
    cfg: &ChainConfig,
    share_difficulty: u64,
) -> ShareVerdict {
    let mut candidate = header.clone();
    candidate.nonce = nonce;
    candidate.extra_nonce = *extra_nonce;

    let hash = evaluate_pow(&candidate, arena, cfg);

    let block_target = difficulty_to_target(header.difficulty);
    if hash_below_target(&hash, &block_target) {
        return ShareVerdict::BlockFound { hash };
    }

    let share_target = difficulty_to_target(share_difficulty);
    if hash_below_target(&hash, &share_target) {
        return ShareVerdict::ValidShare;
    }

    ShareVerdict::Invalid("hash does not meet share difficulty".into())
}

fn hash_below_target(hash: &Hash256, target: &[u8; 32]) -> bool {
    for (h, t) in hash.as_bytes().iter().zip(target.iter()) {
        match h.cmp(t) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => continue,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_verdict_invalid_high_hash() {
        let cfg = ChainConfig::testnet();
        let epoch_seed = crate::primitives::blake3_hash(b"Hyphen_genesis_epoch_seed");
        let arena = EpochArena::generate(epoch_seed, cfg.arena_size, cfg.page_size);

        let header = BlockHeader {
            version: 1,
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
            difficulty: 1_000_000_000_000,
            nonce: 0,
            extra_nonce: [0u8; 32],
            miner_pubkey: [0u8; 32],
            total_fee: 0,
            reward: 0,
            view_tag: 0,
            block_size: 0,
        };

        let verdict = verify_share(&header, 0, &[0u8; 32], &arena, &cfg, 1_000_000_000_000);
        match verdict {
            ShareVerdict::Invalid(_) => {}
            _ => panic!("expected invalid share for max difficulty"),
        }
    }
}
