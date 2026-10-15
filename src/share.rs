//! Share verdicts. A share is a witness list, and the pool re-derives the
//! commitment and re-applies the node's predicate, so a miner cannot buy credit
//! for work it did not do.

use crate::primitives::{vms, BlockHeader, Hash256, FROZEN_BLOCK_VERSION};

#[derive(Debug, PartialEq, Eq)]
pub enum ShareVerdict {
    /// Fewer witnesses than the block requires: real work, no block.
    Credit,
    /// A complete block candidate.
    BlockFound {
        commitment: Hash256,
    },
    Invalid(String),
}

/// Verifies one submission against the job it claims.
///
/// `required` is the block's witness count, `credit_at` the minimum the pool
/// pays for. The commitment is recomputed from the parent commitment, the
/// header height and the exact list; a full list is a block candidate, a short
/// one earns credit.
pub fn verify_share(
    header: &BlockHeader,
    chain_length: u32,
    parent_work_commitment: &Hash256,
    witnesses: &[u64],
    required: u64,
    credit_at: u64,
) -> ShareVerdict {
    if header.version != FROZEN_BLOCK_VERSION {
        return ShareVerdict::Invalid(format!("unsupported block version {}", header.version));
    }
    if header.difficulty != required {
        return ShareVerdict::Invalid(format!(
            "submission claims difficulty {} but the job requires {required}",
            header.difficulty
        ));
    }
    let count = witnesses.len() as u64;
    if count < credit_at || count > required {
        return ShareVerdict::Invalid(format!(
            "witness count {count} is outside {credit_at}..={required}"
        ));
    }
    if let Err(error) = vms::verify_witnesses(witnesses, chain_length, count) {
        return ShareVerdict::Invalid(format!("witness list rejected: {error}"));
    }
    let commitment = vms::witness_commitment(parent_work_commitment, header.height, witnesses);
    if count == required {
        ShareVerdict::BlockFound { commitment }
    } else {
        ShareVerdict::Credit
    }
}

/// Witnesses already claimed on this pool. The node enforces single use
/// chain-wide; the pool mirrors it so a duplicate earns nothing instead of
/// reaching a full share ledger.
#[derive(Debug, Default)]
pub struct ClaimedWitnesses {
    claimed: std::collections::BTreeSet<u64>,
}

impl ClaimedWitnesses {
    pub fn contains(&self, witness: u64) -> bool {
        self.claimed.contains(&witness)
    }

    /// Claims every witness of an accepted submission. Returns the ones that
    /// were new, which is exactly the credit the miner earned.
    pub fn claim(&mut self, witnesses: &[u64]) -> u64 {
        let mut fresh = 0;
        for witness in witnesses {
            if self.claimed.insert(*witness) {
                fresh += 1;
            }
        }
        fresh
    }

    pub fn len(&self) -> usize {
        self.claimed.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claimed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::ChainConfig;

    fn header(required: u64) -> BlockHeader {
        BlockHeader {
            version: FROZEN_BLOCK_VERSION,
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
            epoch_seed: crate::primitives::blake3_hash(b"Hyphen_genesis_epoch_seed"),
            difficulty: required,
            nonce: 0,
            extra_nonce: [0u8; 32],
            miner_pubkey: [0u8; 32],
            total_fee: 0,
            reward: 0,
            view_tag: 0,
            block_size: 0,
        }
    }

    fn witnesses(length: u32, count: u64) -> Vec<u64> {
        let claimed = |_candidate: u64| false;
        vms::search(&vms::SearchParams {
            length,
            offset: 3,
            stride: 2,
            count,
            max_candidates: 5_000_000,
            is_claimed: &claimed,
        })
        .expect("search")
        .witnesses
    }

    #[test]
    fn full_list_is_a_block_and_short_list_is_credit() {
        let config = ChainConfig::devnet();
        let length = config.pouw_chain_length;
        let parent = Hash256::from_bytes([5u8; 32]);
        let block_header = header(2);
        let list = witnesses(length, 2);

        let verdict = verify_share(&block_header, length, &parent, &list, 2, 1);
        assert_eq!(
            verdict,
            ShareVerdict::BlockFound {
                commitment: vms::witness_commitment(&parent, block_header.height, &list),
            }
        );

        let short = vec![list[0]];
        assert_eq!(
            verify_share(&block_header, length, &parent, &short, 2, 1),
            ShareVerdict::Credit
        );
    }

    #[test]
    fn malformed_witness_lists_are_rejected() {
        let config = ChainConfig::devnet();
        let length = config.pouw_chain_length;
        let parent = Hash256::from_bytes([6u8; 32]);
        let block_header = header(2);
        let list = witnesses(length, 2);

        assert!(matches!(
            verify_share(&block_header, length, &parent, &[], 2, 1),
            ShareVerdict::Invalid(_)
        ));
        assert!(matches!(
            verify_share(&block_header, length, &parent, &[list[1], list[0]], 2, 1),
            ShareVerdict::Invalid(_)
        ));
        assert!(matches!(
            verify_share(&block_header, length, &parent, &[list[0], list[0]], 2, 1),
            ShareVerdict::Invalid(_)
        ));
        assert!(matches!(
            verify_share(&block_header, length + 1, &parent, &list, 2, 1),
            ShareVerdict::Invalid(_)
        ));
        assert!(matches!(
            verify_share(&block_header, length, &parent, &list, 3, 1),
            ShareVerdict::Invalid(_)
        ));
        // A witness for another chain length is not a witness for this job.
        let other = witnesses(length + 1, 1);
        assert!(matches!(
            verify_share(&block_header, length, &parent, &[other[0]], 1, 1),
            ShareVerdict::Invalid(_)
        ));
    }

    #[test]
    fn duplicate_witnesses_earn_credit_once() {
        let mut claimed = ClaimedWitnesses::default();
        assert_eq!(claimed.claim(&[3, 11]), 2);
        assert_eq!(claimed.claim(&[3, 11]), 0);
        assert_eq!(claimed.claim(&[11, 13]), 1);
        assert!(claimed.contains(13));
        assert_eq!(claimed.len(), 3);
    }
}
