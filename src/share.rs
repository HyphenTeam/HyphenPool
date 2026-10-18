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

/// Verifies a one-way neural work solution against the job's header.
///
/// The solution is a `Vec<u64>` on the wire because that is what the protocol
/// already carries; each entry is a Q32.32 component reinterpreted as `u64`. A
/// solution that meets the header's threshold is a complete block — partial
/// neural work is not verifiable, so this profile has no credit shares.
pub fn verify_neural_share(
    header: &BlockHeader,
    parent_hash: &Hash256,
    miner_pubkey: &[u8; 32],
    solution: &[u64],
) -> ShareVerdict {
    if header.version != FROZEN_BLOCK_VERSION {
        return ShareVerdict::Invalid(format!("unsupported block version {}", header.version));
    }
    let spec = hyphen_neural::PROFILE_SPEC;
    if solution.len() != spec.input_dim as usize {
        return ShareVerdict::Invalid(format!(
            "solution carries {} values, the profile wants {}",
            solution.len(),
            spec.input_dim
        ));
    }
    let values: Vec<i64> = solution.iter().map(|value| *value as i64).collect();
    let limit = hyphen_neural::fixed::ONE;
    if values.iter().any(|value| !(-limit..=limit).contains(value)) {
        return ShareVerdict::Invalid("solution component outside [-ONE, ONE]".into());
    }

    let seed = hyphen_core::neural_work_seed(parent_hash, header.height, miner_pubkey);
    let descriptor = hyphen_neural::WorkDescriptor {
        epoch: header.height,
        spec,
        threshold: header.difficulty,
        chain_seed: *seed.as_bytes(),
    };
    if descriptor.validate().is_err() {
        return ShareVerdict::Invalid("job carries an unusable work threshold".into());
    }
    let mut weights = vec![0_i64; spec.weight_count()];
    if descriptor.derive_weights(&mut weights).is_err() {
        return ShareVerdict::Invalid("cannot derive the work network".into());
    }
    let mut hidden = vec![0_i64; spec.hidden_dim as usize];
    let mut output = vec![0_i64; spec.output_dim as usize];
    match descriptor.verify(&weights, &values, &mut hidden, &mut output) {
        Ok(true) => ShareVerdict::BlockFound {
            commitment: hyphen_core::neural_work_commitment(
                parent_hash,
                header.height,
                header.difficulty,
                miner_pubkey,
                solution,
            ),
        },
        Ok(false) => ShareVerdict::Invalid("solution does not meet the header threshold".into()),
        Err(error) => ShareVerdict::Invalid(format!("work verification failed: {error}")),
    }
}

/// Witnesses already claimed on this pool, together with the miner that
/// claimed each one. The node enforces single use chain-wide; the pool mirrors
/// it so a duplicate earns nothing instead of reaching a full share ledger.
///
/// Ownership matters because the miner's normal flow is to submit a credit
/// share and then extend the *same* list into a block candidate. That reuse is
/// legitimate for the miner that earned the credit and theft for any other, so
/// the set records who claimed what instead of only whether a witness is gone.
#[derive(Debug, Default)]
pub struct ClaimedWitnesses {
    claimed: std::collections::BTreeMap<u64, [u8; 32]>,
}

impl ClaimedWitnesses {
    pub fn contains(&self, witness: u64) -> bool {
        self.claimed.contains_key(&witness)
    }

    /// First witness in the list that a different miner already claimed.
    pub fn claimed_by_other(&self, claimant: &[u8; 32], witnesses: &[u64]) -> Option<u64> {
        witnesses.iter().copied().find(|witness| {
            self.claimed
                .get(witness)
                .is_some_and(|owner| owner != claimant)
        })
    }

    /// Claims every witness of an accepted submission for `claimant`. Returns
    /// the ones that were new, which is exactly the credit the miner earned.
    pub fn claim(&mut self, claimant: &[u8; 32], witnesses: &[u64]) -> u64 {
        let mut fresh = 0;
        for witness in witnesses {
            if self.claimed.insert(*witness, *claimant).is_none() {
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

    /// A neural solution is verified with one forward pass against the
    /// header's threshold, and a tampered component is rejected.
    #[test]
    fn a_neural_solution_is_verified_and_tampering_is_rejected() {
        let parent = Hash256::from_bytes([21; 32]);
        let miner = [22; 32];
        let spec = hyphen_neural::PROFILE_SPEC;
        let threshold = 1u64 << 60;
        let seed = hyphen_core::neural_work_seed(&parent, 1, &miner);
        let descriptor = hyphen_neural::WorkDescriptor {
            epoch: 1,
            spec,
            threshold,
            chain_seed: *seed.as_bytes(),
        };
        let mut weights = vec![0_i64; spec.weight_count()];
        descriptor.derive_weights(&mut weights).unwrap();
        let mut solution = vec![0_i64; spec.input_dim as usize];
        let mut hidden = vec![0_i64; spec.hidden_dim as usize];
        let mut output = vec![0_i64; spec.output_dim as usize];
        let mut scratch = vec![0_i64; spec.input_dim as usize];
        let outcome = hyphen_neural::search_work(
            &descriptor,
            &weights,
            0,
            1,
            1 << 20,
            &mut solution,
            &mut hidden,
            &mut output,
            &mut scratch,
        )
        .unwrap();
        assert!(outcome.found);

        let header = header_with_difficulty(1, threshold);
        let encoded: Vec<u64> = solution.iter().map(|value| *value as u64).collect();
        assert!(matches!(
            verify_neural_share(&header, &parent, &miner, &encoded),
            ShareVerdict::BlockFound { .. }
        ));

        let mut tampered = encoded.clone();
        tampered[0] = tampered[0].wrapping_add(1);
        assert!(matches!(
            verify_neural_share(&header, &parent, &miner, &tampered),
            ShareVerdict::Invalid(_)
        ));

        // The same solution under another miner key derives a different network.
        assert!(matches!(
            verify_neural_share(&header, &parent, &[23; 32], &encoded),
            ShareVerdict::Invalid(_)
        ));
    }

    fn header_with_difficulty(height: u64, difficulty: u64) -> BlockHeader {
        BlockHeader {
            version: FROZEN_BLOCK_VERSION,
            height,
            timestamp: 0,
            prev_hash: Hash256::ZERO,
            tx_root: Hash256::ZERO,
            commitment_root: Hash256::ZERO,
            nullifier_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: Hash256::ZERO,
            epoch_seed: Hash256::ZERO,
            difficulty,
            nonce: 0,
            extra_nonce: [0; 32],
            miner_pubkey: [0; 32],
            total_fee: 0,
            reward: 0,
            view_tag: 0,
            block_size: 0,
        }
    }

    #[test]
    fn duplicate_witnesses_earn_credit_once() {
        const MINER: [u8; 32] = [7; 32];
        let mut claimed = ClaimedWitnesses::default();
        assert_eq!(claimed.claim(&MINER, &[3, 11]), 2);
        assert_eq!(claimed.claim(&MINER, &[3, 11]), 0);
        assert_eq!(claimed.claim(&MINER, &[11, 13]), 1);
        assert!(claimed.contains(13));
        assert_eq!(claimed.len(), 3);
    }

    /// A credit share followed by the block candidate that extends it is the
    /// documented flow; only a *different* miner replaying the list is theft.
    #[test]
    fn the_same_miner_may_extend_its_own_credited_list() {
        const MINER: [u8; 32] = [7; 32];
        const OTHER: [u8; 32] = [9; 32];
        let mut claimed = ClaimedWitnesses::default();
        assert_eq!(claimed.claim(&MINER, &[3, 11]), 2);

        assert_eq!(claimed.claimed_by_other(&MINER, &[3, 11, 13]), None);
        assert_eq!(claimed.claimed_by_other(&OTHER, &[3, 11, 13]), Some(3));
        assert_eq!(claimed.claim(&MINER, &[3, 11, 13]), 1);
    }
}
