#![allow(clippy::needless_range_loop)]

use serde::{Deserialize, Serialize};

use crate::primitives::{BlockHeader, ChainConfig, Hash256};

pub const POUW_PROTOCOL_VERSION: u16 = 1;
pub const POUW_GRID_SIDE: usize = 64;
pub const POUW_CELL_COUNT: usize = POUW_GRID_SIDE * POUW_GRID_SIDE;
pub const POUW_ALPHA_Q12: i64 = 512;
pub const MAX_POUW_ITERATIONS: u64 = 4_096;
pub const POUW_ARITHMETIC_OPERATIONS_PER_CELL: u64 = 7;

const INPUT_DOMAIN: &[u8] = b"Hyphen/AetherCompute/PoUW/input/v1";
const OUTPUT_DOMAIN: &[u8] = b"Hyphen/AetherCompute/PoUW/output/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArenaParams {
    pub total_size: usize,
    pub page_size: usize,
    pub epoch_seed: Hash256,
}

pub struct EpochArena {
    pub params: ArenaParams,
}

impl EpochArena {
    pub fn generate(epoch_seed: Hash256, total_size: usize, page_size: usize) -> Self {
        assert!(total_size >= page_size && page_size >= 64);
        assert!(total_size.is_multiple_of(page_size));
        Self {
            params: ArenaParams {
                total_size,
                page_size,
                epoch_seed,
            },
        }
    }
}

#[derive(Clone, Copy)]
pub struct EpochKernelParams;

impl EpochKernelParams {
    pub fn derive(_epoch_seed: &[u8; 32]) -> Self {
        Self
    }
}

pub fn difficulty_to_iterations(difficulty: u64) -> Option<u32> {
    (1..=MAX_POUW_ITERATIONS)
        .contains(&difficulty)
        .then_some(difficulty as u32)
}

pub fn operation_count(difficulty: u64) -> Option<u64> {
    difficulty_to_iterations(difficulty).map(|iterations| {
        u64::from(iterations) * POUW_CELL_COUNT as u64 * POUW_ARITHMETIC_OPERATIONS_PER_CELL
    })
}

pub fn evaluate_pow(header: &BlockHeader, _arena: &EpochArena, _cfg: &ChainConfig) -> Hash256 {
    evaluate_scientific_work(header).unwrap_or(Hash256::ZERO)
}

pub fn evaluate_pow_with_epoch(
    header: &BlockHeader,
    _arena: &EpochArena,
    _cfg: &ChainConfig,
    _epoch: &EpochKernelParams,
) -> Hash256 {
    evaluate_scientific_work(header).unwrap_or(Hash256::ZERO)
}

pub fn evaluate_scientific_work(header: &BlockHeader) -> Option<Hash256> {
    let iterations = difficulty_to_iterations(header.difficulty)?;
    evaluate_scientific_work_at(header, iterations)
}

pub fn evaluate_scientific_work_at(header: &BlockHeader, iterations: u32) -> Option<Hash256> {
    let block_iterations = difficulty_to_iterations(header.difficulty)?;
    if iterations == 0 || iterations > block_iterations {
        return None;
    }
    let input_seed = scientific_input_seed(header);
    let mut input_bytes = [0u8; POUW_CELL_COUNT * 4];
    let mut input_hasher = blake3::Hasher::new_keyed(input_seed.as_bytes());
    input_hasher.update(INPUT_DOMAIN);
    input_hasher.finalize_xof().fill(&mut input_bytes);

    let mut current = vec![0i32; POUW_CELL_COUNT];
    let mut next = vec![0i32; POUW_CELL_COUNT];
    for (cell, bytes) in current.iter_mut().zip(input_bytes.chunks_exact(4)) {
        *cell = (u32::from_le_bytes(bytes.try_into().expect("four-byte cell")) & 0x3ffff) as i32;
    }

    let center_weight = 4096 - 4 * POUW_ALPHA_Q12;
    for _ in 0..iterations {
        for row in 0..POUW_GRID_SIDE {
            let north = (row + POUW_GRID_SIDE - 1) % POUW_GRID_SIDE;
            let south = (row + 1) % POUW_GRID_SIDE;
            for column in 0..POUW_GRID_SIDE {
                let west = (column + POUW_GRID_SIDE - 1) % POUW_GRID_SIDE;
                let east = (column + 1) % POUW_GRID_SIDE;
                let index = row * POUW_GRID_SIDE + column;
                let neighbours = i64::from(current[north * POUW_GRID_SIDE + column])
                    + i64::from(current[south * POUW_GRID_SIDE + column])
                    + i64::from(current[row * POUW_GRID_SIDE + west])
                    + i64::from(current[row * POUW_GRID_SIDE + east]);
                let numerator =
                    center_weight * i64::from(current[index]) + POUW_ALPHA_Q12 * neighbours;
                next[index] = i32::try_from(numerator / 4096).ok()?;
            }
        }
        std::mem::swap(&mut current, &mut next);
    }

    let mut commitment = blake3::Hasher::new();
    commitment.update(OUTPUT_DOMAIN);
    commitment.update(&POUW_PROTOCOL_VERSION.to_le_bytes());
    commitment.update(&(POUW_GRID_SIDE as u16).to_le_bytes());
    commitment.update(&(POUW_ALPHA_Q12 as u32).to_le_bytes());
    commitment.update(&iterations.to_le_bytes());
    commitment.update(input_seed.as_bytes());
    for cell in current {
        commitment.update(&cell.to_le_bytes());
    }
    Some(Hash256::from_bytes(*commitment.finalize().as_bytes()))
}

fn scientific_input_seed(header: &BlockHeader) -> Hash256 {
    let mut input = blake3::Hasher::new();
    input.update(INPUT_DOMAIN);
    input.update(&POUW_PROTOCOL_VERSION.to_le_bytes());
    input.update(&header.version.to_le_bytes());
    input.update(&header.height.to_le_bytes());
    input.update(&header.timestamp.to_le_bytes());
    input.update(header.prev_hash.as_bytes());
    input.update(header.tx_root.as_bytes());
    input.update(header.commitment_root.as_bytes());
    input.update(header.nullifier_root.as_bytes());
    input.update(header.state_root.as_bytes());
    input.update(header.receipt_root.as_bytes());
    input.update(header.uncle_root.as_bytes());
    input.update(header.epoch_seed.as_bytes());
    input.update(&header.difficulty.to_le_bytes());
    input.update(&header.nonce.to_le_bytes());
    input.update(&header.extra_nonce);
    input.update(&header.miner_pubkey);
    input.update(&header.total_fee.to_le_bytes());
    input.update(&header.reward.to_le_bytes());
    input.update(&[header.view_tag]);
    input.update(&header.block_size.to_le_bytes());
    Hash256::from_bytes(*input.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> BlockHeader {
        BlockHeader {
            version: crate::primitives::FROZEN_BLOCK_VERSION,
            height: 42,
            timestamp: 1_800_000_000_000,
            prev_hash: Hash256::from_bytes([1; 32]),
            tx_root: Hash256::from_bytes([2; 32]),
            commitment_root: Hash256::from_bytes([3; 32]),
            nullifier_root: Hash256::from_bytes([4; 32]),
            state_root: Hash256::from_bytes([5; 32]),
            receipt_root: Hash256::from_bytes([6; 32]),
            uncle_root: Hash256::from_bytes([7; 32]),
            pow_commitment: Hash256::ZERO,
            epoch_seed: Hash256::from_bytes([8; 32]),
            difficulty: 9,
            nonce: 10,
            extra_nonce: [11; 32],
            miner_pubkey: [12; 32],
            total_fee: 13,
            reward: 14,
            view_tag: 15,
            block_size: 16,
        }
    }

    #[test]
    fn scientific_vector_is_stable() {
        assert_eq!(
            evaluate_scientific_work(&header()).unwrap().to_string(),
            "25078c250c5b44211bbf0fea60e90ac7024df6ff94d154161852fdd72684e524"
        );
        assert_eq!(operation_count(9), Some(258_048));
    }

    #[test]
    fn scientific_work_binds_nonce_and_is_bounded() {
        let original = evaluate_scientific_work(&header()).unwrap();
        let mut changed = header();
        changed.nonce += 1;
        assert_ne!(evaluate_scientific_work(&changed).unwrap(), original);
        changed.difficulty = MAX_POUW_ITERATIONS + 1;
        assert_eq!(evaluate_scientific_work(&changed), None);
    }

    #[test]
    fn commitment_is_not_a_recursive_input_and_work_bounds_are_exact() {
        let mut with_placeholder = header();
        with_placeholder.pow_commitment = Hash256::from_bytes([99; 32]);
        assert_eq!(
            evaluate_scientific_work(&with_placeholder),
            evaluate_scientific_work(&header())
        );
        assert_eq!(difficulty_to_iterations(0), None);
        assert_eq!(difficulty_to_iterations(1), Some(1));
        assert_eq!(
            difficulty_to_iterations(MAX_POUW_ITERATIONS),
            Some(MAX_POUW_ITERATIONS as u32)
        );
        assert_eq!(difficulty_to_iterations(MAX_POUW_ITERATIONS + 1), None);
    }
}
