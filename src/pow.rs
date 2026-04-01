#![allow(clippy::needless_range_loop)]

use blake3::Hasher as B3;
use serde::{Deserialize, Serialize};

use crate::primitives::{blake3_hash, BlockHeader, ChainConfig, Hash256};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArenaParams {
    pub total_size: usize,
    pub page_size: usize,
    pub epoch_seed: Hash256,
}

impl ArenaParams {
    pub fn page_count(&self) -> usize {
        self.total_size / self.page_size
    }
}

pub struct EpochArena {
    pub params: ArenaParams,
    pub data: Vec<u8>,
}

impl EpochArena {
    pub fn generate(epoch_seed: Hash256, total_size: usize, page_size: usize) -> Self {
        assert!(total_size >= page_size && page_size >= 64);
        assert!(total_size.is_multiple_of(page_size));
        let page_count = total_size / page_size;
        let mut data = vec![0u8; total_size];

        let key = *epoch_seed.as_bytes();
        for page_index in 0..page_count {
            let offset = page_index * page_size;
            let mut hasher = B3::new_keyed(&key);
            hasher.update(&(page_index as u64).to_le_bytes());
            hasher
                .finalize_xof()
                .fill(&mut data[offset..offset + page_size]);
        }

        for page_index in 0..page_count {
            let offset = page_index * page_size;
            let mut link_seed = [0u8; 32];
            link_seed.copy_from_slice(&data[offset + page_size - 32..offset + page_size]);
            let mut hasher = B3::new_keyed(&key);
            hasher.update(&link_seed);
            let link_hash: [u8; 32] = hasher.finalize().into();
            for slot in 0..4 {
                let start = slot * 8;
                let raw =
                    u64::from_le_bytes(link_hash[start..start + 8].try_into().expect("link slice"));
                let target = (raw % page_count as u64).to_le_bytes();
                data[offset + slot * 8..offset + slot * 8 + 8].copy_from_slice(&target);
            }
        }

        Self {
            params: ArenaParams {
                total_size,
                page_size,
                epoch_seed,
            },
            data,
        }
    }

    pub fn page(&self, index: usize) -> &[u8] {
        let offset = index * self.params.page_size;
        &self.data[offset..offset + self.params.page_size]
    }

    pub fn page_link(&self, page_index: usize, link_slot: usize) -> usize {
        assert!(link_slot < 4);
        let offset = page_index * self.params.page_size + link_slot * 8;
        let raw = u64::from_le_bytes(
            self.data[offset..offset + 8]
                .try_into()
                .expect("page link slice"),
        );
        raw as usize % self.params.page_count()
    }
}

pub struct Scratchpad {
    pub data: Vec<u8>,
    pub state: [u8; 64],
}

impl Scratchpad {
    pub fn new(size: usize, seed: &Hash256) -> Self {
        assert!(size >= 64);
        let mut data = vec![0u8; size];
        let key = *seed.as_bytes();
        let hasher = blake3::Hasher::new_keyed(&key);
        hasher.finalize_xof().fill(&mut data);

        let mut state = [0u8; 64];
        state[..32].copy_from_slice(seed.as_bytes());
        let second = blake3::keyed_hash(&key, &data[..64]);
        state[32..].copy_from_slice(&second.as_bytes()[..32]);

        Self { data, state }
    }

    pub fn write_u64(&mut self, pos: usize, value: u64) {
        let index = pos % (self.data.len() - 7);
        self.data[index..index + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub fn mix_state(&mut self, kernel_out: &[u8; 64]) {
        for (state_byte, output_byte) in self.state.iter_mut().zip(kernel_out.iter()) {
            *state_byte ^= *output_byte;
        }
    }

    pub fn writeback(&mut self) {
        let pos_raw =
            u64::from_le_bytes(self.state[0..8].try_into().expect("writeback slice")) as usize;
        let base = pos_raw % self.data.len().saturating_sub(64);
        for index in 0..64 {
            self.data[base + index] ^= self.state[index];
        }
    }

    pub fn next_page(&self, page_count: usize) -> usize {
        let raw = u64::from_le_bytes(self.state[8..16].try_into().expect("page slice"));
        raw as usize % page_count
    }

    pub fn select_kernel(&self, page_first_byte: u8, kernel_count: u8) -> u8 {
        (self.state[16] ^ page_first_byte) % kernel_count
    }

    pub fn select_link(&self) -> usize {
        (self.state[17] & 0x03) as usize
    }

    pub fn finalize(&self) -> Hash256 {
        let full = blake3::keyed_hash(self.state[..32].try_into().expect("state key"), &self.data);
        Hash256::from_bytes(*full.as_bytes())
    }
}

pub fn difficulty_to_target(difficulty: u64) -> [u8; 32] {
    if difficulty <= 1 {
        return [0xFF; 32];
    }

    let diff = difficulty as u128;
    let high = u128::MAX;
    let low = u128::MAX;
    let quot_high = high / diff;
    let rem_high = high % diff;
    let (quot_low, _) = div_wide(rem_high, low, diff);

    let mut target = [0u8; 32];
    target[..16].copy_from_slice(&quot_high.to_be_bytes());
    target[16..].copy_from_slice(&quot_low.to_be_bytes());
    target
}

fn div_wide(high: u128, low: u128, divisor: u128) -> (u128, u128) {
    if high == 0 {
        return (low / divisor, low % divisor);
    }
    let mut remainder = high % divisor;
    let mut quotient = 0u128;
    for bit in (0..128).rev() {
        remainder = remainder.checked_shl(1).unwrap_or(0);
        if (low >> bit) & 1 == 1 {
            remainder += 1;
        }
        if remainder >= divisor {
            remainder -= divisor;
            quotient |= 1u128 << bit;
        }
    }
    (quotient, remainder)
}

pub fn evaluate_pow(header: &BlockHeader, arena: &EpochArena, cfg: &ChainConfig) -> Hash256 {
    let header_bytes = header.serialise_for_hash();
    let seed = blake3_hash(&header_bytes);
    let mut scratchpad = Scratchpad::new(cfg.scratchpad_size, &seed);
    let page_count = arena.params.page_count();

    for round in 0..cfg.pow_rounds {
        let page_index = scratchpad.next_page(page_count);
        let page = arena.page(page_index);
        let kernel_id = scratchpad.select_kernel(page[32], cfg.kernel_count);
        let kernel_out = execute_kernel(kernel_id, page, &scratchpad.state);
        scratchpad.mix_state(&kernel_out);

        let write_pos =
            u64::from_le_bytes(kernel_out[0..8].try_into().expect("write pos")) as usize;
        let write_value = u64::from_le_bytes(kernel_out[8..16].try_into().expect("write value"));
        scratchpad.write_u64(write_pos, write_value);

        let link_slot = scratchpad.select_link();
        let linked_page = arena.page_link(page_index, link_slot);
        let link_data = arena.page(linked_page);
        let link_mix = u64::from_le_bytes(link_data[32..40].try_into().expect("link mix"));
        scratchpad.write_u64(write_pos.wrapping_add(8), link_mix);

        if round % cfg.writeback_interval == 0 {
            scratchpad.writeback();
        }
    }

    scratchpad.finalize()
}

fn execute_kernel(kernel_id: u8, page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    match kernel_id {
        0 => kernel_div_chain(page, state),
        1 => kernel_bit_weave(page, state),
        2 => kernel_sparse_step(page, state),
        3 => kernel_prefix_scan(page, state),
        4 => kernel_micro_sort(page, state),
        5 => kernel_var_decode(page, state),
        6 => kernel_hash_mix(page, state),
        7 => kernel_branch_maze(page, state),
        8 => kernel_aes_cascade(page, state),
        9 => kernel_float_emulate(page, state),
        10 => kernel_scatter_gather(page, state),
        11 => kernel_mod_exp_chain(page, state),
        _ => kernel_div_chain(page, state),
    }
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let offset = off % (buf.len().saturating_sub(7).max(1));
    u64::from_le_bytes(
        buf[offset..offset + 8]
            .try_into()
            .expect("read_u64_le slice"),
    )
}

fn state_u64(state: &[u8; 64], index: usize) -> u64 {
    u64::from_le_bytes(
        state[index * 8..(index + 1) * 8]
            .try_into()
            .expect("state_u64 slice"),
    )
}

fn to_output(values: &[u64; 8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    for (index, value) in values.iter().enumerate() {
        output[index * 8..(index + 1) * 8].copy_from_slice(&value.to_le_bytes());
    }
    output
}

fn kernel_div_chain(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..64u64 {
        let page_val = read_u64_le(page, (step as usize * 61) % page.len());
        let divisor = page_val.wrapping_add(3) | 3;
        let slot = step as usize % 8;
        let dividend = acc[slot]
            .wrapping_add(acc[(slot + 1) % 8])
            .wrapping_add(step);
        acc[slot] = dividend / divisor;
        acc[(slot + 3) % 8] = acc[(slot + 3) % 8].wrapping_add(dividend % divisor);
    }
    to_output(&acc)
}

fn kernel_bit_weave(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..64u64 {
        let data = read_u64_le(page, (step as usize * 43 + 17) % page.len());
        let rot_amount = (data & 63) as u32;
        let slot = step as usize % 8;
        acc[slot] = acc[slot].rotate_left(rot_amount) ^ data;
        acc[(slot + 5) % 8] = acc[(slot + 5) % 8].rotate_right((acc[slot] & 63) as u32);
        acc[(slot + 2) % 8] ^= acc[slot].wrapping_mul(0x9E3779B97F4A7C15);
    }
    to_output(&acc)
}

fn kernel_sparse_step(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..48u64 {
        let idx_raw = read_u64_le(page, (step as usize * 83) % page.len());
        let idx = (idx_raw as usize) % (page.len() / 8);
        let value = read_u64_le(page, idx * 8 % page.len());
        let slot = step as usize % 8;
        acc[slot] = acc[slot].wrapping_add(value.wrapping_mul(acc[(slot + 1) % 8] | 1));
        acc[(slot + 4) % 8] ^= value.rotate_left((acc[slot] & 31) as u32);
    }
    to_output(&acc)
}

fn kernel_prefix_scan(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut arr = [0u64; 64];
    for index in 0..64 {
        arr[index] =
            read_u64_le(page, index * 61 % page.len()).wrapping_add(state_u64(state, index % 8));
    }
    let mut distance = 1;
    while distance < 64 {
        let mut index = 0;
        while index < 64 {
            let left = index + distance - 1;
            let right = index + 2 * distance - 1;
            if right < 64 {
                arr[right] = arr[right].wrapping_add(arr[left]);
            }
            index += 2 * distance;
        }
        distance *= 2;
    }
    arr[63] = 0;
    distance = 32;
    while distance >= 1 {
        let mut index = 0;
        while index < 64 {
            let left = index + distance - 1;
            let right = index + 2 * distance - 1;
            if right < 64 {
                let tmp = arr[left];
                arr[left] = arr[right];
                arr[right] = arr[right].wrapping_add(tmp);
            }
            index += 2 * distance;
        }
        distance /= 2;
    }
    let mut acc = [0u64; 8];
    for index in 0..64 {
        acc[index % 8] ^= arr[index];
    }
    to_output(&acc)
}

fn kernel_micro_sort(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut arr = [0u64; 32];
    for index in 0..32 {
        arr[index] = read_u64_le(page, index * 127 % page.len()) ^ state_u64(state, index % 8);
    }
    for index in 1..32 {
        let key = arr[index];
        let mut inner = index;
        while inner > 0 && arr[inner - 1] > key {
            arr[inner] = arr[inner - 1];
            inner -= 1;
        }
        arr[inner] = key;
    }
    let mut acc = [0u64; 8];
    for index in 0..32 {
        acc[index % 8] = acc[index % 8].wrapping_add(arr[index].wrapping_mul(index as u64 + 1));
    }
    to_output(&acc)
}

fn kernel_var_decode(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    let mut cursor = (state_u64(state, 0) as usize) % page.len();
    for step in 0..48u64 {
        let mut result = 0u64;
        let mut shift = 0u32;
        for _ in 0..10 {
            let byte = page[cursor % page.len()];
            cursor = cursor.wrapping_add(1);
            result |= ((byte & 0x7F) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 || shift >= 64 {
                break;
            }
        }
        let slot = step as usize % 8;
        acc[slot] = acc[slot].wrapping_add(result);
        acc[(slot + 3) % 8] ^= result.rotate_left((step as u32) & 63);
    }
    to_output(&acc)
}

static SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn kernel_hash_mix(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block.copy_from_slice(state);
    for round in 0..16u32 {
        let page_off = (round as usize * 251) % page.len().saturating_sub(16).max(1);
        for byte in &mut block {
            *byte = SBOX[*byte as usize];
        }
        for index in 0..16 {
            block[index + (round as usize % 4) * 16] ^= page[page_off + index % page.len().min(16)];
        }
        for col in 0..4 {
            let base = col * 16;
            let first = block[base];
            block[base] = block[base + 1];
            block[base + 1] = block[base + 2];
            block[base + 2] = block[base + 3];
            block[base + 3] = first ^ block[base];
        }
    }
    block
}

fn kernel_branch_maze(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    let mut cursor = (acc[0] as usize) % page.len();
    for step in 0..64u64 {
        let value = read_u64_le(page, cursor);
        let slot = step as usize % 8;
        match value & 0x07 {
            0 => {
                acc[slot] = acc[slot].wrapping_add(value);
                cursor = cursor.wrapping_add((value as usize).wrapping_mul(7)) % page.len();
            }
            1 => {
                acc[slot] = acc[slot].wrapping_sub(value.rotate_left(13));
                cursor = cursor.wrapping_add(acc[slot] as usize) % page.len();
            }
            2 => {
                acc[slot] ^= value.wrapping_mul(0xBF58476D1CE4E5B9);
                cursor = cursor.wrapping_add(17 + step as usize) % page.len();
            }
            3 => {
                let div = (value >> 32) | 1;
                acc[slot] = acc[slot].wrapping_mul(value | 1) / div;
                cursor = cursor.wrapping_add(div as usize) % page.len();
            }
            4 => {
                acc[slot] = acc[slot].rotate_left((value & 63) as u32);
                acc[(slot + 1) % 8] ^= value;
                cursor = cursor.wrapping_add(acc[(slot + 1) % 8] as usize) % page.len();
            }
            5 => {
                acc[slot] = acc[slot].wrapping_add((value.count_ones() as u64).wrapping_mul(step));
                cursor = cursor.wrapping_add(3 + value as usize) % page.len();
            }
            6 => {
                acc[slot] = (acc[slot] ^ value).reverse_bits();
                cursor = cursor.wrapping_add(acc[slot] as usize) % page.len();
            }
            _ => {
                acc[slot] = acc[slot]
                    .wrapping_add(value)
                    .wrapping_mul(0x94D049BB133111EB);
                cursor = cursor.wrapping_add((value >> 8) as usize) % page.len();
            }
        }
    }
    to_output(&acc)
}

fn kernel_aes_cascade(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut buf = [0u8; 64];
    buf.copy_from_slice(state);
    for round in 0..24u32 {
        let page_off = (round as usize).wrapping_mul(197) % page.len().saturating_sub(64).max(1);
        for i in 0..64 {
            buf[i] = SBOX[buf[i] as usize];
        }
        for lane in 0..4usize {
            let base = lane * 16;
            let shift = lane + 1;
            let mut tmp = [0u8; 16];
            for i in 0..16 {
                tmp[i] = buf[base + (i + shift) % 16];
            }
            buf[base..base + 16].copy_from_slice(&tmp);
        }
        let safe_len = page.len().min(page_off + 64) - page_off;
        for i in 0..safe_len.min(64) {
            buf[i] ^= page[page_off + i];
        }
        for col in 0..16 {
            let a = buf[col] as u16;
            let b = buf[col + 16] as u16;
            let c = buf[col + 32] as u16;
            let d = buf[col + 48] as u16;
            let mixed = (a.wrapping_mul(2) ^ b.wrapping_mul(3) ^ c ^ d) as u8;
            buf[col] ^= mixed;
            buf[col + 16] ^= (a ^ b.wrapping_mul(2) ^ c.wrapping_mul(3) ^ d) as u8;
            buf[col + 32] ^= (a ^ b ^ c.wrapping_mul(2) ^ d.wrapping_mul(3)) as u8;
            buf[col + 48] ^= (a.wrapping_mul(3) ^ b ^ c ^ d.wrapping_mul(2)) as u8;
        }
    }
    buf
}

fn kernel_float_emulate(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..64u64 {
        let data = read_u64_le(page, (step as usize).wrapping_mul(73) % page.len());
        let slot = step as usize % 8;
        let a_hi = (acc[slot] >> 32) as u32;
        let a_lo = acc[slot] as u32;
        let d_hi = (data >> 32) as u32;
        let d_lo = data as u32;
        let cross1 = (a_hi as u64).wrapping_mul(d_lo as u64);
        let cross2 = (a_lo as u64).wrapping_mul(d_hi as u64);
        let full = (a_hi as u64).wrapping_mul(d_hi as u64);
        let mid = cross1.wrapping_add(cross2).wrapping_add(full << 16);
        let denom = data | 0x8000_0000_0000_0001;
        let est = u64::MAX / denom + 1;
        let refined = est.wrapping_mul(2u64.wrapping_sub(denom.wrapping_mul(est) >> 32));
        acc[slot] = mid ^ refined;
        acc[(slot + 3) % 8] = acc[(slot + 3) % 8].wrapping_add(
            mid.wrapping_mul(0x517CC1B727220A95)
                .rotate_left((step as u32) & 63),
        );
        acc[(slot + 6) % 8] ^= refined.wrapping_sub(acc[slot]);
    }
    to_output(&acc)
}

fn kernel_scatter_gather(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut scratch = [0u8; 2048];
    for index in 0..2048 {
        scratch[index] = state[index % 64] ^ (index as u8).wrapping_mul(0x9D);
    }
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..80u64 {
        let slot = step as usize % 8;
        let page_idx = (acc[slot] as usize) % page.len().saturating_sub(7).max(1);
        let page_val = read_u64_le(page, page_idx);
        let scratch_idx = (page_val as usize) % (2048 - 7);
        let scratch_val = u64::from_le_bytes(
            scratch[scratch_idx..scratch_idx + 8]
                .try_into()
                .expect("scratch slice"),
        );
        let mixed = page_val
            .wrapping_mul(scratch_val | 1)
            .rotate_left((acc[(slot + 1) % 8] & 63) as u32);
        acc[slot] = acc[slot].wrapping_add(mixed);
        let writeback_idx = (acc[slot] as usize) % (2048 - 7);
        scratch[writeback_idx..writeback_idx + 8].copy_from_slice(&acc[slot].to_le_bytes());
        acc[(slot + 4) % 8] ^= acc[slot].wrapping_mul(0x2545F4914F6CDD1D);
    }
    to_output(&acc)
}

fn kernel_mod_exp_chain(page: &[u8], state: &[u8; 64]) -> [u8; 64] {
    let mut acc = [0u64; 8];
    for index in 0..8 {
        acc[index] = state_u64(state, index);
    }
    for step in 0..56u64 {
        let slot = step as usize % 8;
        let data = read_u64_le(page, (step as usize).wrapping_mul(89) % page.len());
        let modulus = data.wrapping_add(acc[(slot + 2) % 8]) | 0x8000_0000_0000_0001;
        let mut base = acc[slot];
        let mut result = 1u64;
        let exp_bits = acc[(slot + 1) % 8];
        for bit in 0..6u32 {
            let square = (base as u128).wrapping_mul(base as u128);
            base = (square % modulus as u128) as u64;
            if (exp_bits >> (bit * 10)) & 1 == 1 {
                let product = (result as u128).wrapping_mul(base as u128);
                result = (product % modulus as u128) as u64;
            }
        }
        acc[slot] = result;
        let remainder = acc[slot] % (data | 1);
        acc[(slot + 5) % 8] = acc[(slot + 5) % 8]
            .wrapping_add(remainder)
            .rotate_left((step as u32) & 63);
    }
    to_output(&acc)
}
