use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum PoolMode {
    #[default]
    Solo,
    Prop,
    Pps,
    Pplns,
    #[value(name = "pps+")]
    #[serde(rename = "pps+")]
    PpsPlus,
    Fpps,
}

impl PoolMode {
    pub fn default_fee_bps(self) -> u16 {
        match self {
            Self::Solo => 0,
            Self::Prop | Self::Pps | Self::Pplns | Self::PpsPlus | Self::Fpps => 100,
        }
    }

    pub fn uses_direct_coinbase(self) -> bool {
        matches!(self, Self::Solo)
    }
}

impl fmt::Display for PoolMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Solo => "solo",
            Self::Prop => "prop",
            Self::Pps => "pps",
            Self::Pplns => "pplns",
            Self::PpsPlus => "pps+",
            Self::Fpps => "fpps",
        };
        f.write_str(text)
    }
}

#[derive(Clone, Debug)]
pub struct PoolAccountingConfig {
    pub mode: PoolMode,
    pub pool_fee_bps: u16,
    pub pool_wallet: [u8; 32],
    pub pplns_window_factor: u32,
    pub state_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ShareCredit {
    miner_pubkey: [u8; 32],
    wallet_address: [u8; 32],
    difficulty: u64,
    timestamp: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MinerLedger {
    pub wallet_address: [u8; 32],
    pub valid_shares: u64,
    pub invalid_shares: u64,
    pub accumulated_share_difficulty: u128,
    pub pending_payout_atomic: u128,
    pub direct_reward_atomic: u128,
    pub total_blocks_found: u64,
    pub total_paid_atomic: u128,
    pub last_share_timestamp: Option<u64>,
    pub last_disconnect_timestamp: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSettlement {
    pub height: u64,
    pub block_hash_hex: String,
    pub finder_pubkey: [u8; 32],
    pub wallet_address: [u8; 32],
    #[serde(default)]
    pub reward_recipient: [u8; 32],
    pub gross_reward_atomic: u64,
    pub total_fee_atomic: u64,
    pub distributed_atomic: u128,
    pub pool_fee_atomic: u128,
    pub mode: PoolMode,
    #[serde(default)]
    pub direct_coinbase: bool,
    pub timestamp: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RewardEventKind {
    DirectCoinbase,
    PoolSettlement,
    FeeSettlement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRewardEvent {
    pub height: u64,
    pub block_hash_hex: String,
    pub wallet_address: [u8; 32],
    pub finder_pubkey: [u8; 32],
    pub reward_recipient: [u8; 32],
    pub amount_atomic: u128,
    pub mode: PoolMode,
    pub kind: RewardEventKind,
    pub direct_coinbase: bool,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletLedgerSummary {
    pub wallet_address: [u8; 32],
    pub mode: PoolMode,
    pub pool_fee_bps: u16,
    pub pool_wallet: [u8; 32],
    pub is_pool_wallet: bool,
    pub direct_coinbase_mode: bool,
    pub active_miners: u64,
    pub valid_shares: u64,
    pub invalid_shares: u64,
    pub accumulated_share_difficulty: u128,
    pub pending_payout_atomic: u128,
    pub direct_reward_atomic: u128,
    pub total_blocks_found: u64,
    pub total_paid_atomic: u128,
    pub last_share_timestamp: Option<u64>,
    pub last_disconnect_timestamp: Option<u64>,
    pub recent_blocks: Vec<BlockSettlement>,
    pub recent_reward_events: Vec<WalletRewardEvent>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccountingState {
    mode: PoolMode,
    pool_fee_bps: u16,
    pool_wallet: [u8; 32],
    pplns_window_factor: u32,
    pool_fee_earned_atomic: u128,
    miners: HashMap<String, MinerLedger>,
    round_shares: Vec<ShareCredit>,
    share_window: Vec<ShareCredit>,
    #[serde(default)]
    reward_events: Vec<WalletRewardEvent>,
    recent_blocks: Vec<BlockSettlement>,
}

impl AccountingState {
    fn new(config: &PoolAccountingConfig) -> Self {
        Self {
            mode: config.mode,
            pool_fee_bps: config.pool_fee_bps,
            pool_wallet: config.pool_wallet,
            pplns_window_factor: config.pplns_window_factor.max(1),
            pool_fee_earned_atomic: 0,
            miners: HashMap::new(),
            round_shares: Vec::new(),
            share_window: Vec::new(),
            reward_events: Vec::new(),
            recent_blocks: Vec::new(),
        }
    }
}

pub struct PoolAccounting {
    state: RwLock<AccountingState>,
    state_path: Option<PathBuf>,
}

impl PoolAccounting {
    pub fn new(config: PoolAccountingConfig) -> Self {
        let state_path = config
            .state_dir
            .as_ref()
            .map(|dir| dir.join("pool_accounting.bin"));
        let state = state_path
            .as_ref()
            .and_then(|path| Self::load_state(path))
            .unwrap_or_else(|| AccountingState::new(&config));
        Self {
            state: RwLock::new(state),
            state_path,
        }
    }

    pub fn mode(&self) -> PoolMode {
        self.state.read().mode
    }

    pub fn parse_wallet_input(input: &str) -> Result<[u8; 32], String> {
        if input.starts_with("hy1") {
            let encoded = &input[3..];
            let payload = bs58::decode(encoded)
                .into_vec()
                .map_err(|error| format!("invalid hy1 address base58: {error}"))?;
            if payload.len() != 69 {
                return Err(format!(
                    "invalid hy1 address length: expected 69, got {}",
                    payload.len()
                ));
            }
            let checksum = blake3::hash(&payload[..65]);
            if checksum.as_bytes()[..4] != payload[65..69] {
                return Err("hy1 address checksum mismatch".into());
            }
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(&payload[33..65]);
            return Ok(pubkey);
        }

        let bytes = hex::decode(input)
            .map_err(|error| format!("wallet must be a hy1... address or 64 hex chars: {error}"))?;
        if bytes.len() != 32 {
            return Err("hex wallet must be exactly 32 bytes (64 hex chars)".into());
        }

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&bytes);
        Ok(pubkey)
    }

    pub fn pool_wallet(&self) -> [u8; 32] {
        self.state.read().pool_wallet
    }

    pub fn pool_fee_bps(&self) -> u16 {
        self.state.read().pool_fee_bps
    }

    pub fn reward_recipient_for_wallet(&self, wallet_address: [u8; 32]) -> [u8; 32] {
        let state = self.state.read();
        if state.mode.uses_direct_coinbase() {
            wallet_address
        } else {
            state.pool_wallet
        }
    }

    pub fn register_miner(&self, miner_pubkey: [u8; 32], wallet_address: [u8; 32]) {
        let now = now_secs();
        {
            let mut state = self.state.write();
            let ledger = state.miners.entry(hex::encode(miner_pubkey)).or_default();
            ledger.wallet_address = wallet_address;
            ledger.last_share_timestamp.get_or_insert(now);
        }
        self.save_if_needed(true);
    }

    pub fn record_valid_share(
        &self,
        miner_pubkey: [u8; 32],
        wallet_address: [u8; 32],
        share_difficulty: u64,
        block_difficulty: u64,
        block_reward_atomic: u64,
        total_fee_atomic: u64,
    ) {
        let now = now_secs();
        let should_save;

        {
            let mut state = self.state.write();
            let miner_key = hex::encode(miner_pubkey);
            let mode = state.mode;
            let pool_fee_bps = state.pool_fee_bps;
            let pplns_window_factor = state.pplns_window_factor;
            let mut fee_delta = 0u128;

            let valid_share_count = {
                let ledger = state.miners.entry(miner_key.clone()).or_default();
                ledger.wallet_address = wallet_address;
                ledger.valid_shares = ledger.valid_shares.saturating_add(1);
                ledger.accumulated_share_difficulty = ledger
                    .accumulated_share_difficulty
                    .saturating_add(share_difficulty as u128);
                ledger.last_share_timestamp = Some(now);

                match mode {
                    PoolMode::Pps => {
                        let gross = proportional_credit(
                            share_difficulty,
                            block_difficulty,
                            block_reward_atomic as u128,
                        );
                        let net = apply_fee(gross, pool_fee_bps);
                        ledger.pending_payout_atomic =
                            ledger.pending_payout_atomic.saturating_add(net);
                        fee_delta = fee_delta.saturating_add(gross.saturating_sub(net));
                    }
                    PoolMode::PpsPlus => {
                        let gross = proportional_credit(
                            share_difficulty,
                            block_difficulty,
                            block_reward_atomic as u128,
                        );
                        let net = apply_fee(gross, pool_fee_bps);
                        ledger.pending_payout_atomic =
                            ledger.pending_payout_atomic.saturating_add(net);
                        fee_delta = fee_delta.saturating_add(gross.saturating_sub(net));
                    }
                    PoolMode::Fpps => {
                        let gross = proportional_credit(
                            share_difficulty,
                            block_difficulty,
                            block_reward_atomic as u128 + total_fee_atomic as u128,
                        );
                        let net = apply_fee(gross, pool_fee_bps);
                        ledger.pending_payout_atomic =
                            ledger.pending_payout_atomic.saturating_add(net);
                        fee_delta = fee_delta.saturating_add(gross.saturating_sub(net));
                    }
                    PoolMode::Solo | PoolMode::Prop | PoolMode::Pplns => {}
                }

                ledger.valid_shares
            };

            let share = ShareCredit {
                miner_pubkey,
                wallet_address,
                difficulty: share_difficulty.max(1),
                timestamp: now,
            };
            state.round_shares.push(share.clone());
            state.share_window.push(share);
            Self::trim_share_window(
                &mut state.share_window,
                block_difficulty,
                pplns_window_factor,
            );
            state.pool_fee_earned_atomic = state.pool_fee_earned_atomic.saturating_add(fee_delta);

            should_save = valid_share_count.is_multiple_of(32);
        }

        self.save_if_needed(should_save);
    }

    pub fn record_invalid_share(&self, miner_pubkey: [u8; 32]) {
        {
            let mut state = self.state.write();
            let ledger = state.miners.entry(hex::encode(miner_pubkey)).or_default();
            ledger.invalid_shares = ledger.invalid_shares.saturating_add(1);
        }
        self.save_if_needed(false);
    }

    pub fn note_disconnect(&self, miner_pubkey: [u8; 32]) {
        {
            let mut state = self.state.write();
            if let Some(ledger) = state.miners.get_mut(&hex::encode(miner_pubkey)) {
                ledger.last_disconnect_timestamp = Some(now_secs());
            }
        }
        self.save_if_needed(false);
    }

    pub fn miner_ledger(&self, miner_pubkey: &[u8; 32]) -> Option<MinerLedger> {
        self.state
            .read()
            .miners
            .get(&hex::encode(miner_pubkey))
            .cloned()
    }

    pub fn wallet_summary(
        &self,
        wallet_address: [u8; 32],
        recent_limit: usize,
    ) -> WalletLedgerSummary {
        let state = self.state.read();
        let mut summary = WalletLedgerSummary {
            wallet_address,
            mode: state.mode,
            pool_fee_bps: state.pool_fee_bps,
            pool_wallet: state.pool_wallet,
            is_pool_wallet: wallet_address == state.pool_wallet,
            direct_coinbase_mode: state.mode.uses_direct_coinbase(),
            active_miners: 0,
            valid_shares: 0,
            invalid_shares: 0,
            accumulated_share_difficulty: 0,
            pending_payout_atomic: 0,
            direct_reward_atomic: 0,
            total_blocks_found: 0,
            total_paid_atomic: 0,
            last_share_timestamp: None,
            last_disconnect_timestamp: None,
            recent_blocks: Vec::new(),
            recent_reward_events: Vec::new(),
        };

        for ledger in state.miners.values() {
            if ledger.wallet_address != wallet_address {
                continue;
            }

            summary.active_miners = summary.active_miners.saturating_add(1);
            summary.valid_shares = summary.valid_shares.saturating_add(ledger.valid_shares);
            summary.invalid_shares = summary.invalid_shares.saturating_add(ledger.invalid_shares);
            summary.accumulated_share_difficulty = summary
                .accumulated_share_difficulty
                .saturating_add(ledger.accumulated_share_difficulty);
            summary.pending_payout_atomic = summary
                .pending_payout_atomic
                .saturating_add(ledger.pending_payout_atomic);
            summary.direct_reward_atomic = summary
                .direct_reward_atomic
                .saturating_add(ledger.direct_reward_atomic);
            summary.total_blocks_found = summary
                .total_blocks_found
                .saturating_add(ledger.total_blocks_found);
            summary.total_paid_atomic = summary
                .total_paid_atomic
                .saturating_add(ledger.total_paid_atomic);
            summary.last_share_timestamp =
                max_option(summary.last_share_timestamp, ledger.last_share_timestamp);
            summary.last_disconnect_timestamp = max_option(
                summary.last_disconnect_timestamp,
                ledger.last_disconnect_timestamp,
            );
        }

        summary.recent_blocks = state
            .recent_blocks
            .iter()
            .rev()
            .filter(|block| block.wallet_address == wallet_address)
            .take(recent_limit.max(1))
            .cloned()
            .collect();

        summary.recent_reward_events = state
            .reward_events
            .iter()
            .rev()
            .filter(|event| event.wallet_address == wallet_address)
            .take(recent_limit.max(1) * 2)
            .cloned()
            .collect();

        summary
    }

    pub fn settle_block(
        &self,
        finder_pubkey: [u8; 32],
        wallet_address: [u8; 32],
        height: u64,
        block_hash_hex: String,
        block_reward_atomic: u64,
        total_fee_atomic: u64,
        block_difficulty: u64,
    ) {
        let now = now_secs();
        {
            let mut state = self.state.write();
            let gross_block_reward = block_reward_atomic as u128;
            let gross_total = gross_block_reward + total_fee_atomic as u128;
            let finder_key = hex::encode(finder_pubkey);
            let mode = state.mode;
            let pool_fee_bps = state.pool_fee_bps;
            let pplns_window_factor = state.pplns_window_factor;
            let reward_recipient = if mode.uses_direct_coinbase() {
                wallet_address
            } else {
                state.pool_wallet
            };
            let round_shares = state.round_shares.clone();
            let pplns_window =
                Self::pplns_window(&state.share_window, block_difficulty, pplns_window_factor);

            {
                let finder = state.miners.entry(finder_key).or_default();
                finder.wallet_address = wallet_address;
                finder.total_blocks_found = finder.total_blocks_found.saturating_add(1);
            }

            let (distributed_atomic, pool_fee_atomic, reward_events) = match mode {
                PoolMode::Solo => {
                    if let Some(finder) = state.miners.get_mut(&hex::encode(finder_pubkey)) {
                        finder.direct_reward_atomic =
                            finder.direct_reward_atomic.saturating_add(gross_total);
                    }
                    (
                        gross_total,
                        0,
                        vec![WalletRewardEvent {
                            height,
                            block_hash_hex: block_hash_hex.clone(),
                            wallet_address,
                            finder_pubkey,
                            reward_recipient,
                            amount_atomic: gross_total,
                            mode,
                            kind: RewardEventKind::DirectCoinbase,
                            direct_coinbase: true,
                            timestamp: now,
                        }],
                    )
                }
                PoolMode::Prop => {
                    let pool_fee = gross_total * pool_fee_bps as u128 / 10_000;
                    let distributable = gross_total.saturating_sub(pool_fee);
                    let reward_events = Self::distribute_weighted(
                        &mut state.miners,
                        &round_shares,
                        distributable,
                        height,
                        &block_hash_hex,
                        finder_pubkey,
                        reward_recipient,
                        mode,
                        RewardEventKind::PoolSettlement,
                        false,
                        now,
                    );
                    (distributable, pool_fee, reward_events)
                }
                PoolMode::Pplns => {
                    let pool_fee = gross_total * pool_fee_bps as u128 / 10_000;
                    let distributable = gross_total.saturating_sub(pool_fee);
                    let reward_events = Self::distribute_weighted(
                        &mut state.miners,
                        &pplns_window,
                        distributable,
                        height,
                        &block_hash_hex,
                        finder_pubkey,
                        reward_recipient,
                        mode,
                        RewardEventKind::PoolSettlement,
                        false,
                        now,
                    );
                    (distributable, pool_fee, reward_events)
                }
                PoolMode::Pps => (0, 0, Vec::new()),
                PoolMode::PpsPlus => {
                    let gross_fee_only = total_fee_atomic as u128;
                    let pool_fee = gross_fee_only * pool_fee_bps as u128 / 10_000;
                    let distributable = gross_fee_only.saturating_sub(pool_fee);
                    let reward_events = Self::distribute_weighted(
                        &mut state.miners,
                        &pplns_window,
                        distributable,
                        height,
                        &block_hash_hex,
                        finder_pubkey,
                        reward_recipient,
                        mode,
                        RewardEventKind::FeeSettlement,
                        false,
                        now,
                    );
                    (distributable, pool_fee, reward_events)
                }
                PoolMode::Fpps => (0, 0, Vec::new()),
            };

            state.pool_fee_earned_atomic =
                state.pool_fee_earned_atomic.saturating_add(pool_fee_atomic);
            state.round_shares.clear();
            state.reward_events.extend(reward_events);
            if state.reward_events.len() > 512 {
                let overflow = state.reward_events.len() - 512;
                state.reward_events.drain(..overflow);
            }
            state.recent_blocks.push(BlockSettlement {
                height,
                block_hash_hex,
                finder_pubkey,
                wallet_address,
                reward_recipient,
                gross_reward_atomic: block_reward_atomic,
                total_fee_atomic,
                distributed_atomic,
                pool_fee_atomic,
                mode,
                direct_coinbase: mode.uses_direct_coinbase(),
                timestamp: now,
            });
            if state.recent_blocks.len() > 128 {
                let overflow = state.recent_blocks.len() - 128;
                state.recent_blocks.drain(..overflow);
            }
        }

        self.save_if_needed(true);
    }

    fn distribute_weighted(
        miners: &mut HashMap<String, MinerLedger>,
        shares: &[ShareCredit],
        distributable: u128,
        height: u64,
        block_hash_hex: &str,
        finder_pubkey: [u8; 32],
        reward_recipient: [u8; 32],
        mode: PoolMode,
        kind: RewardEventKind,
        direct_coinbase: bool,
        timestamp: u64,
    ) -> Vec<WalletRewardEvent> {
        if shares.is_empty() || distributable == 0 {
            return Vec::new();
        }

        let total_weight: u128 = shares.iter().map(|share| share.difficulty as u128).sum();
        if total_weight == 0 {
            return Vec::new();
        }

        let mut allocations: HashMap<String, u128> = HashMap::new();
        let mut wallet_allocations: HashMap<[u8; 32], u128> = HashMap::new();
        let mut allocated = 0u128;

        for share in shares {
            let miner_key = hex::encode(share.miner_pubkey);
            let amount = distributable.saturating_mul(share.difficulty as u128) / total_weight;
            allocated = allocated.saturating_add(amount);
            *allocations.entry(miner_key).or_insert(0) += amount;
            *wallet_allocations.entry(share.wallet_address).or_insert(0) += amount;
        }

        let remainder = distributable.saturating_sub(allocated);
        if remainder > 0 {
            if let Some(top_share) = shares.iter().max_by_key(|share| share.difficulty) {
                *allocations
                    .entry(hex::encode(top_share.miner_pubkey))
                    .or_insert(0) += remainder;
                *wallet_allocations
                    .entry(top_share.wallet_address)
                    .or_insert(0) += remainder;
            }
        }

        for (miner_key, amount) in allocations {
            let ledger = miners.entry(miner_key).or_default();
            ledger.pending_payout_atomic = ledger.pending_payout_atomic.saturating_add(amount);
        }

        wallet_allocations
            .into_iter()
            .filter(|(_, amount)| *amount > 0)
            .map(|(wallet_address, amount_atomic)| WalletRewardEvent {
                height,
                block_hash_hex: block_hash_hex.to_string(),
                wallet_address,
                finder_pubkey,
                reward_recipient,
                amount_atomic,
                mode,
                kind,
                direct_coinbase,
                timestamp,
            })
            .collect()
    }

    fn pplns_window(
        shares: &[ShareCredit],
        block_difficulty: u64,
        factor: u32,
    ) -> Vec<ShareCredit> {
        if shares.is_empty() {
            return Vec::new();
        }

        let target_work = (block_difficulty.max(1) as u128).saturating_mul(factor.max(1) as u128);
        let mut selected = Vec::new();
        let mut work = 0u128;

        for share in shares.iter().rev() {
            selected.push(share.clone());
            work = work.saturating_add(share.difficulty as u128);
            if work >= target_work {
                break;
            }
        }

        selected.reverse();
        selected
    }

    fn trim_share_window(shares: &mut Vec<ShareCredit>, block_difficulty: u64, factor: u32) {
        let max_work = (block_difficulty.max(1) as u128)
            .saturating_mul(factor.max(1) as u128)
            .saturating_mul(4);
        let mut work = 0u128;
        let mut keep_from = shares.len();

        for (index, share) in shares.iter().enumerate().rev() {
            work = work.saturating_add(share.difficulty as u128);
            keep_from = index;
            if work >= max_work {
                break;
            }
        }

        if keep_from > 0 {
            shares.drain(..keep_from);
        }
    }

    fn load_state(path: &Path) -> Option<AccountingState> {
        let raw = std::fs::read(path).ok()?;
        if let Ok(state) = bincode::deserialize::<AccountingState>(&raw) {
            return Some(state);
        }
        let text = std::str::from_utf8(&raw).ok()?;
        serde_json::from_str(text).ok()
    }

    fn save_if_needed(&self, force: bool) {
        if !force {
            return;
        }

        let Some(path) = &self.state_path else {
            return;
        };

        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::create_dir_all(parent) {
                warn!("Failed to create pool accounting dir: {error}");
                return;
            }
        }

        let state = self.state.read().clone();
        match bincode::serialize(&state) {
            Ok(bytes) => {
                if let Err(error) = std::fs::write(path, bytes) {
                    warn!("Failed to persist pool accounting state: {error}");
                }
            }
            Err(error) => warn!("Failed to serialize pool accounting state: {error}"),
        }
    }
}

fn proportional_credit(share_difficulty: u64, block_difficulty: u64, amount: u128) -> u128 {
    if share_difficulty == 0 || block_difficulty == 0 || amount == 0 {
        return 0;
    }
    amount.saturating_mul(share_difficulty as u128) / block_difficulty as u128
}

fn apply_fee(amount: u128, pool_fee_bps: u16) -> u128 {
    amount.saturating_mul(10_000u128.saturating_sub(pool_fee_bps as u128)) / 10_000
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn max_option(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> PoolAccountingConfig {
        PoolAccountingConfig {
            mode: PoolMode::Prop,
            pool_fee_bps: 100,
            pool_wallet: [9u8; 32],
            pplns_window_factor: 2,
            state_dir: None,
        }
    }

    #[test]
    fn wallet_summary_aggregates_multiple_miners() {
        let accounting = PoolAccounting::new(sample_config());
        let wallet = [7u8; 32];
        let miner_a = [1u8; 32];
        let miner_b = [2u8; 32];

        accounting.register_miner(miner_a, wallet);
        accounting.register_miner(miner_b, wallet);
        accounting.record_valid_share(miner_a, wallet, 100, 1_000, 500, 0);
        accounting.record_valid_share(miner_b, wallet, 50, 1_000, 500, 0);

        let summary = accounting.wallet_summary(wallet, 8);
        assert_eq!(summary.wallet_address, wallet);
        assert_eq!(summary.active_miners, 2);
        assert_eq!(summary.valid_shares, 2);
        assert!(summary.pending_payout_atomic > 0);
    }
}
