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
    pub pool_view_public: [u8; 32],
    pub network_magic: [u8; 4],
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
    network_magic: [u8; 4],
    /// Maps spend_public → view_public for all registered miners and the pool wallet.
    view_keys: RwLock<HashMap<[u8; 32], [u8; 32]>>,
}

impl PoolAccounting {
    pub fn new(config: PoolAccountingConfig) -> Self {
        let state_path = config
            .state_dir
            .as_ref()
            .map(|dir| dir.join("pool_accounting.bin"));
        let state = state_path
            .as_ref()
            .and_then(|path| Self::load_state_with_backup(path))
            .unwrap_or_else(|| AccountingState::new(&config));
        let mut view_keys = HashMap::new();
        if config.pool_view_public != [0u8; 32] {
            view_keys.insert(config.pool_wallet, config.pool_view_public);
        }
        Self {
            state: RwLock::new(state),
            state_path,
            network_magic: config.network_magic,
            view_keys: RwLock::new(view_keys),
        }
    }

    pub fn mode(&self) -> PoolMode {
        self.state.read().mode
    }

    /// Parse a wallet address string and return `(view_public, spend_public)`.
    pub fn parse_wallet_input(
        input: &str,
        network_magic: [u8; 4],
    ) -> Result<([u8; 32], [u8; 32]), String> {
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
            let expected_version = match network_magic {
                [0x48, 0x59, 0x50, 0x4e] => 0x01,
                [0x48, 0x59, 0x54, 0x53] | [0x48, 0x59, 0x44, 0x56] => 0x02,
                _ => return Err("unknown Hyphen network magic".into()),
            };
            if payload[0] != expected_version {
                return Err("wallet address belongs to a different Hyphen network".into());
            }
            let mut view_public = [0u8; 32];
            view_public.copy_from_slice(&payload[1..33]);
            let mut spend_public = [0u8; 32];
            spend_public.copy_from_slice(&payload[33..65]);
            return Ok((view_public, spend_public));
        }

        Err("wallet must be a hy1... address".into())
    }

    pub fn decode_wallet(&self, input: &str) -> Result<([u8; 32], [u8; 32]), String> {
        Self::parse_wallet_input(input, self.network_magic)
    }

    pub fn pool_wallet(&self) -> [u8; 32] {
        self.state.read().pool_wallet
    }

    pub fn pool_fee_bps(&self) -> u16 {
        self.state.read().pool_fee_bps
    }

    /// Store the view_public for a given spend_public (miner address).
    pub fn register_view_key(&self, spend_public: [u8; 32], view_public: [u8; 32]) {
        self.view_keys.write().insert(spend_public, view_public);
    }

    /// Look up the view_public for a given spend_public.
    pub fn get_view_public(&self, spend_public: &[u8; 32]) -> Option<[u8; 32]> {
        self.view_keys.read().get(spend_public).copied()
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
            if let Some(latest) = state.recent_blocks.last() {
                if height <= latest.height
                    || state
                        .recent_blocks
                        .iter()
                        .any(|block| block.block_hash_hex == block_hash_hex)
                {
                    warn!(
                        "Ignored duplicate or out-of-order block settlement: height={}, hash={}",
                        height, block_hash_hex
                    );
                    return;
                }
            }
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

    fn load_state_with_backup(path: &Path) -> Option<AccountingState> {
        if let Some(state) = Self::load_state(path) {
            return Some(state);
        }
        let backup = persistence_sidecar(path, "bak");
        let recovered = Self::load_state(&backup);
        if recovered.is_some() {
            warn!(
                "Recovered pool accounting state from {} after primary-state failure",
                backup.display()
            );
        }
        recovered
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
                let temporary = persistence_sidecar(path, "next");
                let backup = persistence_sidecar(path, "bak");
                let write_result = (|| -> Result<(), std::io::Error> {
                    use std::io::Write;

                    let mut file = std::fs::OpenOptions::new()
                        .create(true)
                        .truncate(true)
                        .write(true)
                        .open(&temporary)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;

                    if path.exists() {
                        if backup.exists() {
                            std::fs::remove_file(&backup)?;
                        }
                        std::fs::rename(path, &backup)?;
                    }
                    if let Err(error) = std::fs::rename(&temporary, path) {
                        if !path.exists() && backup.exists() {
                            let _ = std::fs::rename(&backup, path);
                        }
                        return Err(error);
                    }
                    Ok(())
                })();
                if let Err(error) = write_result {
                    warn!("Failed to atomically persist pool accounting state: {error}");
                }
            }
            Err(error) => warn!("Failed to serialize pool accounting state: {error}"),
        }
    }
}

fn persistence_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pool_accounting.bin");
    path.with_file_name(format!("{file_name}.{suffix}"))
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
            pool_view_public: [0u8; 32],
            network_magic: [0x48, 0x59, 0x54, 0x53],
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

        let before_settlement = accounting.wallet_summary(wallet, 8);
        assert_eq!(before_settlement.pending_payout_atomic, 0);

        accounting.settle_block(miner_a, wallet, 1, "01".repeat(32), 500, 0, 1_000);

        let summary = accounting.wallet_summary(wallet, 8);
        assert_eq!(summary.wallet_address, wallet);
        assert_eq!(summary.active_miners, 2);
        assert_eq!(summary.valid_shares, 2);
        assert!(summary.pending_payout_atomic > 0);
    }

    #[test]
    fn rejects_wallet_from_another_network() {
        let mut payload = vec![0x01];
        payload.extend_from_slice(&[7u8; 32]);
        payload.extend_from_slice(&[8u8; 32]);
        let checksum = blake3::hash(&payload);
        payload.extend_from_slice(&checksum.as_bytes()[..4]);
        let address = format!("hy1{}", bs58::encode(payload).into_string());

        let error =
            PoolAccounting::parse_wallet_input(&address, [0x48, 0x59, 0x54, 0x53]).unwrap_err();
        assert!(error.contains("different Hyphen network"));
    }

    #[test]
    fn accepts_test_address_on_devnet() {
        let mut payload = vec![0x02];
        payload.extend_from_slice(&[7u8; 32]);
        payload.extend_from_slice(&[8u8; 32]);
        let checksum = blake3::hash(&payload);
        payload.extend_from_slice(&checksum.as_bytes()[..4]);
        let address = format!("hy1{}", bs58::encode(payload).into_string());

        let (view_public, spend_public) =
            PoolAccounting::parse_wallet_input(&address, [0x48, 0x59, 0x44, 0x56]).unwrap();
        assert_eq!(view_public, [7u8; 32]);
        assert_eq!(spend_public, [8u8; 32]);
    }

    #[test]
    fn recovers_last_committed_ledger_after_primary_corruption() {
        let test_dir = std::env::temp_dir().join(format!(
            "hyphen_pool_fault_injection_{}_{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut config = sample_config();
        config.state_dir = Some(test_dir.clone());
        let first_miner = [31u8; 32];
        let second_miner = [32u8; 32];
        let wallet = [33u8; 32];

        {
            let accounting = PoolAccounting::new(config.clone());
            accounting.register_miner(first_miner, wallet);
            accounting.register_miner(second_miner, wallet);
        }

        let primary = test_dir.join("pool_accounting.bin");
        std::fs::write(&primary, b"fault-injected-truncated-state").unwrap();

        let recovered = PoolAccounting::new(config);
        assert!(recovered.miner_ledger(&first_miner).is_some());
        assert!(recovered.miner_ledger(&second_miner).is_none());

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn duplicate_block_settlement_is_idempotent() {
        let mut config = sample_config();
        config.mode = PoolMode::Solo;
        config.pool_fee_bps = 0;
        let accounting = PoolAccounting::new(config);
        let miner = [41u8; 32];
        let wallet = [42u8; 32];

        accounting.register_miner(miner, wallet);
        accounting.record_valid_share(miner, wallet, 1, 1_000, 500, 5);
        accounting.settle_block(miner, wallet, 7, "ab".repeat(32), 500, 5, 1_000);
        accounting.settle_block(miner, wallet, 7, "ab".repeat(32), 500, 5, 1_000);

        let summary = accounting.wallet_summary(wallet, 8);
        assert_eq!(summary.total_blocks_found, 1);
        assert_eq!(summary.direct_reward_atomic, 505);
        assert_eq!(summary.recent_blocks.len(), 1);
        assert_eq!(summary.recent_reward_events.len(), 1);
    }

    #[test]
    fn pplns_excludes_old_work_after_trailing_target_is_met() {
        let mut config = sample_config();
        config.mode = PoolMode::Pplns;
        config.pool_fee_bps = 0;
        config.pplns_window_factor = 1;
        let accounting = PoolAccounting::new(config);
        let old_miner = [51u8; 32];
        let recent_a = [52u8; 32];
        let recent_b = [53u8; 32];

        accounting.record_valid_share(old_miner, old_miner, 100, 100, 1_000, 0);
        accounting.record_valid_share(recent_a, recent_a, 60, 100, 1_000, 0);
        accounting.record_valid_share(recent_b, recent_b, 40, 100, 1_000, 0);
        accounting.settle_block(recent_b, recent_b, 1, "cd".repeat(32), 1_000, 0, 100);

        assert_eq!(
            accounting
                .miner_ledger(&old_miner)
                .unwrap()
                .pending_payout_atomic,
            0
        );
        assert_eq!(
            accounting
                .miner_ledger(&recent_a)
                .unwrap()
                .pending_payout_atomic,
            600
        );
        assert_eq!(
            accounting
                .miner_ledger(&recent_b)
                .unwrap()
                .pending_payout_atomic,
            400
        );
    }
}
