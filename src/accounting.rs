use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};

use crate::primitives::{base58, blake3_hash, hex_decode, hex_encode};
use clap::ValueEnum;
use parking_lot::RwLock;
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    WriteTransaction,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
mod rewards;
use rewards::RewardAccounting;

const ACCOUNTING_STATE_MAGIC: &[u8; 16] = b"HyPoolAccountV1\0";
const LEDGER: TableDefinition<&str, &[u8]> = TableDefinition::new("ledger_v1");
const WITNESSES: TableDefinition<u64, &[u8; 32]> = TableDefinition::new("witness_owners_v1");
const BLOCK_CREDITS: TableDefinition<&str, &[u8]> = TableDefinition::new("block_credits_v1");
const CANDIDATES: TableDefinition<&str, &[u8]> = TableDefinition::new("pending_blocks_v1");
const CONFIRMED_PAYOUTS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("confirmed_payouts_v1");

#[derive(rustbinary::CompactBinary)]
pub(crate) struct PendingBlock {
    pub wallet: [u8; 32],
    pub block: crate::primitives::Block,
}

fn storage_error(error: impl fmt::Display) -> AccountingError {
    AccountingError::Persistence(error.to_string())
}

/// Settled payout history kept in the ledger.
const PAYOUT_HISTORY_LIMIT: usize = 512;
type RecipientKey = ([u8; 32], [u8; 32]);
type RecipientBalances = Vec<(String, u128)>;

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Serialize,
    Deserialize,
    ValueEnum,
    rustbinary::CompactBinary,
)]
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

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
struct ShareCredit {
    miner_pubkey: [u8; 32],
    wallet_address: [u8; 32],
    difficulty: u64,
    timestamp: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct MinerLedger {
    pub wallet_address: [u8; 32],
    #[serde(default)]
    pub wallet_view_public: [u8; 32],
    pub valid_shares: u64,
    pub invalid_shares: u64,
    pub accumulated_share_difficulty: u128,
    pub pending_payout_atomic: u128,
    #[serde(default)]
    pub reserved_payout_atomic: u128,
    pub direct_reward_atomic: u128,
    pub total_blocks_found: u64,
    pub total_paid_atomic: u128,
    pub last_share_timestamp: Option<u64>,
    pub last_disconnect_timestamp: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, rustbinary::CompactBinary)]
#[serde(rename_all = "snake_case")]
pub enum PayoutStatus {
    Reserved,
    Submitted {
        tx_hash: String,
        submitted_at: u64,
    },
    Confirmed {
        tx_hash: String,
        block_height: u64,
        confirmations: u64,
        confirmed_at: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, rustbinary::CompactBinary)]
struct PayoutAllocation {
    miner_key: String,
    amount_atomic: u128,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, rustbinary::CompactBinary)]
pub struct PayoutRecord {
    pub intent_id: String,
    pub recipient_view_public: [u8; 32],
    pub recipient_spend_public: [u8; 32],
    pub amount_atomic: u64,
    pub created_at: u64,
    pub status: PayoutStatus,
    allocations: Vec<PayoutAllocation>,
}

impl PayoutRecord {
    pub fn recipient_address(&self, network_magic: [u8; 4]) -> Result<String, AccountingError> {
        encode_wallet_address(
            self.recipient_view_public,
            self.recipient_spend_public,
            network_magic,
        )
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AccountingError {
    #[error("witness {0} was already claimed by another miner on this pool")]
    WitnessClaimed(u64),
    #[error("block at height {0} conflicts with the existing settlement history")]
    SettlementConflict(u64),
    #[error("pool accounting is not configured with durable state")]
    PersistenceDisabled,
    #[error("pool accounting persistence failed: {0}")]
    Persistence(String),
    #[error("payout record was not found: {0}")]
    PayoutNotFound(String),
    #[error("invalid payout transition: {0}")]
    InvalidPayoutTransition(String),
    #[error("payout address is unavailable or inconsistent")]
    MissingPayoutAddress,
    #[error("payout amount cannot be represented on chain")]
    PayoutAmountOverflow,
    #[error("invalid network magic")]
    InvalidNetwork,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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

#[derive(Debug, Serialize, rustbinary::CompactBinary)]
pub struct BlockCredits {
    settlement: BlockSettlement,
    pending_by_miner: BTreeMap<String, u128>,
}

/// Read an immutable settlement from a stopped pool's database copy.
pub fn read_block_credits(directory: &Path, hash: &str) -> Result<BlockCredits, AccountingError> {
    validate_hash_hex(hash, "block hash")?;
    let db = Database::open(directory.join("pool_accounting.redb")).map_err(storage_error)?;
    let read = db.begin_read().map_err(storage_error)?;
    let table = read.open_table(BLOCK_CREDITS).map_err(storage_error)?;
    let key = hash.to_ascii_lowercase();
    let bytes = table
        .get(key.as_str())
        .map_err(storage_error)?
        .ok_or_else(|| storage_error("no recorded miner allocation for this block hash"))?;
    crate::wire_config(crate::DEFAULT_WIRE_BYTES)
        .deserialize(bytes.value())
        .map_err(storage_error)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
#[serde(rename_all = "snake_case")]
pub enum RewardEventKind {
    DirectCoinbase,
    PoolSettlement,
    FeeSettlement,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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
    pub reward_deficit_atomic: u128,
    pub reserved_payout_atomic: u128,
    pub direct_reward_atomic: u128,
    pub total_blocks_found: u64,
    pub total_paid_atomic: u128,
    pub last_share_timestamp: Option<u64>,
    pub last_disconnect_timestamp: Option<u64>,
    pub recent_blocks: Vec<BlockSettlement>,
    pub recent_reward_events: Vec<WalletRewardEvent>,
    pub recent_payouts: Vec<PayoutRecord>,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
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
    #[serde(default)]
    payouts: Vec<PayoutRecord>,
    #[serde(default)]
    next_payout_sequence: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
struct LegacyMinerLedgerV0 {
    wallet_address: [u8; 32],
    valid_shares: u64,
    invalid_shares: u64,
    accumulated_share_difficulty: u128,
    pending_payout_atomic: u128,
    direct_reward_atomic: u128,
    total_blocks_found: u64,
    total_paid_atomic: u128,
    last_share_timestamp: Option<u64>,
    last_disconnect_timestamp: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, rustbinary::CompactBinary)]
struct LegacyAccountingStateV0 {
    mode: PoolMode,
    pool_fee_bps: u16,
    pool_wallet: [u8; 32],
    pplns_window_factor: u32,
    pool_fee_earned_atomic: u128,
    miners: HashMap<String, LegacyMinerLedgerV0>,
    round_shares: Vec<ShareCredit>,
    share_window: Vec<ShareCredit>,
    #[serde(default)]
    reward_events: Vec<WalletRewardEvent>,
    recent_blocks: Vec<BlockSettlement>,
}

impl From<LegacyAccountingStateV0> for AccountingState {
    fn from(legacy: LegacyAccountingStateV0) -> Self {
        Self {
            mode: legacy.mode,
            pool_fee_bps: legacy.pool_fee_bps,
            pool_wallet: legacy.pool_wallet,
            pplns_window_factor: legacy.pplns_window_factor,
            pool_fee_earned_atomic: legacy.pool_fee_earned_atomic,
            miners: legacy
                .miners
                .into_iter()
                .map(|(key, ledger)| {
                    (
                        key,
                        MinerLedger {
                            wallet_address: ledger.wallet_address,
                            wallet_view_public: [0u8; 32],
                            valid_shares: ledger.valid_shares,
                            invalid_shares: ledger.invalid_shares,
                            accumulated_share_difficulty: ledger.accumulated_share_difficulty,
                            pending_payout_atomic: ledger.pending_payout_atomic,
                            reserved_payout_atomic: 0,
                            direct_reward_atomic: ledger.direct_reward_atomic,
                            total_blocks_found: ledger.total_blocks_found,
                            total_paid_atomic: ledger.total_paid_atomic,
                            last_share_timestamp: ledger.last_share_timestamp,
                            last_disconnect_timestamp: ledger.last_disconnect_timestamp,
                        },
                    )
                })
                .collect(),
            round_shares: legacy.round_shares,
            share_window: legacy.share_window,
            reward_events: legacy.reward_events,
            recent_blocks: legacy.recent_blocks,
            payouts: Vec::new(),
            next_payout_sequence: 0,
        }
    }
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
            payouts: Vec::new(),
            next_payout_sequence: 0,
        }
    }
}

pub struct PoolAccounting {
    state: RwLock<AccountingState>,
    db: Database,
    rewards: RewardAccounting,
    durable: bool,
    network_magic: [u8; 4],
    view_keys: RwLock<HashMap<[u8; 32], [u8; 32]>>,
}

impl PoolAccounting {
    pub fn new(config: PoolAccountingConfig) -> Self {
        Self::try_new(config).expect("existing pool accounting state must be readable")
    }

    pub fn try_new(config: PoolAccountingConfig) -> Result<Self, AccountingError> {
        let db = match &config.state_dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).map_err(storage_error)?;
                Database::builder()
                    .set_cache_size(16 * 1024 * 1024)
                    .create(dir.join("pool_accounting.redb"))
                    .map_err(storage_error)?
            }
            None => Database::builder()
                .create_with_backend(redb::backends::InMemoryBackend::new())
                .map_err(storage_error)?,
        };
        let write = db.begin_write().map_err(storage_error)?;
        let mut state = {
            let mut ledger = write.open_table(LEDGER).map_err(storage_error)?;
            let network = ledger.get("network").map_err(storage_error)?;
            if network
                .as_ref()
                .is_some_and(|stored| stored.value() != config.network_magic)
            {
                return Err(AccountingError::InvalidNetwork);
            }
            drop(network);
            let stored = ledger
                .get("state")
                .map_err(storage_error)?
                .map(|encoded| {
                    crate::wire_config(crate::DEFAULT_WIRE_BYTES).deserialize(encoded.value())
                })
                .transpose()
                .map_err(storage_error)?;
            if let Some(stored) = stored {
                stored
            } else {
                let path = config
                    .state_dir
                    .as_ref()
                    .map(|dir| dir.join("pool_accounting.bin"));
                let initial = match path {
                    Some(path) if path.exists() || persistence_sidecar(&path, "bak").exists() => {
                        Self::load_state_with_backup(&path).ok_or_else(|| {
                            storage_error(format!(
                                "cannot recover {} or its backup",
                                path.display()
                            ))
                        })?
                    }
                    _ => AccountingState::new(&config),
                };
                let encoded = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .serialize(&initial)
                    .map_err(storage_error)?;
                ledger
                    .insert("network", config.network_magic.as_slice())
                    .map_err(storage_error)?;
                ledger
                    .insert("state", encoded.as_slice())
                    .map_err(storage_error)?;
                initial
            }
        };
        write.open_table(WITNESSES).map_err(storage_error)?;
        let rewards = RewardAccounting::open(&write, &state)?;
        write.open_table(CANDIDATES).map_err(storage_error)?;
        {
            let mut confirmed = write.open_table(CONFIRMED_PAYOUTS).map_err(storage_error)?;
            for payout in &state.payouts {
                if matches!(payout.status, PayoutStatus::Confirmed { .. })
                    && confirmed
                        .get(payout.intent_id.as_str())
                        .map_err(storage_error)?
                        .is_none()
                {
                    let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                        .serialize(payout)
                        .map_err(storage_error)?;
                    confirmed
                        .insert(payout.intent_id.as_str(), bytes.as_slice())
                        .map_err(storage_error)?;
                }
            }
        }
        write.commit().map_err(storage_error)?;
        // Older ledgers populated both histories regardless of payment mode.
        // Only the mode recorded in the ledger determines future settlements.
        if state.mode != PoolMode::Prop {
            state.round_shares = Vec::new();
        }
        if state.mode != PoolMode::Pplns {
            state.share_window = Vec::new();
        }
        let mut view_keys = HashMap::new();
        if config.pool_view_public != [0u8; 32] {
            view_keys.insert(config.pool_wallet, config.pool_view_public);
        }
        for ledger in state.miners.values() {
            if ledger.wallet_address != [0u8; 32] && ledger.wallet_view_public != [0u8; 32] {
                view_keys.insert(ledger.wallet_address, ledger.wallet_view_public);
            }
        }
        Ok(Self {
            state: RwLock::new(state),
            db,
            rewards,
            durable: config.state_dir.is_some(),
            network_magic: config.network_magic,
            view_keys: RwLock::new(view_keys),
        })
    }

    pub fn mode(&self) -> PoolMode {
        self.state.read().mode
    }

    pub(crate) fn pending_block(&self) -> Result<Option<PendingBlock>, AccountingError> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CANDIDATES).map_err(storage_error)?;
        table
            .first()
            .map_err(storage_error)?
            .map(|(key, value)| {
                let candidate: PendingBlock = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .deserialize(value.value())
                    .map_err(storage_error)?;
                if candidate.block.hash().to_string() != key.value() {
                    return Err(storage_error("pending block hash mismatch"));
                }
                Ok(candidate)
            })
            .transpose()
    }

    pub(crate) fn stage_block(&self, candidate: &PendingBlock) -> Result<(), AccountingError> {
        let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(candidate)
            .map_err(storage_error)?;
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(CANDIDATES).map_err(storage_error)?;
            if !table.is_empty().map_err(storage_error)? {
                return Err(storage_error("unresolved block submission"));
            }
            table
                .insert(
                    candidate.block.hash().to_string().as_str(),
                    bytes.as_slice(),
                )
                .map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)
    }

    pub(crate) fn discard_block(&self, hash: &str) -> Result<(), AccountingError> {
        let write = self.db.begin_write().map_err(storage_error)?;
        write
            .open_table(CANDIDATES)
            .map_err(storage_error)?
            .remove(hash)
            .map_err(storage_error)?;
        write.commit().map_err(storage_error)
    }

    /// Parse a wallet address string and return `(view_public, spend_public)`.
    pub fn parse_wallet_input(
        input: &str,
        network_magic: [u8; 4],
    ) -> Result<([u8; 32], [u8; 32]), String> {
        if let Some(encoded) = input.strip_prefix("hy1") {
            let payload = base58::decode(encoded)
                .map_err(|error| format!("invalid hy1 address base58: {error}"))?;
            if payload.len() != 69 {
                return Err(format!(
                    "invalid hy1 address length: expected 69, got {}",
                    payload.len()
                ));
            }
            let checksum = blake3_hash(&payload[..65]);
            if checksum.as_bytes()[..4] != payload[65..69] {
                return Err("hy1 address checksum mismatch".into());
            }
            let expected_version =
                address_version(&network_magic).ok_or("unknown Hyphen network magic")?;
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

    pub fn pool_wallet_address(&self) -> Result<String, AccountingError> {
        let state = self.state.read();
        let view_public = self
            .view_keys
            .read()
            .get(&state.pool_wallet)
            .copied()
            .ok_or(AccountingError::MissingPayoutAddress)?;
        encode_wallet_address(view_public, state.pool_wallet, self.network_magic)
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
        let wallet_view_public = self
            .view_keys
            .read()
            .get(&wallet_address)
            .copied()
            .unwrap_or([0u8; 32]);
        {
            let mut state = self.state.write();
            let ledger = state.miners.entry(hex_encode(miner_pubkey)).or_default();
            ledger.wallet_address = wallet_address;
            ledger.wallet_view_public = wallet_view_public;
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
        _total_fee_atomic: u64,
    ) {
        let mut state = self.state.write();
        self.apply_share(
            &mut state,
            miner_pubkey,
            wallet_address,
            share_difficulty,
            block_difficulty,
            block_reward_atomic,
        );
        if state.miners[&hex_encode(miner_pubkey)]
            .valid_shares
            .is_multiple_of(32)
            && let Err(error) = self.persist_state(&state)
        {
            warn!("Failed to persist pool accounting state: {error}");
        }
    }

    /// Commit witness ownership and the resulting financial credit together, before issuing a receipt.
    pub fn credit_witnesses(
        &self,
        miner: [u8; 32],
        wallet: [u8; 32],
        witnesses: &[u64],
        difficulty: u64,
        reward: u64,
    ) -> Result<(u64, u64), AccountingError> {
        let mut current = self.state.write();
        let write = self.db.begin_write().map_err(storage_error)?;
        let mut owners = write.open_table(WITNESSES).map_err(storage_error)?;
        let mut fresh = 0;
        for &witness in witnesses {
            if let Some(previous) = owners.insert(witness, &miner).map_err(storage_error)? {
                if previous.value() != &miner {
                    return Err(AccountingError::WitnessClaimed(witness));
                }
            } else {
                fresh += 1;
            }
        }
        let count = owners.len().map_err(storage_error)?;
        drop(owners);
        if fresh > 0 {
            let mut next = current.clone();
            self.apply_share(&mut next, miner, wallet, fresh, difficulty, reward);
            Self::commit_state(write, &next)?;
            *current = next;
        }
        Ok((fresh, count))
    }

    fn apply_share(
        &self,
        state: &mut AccountingState,
        miner_pubkey: [u8; 32],
        wallet_address: [u8; 32],
        share_difficulty: u64,
        block_difficulty: u64,
        block_reward_atomic: u64,
    ) {
        let now = now_secs();
        let miner_key = hex_encode(miner_pubkey);
        let mode = state.mode;
        let pool_fee_bps = state.pool_fee_bps;
        let pplns_window_factor = state.pplns_window_factor;
        let mut fee_delta = 0u128;

        {
            let ledger = state.miners.entry(miner_key).or_default();
            ledger.wallet_address = wallet_address;
            if let Some(view_public) = self.view_keys.read().get(&wallet_address) {
                ledger.wallet_view_public = *view_public;
            }
            ledger.valid_shares = ledger.valid_shares.saturating_add(1);
            ledger.accumulated_share_difficulty = ledger
                .accumulated_share_difficulty
                .saturating_add(share_difficulty as u128);
            ledger.last_share_timestamp = Some(now);

            match mode {
                // Block v5 credits only header.reward to the reward output.
                PoolMode::Pps | PoolMode::PpsPlus | PoolMode::Fpps => {
                    let gross = proportional_credit(
                        share_difficulty,
                        block_difficulty,
                        block_reward_atomic as u128,
                    );
                    let net = apply_fee(gross, pool_fee_bps);
                    ledger.pending_payout_atomic = ledger.pending_payout_atomic.saturating_add(net);
                    fee_delta = fee_delta.saturating_add(gross.saturating_sub(net));
                }
                PoolMode::Solo | PoolMode::Prop | PoolMode::Pplns => {}
            }
        }

        let share = ShareCredit {
            miner_pubkey,
            wallet_address,
            difficulty: share_difficulty.max(1),
            timestamp: now,
        };
        match mode {
            PoolMode::Prop => state.round_shares.push(share),
            PoolMode::Pplns => {
                state.share_window.push(share);
                Self::trim_share_window(
                    &mut state.share_window,
                    block_difficulty,
                    pplns_window_factor,
                );
            }
            PoolMode::Solo | PoolMode::Pps | PoolMode::PpsPlus | PoolMode::Fpps => {}
        }
        state.pool_fee_earned_atomic = state.pool_fee_earned_atomic.saturating_add(fee_delta);
    }

    pub fn record_invalid_share(&self, miner_pubkey: [u8; 32]) {
        {
            let mut state = self.state.write();
            let ledger = state.miners.entry(hex_encode(miner_pubkey)).or_default();
            ledger.invalid_shares = ledger.invalid_shares.saturating_add(1);
        }
        self.save_if_needed(false);
    }

    pub fn note_disconnect(&self, miner_pubkey: [u8; 32]) {
        {
            let mut state = self.state.write();
            if let Some(ledger) = state.miners.get_mut(&hex_encode(miner_pubkey)) {
                ledger.last_disconnect_timestamp = Some(now_secs());
            }
        }
        self.save_if_needed(false);
    }

    pub fn miner_ledger(&self, miner_pubkey: &[u8; 32]) -> Option<MinerLedger> {
        let state = self.state.read();
        let key = hex_encode(miner_pubkey);
        let mut ledger = state.miners.get(&key)?.clone();
        ledger.pending_payout_atomic = ledger
            .pending_payout_atomic
            .saturating_sub(*self.rewards.debits.read().get(&key).unwrap_or(&0));
        Some(ledger)
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
            reward_deficit_atomic: 0,
            reserved_payout_atomic: 0,
            direct_reward_atomic: 0,
            total_blocks_found: 0,
            total_paid_atomic: 0,
            last_share_timestamp: None,
            last_disconnect_timestamp: None,
            recent_blocks: Vec::new(),
            recent_reward_events: Vec::new(),
            recent_payouts: Vec::new(),
        };

        let debits = self.rewards.debits.read();
        for (key, ledger) in &state.miners {
            if ledger.wallet_address != wallet_address {
                continue;
            }

            summary.active_miners = summary.active_miners.saturating_add(1);
            summary.valid_shares = summary.valid_shares.saturating_add(ledger.valid_shares);
            summary.invalid_shares = summary.invalid_shares.saturating_add(ledger.invalid_shares);
            summary.accumulated_share_difficulty = summary
                .accumulated_share_difficulty
                .saturating_add(ledger.accumulated_share_difficulty);
            let debit = debits.get(key).copied().unwrap_or(0);
            summary.reward_deficit_atomic += debit.saturating_sub(ledger.pending_payout_atomic);
            summary.pending_payout_atomic = summary
                .pending_payout_atomic
                .saturating_add(ledger.pending_payout_atomic.saturating_sub(debit));
            summary.reserved_payout_atomic = summary
                .reserved_payout_atomic
                .saturating_add(ledger.reserved_payout_atomic);
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

        summary.recent_payouts = state
            .payouts
            .iter()
            .rev()
            .filter(|payout| payout.recipient_spend_public == wallet_address)
            .take(recent_limit.max(1))
            .cloned()
            .collect();

        summary
    }

    pub fn network_magic(&self) -> [u8; 4] {
        self.network_magic
    }

    /// Relay already signed payouts before asking the agent to select fresh inputs.
    pub fn active_payout(&self) -> Option<PayoutRecord> {
        let state = self.state.read();
        state
            .payouts
            .iter()
            .find(|record| matches!(record.status, PayoutStatus::Submitted { .. }))
            .or_else(|| {
                state
                    .payouts
                    .iter()
                    .find(|record| matches!(record.status, PayoutStatus::Reserved))
            })
            .cloned()
    }

    pub fn recent_payouts(&self, limit: usize) -> Vec<PayoutRecord> {
        self.state
            .read()
            .payouts
            .iter()
            .rev()
            .take(limit.max(1))
            .cloned()
            .collect()
    }

    pub(crate) fn next_confirmed_payout(
        &self,
        after: &str,
    ) -> Result<Option<PayoutRecord>, AccountingError> {
        use std::ops::Bound::{Excluded, Unbounded};
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CONFIRMED_PAYOUTS).map_err(storage_error)?;
        let mut following = table
            .range((Excluded(after), Unbounded))
            .map_err(storage_error)?;
        let entry = match following.next() {
            Some(entry) => Some(entry.map_err(storage_error)?),
            None => table.first().map_err(storage_error)?,
        };
        entry
            .map(|(_, bytes)| {
                crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                    .deserialize(bytes.value())
                    .map_err(storage_error)
            })
            .transpose()
    }

    pub(crate) fn reconcile_confirmed_payout(
        &self,
        intent: &str,
        hash: &str,
        inclusion: Option<(u64, u64)>,
    ) -> Result<(), AccountingError> {
        let mut current = self.state.write();
        let write = self.db.begin_write().map_err(storage_error)?;
        let mut table = write.open_table(CONFIRMED_PAYOUTS).map_err(storage_error)?;
        let Some(bytes) = table.get(intent).map_err(storage_error)? else {
            return Ok(());
        };
        let mut record: PayoutRecord = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .deserialize(bytes.value())
            .map_err(storage_error)?;
        drop(bytes);
        let PayoutStatus::Confirmed {
            ref tx_hash,
            block_height,
            ..
        } = record.status
        else {
            return Err(storage_error(
                "expected a confirmed payout in the reconciliation index",
            ));
        };
        if record.intent_id != intent || tx_hash != hash {
            return Err(AccountingError::InvalidPayoutTransition(
                "reconciliation identity mismatch".into(),
            ));
        }
        if inclusion.is_some_and(|(height, _)| height == block_height) {
            return Ok(());
        }
        let mut next = current.clone();
        if let Some((block_height, confirmations)) = inclusion {
            record.status = PayoutStatus::Confirmed {
                tx_hash: hash.to_owned(),
                block_height,
                confirmations,
                confirmed_at: now_secs(),
            };
            let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&record)
                .map_err(storage_error)?;
            table
                .insert(intent, bytes.as_slice())
                .map_err(storage_error)?;
        } else {
            for allocation in &record.allocations {
                let ledger = next
                    .miners
                    .get_mut(&allocation.miner_key)
                    .ok_or_else(|| storage_error("payout allocation has no miner ledger"))?;
                ledger.total_paid_atomic = ledger
                    .total_paid_atomic
                    .checked_sub(allocation.amount_atomic)
                    .ok_or_else(|| storage_error("detached payout exceeds paid balance"))?;
                ledger.reserved_payout_atomic = ledger
                    .reserved_payout_atomic
                    .checked_add(allocation.amount_atomic)
                    .ok_or(AccountingError::PayoutAmountOverflow)?;
            }
            record.status = PayoutStatus::Submitted {
                tx_hash: hash.to_owned(),
                submitted_at: now_secs(),
            };
            table.remove(intent).map_err(storage_error)?;
        }
        drop(table);
        if let Some(existing) = next.payouts.iter_mut().find(|p| p.intent_id == intent) {
            *existing = record;
        } else if matches!(record.status, PayoutStatus::Submitted { .. }) {
            next.payouts.push(record);
        }
        Self::commit_state(write, &next)?;
        *current = next;
        Ok(())
    }

    /// Atomically reserves one wallet's payable balance. A reservation
    /// subtracts from `pending_payout_atomic` and moves the same amount into
    /// `reserved_payout_atomic`; no value is counted as paid yet.
    pub fn reserve_next_payout(
        &self,
        minimum_payout_atomic: u64,
        maximum_payout_atomic: u64,
    ) -> Result<Option<PayoutRecord>, AccountingError> {
        self.reserve_payout(minimum_payout_atomic, maximum_payout_atomic, false)
    }

    pub(crate) fn reserve_payout(
        &self,
        minimum_payout_atomic: u64,
        maximum_payout_atomic: u64,
        require_reconciled: bool,
    ) -> Result<Option<PayoutRecord>, AccountingError> {
        if minimum_payout_atomic == 0 || maximum_payout_atomic < minimum_payout_atomic {
            return Err(AccountingError::InvalidPayoutTransition(
                "invalid minimum/maximum payout bounds".into(),
            ));
        }
        if !self.durable {
            return Err(AccountingError::PersistenceDisabled);
        }

        let mut state = self.state.write();
        if require_reconciled && !self.rewards_verified() {
            return Ok(None);
        }
        if state
            .payouts
            .iter()
            .any(|record| !matches!(record.status, PayoutStatus::Confirmed { .. }))
        {
            return Ok(None);
        }

        let mut recipients: BTreeMap<RecipientKey, RecipientBalances> = BTreeMap::new();
        let mut missing_address_balance = 0u128;
        let debits = self.rewards.debits.read();
        for (miner_key, ledger) in &state.miners {
            let available = ledger
                .pending_payout_atomic
                .saturating_sub(debits.get(miner_key).copied().unwrap_or(0));
            if available == 0 {
                continue;
            }
            if ledger.wallet_address == [0u8; 32] || ledger.wallet_view_public == [0u8; 32] {
                missing_address_balance = missing_address_balance.saturating_add(available);
                continue;
            }
            recipients
                .entry((ledger.wallet_view_public, ledger.wallet_address))
                .or_default()
                .push((miner_key.clone(), available));
        }

        let minimum = minimum_payout_atomic as u128;
        let selected = recipients.into_iter().find(|(_, allocations)| {
            allocations
                .iter()
                .try_fold(0u128, |total, (_, amount)| total.checked_add(*amount))
                .is_some_and(|total| total >= minimum)
        });
        let Some(((view_public, spend_public), mut balances)) = selected else {
            if missing_address_balance >= minimum {
                return Err(AccountingError::MissingPayoutAddress);
            }
            return Ok(None);
        };
        balances.sort_by(|left, right| left.0.cmp(&right.0));

        let target = balances
            .iter()
            .try_fold(0u128, |total, (_, amount)| total.checked_add(*amount))
            .ok_or(AccountingError::PayoutAmountOverflow)?
            .min(maximum_payout_atomic as u128);
        let amount_atomic =
            u64::try_from(target).map_err(|_| AccountingError::PayoutAmountOverflow)?;
        let mut remaining = target;
        let mut allocations = Vec::new();
        for (miner_key, balance) in balances {
            if remaining == 0 {
                break;
            }
            let amount = balance.min(remaining);
            allocations.push(PayoutAllocation {
                miner_key,
                amount_atomic: amount,
            });
            remaining -= amount;
        }
        if remaining != 0 {
            return Err(AccountingError::InvalidPayoutTransition(
                "reservation allocations do not sum to the payout".into(),
            ));
        }

        let sequence = state.next_payout_sequence;
        let next_sequence = sequence.checked_add(1).ok_or_else(|| {
            AccountingError::InvalidPayoutTransition("payout sequence exhausted".into())
        })?;
        let intent_hash = blake3_hash(
            &[
                b"Hyphen/Pool/PayoutIntent/v1".as_slice(),
                self.network_magic.as_slice(),
                state.pool_wallet.as_slice(),
                sequence.to_le_bytes().as_slice(),
                view_public.as_slice(),
                spend_public.as_slice(),
                amount_atomic.to_le_bytes().as_slice(),
            ]
            .concat(),
        );
        let record = PayoutRecord {
            intent_id: hex_encode(intent_hash.as_bytes()),
            recipient_view_public: view_public,
            recipient_spend_public: spend_public,
            amount_atomic,
            created_at: now_secs(),
            status: PayoutStatus::Reserved,
            allocations,
        };

        let previous = state.clone();
        for allocation in &record.allocations {
            let ledger = state.miners.get(&allocation.miner_key).ok_or_else(|| {
                AccountingError::InvalidPayoutTransition("reservation miner disappeared".into())
            })?;
            if ledger.pending_payout_atomic < allocation.amount_atomic {
                return Err(AccountingError::InvalidPayoutTransition(
                    "reservation exceeds pending balance".into(),
                ));
            }
            ledger
                .reserved_payout_atomic
                .checked_add(allocation.amount_atomic)
                .ok_or(AccountingError::PayoutAmountOverflow)?;
        }
        for allocation in &record.allocations {
            let ledger = state
                .miners
                .get_mut(&allocation.miner_key)
                .expect("reservation was validated against the same locked state");
            ledger.pending_payout_atomic -= allocation.amount_atomic;
            ledger.reserved_payout_atomic += allocation.amount_atomic;
        }
        state.next_payout_sequence = next_sequence;
        state.payouts.push(record.clone());
        Self::trim_payouts(&mut state.payouts);
        if let Err(error) = self.persist_state(&state) {
            *state = previous;
            return Err(error);
        }
        Ok(Some(record))
    }

    pub fn mark_payout_submitted(
        &self,
        intent_id: &str,
        tx_hash: &str,
    ) -> Result<PayoutRecord, AccountingError> {
        validate_hash_hex(tx_hash, "transaction hash")?;
        let mut state = self.state.write();
        let previous = state.clone();
        let record = state
            .payouts
            .iter_mut()
            .find(|record| record.intent_id == intent_id)
            .ok_or_else(|| AccountingError::PayoutNotFound(intent_id.to_owned()))?;
        match &record.status {
            PayoutStatus::Reserved => {
                record.status = PayoutStatus::Submitted {
                    tx_hash: tx_hash.to_owned(),
                    submitted_at: now_secs(),
                };
            }
            PayoutStatus::Submitted {
                tx_hash: existing, ..
            } if existing == tx_hash => {}
            PayoutStatus::Confirmed {
                tx_hash: existing, ..
            } if existing == tx_hash => return Ok(record.clone()),
            _ => {
                return Err(AccountingError::InvalidPayoutTransition(
                    "intent is already bound to another transaction".into(),
                ));
            }
        }
        let updated = record.clone();
        if let Err(error) = self.persist_state(&state) {
            *state = previous;
            return Err(error);
        }
        Ok(updated)
    }

    pub fn mark_payout_confirmed(
        &self,
        intent_id: &str,
        tx_hash: &str,
        block_height: u64,
        confirmations: u64,
    ) -> Result<PayoutRecord, AccountingError> {
        if confirmations == 0 {
            return Err(AccountingError::InvalidPayoutTransition(
                "a confirmed payout must have at least one confirmation".into(),
            ));
        }
        validate_hash_hex(tx_hash, "transaction hash")?;
        let mut state = self.state.write();
        let previous = state.clone();
        let index = state
            .payouts
            .iter()
            .position(|record| record.intent_id == intent_id)
            .ok_or_else(|| AccountingError::PayoutNotFound(intent_id.to_owned()))?;
        match &state.payouts[index].status {
            PayoutStatus::Confirmed {
                tx_hash: existing, ..
            } if existing == tx_hash => return Ok(state.payouts[index].clone()),
            PayoutStatus::Submitted {
                tx_hash: existing, ..
            } if existing == tx_hash => {}
            _ => {
                return Err(AccountingError::InvalidPayoutTransition(
                    "payout must be submitted under the same transaction before confirmation"
                        .into(),
                ));
            }
        }

        let allocations = state.payouts[index].allocations.clone();
        for allocation in &allocations {
            let ledger = state.miners.get(&allocation.miner_key).ok_or_else(|| {
                AccountingError::InvalidPayoutTransition("confirmed miner disappeared".into())
            })?;
            if ledger.reserved_payout_atomic < allocation.amount_atomic {
                return Err(AccountingError::InvalidPayoutTransition(
                    "confirmed amount exceeds reserved balance".into(),
                ));
            }
            ledger
                .total_paid_atomic
                .checked_add(allocation.amount_atomic)
                .ok_or(AccountingError::PayoutAmountOverflow)?;
        }
        for allocation in allocations {
            let ledger = state
                .miners
                .get_mut(&allocation.miner_key)
                .expect("confirmation was validated against the same locked state");
            ledger.reserved_payout_atomic -= allocation.amount_atomic;
            ledger.total_paid_atomic += allocation.amount_atomic;
        }
        state.payouts[index].status = PayoutStatus::Confirmed {
            tx_hash: tx_hash.to_owned(),
            block_height,
            confirmations,
            confirmed_at: now_secs(),
        };
        let updated = state.payouts[index].clone();
        let persist = || {
            let write = self.db.begin_write().map_err(storage_error)?;
            let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&updated)
                .map_err(storage_error)?;
            write
                .open_table(CONFIRMED_PAYOUTS)
                .map_err(storage_error)?
                .insert(intent_id, bytes.as_slice())
                .map_err(storage_error)?;
            Self::commit_state(write, &state)
        };
        if let Err(error) = persist() {
            *state = previous;
            return Err(error);
        }
        Ok(updated)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn settle_block(
        &self,
        finder_pubkey: [u8; 32],
        wallet_address: [u8; 32],
        height: u64,
        block_hash_hex: String,
        block_reward_atomic: u64,
        total_fee_atomic: u64,
        block_difficulty: u64,
    ) -> Result<(), AccountingError> {
        self.settle_reward(
            finder_pubkey,
            wallet_address,
            height,
            block_hash_hex,
            block_reward_atomic,
            total_fee_atomic,
            block_difficulty,
            false,
        )
    }

    pub(crate) fn settle_accepted_block(
        &self,
        candidate: &PendingBlock,
    ) -> Result<(), AccountingError> {
        let header = &candidate.block.header;
        self.settle_reward(
            header.miner_pubkey,
            candidate.wallet,
            header.height,
            candidate.block.hash().to_string(),
            header.reward,
            header.total_fee,
            header.difficulty,
            true,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn settle_reward(
        &self,
        finder_pubkey: [u8; 32],
        wallet_address: [u8; 32],
        height: u64,
        block_hash_hex: String,
        block_reward_atomic: u64,
        total_fee_atomic: u64,
        block_difficulty: u64,
        replace: bool,
    ) -> Result<(), AccountingError> {
        let now = now_secs();
        {
            let mut current = self.state.write();
            if replace {
                self.rewards.invalidate_scan(height);
            }
            let write = self.db.begin_write().map_err(storage_error)?;
            let read = self.db.begin_read().map_err(storage_error)?;
            let changes = Self::reward_changes(&read, height, &block_hash_hex)?;
            let mut credits_table = write.open_table(BLOCK_CREDITS).map_err(storage_error)?;
            let recorded = credits_table
                .get(block_hash_hex.as_str())
                .map_err(storage_error)?
                .is_some();
            let known = current
                .recent_blocks
                .iter()
                .any(|block| block.height == height && block.block_hash_hex == block_hash_hex)
                || recorded;
            if !replace && !known && !changes.is_empty() {
                return Err(AccountingError::SettlementConflict(height));
            }
            let mut state = current.clone();
            let balances = if replace && !changes.is_empty() {
                Some(self.apply_reward_changes(&read, &write, height, changes, &mut state)?)
            } else {
                None
            };
            if known {
                drop(credits_table);
                write
                    .open_table(CANDIDATES)
                    .map_err(storage_error)?
                    .remove(block_hash_hex.as_str())
                    .map_err(storage_error)?;
                if let Some(balances) = balances {
                    Self::commit_state(write, &state)?;
                    *current = state;
                    *self.rewards.debits.write() = balances;
                    return Ok(());
                }
                return write.commit().map_err(storage_error);
            }
            if self.network_magic == *b"HYNN" {
                // The full solution is the only credit-bearing share on this profile.
                self.apply_share(
                    &mut state,
                    finder_pubkey,
                    wallet_address,
                    block_difficulty,
                    block_difficulty,
                    block_reward_atomic,
                );
            }
            let gross_total = u128::from(block_reward_atomic);
            let finder_key = hex_encode(finder_pubkey);
            let mode = state.mode;
            let pool_fee_bps = state.pool_fee_bps;
            let pplns_window_factor = state.pplns_window_factor;
            let reward_recipient = if mode.uses_direct_coinbase() {
                wallet_address
            } else {
                state.pool_wallet
            };

            {
                let finder = state.miners.entry(finder_key).or_default();
                finder.wallet_address = wallet_address;
                finder.total_blocks_found = finder.total_blocks_found.saturating_add(1);
            }

            let (distributed_atomic, pool_fee_atomic, reward_events) = match mode {
                PoolMode::Solo => {
                    if let Some(finder) = state.miners.get_mut(&hex_encode(finder_pubkey)) {
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
                PoolMode::Prop | PoolMode::Pplns => {
                    let pool_fee = gross_total * pool_fee_bps as u128 / 10_000;
                    let distributable = gross_total.saturating_sub(pool_fee);
                    let shares = if mode == PoolMode::Prop {
                        state.round_shares.as_slice()
                    } else {
                        Self::pplns_window(
                            &state.share_window,
                            block_difficulty,
                            pplns_window_factor,
                        )
                    };
                    let reward_events = Self::distribute_weighted(
                        &mut state.miners,
                        shares,
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
                    let distributed = reward_events.iter().map(|event| event.amount_atomic).sum();
                    (distributed, pool_fee, reward_events)
                }
                PoolMode::Pps | PoolMode::PpsPlus | PoolMode::Fpps => (0, 0, Vec::new()),
            };

            state.pool_fee_earned_atomic =
                state.pool_fee_earned_atomic.saturating_add(pool_fee_atomic);
            state.round_shares.clear();
            RewardAccounting::record(&write, height, &block_hash_hex, &reward_events)?;
            state.reward_events.extend(reward_events);
            if state.reward_events.len() > 512 {
                let overflow = state.reward_events.len() - 512;
                state.reward_events.drain(..overflow);
            }
            write
                .open_table(CANDIDATES)
                .map_err(storage_error)?
                .remove(block_hash_hex.as_str())
                .map_err(storage_error)?;
            let settlement = BlockSettlement {
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
            };
            let pending_by_miner = state
                .miners
                .iter()
                .filter_map(|(key, miner)| {
                    let before = current
                        .miners
                        .get(key)
                        .map_or(0, |m| m.pending_payout_atomic);
                    let increase = miner.pending_payout_atomic - before;
                    (increase != 0).then(|| (key.clone(), increase))
                })
                .collect();
            let record = BlockCredits {
                settlement,
                pending_by_miner,
            };
            let bytes = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&record)
                .map_err(storage_error)?;
            credits_table
                .insert(record.settlement.block_hash_hex.as_str(), bytes.as_slice())
                .map_err(storage_error)?;
            drop(credits_table);
            state.recent_blocks.push(record.settlement);
            state.recent_blocks.sort_by_key(|block| block.height);
            if state.recent_blocks.len() > 128 {
                let overflow = state.recent_blocks.len() - 128;
                state.recent_blocks.drain(..overflow);
            }
            Self::commit_state(write, &state)?;
            if !replace {
                self.rewards.invalidate_scan(height);
            }
            *current = state;
            if let Some(balances) = balances {
                *self.rewards.debits.write() = balances;
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
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
            let miner_key = hex_encode(share.miner_pubkey);
            let amount = distributable.saturating_mul(share.difficulty as u128) / total_weight;
            allocated = allocated.saturating_add(amount);
            *allocations.entry(miner_key).or_insert(0) += amount;
            *wallet_allocations.entry(share.wallet_address).or_insert(0) += amount;
        }

        let remainder = distributable.saturating_sub(allocated);
        if remainder > 0
            && let Some(top_share) = shares.iter().max_by_key(|share| share.difficulty)
        {
            *allocations
                .entry(hex_encode(top_share.miner_pubkey))
                .or_insert(0) += remainder;
            *wallet_allocations
                .entry(top_share.wallet_address)
                .or_insert(0) += remainder;
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

    fn pplns_window(shares: &[ShareCredit], block_difficulty: u64, factor: u32) -> &[ShareCredit] {
        let target_work = (block_difficulty.max(1) as u128).saturating_mul(factor.max(1) as u128);
        let mut work = 0u128;
        for (index, share) in shares.iter().enumerate().rev() {
            work = work.saturating_add(share.difficulty as u128);
            if work >= target_work {
                return &shares[index..];
            }
        }
        shares
    }

    /// Drops the oldest settled payouts once the ledger exceeds its history
    /// budget.
    ///
    /// A payout that is still `Reserved` or `Submitted` must stay addressable
    /// for reconciliation after a restart, so only `Confirmed` records are
    /// dropped. Without this the ledger grows for the lifetime of the pool and
    /// every atomic save rewrites the whole file.
    fn trim_payouts(payouts: &mut Vec<PayoutRecord>) {
        if payouts.len() <= PAYOUT_HISTORY_LIMIT {
            return;
        }
        let mut excess = payouts.len() - PAYOUT_HISTORY_LIMIT;
        payouts.retain(|record| {
            if excess > 0 && matches!(record.status, PayoutStatus::Confirmed { .. }) {
                excess -= 1;
                false
            } else {
                true
            }
        });
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
        if let Some(encoded) = raw.strip_prefix(ACCOUNTING_STATE_MAGIC) {
            return crate::wire_config(64 * 1024 * 1024)
                .deserialize::<AccountingState>(encoded)
                .ok();
        }
        if let Ok(state) =
            crate::wire_config(64 * 1024 * 1024).deserialize::<LegacyAccountingStateV0>(&raw)
        {
            return Some(state.into());
        }
        let text = std::str::from_utf8(&raw).ok()?;
        serde_json::from_str(text).ok().or_else(|| {
            serde_json::from_str::<LegacyAccountingStateV0>(text)
                .ok()
                .map(Into::into)
        })
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

        let state = self.state.read();
        if let Err(error) = self.persist_state(&state) {
            warn!("Failed to atomically persist pool accounting state: {error}");
        }
    }

    fn persist_state(&self, state: &AccountingState) -> Result<(), AccountingError> {
        Self::commit_state(self.db.begin_write().map_err(storage_error)?, state)
    }

    fn commit_state(
        write: WriteTransaction,
        state: &AccountingState,
    ) -> Result<(), AccountingError> {
        let encoded = crate::wire_config(64 * 1024 * 1024)
            .serialize(state)
            .map_err(storage_error)?;
        write
            .open_table(LEDGER)
            .map_err(storage_error)?
            .insert("state", encoded.as_slice())
            .map_err(storage_error)?;
        write.commit().map_err(storage_error)
    }
}

fn persistence_sidecar(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pool_accounting.bin");
    path.with_file_name(format!("{file_name}.{suffix}"))
}

fn validate_hash_hex(value: &str, name: &str) -> Result<(), AccountingError> {
    let bytes = hex_decode(value).map_err(|_| {
        AccountingError::InvalidPayoutTransition(format!("{name} must be hexadecimal"))
    })?;
    if bytes.len() != 32 {
        return Err(AccountingError::InvalidPayoutTransition(format!(
            "{name} must be exactly 32 bytes"
        )));
    }
    Ok(())
}

fn encode_wallet_address(
    view_public: [u8; 32],
    spend_public: [u8; 32],
    network_magic: [u8; 4],
) -> Result<String, AccountingError> {
    if view_public == [0u8; 32] || spend_public == [0u8; 32] {
        return Err(AccountingError::MissingPayoutAddress);
    }
    let version = address_version(&network_magic).ok_or(AccountingError::InvalidNetwork)?;
    let mut payload = Vec::with_capacity(69);
    payload.push(version);
    payload.extend_from_slice(&view_public);
    payload.extend_from_slice(&spend_public);
    let checksum = blake3_hash(&payload);
    payload.extend_from_slice(&checksum.as_bytes()[..4]);
    Ok(format!("hy1{}", base58::encode(&payload)))
}

fn address_version(network: &[u8; 4]) -> Option<u8> {
    match network {
        b"HYPN" => Some(1),
        b"HYTS" | b"HYDV" | b"HYNN" | b"HYCD" | b"HYAC" | b"HYOF" => Some(2),
        _ => None,
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
    hyphen_core::timestamp::ntp_adjusted_timestamp_secs()
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
    fn weighted_settlement_preserves_window_order_and_rounding() {
        // At one unit per share the two-unit PPLNS window keeps the last two.
        // The last maximum-weight share receives the integer division remainder.
        for (mode, amounts) in [(PoolMode::Prop, [1, 1, 3]), (PoolMode::Pplns, [0, 2, 3])] {
            let accounting = PoolAccounting::new(PoolAccountingConfig {
                mode,
                pool_fee_bps: 0,
                ..sample_config()
            });
            for id in 1..=3 {
                accounting.record_valid_share([id; 32], [id; 32], 1, 1, 5, 0);
            }
            accounting
                .settle_block([3; 32], [3; 32], 1, "01".repeat(32), 5, 0, 1)
                .unwrap();
            for (id, amount) in (1..=3).zip(amounts) {
                assert_eq!(
                    accounting.wallet_summary([id; 32], 1).pending_payout_atomic,
                    amount
                );
            }
        }
    }

    #[test]
    fn wallet_summary_aggregates_multiple_miners() {
        let directory = std::env::temp_dir().join(format!(
            "hyphen_pool_credit_test_{}_{}",
            std::process::id(),
            crate::random_u64()
        ));
        let accounting = PoolAccounting::new(PoolAccountingConfig {
            state_dir: Some(directory.clone()),
            ..sample_config()
        });
        let wallet = [7u8; 32];
        let miner_a = [1u8; 32];
        let miner_b = [2u8; 32];

        accounting.register_miner(miner_a, wallet);
        accounting.register_miner(miner_b, wallet);
        accounting.record_valid_share(miner_a, wallet, 100, 1_000, 500, 0);
        accounting.record_valid_share(miner_b, wallet, 50, 1_000, 500, 0);

        let before_settlement = accounting.wallet_summary(wallet, 8);
        assert_eq!(before_settlement.pending_payout_atomic, 0);

        accounting
            .settle_block(miner_a, wallet, 1, "01".repeat(32), 500, 0, 1_000)
            .unwrap();

        let summary = accounting.wallet_summary(wallet, 8);
        assert_eq!(summary.wallet_address, wallet);
        assert_eq!(summary.active_miners, 2);
        assert_eq!(summary.valid_shares, 2);
        assert!(summary.pending_payout_atomic > 0);
        drop(accounting);
        let record = read_block_credits(&directory, &"01".repeat(32)).unwrap();
        assert_eq!(record.settlement.pool_fee_atomic, 5);
        assert_eq!(record.pending_by_miner[&hex_encode(miner_a)], 330);
        assert_eq!(record.pending_by_miner[&hex_encode(miner_b)], 165);
        let reopened = PoolAccounting::new(PoolAccountingConfig {
            state_dir: Some(directory.clone()),
            ..sample_config()
        });
        reopened
            .settle_block(miner_a, wallet, 1, "01".repeat(32), 500, 0, 1_000)
            .unwrap();
        assert_eq!(
            reopened.wallet_summary(wallet, 8).pending_payout_atomic,
            495
        );
        drop(reopened);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_wallet_from_another_network() {
        let mut payload = vec![0x01];
        payload.extend_from_slice(&[7u8; 32]);
        payload.extend_from_slice(&[8u8; 32]);
        let checksum = blake3_hash(&payload);
        payload.extend_from_slice(&checksum.as_bytes()[..4]);
        let address = format!("hy1{}", base58::encode(&payload));

        let error =
            PoolAccounting::parse_wallet_input(&address, [0x48, 0x59, 0x54, 0x53]).unwrap_err();
        assert!(error.contains("different Hyphen network"));
    }

    #[test]
    fn accepts_test_address_on_devnet() {
        let mut payload = vec![0x02];
        payload.extend_from_slice(&[7u8; 32]);
        payload.extend_from_slice(&[8u8; 32]);
        let checksum = blake3_hash(&payload);
        payload.extend_from_slice(&checksum.as_bytes()[..4]);
        let address = format!("hy1{}", base58::encode(&payload));

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
            crate::random_u64()
        ));
        let mut config = sample_config();
        config.state_dir = Some(test_dir.clone());
        let first_miner = [31u8; 32];
        let second_miner = [32u8; 32];
        let wallet = [33u8; 32];

        std::fs::create_dir_all(&test_dir).unwrap();
        let primary = test_dir.join("pool_accounting.bin");
        let mut legacy = AccountingState::new(&config);
        legacy.miners.insert(
            hex_encode(first_miner),
            MinerLedger {
                wallet_address: wallet,
                ..Default::default()
            },
        );
        let encoded = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&legacy)
            .unwrap();
        std::fs::write(
            persistence_sidecar(&primary, "bak"),
            [ACCOUNTING_STATE_MAGIC.as_slice(), &encoded].concat(),
        )
        .unwrap();
        std::fs::write(&primary, b"fault-injected-truncated-state").unwrap();

        let recovered = PoolAccounting::new(config);
        assert!(recovered.miner_ledger(&first_miner).is_some());
        assert!(recovered.miner_ledger(&second_miner).is_none());
        drop(recovered);

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn refuses_to_replace_unreadable_existing_ledgers() {
        let test_dir = std::env::temp_dir().join(format!(
            "hyphen_pool_fail_closed_{}_{}",
            std::process::id(),
            crate::random_u64()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let primary = test_dir.join("pool_accounting.bin");
        std::fs::write(&primary, b"corrupt-primary").unwrap();
        std::fs::write(persistence_sidecar(&primary, "bak"), b"corrupt-backup").unwrap();

        let mut config = sample_config();
        config.state_dir = Some(test_dir.clone());
        assert!(matches!(
            PoolAccounting::try_new(config),
            Err(AccountingError::Persistence(_))
        ));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn witness_ownership_and_credit_survive_restart_together() {
        let dir = std::env::temp_dir().join(format!("hyphen-witness-test-{}", crate::random_u64()));
        let mut config = sample_config();
        config.state_dir = Some(dir.clone());
        config.mode = PoolMode::Pps;
        config.pool_fee_bps = 0;
        let miner = [9; 32];
        let other = [2; 32];
        {
            let pool = PoolAccounting::new(config.clone());
            assert_eq!(
                pool.credit_witnesses(miner, miner, &[11, 17], 4, 400)
                    .unwrap(),
                (2, 2)
            );
        }
        {
            let pool = PoolAccounting::new(config.clone());
            assert!(matches!(
                pool.credit_witnesses(other, other, &[7, 17], 4, 400),
                Err(AccountingError::WitnessClaimed(17))
            ));
            assert_eq!(
                pool.credit_witnesses(miner, miner, &[7, 11, 17, 19], 4, 400)
                    .unwrap(),
                (2, 4)
            );
            assert_eq!(
                pool.credit_witnesses(miner, miner, &[7, 11, 17, 19], 4, 400)
                    .unwrap(),
                (0, 4)
            );
        }
        let pool = PoolAccounting::new(config);
        let ledger = pool.miner_ledger(&miner).unwrap();
        assert_eq!(
            (
                ledger.accumulated_share_difficulty,
                ledger.pending_payout_atomic
            ),
            (4, 400)
        );
        assert!(pool.miner_ledger(&other).is_none());
        drop(pool);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_block_settlement_is_idempotent() {
        let mut config = sample_config();
        config.mode = PoolMode::Solo;
        config.network_magic = *b"HYNN";
        config.pool_fee_bps = 0;
        let accounting = PoolAccounting::new(config);
        let miner = [41u8; 32];
        let wallet = [42u8; 32];

        accounting.register_miner(miner, wallet);
        accounting
            .settle_block(miner, wallet, 7, "ab".repeat(32), 500, 5, 1_000)
            .unwrap();
        accounting
            .settle_block(miner, wallet, 7, "ab".repeat(32), 500, 5, 1_000)
            .unwrap();

        let summary = accounting.wallet_summary(wallet, 8);
        assert_eq!(summary.total_blocks_found, 1);
        assert_eq!(summary.valid_shares, 1);
        assert_eq!(summary.direct_reward_atomic, 500);
        assert_eq!(summary.recent_blocks.len(), 1);
        assert_eq!(summary.recent_reward_events.len(), 1);
    }

    #[test]
    fn shared_modes_distribute_only_the_v5_coinbase() {
        for mode in [
            PoolMode::Pps,
            PoolMode::PpsPlus,
            PoolMode::Fpps,
            PoolMode::Prop,
            PoolMode::Pplns,
        ] {
            let config = PoolAccountingConfig {
                mode,
                pool_fee_bps: 0,
                ..sample_config()
            };
            let accounting = PoolAccounting::new(config);
            let miner = [42; 32];
            accounting.register_miner(miner, miner);
            accounting.record_valid_share(miner, miner, 10, 10, 500, 17);
            accounting
                .settle_block(miner, miner, 1, "ab".repeat(32), 500, 17, 10)
                .unwrap();
            assert_eq!(
                accounting.wallet_summary(miner, 8).pending_payout_atomic,
                500,
                "{mode:?}"
            );
        }
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
        accounting
            .settle_block(recent_b, recent_b, 1, "cd".repeat(32), 1_000, 0, 100)
            .unwrap();

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

    #[test]
    fn payout_reservation_submission_and_confirmation_are_durable_and_idempotent() {
        let test_dir = std::env::temp_dir().join(format!(
            "hyphen_pool_payout_test_{}_{}",
            std::process::id(),
            crate::random_u64()
        ));
        let mut config = sample_config();
        config.mode = PoolMode::Pps;
        config.pool_fee_bps = 100;
        config.pool_view_public = [6u8; 32];
        config.state_dir = Some(test_dir.clone());
        let miner = [7u8; 32];
        let view_public = [8u8; 32];
        let wallet = [9u8; 32];
        let tx_hash = "ab".repeat(32);

        let intent_id = {
            let accounting = PoolAccounting::new(config.clone());
            accounting.register_view_key(wallet, view_public);
            accounting.register_miner(miner, wallet);
            accounting.record_valid_share(miner, wallet, 1, 1, 100, 0);

            let reserved = accounting.reserve_next_payout(50, 90).unwrap().unwrap();
            assert_eq!(reserved.amount_atomic, 90);
            assert!(
                reserved
                    .recipient_address(accounting.network_magic())
                    .unwrap()
                    .starts_with("hy1")
            );
            let ledger = accounting.miner_ledger(&miner).unwrap();
            assert_eq!(ledger.pending_payout_atomic, 9);
            assert_eq!(ledger.reserved_payout_atomic, 90);
            assert!(accounting.reserve_next_payout(1, 90).unwrap().is_none());

            accounting
                .mark_payout_submitted(&reserved.intent_id, &tx_hash)
                .unwrap();
            accounting
                .mark_payout_submitted(&reserved.intent_id, &tx_hash)
                .unwrap();
            accounting
                .mark_payout_confirmed(&reserved.intent_id, &tx_hash, 12, 20)
                .unwrap();
            accounting
                .mark_payout_confirmed(&reserved.intent_id, &tx_hash, 12, 20)
                .unwrap();

            let ledger = accounting.miner_ledger(&miner).unwrap();
            assert_eq!(ledger.pending_payout_atomic, 9);
            assert_eq!(ledger.reserved_payout_atomic, 0);
            assert_eq!(ledger.total_paid_atomic, 90);
            reserved.intent_id
        };

        let reopened = PoolAccounting::new(config.clone());
        let ledger = reopened.miner_ledger(&miner).unwrap();
        assert_eq!(ledger.total_paid_atomic, 90);
        assert!(matches!(
            reopened
                .recent_payouts(1)
                .into_iter()
                .find(|record| record.intent_id == intent_id)
                .unwrap()
                .status,
            PayoutStatus::Confirmed {
                confirmations: 20,
                ..
            }
        ));

        assert_eq!(
            reopened
                .next_confirmed_payout("")
                .unwrap()
                .unwrap()
                .intent_id,
            intent_id
        );
        reopened
            .reconcile_confirmed_payout(&intent_id, &tx_hash, None)
            .unwrap();
        reopened
            .reconcile_confirmed_payout(&intent_id, &tx_hash, None)
            .unwrap();
        assert!(reopened.next_confirmed_payout("").unwrap().is_none());
        drop(reopened);
        let reopened = PoolAccounting::new(config);
        let ledger = reopened.miner_ledger(&miner).unwrap();
        assert_eq!(
            (
                ledger.pending_payout_atomic,
                ledger.reserved_payout_atomic,
                ledger.total_paid_atomic
            ),
            (9, 90, 0)
        );
        assert!(reopened.reserve_next_payout(1, 90).unwrap().is_none());
        reopened
            .mark_payout_confirmed(&intent_id, &tx_hash, 18, 20)
            .unwrap();
        let ledger = reopened.miner_ledger(&miner).unwrap();
        assert_eq!(
            (
                ledger.pending_payout_atomic,
                ledger.reserved_payout_atomic,
                ledger.total_paid_atomic
            ),
            (9, 0, 90)
        );
        drop(reopened);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn accepted_replacement_switches_credit_and_fee_atomically() {
        let old = "bb".repeat(32);
        let new = "aa".repeat(32);
        let first = [1; 32];
        let second = [2; 32];
        for mode in [
            PoolMode::Solo,
            PoolMode::Pplns,
            PoolMode::Prop,
            PoolMode::Pps,
        ] {
            let pool = PoolAccounting::new(PoolAccountingConfig {
                mode,
                ..sample_config()
            });
            pool.record_valid_share(first, first, 10, 10, 1000, 0);
            pool.settle_reward(first, first, 3, old.clone(), 1000, 0, 10, true)
                .unwrap();
            pool.record_valid_share(second, second, 20, 10, 500, 0);
            let before_fee = pool.state.read().pool_fee_earned_atomic;
            let before_credit = pool.wallet_summary(first, 3);
            assert_eq!(
                pool.settle_block(second, second, 3, new.clone(), 500, 0, 10),
                Err(AccountingError::SettlementConflict(3))
            );
            for _ in 0..2 {
                pool.settle_reward(second, second, 3, new.clone(), 500, 0, 10, true)
                    .unwrap();
                let first_balance = pool.wallet_summary(first, 3);
                let second_balance = pool.wallet_summary(second, 3);
                assert_eq!(first_balance.total_blocks_found, 0);
                assert_eq!(second_balance.total_blocks_found, 1);
                match mode {
                    PoolMode::Solo => assert_eq!(
                        (
                            first_balance.direct_reward_atomic,
                            second_balance.direct_reward_atomic
                        ),
                        (0, 500)
                    ),
                    PoolMode::Prop | PoolMode::Pplns => {
                        assert_eq!(
                            (
                                first_balance.pending_payout_atomic,
                                second_balance.pending_payout_atomic
                            ),
                            (0, 495)
                        );
                        assert_eq!(pool.state.read().pool_fee_earned_atomic, 5);
                    }
                    _ => assert_eq!(
                        first_balance.pending_payout_atomic,
                        before_credit.pending_payout_atomic
                    ),
                }
                pool.settle_reward(first, first, 3, old.clone(), 1000, 0, 10, true)
                    .unwrap();
                let restored = pool.wallet_summary(first, 3);
                assert_eq!(restored.total_blocks_found, 1);
                assert_eq!(
                    restored.direct_reward_atomic,
                    before_credit.direct_reward_atomic
                );
                assert_eq!(
                    restored.pending_payout_atomic,
                    before_credit.pending_payout_atomic
                );
                assert_eq!(
                    restored.recent_reward_events.len(),
                    before_credit.recent_reward_events.len()
                );
                assert_eq!(pool.state.read().pool_fee_earned_atomic, before_fee);
            }
        }
    }

    #[test]
    fn failed_accepted_reattachment_keeps_candidate_and_previous_settlement() {
        let directory =
            std::env::temp_dir().join(format!("hyphen-reattach-{}", crate::random_u64()));
        let config = PoolAccountingConfig {
            mode: PoolMode::Prop,
            state_dir: Some(directory.clone()),
            ..sample_config()
        };
        let pool = PoolAccounting::try_new(config.clone()).unwrap();
        let candidate = |wallet, reward| {
            let mut block =
                crate::primitives::build_genesis_block(&crate::primitives::ChainConfig::devnet());
            block.header.height = 3;
            block.header.miner_pubkey = wallet;
            block.header.reward = reward;
            block.header.difficulty = 10;
            PendingBlock { block, wallet }
        };
        let original = candidate([1; 32], 1000);
        let replacement = candidate([2; 32], 500);
        for block in [&original, &replacement] {
            pool.record_valid_share(
                block.wallet,
                block.wallet,
                10,
                10,
                block.block.header.reward,
                0,
            );
            pool.stage_block(block).unwrap();
            pool.settle_accepted_block(block).unwrap();
        }

        let hash = original.block.hash().to_string();
        let saved_events = {
            let write = pool.db.begin_write().unwrap();
            let saved = write
                .open_table(rewards::EVENTS)
                .unwrap()
                .insert(hash.as_str(), &[0xff][..])
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            write.commit().unwrap();
            saved
        };
        pool.stage_block(&original).unwrap();
        pool.begin_reward_scan();
        assert!(pool.finish_reward_scan());
        assert!(pool.settle_accepted_block(&original).is_err());
        assert!(!pool.rewards_verified());
        assert_eq!(pool.begin_reward_scan(), Some(3));
        drop(pool);
        let pool = PoolAccounting::try_new(config).unwrap();
        let pending = pool.pending_block().unwrap().unwrap();
        assert_eq!(pending.block.hash(), original.block.hash());
        assert_eq!(
            pool.wallet_summary(original.wallet, 4)
                .pending_payout_atomic,
            0
        );
        let winner = pool.wallet_summary(replacement.wallet, 4);
        assert_eq!(
            (winner.total_blocks_found, winner.pending_payout_atomic),
            (1, 495)
        );
        assert_eq!(
            winner.recent_blocks[0].block_hash_hex,
            replacement.block.hash().to_string()
        );
        assert_eq!(pool.state.read().pool_fee_earned_atomic, 5);
        let write = pool.db.begin_write().unwrap();
        write
            .open_table(rewards::EVENTS)
            .unwrap()
            .insert(hash.as_str(), saved_events.as_slice())
            .unwrap();
        write.commit().unwrap();
        pool.settle_accepted_block(&pending).unwrap();
        assert!(pool.pending_block().unwrap().is_none());
        assert_eq!(
            pool.wallet_summary(original.wallet, 4)
                .pending_payout_atomic,
            990
        );
        assert_eq!(
            pool.wallet_summary(replacement.wallet, 4)
                .pending_payout_atomic,
            0
        );
        assert_eq!(pool.state.read().pool_fee_earned_atomic, 10);
        drop(pool);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_migration_reverses_only_recoverable_allocations() {
        for mode in [PoolMode::Solo, PoolMode::Prop] {
            let directory =
                std::env::temp_dir().join(format!("hyphen-legacy-reward-{}", crate::random_u64()));
            let config = PoolAccountingConfig {
                mode,
                state_dir: Some(directory.clone()),
                ..sample_config()
            };
            let old = "11".repeat(32);
            let new = "22".repeat(32);
            let miner = [1; 32];
            let pool = PoolAccounting::new(config.clone());
            pool.record_valid_share(miner, miner, 1, 1, 100, 0);
            pool.settle_block(miner, miner, 1, old.clone(), 100, 0, 1)
                .unwrap();
            let write = pool.db.begin_write().unwrap();
            write
                .open_table(LEDGER)
                .unwrap()
                .remove("reward_index_v1")
                .unwrap();
            write.delete_table(BLOCK_CREDITS).unwrap();
            write.commit().unwrap();
            drop(pool);

            let pool = PoolAccounting::new(config);
            assert_eq!(pool.reward_heights(0, 127).unwrap(), vec![1]);
            pool.reconcile_reward_height(1, &old).unwrap();
            let result = pool.settle_reward(miner, miner, 1, new.clone(), 90, 0, 1, true);
            let summary = pool.wallet_summary(miner, 8);
            if mode == PoolMode::Solo {
                result.unwrap();
                assert_eq!(summary.direct_reward_atomic, 90);
                pool.reconcile_reward_height(1, &old).unwrap();
                assert_eq!(pool.wallet_summary(miner, 8).direct_reward_atomic, 100);
            } else {
                assert!(
                    matches!(result, Err(AccountingError::Persistence(message)) if message.contains(&old))
                );
                assert_eq!(summary.pending_payout_atomic, 99);
                assert_eq!(summary.recent_blocks[0].block_hash_hex, old);
                assert_eq!(pool.state.read().pool_fee_earned_atomic, 1);
            }
            assert_eq!(summary.total_blocks_found, 1);
            drop(pool);
            std::fs::remove_dir_all(directory).unwrap();
        }
    }

    #[test]
    fn reservations_wait_for_an_uninterrupted_reward_scan() {
        let directory =
            std::env::temp_dir().join(format!("hyphen-reservation-scan-{}", crate::random_u64()));
        let pool = PoolAccounting::new(PoolAccountingConfig {
            state_dir: Some(directory.clone()),
            ..sample_config()
        });
        let miner = [1; 32];
        pool.register_view_key(miner, [2; 32]);
        pool.register_miner(miner, miner);
        pool.record_valid_share(miner, miner, 1, 1, 100, 0);
        pool.begin_reward_scan();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                pool.settle_block(miner, miner, 4, "01".repeat(32), 100, 0, 1)
                    .unwrap()
            });
        });
        assert!(!pool.finish_reward_scan());
        assert!(pool.reserve_payout(1, 50, true).unwrap().is_none());
        assert_eq!(pool.begin_reward_scan(), Some(4));
        assert!(pool.reserve_payout(1, 50, true).unwrap().is_none());
        assert!(pool.finish_reward_scan());
        assert_eq!(
            pool.reserve_payout(1, 50, true)
                .unwrap()
                .unwrap()
                .amount_atomic,
            50
        );
        drop(pool);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fork_reverses_original_shares_across_reservations_and_restart() {
        let directory =
            std::env::temp_dir().join(format!("hyphen-reward-fork-{}", crate::random_u64()));
        let config = PoolAccountingConfig {
            state_dir: Some(directory.clone()),
            pool_fee_bps: 0,
            ..sample_config()
        };
        let old = "11".repeat(32);
        let replacement = "22".repeat(32);
        let tx = "ab".repeat(32);
        let wallet = [4; 32];
        let first = [1; 32];
        let second = [2; 32];
        let pool = PoolAccounting::new(config.clone());
        pool.register_view_key(wallet, [8; 32]);
        for miner in [first, second] {
            pool.register_miner(miner, wallet);
            pool.record_valid_share(miner, wallet, 1, 2, 100, 0);
        }
        pool.settle_block(first, wallet, 7, old.clone(), 100, 0, 2)
            .unwrap();
        let paid = pool.reserve_next_payout(1, 30).unwrap().unwrap();
        pool.mark_payout_submitted(&paid.intent_id, &tx).unwrap();
        pool.mark_payout_confirmed(&paid.intent_id, &tx, 9, 1)
            .unwrap();
        let reserved = pool.reserve_next_payout(1, 10).unwrap().unwrap();
        for _ in 0..2 {
            pool.reconcile_reward_height(7, &replacement).unwrap();
        }
        let balance = pool.wallet_summary(wallet, 8);
        assert_eq!(
            (
                balance.pending_payout_atomic,
                balance.reward_deficit_atomic,
                balance.total_paid_atomic,
                balance.reserved_payout_atomic
            ),
            (0, 40, 30, 10)
        );
        assert!(balance.recent_blocks.is_empty() && balance.recent_reward_events.is_empty());
        drop(pool);
        let pool = PoolAccounting::new(config);
        assert_eq!(pool.wallet_summary(wallet, 8).reward_deficit_atomic, 40);
        pool.record_valid_share(first, wallet, 1, 1, 20, 0);
        pool.settle_block(first, wallet, 7, replacement.clone(), 20, 0, 1)
            .unwrap();
        assert_eq!(pool.wallet_summary(wallet, 8).reward_deficit_atomic, 20);
        pool.reconcile_confirmed_payout(&paid.intent_id, &tx, None)
            .unwrap();
        // A pruned confirmed record can be reinserted after another reservation.
        pool.state.write().payouts.reverse();
        assert_eq!(pool.active_payout().unwrap().intent_id, paid.intent_id);
        pool.mark_payout_confirmed(&paid.intent_id, &tx, 11, 1)
            .unwrap();
        assert_eq!(pool.active_payout().unwrap().intent_id, reserved.intent_id);
        for _ in 0..2 {
            pool.reconcile_reward_height(7, &old).unwrap();
        }
        let balance = pool.wallet_summary(wallet, 8);
        assert_eq!(
            (
                balance.pending_payout_atomic,
                balance.reward_deficit_atomic,
                balance.total_paid_atomic,
                balance.reserved_payout_atomic
            ),
            (60, 0, 30, 10)
        );
        assert_eq!(balance.total_blocks_found, 1);
        assert_eq!(balance.recent_reward_events.len(), 1);
        assert_eq!(balance.recent_reward_events[0].amount_atomic, 100);
        assert_eq!(pool.miner_ledger(&first).unwrap().pending_payout_atomic, 10);
        assert_eq!(
            pool.miner_ledger(&second).unwrap().pending_payout_atomic,
            50
        );
        drop(pool);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn legacy_accounting_state_is_migrated_without_losing_pending_credit() {
        let test_dir = std::env::temp_dir().join(format!(
            "hyphen_pool_legacy_test_{}_{}",
            std::process::id(),
            crate::random_u64()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let miner = [21u8; 32];
        let mut miners = HashMap::new();
        miners.insert(
            hex_encode(miner),
            LegacyMinerLedgerV0 {
                wallet_address: [22u8; 32],
                valid_shares: 3,
                invalid_shares: 1,
                accumulated_share_difficulty: 7,
                pending_payout_atomic: 55,
                direct_reward_atomic: 0,
                total_blocks_found: 0,
                total_paid_atomic: 0,
                last_share_timestamp: None,
                last_disconnect_timestamp: None,
            },
        );
        let legacy = LegacyAccountingStateV0 {
            mode: PoolMode::Pps,
            pool_fee_bps: 100,
            pool_wallet: [9u8; 32],
            pplns_window_factor: 2,
            pool_fee_earned_atomic: 0,
            miners,
            round_shares: Vec::new(),
            share_window: Vec::new(),
            reward_events: Vec::new(),
            recent_blocks: Vec::new(),
        };
        std::fs::write(
            test_dir.join("pool_accounting.bin"),
            crate::wire_config(crate::DEFAULT_WIRE_BYTES)
                .serialize(&legacy)
                .unwrap(),
        )
        .unwrap();
        let mut config = sample_config();
        config.state_dir = Some(test_dir.clone());
        let accounting = PoolAccounting::new(config);
        let ledger = accounting.miner_ledger(&miner).unwrap();
        assert_eq!(ledger.pending_payout_atomic, 55);
        assert_eq!(ledger.reserved_payout_atomic, 0);

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
