use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use prost::Message;
use tracing::{info, warn};

use crate::pow::{difficulty_to_target, evaluate_pow, EpochArena};
use crate::primitives::{
    blake3_hash, blake3_hash_many, Block, BlockHeader, ChainConfig, Hash256, SecretKey,
};
use crate::tp::*;

/// Percentage of block reward that goes to the network fee pool (burned/treasury)
pub const REWARD_NETWORK_PCT: u64 = 5;
/// Percentage of block reward that goes to the developer fund
pub const REWARD_DEV_PCT: u64 = 35;
/// Percentage of block reward that goes to the miner
pub const REWARD_MINER_PCT: u64 = 60;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockRecord {
    pub hash: Hash256,
    pub height: u64,
    pub timestamp: u64,
    pub difficulty: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ChainTip {
    hash: Hash256,
    height: u64,
    timestamp: u64,
    difficulty: u64,
    epoch_seed: Hash256,
    cumulative_difficulty: u128,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedState {
    tip: ChainTip,
    history: Vec<BlockRecord>,
    #[serde(default)]
    balances: HashMap<String, u128>,
}

pub struct ChainState {
    tip: RwLock<ChainTip>,
    history: RwLock<Vec<BlockRecord>>,
    cfg: ChainConfig,
    data_dir: Option<PathBuf>,
    arena_cache: RwLock<Option<(Hash256, Arc<EpochArena>)>>,
    /// Cumulative balances: pubkey_hex → balance
    balances: RwLock<HashMap<String, u128>>,
    /// Dev fund address (fixed, derived from dev key)
    dev_address: String,
}

impl ChainState {
    pub fn new(cfg: ChainConfig, data_dir: Option<PathBuf>) -> Self {
        let genesis_seed = blake3_hash(b"Hyphen_genesis_epoch_seed");
        let dev_address = hex::encode(blake3_hash(b"Hyphen_developer_fund").as_bytes());

        let state = Self {
            tip: RwLock::new(ChainTip {
                hash: Hash256::ZERO,
                height: 0,
                timestamp: chrono::Utc::now().timestamp() as u64,
                difficulty: cfg.genesis_difficulty,
                epoch_seed: genesis_seed,
                cumulative_difficulty: 0,
            }),
            history: RwLock::new(Vec::new()),
            cfg,
            data_dir: data_dir.clone(),
            arena_cache: RwLock::new(None),
            balances: RwLock::new(HashMap::new()),
            dev_address,
        };

        if let Some(ref dir) = data_dir {
            state.load_from_disk(dir);
        }

        state
    }

    fn load_from_disk(&self, dir: &Path) {
        let bin_path = dir.join("chain_state.bin");
        let json_path = dir.join("chain_state.json");
        let loaded = if bin_path.exists() {
            std::fs::read(&bin_path).ok().and_then(|raw| {
                bincode::deserialize::<PersistedState>(&raw).ok()
            })
        } else if json_path.exists() {
            std::fs::read_to_string(&json_path).ok().and_then(|data| {
                serde_json::from_str::<PersistedState>(&data).ok()
            })
        } else {
            None
        };

        match loaded {
            Some(p) => {
                info!(
                    "Loaded chain state: height={}, difficulty={}, tip={}",
                    p.tip.height, p.tip.difficulty, p.tip.hash
                );
                *self.tip.write() = p.tip;
                *self.history.write() = p.history;
                *self.balances.write() = p.balances;
            }
            None => info!("No existing chain state, starting from genesis"),
        }
    }

    fn save_to_disk(&self) {
        if let Some(ref dir) = self.data_dir {
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!("Failed to create data dir: {e}");
                return;
            }
            let persisted = PersistedState {
                tip: self.tip.read().clone(),
                history: self.history.read().clone(),
                balances: self.balances.read().clone(),
            };
            match bincode::serialize(&persisted) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(dir.join("chain_state.bin"), bytes) {
                        warn!("Failed to write chain_state.bin: {e}");
                    }
                }
                Err(e) => warn!("Failed to serialize chain state: {e}"),
            }
        }
    }

    pub fn tip_height(&self) -> u64 {
        self.tip.read().height
    }

    pub fn balance_of(&self, pubkey_hex: &str) -> u128 {
        self.balances.read().get(pubkey_hex).copied().unwrap_or(0)
    }

    pub fn all_balances(&self) -> HashMap<String, u128> {
        self.balances.read().clone()
    }

    pub fn tip_hash(&self) -> Hash256 {
        self.tip.read().hash
    }

    pub fn current_difficulty(&self) -> u64 {
        self.tip.read().difficulty
    }

    pub fn epoch_seed(&self) -> Hash256 {
        self.tip.read().epoch_seed
    }

    fn get_arena(&self, epoch_seed: Hash256) -> Arc<EpochArena> {
        {
            let guard = self.arena_cache.read();
            if let Some((seed, ref a)) = *guard {
                if seed == epoch_seed {
                    return Arc::clone(a);
                }
            }
        }
        info!(
            "Generating epoch arena ({}MiB) for seed {}…",
            self.cfg.arena_size / (1024 * 1024),
            epoch_seed
        );
        let arena = Arc::new(EpochArena::generate(
            epoch_seed,
            self.cfg.arena_size,
            self.cfg.page_size,
        ));
        *self.arena_cache.write() = Some((epoch_seed, Arc::clone(&arena)));
        arena
    }

    pub fn generate_template(&self, miner_pubkey: [u8; 32]) -> BlockTemplate {
        let tip = self.tip.read().clone();
        let next_height = tip.height + 1;
        let next_difficulty = self.next_difficulty_unlocked(&self.history.read());
        let reward = self.calculate_reward(next_height);

        let header = BlockHeader {
            version: 1,
            height: next_height,
            timestamp: chrono::Utc::now().timestamp() as u64,
            prev_hash: tip.hash,
            tx_root: Hash256::ZERO,
            commitment_root: Hash256::ZERO,
            nullifier_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            receipt_root: Hash256::ZERO,
            uncle_root: Hash256::ZERO,
            pow_commitment: blake3_hash(tip.epoch_seed.as_bytes()),
            epoch_seed: tip.epoch_seed,
            difficulty: next_difficulty,
            nonce: 0,
            extra_nonce: [0u8; 32],
            miner_pubkey,
            total_fee: 0,
            reward,
            view_tag: 0,
            block_size: 0,
        };

        let header_data = bincode::serialize(&header).expect("header serialisation");
        let template_id = blake3_hash_many(&[
            &next_height.to_le_bytes(),
            &next_difficulty.to_le_bytes(),
            tip.hash.as_bytes(),
        ]);

        BlockTemplate {
            template_id: template_id.as_bytes().to_vec(),
            header_data,
            transactions: Vec::new(),
            height: next_height,
            difficulty: next_difficulty,
            reward,
            total_fee: 0,
            epoch_seed: tip.epoch_seed.as_bytes().to_vec(),
            prev_hash: tip.hash.as_bytes().to_vec(),
            arena_size: self.cfg.arena_size as u64,
            page_size: self.cfg.page_size as u64,
            clean: true,
        }
    }

    pub fn accept_block(&self, block: &Block) -> Result<Hash256, String> {
        // Hold write lock for the entire operation to prevent race conditions
        // where two blocks at the same height are accepted concurrently.
        let mut tip_guard = self.tip.write();
        let tip = tip_guard.clone();

        if block.header.height != tip.height + 1 {
            return Err(format!(
                "bad height: got {}, expected {}",
                block.header.height,
                tip.height + 1
            ));
        }
        if block.header.prev_hash != tip.hash {
            return Err(format!(
                "bad prev_hash: got {}, expected {}",
                block.header.prev_hash, tip.hash
            ));
        }

        let now = chrono::Utc::now().timestamp() as u64;
        if block.header.timestamp > now + self.cfg.timestamp_future_limit_ms / 1000 {
            return Err("timestamp too far in the future".into());
        }
        if block.header.height > 1 && block.header.timestamp <= tip.timestamp {
            return Err("timestamp must be after parent".into());
        }

        let arena = self.get_arena(tip.epoch_seed);
        let pow_hash = evaluate_pow(&block.header, &arena, &self.cfg);
        let target = difficulty_to_target(block.header.difficulty);
        if !hash_below_target(&pow_hash, &target) {
            return Err("PoW hash does not meet difficulty target".into());
        }

        let block_hash = block.hash();

        let new_epoch_seed = if block.header.height.is_multiple_of(self.cfg.epoch_length) {
            blake3_hash_many(&[tip.epoch_seed.as_bytes(), block_hash.as_bytes()])
        } else {
            tip.epoch_seed
        };

        let record = BlockRecord {
            hash: block_hash,
            height: block.header.height,
            timestamp: block.header.timestamp,
            difficulty: block.header.difficulty,
        };

        {
            let mut history = self.history.write();
            history.push(record);
            let max = (self.cfg.difficulty_window as usize) * 2;
            if history.len() > max {
                let drain = history.len() - max;
                history.drain(..drain);
            }
        }

        let next_diff = self.next_difficulty_unlocked(&self.history.read());
        tip_guard.hash = block_hash;
        tip_guard.height = block.header.height;
        tip_guard.timestamp = block.header.timestamp;
        tip_guard.difficulty = next_diff;
        tip_guard.epoch_seed = new_epoch_seed;
        tip_guard.cumulative_difficulty += block.header.difficulty as u128;
        drop(tip_guard);

        self.save_to_disk();

        let total_reward = block.header.reward;
        if total_reward > 0 {
            let miner_key = hex::encode(block.header.miner_pubkey);
            let network_share = total_reward * REWARD_NETWORK_PCT / 100;
            let dev_share = total_reward * REWARD_DEV_PCT / 100;
            let miner_share = total_reward - network_share - dev_share;

            let mut bal = self.balances.write();
            *bal.entry(miner_key.clone()).or_insert(0) += miner_share as u128;
            *bal.entry(self.dev_address.clone()).or_insert(0) += dev_share as u128;
            // network_share is not credited to anyone (effectively burned)

            info!(
                "Reward: total={} → miner({})={} dev={} network(burned)={}",
                total_reward,
                &miner_key[..8],
                miner_share,
                dev_share,
                network_share
            );
        }

        info!(
            "Chain: height={} hash={} next_diff={} epoch_seed={}",
            block.header.height, block_hash, next_diff, new_epoch_seed
        );

        Ok(block_hash)
    }

    fn next_difficulty_unlocked(&self, history: &[BlockRecord]) -> u64 {
        let n = history.len();
        if n < 2 {
            return self.cfg.genesis_difficulty;
        }

        let window = self.cfg.difficulty_window as usize;
        let w = n.min(window);
        if w < 2 {
            return self.cfg.genesis_difficulty;
        }

        let start = n - w;
        let target_secs = self.cfg.block_time.as_secs() as i128;

        let mut weighted_solve: i128 = 0;
        let mut total_weight: i128 = 0;
        let mut diff_sum: u128 = 0;

        for i in 1..w {
            let idx = start + i;
            let prev = start + i - 1;

            let solve = history[idx].timestamp as i64 - history[prev].timestamp as i64;
            let clamped = (solve.max(1) as i128).min(target_secs * 10);

            let weight = i as i128;
            weighted_solve += clamped * weight;
            total_weight += weight;
            diff_sum += history[idx].difficulty as u128;
        }

        if weighted_solve <= 0 || total_weight <= 0 {
            return self.cfg.genesis_difficulty;
        }

        let avg_diff = diff_sum / (w - 1) as u128;
        let numerator = avg_diff as i128 * target_secs * total_weight;
        let next = (numerator / weighted_solve).max(1) as u64;

        let cur = history
            .last()
            .map(|b| b.difficulty)
            .unwrap_or(self.cfg.genesis_difficulty);
        let up = cur.saturating_add(cur / self.cfg.difficulty_clamp_up);
        let down = cur.saturating_sub(cur / self.cfg.difficulty_clamp_down);

        next.clamp(down.max(1), up)
    }

    fn calculate_reward(&self, height: u64) -> u64 {
        if self.cfg.tail_emission_height > 0 && height >= self.cfg.tail_emission_height {
            return self.cfg.tail_emission;
        }
        let halvings = height / self.cfg.emission_half_life;
        if halvings >= 64 {
            return self.cfg.tail_emission;
        }
        let reward = self.cfg.initial_reward >> halvings;
        reward.max(self.cfg.tail_emission)
    }
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

pub struct StandaloneProvider {
    chain: ChainState,
    pool_pubkey: [u8; 32],
    sk: SecretKey,
    notify_tx: tokio::sync::broadcast::Sender<()>,
    notify_rx: tokio::sync::Mutex<tokio::sync::broadcast::Receiver<()>>,
}

impl StandaloneProvider {
    pub fn new(cfg: ChainConfig, data_dir: Option<PathBuf>, sk: SecretKey) -> Self {
        let pool_pubkey = *sk.public_key().as_bytes();
        let (notify_tx, notify_rx) = tokio::sync::broadcast::channel(64);
        Self {
            chain: ChainState::new(cfg, data_dir),
            pool_pubkey,
            sk,
            notify_tx,
            notify_rx: tokio::sync::Mutex::new(notify_rx),
        }
    }

    pub fn chain(&self) -> &ChainState {
        &self.chain
    }
}

#[async_trait::async_trait]
impl TemplateProvider for StandaloneProvider {
    async fn get_template(&self) -> Result<BlockTemplate, TPError> {
        Ok(self.chain.generate_template(self.pool_pubkey))
    }

    async fn submit_block(&self, block_data: Vec<u8>) -> Result<SubmitBlockResult, TPError> {
        let block: Block = bincode::deserialize(&block_data)
            .map_err(|e| TPError::Protocol(format!("deserialize: {e}")))?;

        match self.chain.accept_block(&block) {
            Ok(hash) => {
                let _ = self.notify_tx.send(());
                Ok(SubmitBlockResult {
                    accepted: true,
                    error: String::new(),
                    block_hash: hash.as_bytes().to_vec(),
                })
            }
            Err(e) => Ok(SubmitBlockResult {
                accepted: false,
                error: e,
                block_hash: Vec::new(),
            }),
        }
    }

    async fn declare_job(
        &self,
        _template_id: Vec<u8>,
        _custom_transactions: Vec<Vec<u8>>,
        _coinbase_script: Vec<u8>,
    ) -> Result<DeclareJobResult, TPError> {
        Ok(DeclareJobResult {
            accepted: true,
            job_id: Vec::new(),
            error: String::new(),
            updated_header: Vec::new(),
        })
    }

    async fn subscribe(&self) -> Result<(), TPError> {
        Ok(())
    }

    async fn read_next(&self) -> Result<SignedEnvelope, TPError> {
        let mut rx = self.notify_rx.lock().await;
        rx.recv()
            .await
            .map_err(|e| TPError::Protocol(format!("channel: {e}")))?;

        let tpl = self.chain.generate_template(self.pool_pubkey);
        let env = SignedEnvelope::sign(TP_TEMPLATE, tpl.encode_to_vec(), &self.sk);
        Ok(env)
    }
}
