use parking_lot::RwLock;
use prost::Message;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::accounting::{PendingBlock, PoolAccounting};
use crate::primitives::{
    Block, BlockAuthorization, ChainConfig, FROZEN_BLOCK_VERSION, SecretKey, blake3_hash,
};
use crate::tp::{BlockTemplate, TP_TEMPLATE, TemplateProvider};

use crate::job::{ActiveJob, JobManager};
use crate::primitives::{ChainIdentity, hex_encode};
use crate::protocol::*;
use crate::share::{ShareVerdict, verify_share};
use crate::telemetry::PoolTelemetry;

/// Target seconds between shares per miner
const VARDIFF_TARGET_SECS: f64 = 15.0;
/// Minimum share difficulty
const VARDIFF_MIN: u64 = 10;
/// A checkpoint can never exceed the consensus iteration ceiling.
const VARDIFF_MAX: u64 = hyphen_pow::vms::MAX_WITNESSES_PER_BLOCK;
/// Number of shares to look back for rate calculation
const VARDIFF_WINDOW: usize = 24;
/// Retarget check interval (after this many shares)
const VARDIFF_RETARGET_SHARES: usize = 6;

/// Minimum wall-clock gap between decisions. Shares mined under the previous
/// threshold carry no information about the next one.
const VARDIFF_MIN_RETARGET_MS: u64 = 20_000;

/// A change smaller than this keeps the threshold and only consumes the
/// sample window, so the controller settles instead of dithering.
const VARDIFF_SIGNIFICANT_CHANGE: f64 = 0.25;

/// Attempts made to fetch the next template after the node accepts a block.
const REFRESH_ATTEMPTS: u32 = 4;
/// Initial low difficulty for new miners (ramps up quickly)
const VARDIFF_INITIAL: u64 = 100;

/// ── GTM: Graduated Trust Mining ──
/// Number of shares during warmup phase — difficulty ramps exponentially
/// from VARDIFF_INITIAL toward the estimated target.
const GTM_WARMUP_SHARES: u64 = 100;
/// Maximum connections from a single IP address
const GTM_MAX_CONNECTIONS_PER_IP: usize = 32;
const MAX_MINER_CONNECTIONS: usize = 256;

/// Grace window duration for VarDiff transitions. Shares mined at any
/// difficulty that was active within this window will be accepted.
const VARDIFF_GRACE_WINDOW_SECS: u64 = 30;

struct MinerSession {
    shares: u64,
    invalid_shares: u64,
    vardiff: VarDiffState,
    thread_count: u32,
    /// The miner's payout wallet address (32-byte spend_public).
    wallet_address: [u8; 32],
    /// The miner's view public key (32 bytes), used for coinbase output creation.
    #[allow(dead_code)]
    view_public: [u8; 32],
    /// GTM: total shares submitted (for warmup ramp calculation)
    total_lifetime_shares: u64,
    /// GTM: estimated target difficulty once warmup completes
    estimated_target_diff: u64,
    /// Minimum difficulty within the grace window. Shares mined at any
    /// difficulty >= this floor are accepted, preventing spurious rejections
    /// when VarDiff ramps rapidly during GTM warmup.
    difficulty_floor: u64,
    /// When the difficulty floor was last set; resets after the grace window.
    floor_set_at: std::time::Instant,
    receipt_sequence: u64,
    receipt_head: [u8; 32],
    seen_submission_nonces: VecDeque<u64>,
}

struct VarDiffState {
    current_difficulty: u64,
    share_timestamps: VecDeque<u64>,
    /// Wall-clock time of the last decision. Samples are one difficulty's
    /// worth of shares; deciding again on a mixed window is what makes the
    /// controller oscillate.
    last_retarget_ms: u64,
}

/// Retires a miner session however its connection ends.
///
/// The frame loop returns early on every transport error, so teardown written
/// after the loop only ran when the peer closed politely. An abruptly closed
/// socket leaked its session, its difficulty history and a wallet the accounting
/// never saw disconnect.
struct SessionGuard<'a, T: TemplateProvider + Send + Sync + 'static> {
    server: &'a PoolServer<T>,
    miner_pk: [u8; 32],
}

impl<T: TemplateProvider + Send + Sync + 'static> Drop for SessionGuard<'_, T> {
    fn drop(&mut self) {
        self.server.retire_session(&self.miner_pk);
    }
}

impl VarDiffState {
    fn new(initial_difficulty: u64) -> Self {
        Self {
            current_difficulty: initial_difficulty,
            share_timestamps: VecDeque::with_capacity(VARDIFF_WINDOW + 1),
            last_retarget_ms: 0,
        }
    }

    /// GTM warmup difficulty: exponential ramp from VARDIFF_INITIAL toward
    /// `target_diff` over `GTM_WARMUP_SHARES` submissions.
    ///
    /// d(n) = d_init + (d_target - d_init) · (1 - e^{-5n/W})
    ///
    /// At n=0:  d ≈ d_init
    /// At n=W:  d ≈ 0.993 · d_target  (within 1% of target)
    fn warmup_difficulty(total_shares: u64, target_diff: u64) -> u64 {
        if total_shares >= GTM_WARMUP_SHARES {
            return target_diff.clamp(VARDIFF_MIN, VARDIFF_MAX);
        }
        let ratio = 5.0 * total_shares as f64 / GTM_WARMUP_SHARES as f64;
        let factor = 1.0 - (-ratio).exp();
        let d_init = VARDIFF_INITIAL as f64;
        let d_target = target_diff as f64;
        let d = d_init + (d_target - d_init) * factor;
        (d.max(VARDIFF_MIN as f64).min(VARDIFF_MAX as f64)) as u64
    }

    /// Record a share and return Some(new_diff) if adjustment is needed.
    /// During GTM warmup, always returns the warmup-ramped difficulty.
    fn record_share_with_warmup(
        &mut self,
        total_lifetime_shares: u64,
        estimated_target: u64,
    ) -> Option<u64> {
        let now_ms = hyphen_core::timestamp::ntp_adjusted_timestamp_ms();
        // The warmup ramp is a value function of the share count, but issuing a
        // new threshold on every share re-sends a job per share and starves the
        // miner of the one thing it needs: a stable job to finish.
        if self.last_retarget_ms != 0
            && now_ms.saturating_sub(self.last_retarget_ms) < VARDIFF_MIN_RETARGET_MS
        {
            return None;
        }

        // During warmup, always return the exponentially ramped difficulty
        if total_lifetime_shares < GTM_WARMUP_SHARES {
            let warmup_diff = Self::warmup_difficulty(total_lifetime_shares, estimated_target);
            if warmup_diff != self.current_difficulty {
                self.current_difficulty = warmup_diff;
                self.last_retarget_ms = now_ms;
                return Some(warmup_diff);
            }
            return None;
        }

        // Post-warmup: standard VarDiff behaviour
        self.record_share()
    }

    /// Record a share and return Some(new_diff) if adjustment is needed.
    fn record_share(&mut self) -> Option<u64> {
        let now_ms = hyphen_core::timestamp::ntp_adjusted_timestamp_ms();
        self.share_timestamps.push_back(now_ms);
        if self.share_timestamps.len() > VARDIFF_WINDOW {
            self.share_timestamps.pop_front();
        }

        // Only retarget after enough samples
        if self.share_timestamps.len() < VARDIFF_RETARGET_SHARES {
            return None;
        }

        // Only retarget every VARDIFF_RETARGET_SHARES shares
        let total_shares = self.share_timestamps.len();
        if !total_shares.is_multiple_of(VARDIFF_RETARGET_SHARES) {
            return None;
        }

        // A retarget moves the threshold. Samples collected under the old
        // threshold say nothing about the new one, and deciding again
        // immediately is what drove the controller into a
        // 200 → 29 → 45 → 43 oscillation that starved every miner of block
        // candidates.
        if now_ms.saturating_sub(self.last_retarget_ms) < VARDIFF_MIN_RETARGET_MS {
            return None;
        }

        let oldest = *self.share_timestamps.front()?;
        let newest = *self.share_timestamps.back()?;
        let elapsed_secs = (newest.saturating_sub(oldest)) as f64 / 1000.0;

        let proposed = if elapsed_secs < 1.0 {
            // Too fast to measure: double, still bounded by the hard ceiling.
            self.current_difficulty.saturating_mul(2)
        } else {
            let actual_rate = elapsed_secs / (total_shares.saturating_sub(1)) as f64;
            let ratio = actual_rate / VARDIFF_TARGET_SECS;
            // Bounded factor per decision so one burst cannot swing the pool.
            let clamped = ratio.clamp(0.5, 2.0);
            (self.current_difficulty as f64 / clamped) as u64
        };
        let proposed = proposed.clamp(VARDIFF_MIN, VARDIFF_MAX);

        // Every decision consumes the window, whether or not it changes the
        // threshold: the next one must be measured under the threshold that is
        // active when its shares were mined.
        self.share_timestamps.clear();
        self.last_retarget_ms = now_ms;

        let change_pct = (proposed as f64 - self.current_difficulty as f64).abs()
            / self.current_difficulty.max(1) as f64;
        if change_pct > VARDIFF_SIGNIFICANT_CHANGE {
            self.current_difficulty = proposed;
            Some(proposed)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
enum PoolBroadcast {
    NewTemplate,
    BlockFound(BlockFoundNotify),
}

pub struct PoolServer<T: TemplateProvider + Send + Sync + 'static> {
    job_manager: Arc<JobManager>,
    tp_client: Arc<T>,
    accounting: Arc<PoolAccounting>,
    candidate_submission: tokio::sync::Mutex<()>,
    block_refresh: tokio::sync::Notify,
    pool_key: SecretKey,
    pool_id: String,
    cfg: ChainConfig,
    bind_addr: SocketAddr,
    job_tx: broadcast::Sender<PoolBroadcast>,
    miners: Arc<RwLock<HashMap<[u8; 32], MinerSession>>>,
    /// Live loop state for `/api/pool/status`.
    telemetry: Arc<PoolTelemetry>,
}

impl<T: TemplateProvider + Send + Sync + 'static> PoolServer<T> {
    /// Witness count that should arrive roughly every `VARDIFF_TARGET_SECS`.
    ///
    /// Witness density is analytic rather than empirical: a chain of length `L`
    /// needs `L` primes, and a random 64-bit origin is prime with probability
    /// about `1 / ln(2^63)`. Estimating beats guessing, and the value is capped
    /// against the job's own difficulty before it is ever enforced.
    fn recommended_share_difficulty(
        cfg: &ChainConfig,
        operations_per_second: u64,
        thread_count: u32,
    ) -> u64 {
        if operations_per_second == 0 {
            return if thread_count > 0 {
                (thread_count as u64 * VARDIFF_INITIAL).clamp(VARDIFF_MIN, VARDIFF_MAX)
            } else {
                VARDIFF_INITIAL
            };
        }
        let length = cfg.pouw_chain_length.max(1) as f64;
        let witness_probability = (1.0 / 43.7_f64).powf(length);
        let expected = operations_per_second as f64 * witness_probability * VARDIFF_TARGET_SECS;
        (expected.round() as u64).clamp(1, VARDIFF_MAX)
    }

    pub fn new(
        job_manager: Arc<JobManager>,
        tp_client: Arc<T>,
        accounting: Arc<PoolAccounting>,
        pool_key: SecretKey,
        pool_id: String,
        cfg: ChainConfig,
        bind_addr: SocketAddr,
    ) -> Self {
        let (job_tx, _) = broadcast::channel(64);
        Self {
            job_manager,
            tp_client,
            accounting,
            candidate_submission: tokio::sync::Mutex::new(()),
            block_refresh: tokio::sync::Notify::new(),
            pool_key,
            pool_id,
            cfg,
            bind_addr,
            job_tx,
            miners: Arc::new(RwLock::new(HashMap::new())),
            telemetry: Arc::new(PoolTelemetry::new()),
        }
    }

    /// Handle on the live mining state, for the status endpoint.
    pub fn telemetry(&self) -> Arc<PoolTelemetry> {
        Arc::clone(&self.telemetry)
    }

    /// Retires a session once, on any exit path, and keeps the attached-miner
    /// count equal to the session map.
    fn retire_session(&self, miner_pk: &[u8; 32]) {
        let mut miners = self.miners.write();
        if let Some(session) = miners.remove(miner_pk) {
            self.accounting.note_disconnect(*miner_pk);
            info!(
                "Miner disconnected: pk={}, wallet={}, shares={}, invalid={}",
                hex_encode(miner_pk),
                hex_encode(session.wallet_address),
                session.shares,
                session.invalid_shares
            );
        }
        self.telemetry.set_connected_miners(miners.len());
    }

    fn session_wallet(&self, miner_pk: &[u8; 32]) -> [u8; 32] {
        self.miners
            .read()
            .get(miner_pk)
            .map(|session| session.wallet_address)
            .unwrap_or(*miner_pk)
    }

    fn session_share_difficulty(&self, miner_pk: &[u8; 32], fallback: u64) -> u64 {
        self.miners
            .read()
            .get(miner_pk)
            .map(|session| session.vardiff.current_difficulty)
            .unwrap_or(fallback)
    }

    fn register_submission_nonce(&self, miner_pk: &[u8; 32], nonce: u64) -> bool {
        let mut miners = self.miners.write();
        let Some(session) = miners.get_mut(miner_pk) else {
            return false;
        };
        if session.seen_submission_nonces.contains(&nonce) {
            return false;
        }
        session.seen_submission_nonces.push_back(nonce);
        if session.seen_submission_nonces.len() > 4_096 {
            session.seen_submission_nonces.pop_front();
        }
        true
    }

    fn next_share_receipt(
        &self,
        miner_pk: &[u8; 32],
        submission_payload: &[u8],
        result_payload: &[u8],
    ) -> (u64, Vec<u8>, Vec<u8>) {
        let mut miners = self.miners.write();
        let Some(session) = miners.get_mut(miner_pk) else {
            return (0, Vec::new(), Vec::new());
        };
        let previous = session.receipt_head;
        let sequence = session.receipt_sequence.saturating_add(1);
        let submission_hash = blake3_hash(submission_payload);
        let result_hash = blake3_hash(result_payload);
        let pool_pubkey = self.pool_key.public_key();
        let receipt = share_receipt_hash(
            pool_pubkey.as_bytes(),
            miner_pk,
            sequence,
            &previous,
            submission_hash.as_bytes(),
            result_hash.as_bytes(),
        );
        session.receipt_sequence = sequence;
        session.receipt_head = receipt;
        (sequence, previous.to_vec(), receipt.to_vec())
    }

    fn build_job_template_for_miner(
        &self,
        job: &ActiveJob,
        clean_jobs: bool,
        wallet_address: [u8; 32],
        miner_pubkey: [u8; 32],
        share_difficulty: u64,
    ) -> Result<JobTemplate, PoolError> {
        let mut header = job.header.clone();
        header.miner_pubkey = miner_pubkey;
        // Neural work has no partial credit, so every job is all-or-nothing:
        // advertising the block threshold as the share difficulty keeps the
        // miner's view of the job coherent instead of suggesting variance that
        // the accounting cannot honour.
        let share_difficulty = if self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
            header.difficulty
        } else {
            share_difficulty.clamp(1, header.difficulty)
        };
        let reward_spend_public = self.accounting.reward_recipient_for_wallet(wallet_address);
        let reward_view_public = self
            .accounting
            .get_view_public(&reward_spend_public)
            .unwrap_or([0u8; 32]);
        crate::primitives::bind_reward(
            &self.cfg,
            &mut header,
            &reward_view_public,
            &reward_spend_public,
        );
        let header_data = crate::wire_config(crate::DEFAULT_WIRE_BYTES)
            .serialize(&header)
            .map_err(|error| PoolError::Internal(format!("header serialisation: {error}")))?;
        let identity = ChainIdentity::of(&self.cfg);

        Ok(JobTemplate {
            job_id: job.job_id.to_vec(),
            header_data,
            height: header.height,
            block_difficulty: header.difficulty,
            share_difficulty,
            epoch_seed: job.epoch_seed.as_bytes().to_vec(),
            prev_hash: header.prev_hash.as_bytes().to_vec(),
            chain_length: job.chain_length as u64,
            clean_jobs,
            consensus_params_hash: identity.consensus_params_hash.to_vec(),
            genesis_hash: identity.genesis_hash.as_bytes().to_vec(),
            reward_view_public: reward_view_public.to_vec(),
            reward_spend_public: reward_spend_public.to_vec(),
            transactions: job.transactions.clone(),
            parent_work_commitment: job.parent_work_commitment.as_bytes().to_vec(),
        })
    }

    fn is_expected_disconnect(error: &PoolError) -> bool {
        matches!(
            error,
            PoolError::Io(io_error)
                if matches!(
                    io_error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                )
        )
    }

    pub async fn run(self: Arc<Self>) -> Result<(), PoolError> {
        self.recover_pending_block()
            .await
            .map_err(PoolError::Internal)?;
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!("Pool server listening on {}", self.bind_addr);

        let mut refresh = std::pin::pin!(self.template_refresh_loop());
        let mut accepted_blocks = std::pin::pin!(async {
            loop {
                self.block_refresh.notified().await;
                self.refresh_template_after_block().await;
            }
        });
        let mut sessions = tokio::task::JoinSet::new();
        let mut ip_counts = HashMap::<std::net::IpAddr, usize>::new();
        let mut peers = HashMap::new();

        loop {
            let (stream, addr) = tokio::select! {
                () = &mut refresh => return Err(PoolError::Internal("template refresh stopped".into())),
                () = &mut accepted_blocks => return Err(PoolError::Internal("block refresh stopped".into())),
                Some(done) = sessions.join_next_with_id(), if !sessions.is_empty() => {
                    let id = match done { Ok((id, ())) => id, Err(error) => { warn!("miner session stopped: {error}"); error.id() } };
                    if let Some(ip) = peers.remove(&id) && let Some(count) = ip_counts.get_mut(&ip) {
                        *count -= 1;
                        if *count == 0 { ip_counts.remove(&ip); }
                    }
                    continue;
                }
                incoming = listener.accept(), if sessions.len() < MAX_MINER_CONNECTIONS => incoming?,
            };
            let count = ip_counts.entry(addr.ip()).or_default();
            if *count >= GTM_MAX_CONNECTIONS_PER_IP {
                continue;
            }
            *count += 1;

            info!("Miner connected from {addr}");
            let server = Arc::clone(&self);
            let task = sessions.spawn(async move {
                if let Err(e) = server.handle_connection(stream, addr).await {
                    match e {
                        PoolError::FrameTooLarge(len) => {
                            warn!(
                                "Rejected non-Hyphen or incompatible miner traffic from {addr}: frame too large ({len} bytes)"
                            );
                        }
                        other if Self::is_expected_disconnect(&other) => {
                            info!("Miner {addr} disconnected: {other}");
                        }
                        other => warn!("Miner {addr} disconnected: {other}"),
                    }
                }
            });
            peers.insert(task.id(), addr.ip());
        }
    }

    async fn template_refresh_loop(self: &Arc<Self>) {
        let mut poll_interval = tokio::time::interval(self.cfg.block_time / 2);
        let mut subscribed = false;

        loop {
            if !subscribed {
                match self.tp_client.subscribe().await {
                    Ok(()) => {
                        info!("Subscribed to TP template updates");
                        subscribed = true;
                    }
                    Err(e) => {
                        warn!("Failed to subscribe to TP: {e}, retrying");
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        continue;
                    }
                }
            }

            tokio::select! {
                  _ = poll_interval.tick() => {
                    {
                        let _submission = self.candidate_submission.lock().await;
                        if let Err(error) = self.recover_pending_block().await { warn!("Pending block recovery: {error}"); }
                    }
                    match self.tp_client.get_template().await {
                        Ok(tpl) => self.apply_template(tpl),
                        Err(e) => warn!("TP poll failed: {e}"),
                    }
                }
                result = self.tp_client.read_next() => {
                    match result {
                        Ok(env) if env.msg_type == TP_TEMPLATE => {
                            if let Ok(tpl) = BlockTemplate::decode(&env.payload[..]) {
                                info!("Received pushed template update: height={}", tpl.height);
                                self.apply_template(tpl);
                                poll_interval.reset();
                            }
                        }
                        Err(e) => {
                            error!("TP subscription connection lost: {e}");
                            subscribed = false;
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    /// Fetch the post-block template, retrying a few times.
    ///
    /// The node has just accepted a block, so the pool must not sit on the old
    /// height. A single failed `get_template` used to be terminal: the job stayed
    /// blocked and no new template arrives while the chain is stuck, so a
    /// transient node hiccup stopped the pool until an operator intervened.
    async fn refresh_template_after_block(&self) {
        let mut delay = std::time::Duration::from_millis(200);
        for attempt in 1..=REFRESH_ATTEMPTS {
            match self.tp_client.get_template().await {
                Ok(tpl) => {
                    info!(
                        "Refreshed template after block accept: height={}",
                        tpl.height
                    );
                    self.apply_template(tpl);
                    return;
                }
                Err(error) => {
                    self.telemetry.record_template_refresh_failure();
                    warn!(
                        "Template refresh after block failed (attempt {attempt}/{REFRESH_ATTEMPTS}): {error}"
                    );
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
            }
        }
        // The node pushes a template when it produces the next one; the pool is
        // not wedged because the job claim is already released.
        warn!("Giving up on post-block template refresh; waiting for the node push");
    }

    fn apply_template(&self, tpl: BlockTemplate) {
        // The template protocol version is the node's, which is a different
        // contract from the miner-facing protocol version in `crate::protocol`.
        if tpl.protocol_version != hyphen_transport::POOL_PROTOCOL_VERSION
            || tpl.network_magic.as_slice() != self.cfg.network_magic
            || tpl.consensus_params_hash.as_slice() != self.cfg.consensus_params_hash()
            || tpl.genesis_hash.as_slice() != ChainIdentity::of(&self.cfg).genesis_hash.as_bytes()
        {
            warn!(
                "Rejected template for wrong chain/protocol: version={}, magic={}",
                tpl.protocol_version,
                hex_encode(&tpl.network_magic),
            );
            return;
        }
        if tpl.template_id.len() != 32
            || tpl.epoch_seed.len() != 32
            || tpl.prev_hash.len() != 32
            || tpl.difficulty == 0
            || tpl.pouw_chain_length != self.cfg.pouw_chain_length as u64
            || tpl.parent_work_commitment.len() != 32
        {
            warn!("Rejected malformed or incompatible node template");
            return;
        }
        let header: crate::primitives::BlockHeader =
            match crate::wire_config(4096).deserialize(&tpl.header_data) {
                Ok(header) => header,
                Err(error) => {
                    warn!("Rejected template with invalid header: {error}");
                    return;
                }
            };
        if header.version != FROZEN_BLOCK_VERSION
            || header.height != tpl.height
            || header.difficulty != tpl.difficulty
            || header.epoch_seed.as_bytes() != tpl.epoch_seed.as_slice()
            || header.prev_hash.as_bytes() != tpl.prev_hash.as_slice()
        {
            warn!("Rejected template whose header metadata does not match its envelope");
            return;
        }
        match self.job_manager.ingest_owned_template(tpl) {
            Ok(job) => {
                self.telemetry.record_job(&job);
                let _ = self.job_tx.send(PoolBroadcast::NewTemplate);
            }
            Err(e) => warn!("Failed to ingest template: {e}"),
        }
    }

    async fn handle_connection(
        self: &Arc<Self>,
        mut stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), PoolError> {
        let login_env = PoolCodec::read_envelope(&mut stream).await?;
        login_env.verify()?;

        if login_env.msg_type != MSG_LOGIN {
            return Err(PoolError::Internal("expected LOGIN".into()));
        }

        let login = LoginRequest::decode(&login_env.payload[..])?;
        if login.protocol_version != POOL_PROTOCOL_VERSION
            || login.network_magic.as_slice() != self.cfg.network_magic
            || login.consensus_params_hash.as_slice() != self.cfg.consensus_params_hash()
            || login.genesis_hash.as_slice() != ChainIdentity::of(&self.cfg).genesis_hash.as_bytes()
        {
            let ack = LoginAck {
                accepted: false,
                pool_id: self.pool_id.clone(),
                error: format!(
                    "network/protocol mismatch (expected {} / v{})",
                    self.cfg.network_name, POOL_PROTOCOL_VERSION
                ),
                share_difficulty: 0,
                chain_tip_hash: Vec::new(),
                chain_height: 0,
                block_difficulty: 0,
                block_time_target_ms: self.cfg.block_time.as_millis() as u64,
                network_name: self.cfg.network_name.clone(),
                network_magic: self.cfg.network_magic.to_vec(),
                protocol_version: POOL_PROTOCOL_VERSION,
                consensus_params_hash: self.cfg.consensus_params_hash().to_vec(),
                genesis_hash: ChainIdentity::of(&self.cfg)
                    .genesis_hash
                    .as_bytes()
                    .to_vec(),
            };
            let envelope = PoolEnvelope::sign(MSG_LOGIN_ACK, ack.encode_to_vec(), &self.pool_key);
            PoolCodec::write_envelope(&mut stream, &envelope).await?;
            return Ok(());
        }
        let mut miner_pk = [0u8; 32];
        if login_env.sender_pubkey.len() != 32 {
            return Err(PoolError::InvalidPublicKey);
        }
        miner_pk.copy_from_slice(&login_env.sender_pubkey);

        let mut wallet_addr = miner_pk;
        let mut view_public = [0u8; 32];
        if login.payout_pubkey.len() == 64 {
            // New format: view_public (32) + spend_public (32)
            view_public.copy_from_slice(&login.payout_pubkey[..32]);
            wallet_addr.copy_from_slice(&login.payout_pubkey[32..64]);
        } else {
            return Err(PoolError::Internal(
                "pool protocol v3 requires a 64-byte view/spend payout address".into(),
            ));
        }
        if view_public == [0u8; 32] || wallet_addr == [0u8; 32] {
            return Err(PoolError::Internal(
                "payout address contains a zero public key".into(),
            ));
        }

        info!(
            "Miner authenticated: id={}, addr={}, pk={}, wallet={}, threads={}",
            login.miner_id,
            addr,
            hex_encode(miner_pk),
            hex_encode(wallet_addr),
            login.thread_count,
        );

        let initial_diff = Self::recommended_share_difficulty(
            &self.cfg,
            login.estimated_operations_per_second,
            login.thread_count,
        );

        // New miners start at VARDIFF_INITIAL while compute-rate telemetry warms up.
        // the estimated target is stored so the warmup ramp has something to aim for.
        let gtm_initial = VARDIFF_INITIAL;

        {
            let mut miners = self.miners.write();
            if miners.contains_key(&miner_pk) {
                return Err(PoolError::Internal(
                    "miner already has an active session".into(),
                ));
            }
            miners.insert(
                miner_pk,
                MinerSession {
                    shares: 0,
                    invalid_shares: 0,
                    vardiff: VarDiffState::new(gtm_initial),
                    thread_count: login.thread_count,
                    wallet_address: wallet_addr,
                    view_public,
                    total_lifetime_shares: 0,
                    estimated_target_diff: initial_diff,
                    difficulty_floor: gtm_initial,
                    floor_set_at: std::time::Instant::now(),
                    receipt_sequence: 0,
                    receipt_head: [0u8; 32],
                    seen_submission_nonces: VecDeque::with_capacity(256),
                },
            );
            self.telemetry.set_connected_miners(miners.len());
        }
        // Armed only once the session exists: every exit from here on, including
        // the `?` early returns inside the frame loop, has to retire it.
        let _session_guard = SessionGuard {
            server: self.as_ref(),
            miner_pk,
        };
        self.accounting.register_view_key(wallet_addr, view_public);
        self.accounting.register_miner(miner_pk, wallet_addr);

        let mut job_rx = self.job_tx.subscribe();
        let current_job = self.job_manager.shared_current_job();
        let (tip_hash, tip_height, block_diff) = match &current_job {
            Some(j) => (
                j.header.prev_hash.as_bytes().to_vec(),
                j.header.height - 1,
                j.header.difficulty,
            ),
            None => (vec![0u8; 32], 0, self.cfg.genesis_difficulty),
        };

        let ack = LoginAck {
            accepted: true,
            pool_id: self.pool_id.clone(),
            error: String::new(),
            share_difficulty: gtm_initial,
            chain_tip_hash: tip_hash,
            chain_height: tip_height,
            block_difficulty: block_diff,
            block_time_target_ms: self.cfg.block_time.as_millis() as u64,
            network_name: self.cfg.network_name.clone(),
            network_magic: self.cfg.network_magic.to_vec(),
            protocol_version: POOL_PROTOCOL_VERSION,
            consensus_params_hash: self.cfg.consensus_params_hash().to_vec(),
            genesis_hash: ChainIdentity::of(&self.cfg)
                .genesis_hash
                .as_bytes()
                .to_vec(),
        };
        let ack_env = PoolEnvelope::sign(MSG_LOGIN_ACK, ack.encode_to_vec(), &self.pool_key);
        PoolCodec::write_envelope(&mut stream, &ack_env).await?;

        if let Some(job) = current_job {
            let template =
                self.build_job_template_for_miner(&job, true, wallet_addr, miner_pk, gtm_initial)?;
            let job_env = PoolEnvelope::sign(MSG_JOB, template.encode_to_vec(), &self.pool_key);
            PoolCodec::write_envelope(&mut stream, &job_env).await?;
        }

        let (mut reader, mut writer) = stream.into_split();
        'session: loop {
            // Keep the partially read frame alive while sending pool broadcasts.
            let mut incoming = std::pin::pin!(PoolCodec::read_envelope(&mut reader));
            loop {
                tokio::select! {
                    result = &mut incoming => {
                        let env = result?;
                        env.verify()?;

                        if env.sender_pubkey.len() != 32 || env.sender_pubkey[..] != miner_pk[..] {
                            return Err(PoolError::Internal("pubkey mismatch".into()));
                        }

                        match env.msg_type {
                            MSG_SUBMIT => {
                                if !self.register_submission_nonce(&miner_pk, env.nonce) {
                                    return Err(PoolError::Internal(
                                        "duplicate or unauthenticated share envelope".into(),
                                    ));
                                }
                                let reply = self.handle_share(&env, &miner_pk).await;
                                if reply.accepted {
                                    self.telemetry.record_share_accepted();
                                } else {
                                    self.telemetry.record_share_rejected(&reply.error);
                                }
                                let reply_payload = reply.encode_to_vec();
                                let (sequence, previous, receipt) = if reply.accepted {
                                    self.next_share_receipt(
                                        &miner_pk,
                                        &env.payload,
                                        &reply_payload,
                                    )
                                } else {
                                    (0, Vec::new(), Vec::new())
                                };
                                let reply_env = PoolEnvelope::sign_with_receipt(
                                    MSG_SUBMIT_RESULT,
                                    reply_payload,
                                    &self.pool_key,
                                    sequence,
                                    previous,
                                    receipt,
                                );
                                PoolCodec::write_envelope(&mut writer, &reply_env).await?;

                                if reply.accepted && !self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) {
                                    let new_diff = {
                                        let mut miners = self.miners.write();
                                        if let Some(session) = miners.get_mut(&miner_pk) {
                                            let old_diff = session.vardiff.current_difficulty;
                                            session.total_lifetime_shares += 1;
                                            let result = session.vardiff.record_share_with_warmup(
                                                session.total_lifetime_shares,
                                                session.estimated_target_diff,
                                            );
                                            if result.is_some() {
                                                // Maintain the difficulty floor as the minimum of the
                                                // old floor and the outgoing difficulty. This ensures
                                                // all in-flight shares mined at any difficulty within
                                                // the grace window are still accepted.
                                                let now = std::time::Instant::now();
                                                if now.duration_since(session.floor_set_at).as_secs()
                                                    >= VARDIFF_GRACE_WINDOW_SECS
                                                {
                                                    // Grace window expired — reset floor to old_diff
                                                    session.difficulty_floor = old_diff;
                                                } else {
                                                    session.difficulty_floor =
                                                        session.difficulty_floor.min(old_diff);
                                                }
                                                session.floor_set_at = now;
                                            }
                                            result
                                        } else {
                                            None
                                        }
                                    };
                                    if let Some(diff) = new_diff {
                                        info!(
                                            "VarDiff: miner {} → share_diff={}",
                                            hex_encode(miner_pk),
                                            diff
                                        );
                                        let set_msg = SetDifficulty {
                                            share_difficulty: diff,
                                        };
                                        let diff_env = PoolEnvelope::sign(
                                            MSG_SET_DIFFICULTY,
                                            set_msg.encode_to_vec(),
                                            &self.pool_key,
                                        );
                                        PoolCodec::write_envelope(
                                            &mut writer,
                                            &diff_env,
                                        )
                                        .await?;

                                        if let Some(job) = self.job_manager.shared_current_job() {
                                            let wallet = self.session_wallet(&miner_pk);
                                            let template = self.build_job_template_for_miner(
                                                &job,
                                                true,
                                                wallet,
                                                miner_pk,
                                                diff,
                                            )?;
                                            let job_env = PoolEnvelope::sign(
                                                MSG_JOB,
                                                template.encode_to_vec(),
                                                &self.pool_key,
                                            );
                                            PoolCodec::write_envelope(&mut writer, &job_env).await?;
                                        }
                                    }
                                }
                            }
                            MSG_KEEPALIVE => {}
                            MSG_COMPUTE_RATE_REPORT if !self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK) => {
                                if let Ok(report) = ComputeRateReport::decode(&env.payload[..]) {
                                    info!(
                                        "Scientific compute report from {}: {} ops/s, total={}, uptime={}s",
                                        hex_encode(miner_pk),
                                        report.operations_per_second,
                                        report.total_operations,
                                        report.uptime_secs,
                                    );

                                    let new_diff = {
                                        let mut miners = self.miners.write();
                                        miners.get_mut(&miner_pk).and_then(|session| {
                                            // A report measured over an idle window
                                            // says nothing about sustainable rate.
                                            if report.operations_per_second == 0 {
                                                return None;
                                            }
                                            // Same decision gate as the share-driven
                                            // controller: one threshold change per
                                            // interval, so the pool is not re-issuing
                                            // jobs faster than miners can mine them.
                                            let now_ms = hyphen_core::timestamp::ntp_adjusted_timestamp_ms();
                                            if now_ms.saturating_sub(session.vardiff.last_retarget_ms)
                                                < VARDIFF_MIN_RETARGET_MS
                                            {
                                                return None;
                                            }
                                            let recommended = Self::recommended_share_difficulty(&self.cfg,
                                                report.operations_per_second,
                                                session.thread_count,
                                            );
                                            let current = session.vardiff.current_difficulty.max(1);
                                            let change_pct = (recommended as f64 - current as f64).abs()
                                                / current as f64;
                                            if change_pct >= VARDIFF_SIGNIFICANT_CHANGE {
                                                let now = std::time::Instant::now();
                                                if now.duration_since(session.floor_set_at).as_secs()
                                                    >= VARDIFF_GRACE_WINDOW_SECS
                                                {
                                                    session.difficulty_floor = current;
                                                } else {
                                                    session.difficulty_floor =
                                                        session.difficulty_floor.min(current);
                                                }
                                                session.floor_set_at = now;
                                                session.vardiff.current_difficulty = recommended;
                                                session.vardiff.share_timestamps.clear();
                                                session.vardiff.last_retarget_ms = now_ms;
                                                Some(recommended)
                                            } else {
                                                None
                                            }
                                        })
                                    };

                                    if let Some(diff) = new_diff {
                                        info!(
                                            "Checkpoint update: miner {} -> iterations={} (compute={} ops/s)",
                                            hex_encode(miner_pk),
                                            diff,
                                            report.operations_per_second,
                                        );
                                        let set_msg = SetDifficulty {
                                            share_difficulty: diff,
                                        };
                                        let diff_env = PoolEnvelope::sign(
                                            MSG_SET_DIFFICULTY,
                                            set_msg.encode_to_vec(),
                                            &self.pool_key,
                                        );
                                        PoolCodec::write_envelope(&mut writer, &diff_env).await?;

                                        if let Some(job) = self.job_manager.shared_current_job() {
                                            let wallet = self.session_wallet(&miner_pk);
                                            let template = self.build_job_template_for_miner(
                                                &job,
                                                true,
                                                wallet,
                                                miner_pk,
                                                diff,
                                            )?;
                                            let job_env = PoolEnvelope::sign(
                                                MSG_JOB,
                                                template.encode_to_vec(),
                                                &self.pool_key,
                                            );
                                            PoolCodec::write_envelope(&mut writer, &job_env).await?;
                                        }
                                    }
                                }
                            }
                            MSG_COMPUTE_RATE_REPORT => {}
                            _ => {
                                warn!("Unexpected msg type {} from {addr}", env.msg_type);
                            }
                        }
                        break;
                    }

                    frame = job_rx.recv() => {
                        match frame {
                            Ok(PoolBroadcast::NewTemplate) => {
                                if let Some(job) = self.job_manager.shared_current_job() {
                                    let wallet = self.session_wallet(&miner_pk);
                                    let diff = self.session_share_difficulty(&miner_pk, job.share_difficulty);
                                    let template = self.build_job_template_for_miner(
                                        &job,
                                        true,
                                        wallet,
                                        miner_pk,
                                        diff,
                                    )?;
                                    let env = PoolEnvelope::sign(MSG_JOB, template.encode_to_vec(), &self.pool_key);
                                    PoolCodec::write_envelope(&mut writer, &env).await?;
                                }
                            }
                            Ok(PoolBroadcast::BlockFound(notify)) => {
                                let notify_env = PoolEnvelope::sign(
                                    MSG_BLOCK_FOUND,
                                    notify.encode_to_vec(),
                                    &self.pool_key,
                                );
                                PoolCodec::write_envelope(&mut writer, &notify_env).await?;
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!("Miner {addr} lagged {n} broadcasts");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                break 'session;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
    async fn handle_share(
        self: &Arc<Self>,
        env: &PoolEnvelope,
        miner_pk: &[u8; 32],
    ) -> SubmitResult {
        let submission = match ShareSubmission::decode(&env.payload[..]) {
            Ok(s) => s,
            Err(e) => {
                return SubmitResult {
                    accepted: false,
                    error: format!("decode: {e}"),
                    block_found: false,
                    block_hash: Vec::new(),
                };
            }
        };

        let mut job_id = [0u8; 32];
        if submission.job_id.len() != 32 {
            return SubmitResult {
                accepted: false,
                error: "invalid job_id".into(),
                block_found: false,
                block_hash: Vec::new(),
            };
        }
        job_id.copy_from_slice(&submission.job_id);

        let job = match self.job_manager.shared_job(&job_id) {
            Some(j) => j,
            None => {
                return SubmitResult {
                    accepted: false,
                    error: "stale job".into(),
                    block_found: false,
                    block_hash: Vec::new(),
                };
            }
        };

        if let Some(current_job) = self.job_manager.shared_current_job() {
            let chain_advanced = current_job.header.height != job.header.height
                || current_job.header.prev_hash != job.header.prev_hash;
            if chain_advanced && current_job.job_id != job.job_id {
                return SubmitResult {
                    accepted: false,
                    error: "stale job".into(),
                    block_found: false,
                    block_hash: Vec::new(),
                };
            }
        }

        if self.job_manager.is_blocked(&job_id) {
            return SubmitResult {
                accepted: false,
                error: "stale job".into(),
                block_found: false,
                block_hash: Vec::new(),
            };
        }

        let wallet_address = self.session_wallet(miner_pk);
        let reward_recipient = self.accounting.reward_recipient_for_wallet(wallet_address);
        let mut effective_header = job.header.clone();
        effective_header.miner_pubkey = *miner_pk;

        // Use the difficulty floor as the effective share difficulty during
        // VarDiff transitions. The floor tracks the minimum difficulty over a
        // grace window, so in-flight shares mined at any recently-active
        // difficulty are accepted rather than spuriously rejected.
        let (_miner_share_diff, effective_share_diff) = {
            let miners = self.miners.read();
            if let Some(session) = miners.get(miner_pk) {
                let cur = session.vardiff.current_difficulty;
                let floor = if std::time::Instant::now()
                    .duration_since(session.floor_set_at)
                    .as_secs()
                    < VARDIFF_GRACE_WINDOW_SECS
                {
                    session.difficulty_floor
                } else {
                    cur
                };
                (cur, cur.min(floor))
            } else {
                (job.share_difficulty, job.share_difficulty)
            }
        };

        let neural = self.cfg.feature_enabled(hyphen_core::FEATURE_NEURAL_WORK);
        // Neural work has no verifiable partial result, so every accepted
        // submission is a complete block candidate and `credit_at` is the block
        // difficulty by definition.
        let credit_at = if neural {
            effective_header.difficulty.max(1)
        } else {
            effective_share_diff.clamp(1, effective_header.difficulty)
        };
        if !neural && submission.chain_length != job.chain_length as u64 {
            return SubmitResult {
                accepted: false,
                error: format!(
                    "submission claims chain length {} but the job requires {}",
                    submission.chain_length, job.chain_length
                ),
                block_found: false,
                block_hash: Vec::new(),
            };
        }
        let verdict = if neural {
            crate::share::verify_neural_share(
                &effective_header,
                &job.header.prev_hash,
                miner_pk,
                &submission.witnesses,
            )
        } else {
            verify_share(
                &effective_header,
                job.chain_length,
                &job.parent_work_commitment,
                &submission.witnesses,
                effective_header.difficulty,
                credit_at,
            )
        };

        match verdict {
            ShareVerdict::BlockFound { commitment } => {
                if submission.work_commitment.as_slice() != commitment.as_bytes() {
                    return SubmitResult {
                        accepted: false,
                        error: "submitted scientific-work commitment does not match recomputation"
                            .into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }
                let authorization: BlockAuthorization =
                    match crate::wire_config(256).deserialize(&submission.block_authorization) {
                        Ok(authorization) => authorization,
                        Err(error) => {
                            return SubmitResult {
                                accepted: false,
                                error: format!("missing or malformed block authorization: {error}"),
                                block_found: false,
                                block_hash: Vec::new(),
                            };
                        }
                    };
                let expected_view = self
                    .accounting
                    .get_view_public(&reward_recipient)
                    .unwrap_or([0u8; 32]);
                if authorization.reward_view_public != expected_view
                    || authorization.reward_spend_public != reward_recipient
                {
                    return SubmitResult {
                        accepted: false,
                        error: "miner authorization reward keys do not match the advertised job"
                            .into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }

                let mut authorized_header = effective_header.clone();
                crate::primitives::bind_reward(
                    &self.cfg,
                    &mut authorized_header,
                    &expected_view,
                    &reward_recipient,
                );
                authorized_header.pow_commitment = commitment;
                if let Err(error) = authorization.verify(
                    &authorized_header,
                    self.cfg.network_magic,
                    self.cfg.consensus_params_hash(),
                    ChainIdentity::of(&self.cfg).genesis_hash,
                ) {
                    return SubmitResult {
                        accepted: false,
                        error: error.to_string(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }

                let Some(_lease) = self.job_manager.try_begin_block_submission(job.job_id) else {
                    return SubmitResult {
                        accepted: false,
                        error: "stale job".into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                };
                let _submission = self.candidate_submission.lock().await;
                if let Err(error) = self.recover_pending_block().await {
                    return SubmitResult {
                        error,
                        ..Default::default()
                    };
                }
                let credited = if neural {
                    effective_header.difficulty
                } else {
                    match self.credit_witnesses(
                        miner_pk,
                        wallet_address,
                        &submission.witnesses,
                        &effective_header,
                    ) {
                        Ok(fresh) => fresh,
                        Err(rejection) => {
                            return rejection;
                        }
                    }
                };

                let wallet_hex = {
                    let miners = self.miners.read();
                    miners
                        .get(miner_pk)
                        .map(|s| hex_encode(s.wallet_address))
                        .unwrap_or_default()
                };
                info!(
                    "BLOCK FOUND by {} (wallet={}) at height {} work_commitment={}",
                    hex_encode(miner_pk),
                    wallet_hex,
                    effective_header.height,
                    commitment
                );

                // The miner signed this exact header, so it is the block header.
                let mined_header = authorized_header;

                let block = Block {
                    header: mined_header,
                    pow_witnesses: submission.witnesses.clone(),
                    transactions: job.transactions.clone(),
                    uncle_headers: Vec::new(),
                    block_authorization: submission.block_authorization.clone(),
                };

                let block_hash = block.hash();
                info!("Submitting block {} to the node", block_hash);

                let candidate = PendingBlock {
                    block,
                    wallet: wallet_address,
                };
                let bytes =
                    match crate::wire_config(self.cfg.max_block_size).serialize(&candidate.block) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            return SubmitResult {
                                accepted: !neural && credited > 0,
                                error: error.to_string(),
                                ..Default::default()
                            };
                        }
                    };
                let result = match self.accounting.stage_block(&candidate) {
                    Ok(()) => self.submit_pending_block(&candidate, bytes).await,
                    Err(error) => Err(error.to_string()),
                };
                let error = match result {
                    Ok(reply) if !reply.accepted => Some(reply.error),
                    Ok(_) => None,
                    Err(error) => Some(error),
                };
                if let Some(error) = error {
                    warn!("Block {block_hash} submission: {error}");
                    return SubmitResult {
                        accepted: !neural && credited > 0,
                        error,
                        ..Default::default()
                    };
                }
                self.block_refresh.notify_one();

                {
                    let mut miners = self.miners.write();
                    if let Some(session) = miners.get_mut(miner_pk) {
                        session.shares += 1;
                    }
                }

                let notify = BlockFoundNotify {
                    height: effective_header.height,
                    block_hash: block_hash.as_bytes().to_vec(),
                    finder_pubkey: miner_pk.to_vec(),
                };
                let _ = self.job_tx.send(PoolBroadcast::BlockFound(notify));

                SubmitResult {
                    accepted: true,
                    error: String::new(),
                    block_found: true,
                    block_hash: block_hash.as_bytes().to_vec(),
                }
            }

            ShareVerdict::Credit => {
                if submission.work_commitment.as_slice()
                    != hyphen_pow::vms::witness_commitment(
                        &job.parent_work_commitment,
                        effective_header.height,
                        &submission.witnesses,
                    )
                    .as_bytes()
                    || !submission.block_authorization.is_empty()
                {
                    return SubmitResult {
                        accepted: false,
                        error: "witness commitment mismatch".into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }
                let credited = match self.credit_witnesses(
                    miner_pk,
                    wallet_address,
                    &submission.witnesses,
                    &effective_header,
                ) {
                    Ok(fresh) => fresh,
                    Err(rejection) => return rejection,
                };
                if credited == 0 {
                    return SubmitResult {
                        accepted: false,
                        error: "submission repeats witnesses this pool already credited".into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }
                {
                    let mut miners = self.miners.write();
                    if let Some(session) = miners.get_mut(miner_pk) {
                        session.shares += 1;
                    }
                }
                SubmitResult {
                    accepted: true,
                    error: String::new(),
                    block_found: false,
                    block_hash: Vec::new(),
                }
            }

            ShareVerdict::Invalid(reason) => {
                self.accounting.record_invalid_share(*miner_pk);
                {
                    let mut miners = self.miners.write();
                    if let Some(session) = miners.get_mut(miner_pk) {
                        session.invalid_shares += 1;
                    }
                }
                SubmitResult {
                    accepted: false,
                    error: reason,
                    block_found: false,
                    block_hash: Vec::new(),
                }
            }
        }
    }

    /// Called before listening and under the submission mutex while serving miners.
    async fn recover_pending_block(&self) -> Result<(), String> {
        if let Some(candidate) = self.accounting.pending_block().map_err(|e| e.to_string())? {
            info!("Recovering pending block {}", candidate.block.hash());
            let bytes = crate::wire_config(self.cfg.max_block_size)
                .serialize(&candidate.block)
                .map_err(|e| e.to_string())?;
            self.submit_pending_block(&candidate, bytes).await?;
        }
        Ok(())
    }

    async fn submit_pending_block(
        &self,
        candidate: &PendingBlock,
        bytes: Vec<u8>,
    ) -> Result<crate::tp::SubmitBlockResult, String> {
        let hash = candidate.block.hash();
        let header = &candidate.block.header;
        self.telemetry.record_block_submitted();
        let reply = self
            .tp_client
            .submit_block(bytes)
            .await
            .map_err(|e| e.to_string())?;
        if reply.block_hash.as_slice() != hash.as_bytes() {
            return Err("node acknowledged a different block hash".into());
        }
        if reply.accepted {
            self.accounting
                .settle_accepted_block(candidate)
                .map_err(|e| e.to_string())?;
        } else {
            self.accounting
                .discard_block(&hash.to_string())
                .map_err(|e| e.to_string())?;
        }
        self.telemetry.record_block_settled(
            header.height,
            hash.to_string(),
            reply.accepted,
            &reply.error,
        );
        Ok(reply)
    }

    fn credit_witnesses(
        &self,
        miner: &[u8; 32],
        wallet: [u8; 32],
        witnesses: &[u64],
        header: &crate::primitives::BlockHeader,
    ) -> Result<u64, SubmitResult> {
        let (fresh, count) = self
            .accounting
            .credit_witnesses(*miner, wallet, witnesses, header.difficulty, header.reward)
            .map_err(|error| SubmitResult {
                error: error.to_string(),
                ..Default::default()
            })?;
        self.telemetry.set_claimed_witnesses(count);
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn lost_node_acknowledgement_is_recovered_after_reopening_the_pool() {
        use crate::accounting::{PoolAccountingConfig, PoolMode};
        use crate::template::TemplateProviderClient;
        use crate::tp::{
            SignedEnvelope, SubmitBlockRequest, SubmitBlockResult, TP_SUBMIT_RESULT, read_envelope,
            write_envelope,
        };

        let cfg = ChainConfig::neural_devnet();
        let wallet = [7; 32];
        let mut block = crate::primitives::build_genesis_block(&cfg);
        block.header.height = 1;
        block.header.reward = 123;
        block.header.miner_pubkey = [9; 32];
        let hash = block.hash();
        let expected_bytes = crate::wire_config(cfg.max_block_size)
            .serialize(&block)
            .unwrap();
        let candidate = PendingBlock { wallet, block };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let peer = tokio::spawn(async move {
            // First connection and its transport retry lose the reply. The restarted
            // pool contacts the peer a third time with exactly the same signed block.
            for attempt in 0..3 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_envelope(&mut stream).await.unwrap();
                assert_eq!(request.msg_type, crate::tp::TP_SUBMIT_BLOCK);
                assert_eq!(
                    SubmitBlockRequest::decode(request.payload.as_slice())
                        .unwrap()
                        .block_data,
                    expected_bytes
                );
                if attempt == 2 {
                    let reply = SubmitBlockResult {
                        accepted: true,
                        block_hash: hash.as_bytes().to_vec(),
                        error: String::new(),
                    };
                    let env = SignedEnvelope::sign(
                        TP_SUBMIT_RESULT,
                        reply.encode_to_vec(),
                        &SecretKey([8; 32]),
                    );
                    write_envelope(&mut stream, &env).await.unwrap();
                }
            }
        });
        let dir =
            std::env::temp_dir().join(format!("hyphen-pending-block-{}", crate::random_u64()));
        let config = PoolAccountingConfig {
            mode: PoolMode::Solo,
            pool_fee_bps: 0,
            pool_wallet: wallet,
            pool_view_public: [0; 32],
            network_magic: cfg.network_magic,
            pplns_window_factor: 2,
            state_dir: Some(dir.clone()),
        };
        for restarted in [false, true] {
            let ledger = Arc::new(PoolAccounting::try_new(config.clone()).unwrap());
            let sk = SecretKey([3; 32]);
            let client = TemplateProviderClient::connect(&addr, &sk, &cfg)
                .await
                .unwrap();
            let pool = PoolServer::new(
                Arc::new(JobManager::new(1)),
                Arc::new(client),
                Arc::clone(&ledger),
                sk,
                "test".into(),
                cfg.clone(),
                "127.0.0.1:0".parse().unwrap(),
            );
            if !restarted {
                ledger.stage_block(&candidate).unwrap();
                assert!(pool.recover_pending_block().await.is_err());
                assert_eq!(ledger.wallet_summary(wallet, 2).valid_shares, 0);
                assert!(ledger.pending_block().unwrap().is_some());
            } else {
                pool.recover_pending_block().await.unwrap();
                pool.recover_pending_block().await.unwrap();
                assert!(ledger.pending_block().unwrap().is_none());
            }
        }
        peer.await.unwrap();
        let summary = PoolAccounting::try_new(config)
            .unwrap()
            .wallet_summary(wallet, 2);
        assert_eq!(
            (
                summary.valid_shares,
                summary.total_blocks_found,
                summary.direct_reward_atomic
            ),
            (1, 1, 123)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn vardiff_warmup_never_exceeds_consensus_iterations() {
        assert_eq!(
            VarDiffState::warmup_difficulty(GTM_WARMUP_SHARES - 1, u64::MAX),
            VARDIFF_MAX
        );
        assert_eq!(
            VarDiffState::warmup_difficulty(GTM_WARMUP_SHARES, u64::MAX),
            VARDIFF_MAX
        );
    }
}
