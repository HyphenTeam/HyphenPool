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

use crate::accounting::PoolAccounting;
use crate::pow::EpochArena;
use crate::primitives::{Block, ChainConfig, Hash256, SecretKey};
use crate::tp::{BlockTemplate, TemplateProvider, TP_TEMPLATE};

use crate::job::{ActiveJob, JobManager};
use crate::protocol::*;
use crate::share::{verify_share, ShareVerdict};

/// Target seconds between shares per miner
const VARDIFF_TARGET_SECS: f64 = 15.0;
/// Minimum share difficulty
const VARDIFF_MIN: u64 = 10;
/// Maximum share difficulty (2^48, higher than any testnet block difficulty)
const VARDIFF_MAX: u64 = 1 << 48;
/// Number of shares to look back for rate calculation
const VARDIFF_WINDOW: usize = 24;
/// Retarget check interval (after this many shares)
const VARDIFF_RETARGET_SHARES: usize = 6;
/// Initial low difficulty for new miners (ramps up quickly)
const VARDIFF_INITIAL: u64 = 100;

/// ── GTM: Graduated Trust Mining ──
/// Number of shares during warmup phase — difficulty ramps exponentially
/// from VARDIFF_INITIAL toward the estimated target.
const GTM_WARMUP_SHARES: u64 = 100;
/// Maximum connections from a single IP address
const GTM_MAX_CONNECTIONS_PER_IP: usize = 32;

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
}

struct VarDiffState {
    current_difficulty: u64,
    share_timestamps: VecDeque<u64>,
}

impl VarDiffState {
    fn new(initial_difficulty: u64) -> Self {
        Self {
            current_difficulty: initial_difficulty,
            share_timestamps: VecDeque::with_capacity(VARDIFF_WINDOW + 1),
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
            return target_diff;
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
        // During warmup, always return the exponentially ramped difficulty
        if total_lifetime_shares < GTM_WARMUP_SHARES {
            let warmup_diff = Self::warmup_difficulty(total_lifetime_shares, estimated_target);
            if warmup_diff != self.current_difficulty {
                self.current_difficulty = warmup_diff;
                return Some(warmup_diff);
            }
            return None;
        }

        // Post-warmup: standard VarDiff behaviour
        self.record_share()
    }

    /// Record a share and return Some(new_diff) if adjustment is needed.
    fn record_share(&mut self) -> Option<u64> {
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
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

        let oldest = *self.share_timestamps.front()?;
        let newest = *self.share_timestamps.back()?;
        let elapsed_secs = (newest.saturating_sub(oldest)) as f64 / 1000.0;
        if elapsed_secs < 1.0 {
            // Too fast – double difficulty
            let new_diff = (self.current_difficulty * 2).clamp(VARDIFF_MIN, VARDIFF_MAX);
            if new_diff != self.current_difficulty {
                self.current_difficulty = new_diff;
                return Some(new_diff);
            }
            return None;
        }

        let actual_rate = elapsed_secs / (total_shares.saturating_sub(1)) as f64;
        let ratio = actual_rate / VARDIFF_TARGET_SECS;

        // Clamp ratio to avoid wild swings (max 4x change per retarget)
        let clamped = ratio.clamp(0.25, 4.0);

        let new_diff =
            ((self.current_difficulty as f64 / clamped) as u64).clamp(VARDIFF_MIN, VARDIFF_MAX);

        // Only notify if change is significant (> 10%)
        let change_pct = (new_diff as f64 - self.current_difficulty as f64).abs()
            / self.current_difficulty as f64;
        if change_pct > 0.10 {
            self.current_difficulty = new_diff;
            Some(new_diff)
        } else {
            None
        }
    }
}

type ArenaCache = Option<(Hash256, Arc<EpochArena>)>;

#[derive(Clone, Debug)]
enum PoolBroadcast {
    NewTemplate,
    BlockFound(BlockFoundNotify),
}

pub struct PoolServer<T: TemplateProvider + Send + Sync + 'static> {
    job_manager: Arc<JobManager>,
    tp_client: Arc<T>,
    accounting: Arc<PoolAccounting>,
    pool_key: SecretKey,
    pool_id: String,
    cfg: ChainConfig,
    bind_addr: SocketAddr,
    job_tx: broadcast::Sender<PoolBroadcast>,
    miners: Arc<RwLock<HashMap<[u8; 32], MinerSession>>>,
    arena: Arc<RwLock<ArenaCache>>,
    /// GTM: per-IP connection counts for rate limiting
    ip_connections: Arc<RwLock<HashMap<std::net::IpAddr, usize>>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ArenaParamsData {
    pub arena_size: u64,
    pub page_size: u64,
}

impl<T: TemplateProvider + Send + Sync + 'static> PoolServer<T> {
    fn recommended_share_difficulty(hashrate: u64, thread_count: u32) -> u64 {
        if hashrate > 0 {
            (hashrate as f64 * VARDIFF_TARGET_SECS)
                .round()
                .max(VARDIFF_MIN as f64)
                .min(VARDIFF_MAX as f64) as u64
        } else if thread_count > 0 {
            let rough_hps = thread_count as u64 * 10;
            (rough_hps * VARDIFF_TARGET_SECS as u64).clamp(VARDIFF_MIN, VARDIFF_MAX)
        } else {
            VARDIFF_INITIAL
        }
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
            pool_key,
            pool_id,
            cfg,
            bind_addr,
            job_tx,
            miners: Arc::new(RwLock::new(HashMap::new())),
            arena: Arc::new(RwLock::new(None)),
            ip_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn get_arena(&self, epoch_seed: Hash256) -> Arc<EpochArena> {
        {
            let guard = self.arena.read();
            if let Some((seed, ref a)) = *guard {
                if seed == epoch_seed {
                    return Arc::clone(a);
                }
            }
        }
        let new_arena = Arc::new(EpochArena::generate(
            epoch_seed,
            self.cfg.arena_size,
            self.cfg.page_size,
        ));
        *self.arena.write() = Some((epoch_seed, Arc::clone(&new_arena)));
        new_arena
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

    fn build_job_template_for_miner(
        &self,
        job: &ActiveJob,
        clean_jobs: bool,
        wallet_address: [u8; 32],
        share_difficulty: u64,
    ) -> JobTemplate {
        let mut header = job.header.clone();
        header.miner_pubkey = self.accounting.reward_recipient_for_wallet(wallet_address);
        let header_data = bincode::serialize(&header).expect("header serialisation");
        let arena_params = bincode::serialize(&ArenaParamsData {
            arena_size: job.arena_size as u64,
            page_size: job.page_size as u64,
        })
        .expect("arena params serialisation");

        JobTemplate {
            job_id: job.job_id.to_vec(),
            header_data,
            height: header.height,
            block_difficulty: header.difficulty,
            share_difficulty,
            epoch_seed: job.epoch_seed.as_bytes().to_vec(),
            prev_hash: header.prev_hash.as_bytes().to_vec(),
            arena_params,
            clean_jobs,
        }
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
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!("Pool server listening on {}", self.bind_addr);

        let server = Arc::clone(&self);
        tokio::spawn(async move {
            server.template_refresh_loop().await;
        });

        loop {
            let (stream, addr) = listener.accept().await?;

            // ── GTM: per-IP connection limiting ──
            {
                let mut ip_map = self.ip_connections.write();
                let count = ip_map.entry(addr.ip()).or_insert(0);
                if *count >= GTM_MAX_CONNECTIONS_PER_IP {
                    warn!(
                        "GTM: rejecting connection from {addr}: {} connections already active from this IP",
                        *count
                    );
                    drop(stream);
                    continue;
                }
                *count += 1;
            }

            info!("Miner connected from {addr}");
            let server = Arc::clone(&self);
            let ip_connections = Arc::clone(&self.ip_connections);
            let peer_ip = addr.ip();
            tokio::spawn(async move {
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
                // GTM: decrement IP connection count on disconnect
                {
                    let mut ip_map = ip_connections.write();
                    if let Some(count) = ip_map.get_mut(&peer_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            ip_map.remove(&peer_ip);
                        }
                    }
                }
            });
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
                    match self.tp_client.get_template().await {
                        Ok(tpl) => self.apply_template(&tpl),
                        Err(e) => warn!("TP poll failed: {e}"),
                    }
                }
                result = self.tp_client.read_next() => {
                    match result {
                        Ok(env) if env.msg_type == TP_TEMPLATE => {
                            if let Ok(tpl) = BlockTemplate::decode(&env.payload[..]) {
                                info!("Received pushed template update: height={}", tpl.height);
                                self.apply_template(&tpl);
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

    fn apply_template(&self, tpl: &BlockTemplate) {
        match self.job_manager.ingest_template(tpl) {
            Ok(_job) => {
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
        } else if login.payout_pubkey.len() == 32 {
            wallet_addr.copy_from_slice(&login.payout_pubkey);
        }

        info!(
            "Miner authenticated: id={}, addr={}, pk={}, wallet={}, threads={}",
            login.miner_id,
            addr,
            hex::encode(miner_pk),
            hex::encode(wallet_addr),
            login.thread_count,
        );

        let initial_diff =
            Self::recommended_share_difficulty(login.estimated_hashrate, login.thread_count);

        // GTM: new miners start at VARDIFF_INITIAL regardless of reported hashrate;
        // the estimated target is stored so the warmup ramp has something to aim for.
        let gtm_initial = VARDIFF_INITIAL;

        {
            let mut miners = self.miners.write();
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
                },
            );
        }
        self.accounting.register_view_key(wallet_addr, view_public);
        self.accounting.register_miner(miner_pk, wallet_addr);

        let current_job = self.job_manager.current_job();
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
        };
        let ack_env = PoolEnvelope::sign(MSG_LOGIN_ACK, ack.encode_to_vec(), &self.pool_key);
        PoolCodec::write_envelope(&mut stream, &ack_env).await?;

        if let Some(job) = current_job {
            let template = self.build_job_template_for_miner(&job, true, wallet_addr, gtm_initial);
            let job_env = PoolEnvelope::sign(MSG_JOB, template.encode_to_vec(), &self.pool_key);
            PoolCodec::write_envelope(&mut stream, &job_env).await?;
        }

        let mut job_rx = self.job_tx.subscribe();

        loop {
            tokio::select! {
                result = PoolCodec::read_envelope(&mut stream) => {
                    let env = result?;
                    env.verify()?;

                    if env.sender_pubkey.len() != 32 || env.sender_pubkey[..] != miner_pk[..] {
                        return Err(PoolError::Internal("pubkey mismatch".into()));
                    }

                    match env.msg_type {
                        MSG_SUBMIT => {
                            let reply = self.handle_share(&env, &miner_pk).await;
                            let reply_env = PoolEnvelope::sign(
                                MSG_SUBMIT_RESULT,
                                reply.encode_to_vec(),
                                &self.pool_key,
                            );
                            PoolCodec::write_envelope(&mut stream, &reply_env).await?;

                            if reply.accepted {
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
                                        hex::encode(miner_pk),
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
                                        &mut stream,
                                        &diff_env,
                                    )
                                    .await?;

                                    if let Some(job) = self.job_manager.current_job() {
                                        let wallet = self.session_wallet(&miner_pk);
                                        let template = self.build_job_template_for_miner(
                                            &job,
                                            true,
                                            wallet,
                                            diff,
                                        );
                                        let job_env = PoolEnvelope::sign(
                                            MSG_JOB,
                                            template.encode_to_vec(),
                                            &self.pool_key,
                                        );
                                        PoolCodec::write_envelope(&mut stream, &job_env).await?;
                                    }
                                }
                            }
                        }
                        MSG_KEEPALIVE => {}
                        MSG_HASHRATE_REPORT => {
                            if let Ok(report) = HashrateReport::decode(&env.payload[..]) {
                                info!(
                                    "Hashrate report from {}: {} H/s, total={}, uptime={}s",
                                    hex::encode(miner_pk),
                                    report.hashrate,
                                    report.total_hashes,
                                    report.uptime_secs,
                                );

                                let new_diff = {
                                    let mut miners = self.miners.write();
                                    miners.get_mut(&miner_pk).and_then(|session| {
                                        let recommended = Self::recommended_share_difficulty(
                                            report.hashrate,
                                            session.thread_count,
                                        );
                                        let current = session.vardiff.current_difficulty.max(1);
                                        let change_pct = (recommended as f64 - current as f64).abs()
                                            / current as f64;
                                        if change_pct >= 0.15 {
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
                                            Some(recommended)
                                        } else {
                                            None
                                        }
                                    })
                                };

                                if let Some(diff) = new_diff {
                                    info!(
                                        "VarDiff report update: miner {} -> share_diff={} (hashrate={} H/s)",
                                        hex::encode(miner_pk),
                                        diff,
                                        report.hashrate,
                                    );
                                    let set_msg = SetDifficulty {
                                        share_difficulty: diff,
                                    };
                                    let diff_env = PoolEnvelope::sign(
                                        MSG_SET_DIFFICULTY,
                                        set_msg.encode_to_vec(),
                                        &self.pool_key,
                                    );
                                    PoolCodec::write_envelope(&mut stream, &diff_env).await?;

                                    if let Some(job) = self.job_manager.current_job() {
                                        let wallet = self.session_wallet(&miner_pk);
                                        let template = self.build_job_template_for_miner(
                                            &job,
                                            true,
                                            wallet,
                                            diff,
                                        );
                                        let job_env = PoolEnvelope::sign(
                                            MSG_JOB,
                                            template.encode_to_vec(),
                                            &self.pool_key,
                                        );
                                        PoolCodec::write_envelope(&mut stream, &job_env).await?;
                                    }
                                }
                            }
                        }
                        _ => {
                            warn!("Unexpected msg type {} from {addr}", env.msg_type);
                        }
                    }
                }

                frame = job_rx.recv() => {
                    match frame {
                        Ok(PoolBroadcast::NewTemplate) => {
                            if let Some(job) = self.job_manager.current_job() {
                                let wallet = self.session_wallet(&miner_pk);
                                let diff = self.session_share_difficulty(&miner_pk, job.share_difficulty);
                                let template = self.build_job_template_for_miner(
                                    &job,
                                    true,
                                    wallet,
                                    diff,
                                );
                                let env = PoolEnvelope::sign(MSG_JOB, template.encode_to_vec(), &self.pool_key);
                                PoolCodec::write_envelope(&mut stream, &env).await?;
                            }
                        }
                        Ok(PoolBroadcast::BlockFound(notify)) => {
                            let notify_env = PoolEnvelope::sign(
                                MSG_BLOCK_FOUND,
                                notify.encode_to_vec(),
                                &self.pool_key,
                            );
                            PoolCodec::write_envelope(&mut stream, &notify_env).await?;
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Miner {addr} lagged {n} broadcasts");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }

        {
            let mut miners = self.miners.write();
            if let Some(session) = miners.remove(&miner_pk) {
                self.accounting.note_disconnect(miner_pk);
                info!(
                    "Miner disconnected: pk={}, wallet={}, shares={}, invalid={}",
                    hex::encode(miner_pk),
                    hex::encode(session.wallet_address),
                    session.shares,
                    session.invalid_shares
                );
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

        let job = match self.job_manager.get_job(&job_id) {
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

        if let Some(current_job) = self.job_manager.current_job() {
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

        let mut extra_nonce = [0u8; 32];
        if submission.extra_nonce.len() == 32 {
            extra_nonce.copy_from_slice(&submission.extra_nonce);
        }

        let arena = self.get_arena(job.epoch_seed);
        let wallet_address = self.session_wallet(miner_pk);
        let reward_recipient = self.accounting.reward_recipient_for_wallet(wallet_address);
        let mut effective_header = job.header.clone();
        effective_header.miner_pubkey = reward_recipient;

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

        let verdict = verify_share(
            &effective_header,
            submission.nonce,
            &extra_nonce,
            &arena,
            &self.cfg,
            effective_share_diff,
        );

        match verdict {
            ShareVerdict::BlockFound { hash } => {
                if !self.job_manager.try_begin_block_submission(job.job_id) {
                    return SubmitResult {
                        accepted: false,
                        error: "stale job".into(),
                        block_found: false,
                        block_hash: Vec::new(),
                    };
                }

                let wallet_hex = {
                    let miners = self.miners.read();
                    miners
                        .get(miner_pk)
                        .map(|s| hex::encode(s.wallet_address))
                        .unwrap_or_default()
                };
                info!(
                    "BLOCK FOUND by {} (wallet={}) at height {} hash={}",
                    hex::encode(miner_pk),
                    wallet_hex,
                    effective_header.height,
                    hash
                );

                self.accounting.record_valid_share(
                    *miner_pk,
                    wallet_address,
                    effective_share_diff,
                    effective_header.difficulty,
                    effective_header.reward,
                    effective_header.total_fee,
                );

                let mut mined_header = effective_header.clone();
                mined_header.nonce = submission.nonce;
                mined_header.extra_nonce = extra_nonce;
                let block_height = mined_header.height;
                let block_reward = mined_header.reward;
                let block_total_fee = mined_header.total_fee;
                let block_difficulty = mined_header.difficulty;

                // Look up view_public for the reward recipient to enable coinbase creation
                let view_pub = self.accounting.get_view_public(&reward_recipient)
                    .unwrap_or([0u8; 32]);

                let block = Block {
                    header: mined_header,
                    transactions: job.transactions.clone(),
                    uncle_headers: Vec::new(),
                    pq_signature: view_pub.to_vec(),
                };

                let block_hash = block.hash();

                let block_data = bincode::serialize(&block).unwrap_or_default();
                let tp = Arc::clone(&self.tp_client);
                let self_ref = Arc::clone(self);
                let job_id = job.job_id;
                let submit_hash = block_hash;
                let finder_pubkey = *miner_pk;
                let payout_wallet = wallet_address;
                tokio::spawn(async move {
                    match tp.submit_block(block_data).await {
                        Ok(result) => {
                            if result.accepted {
                                info!("Block {} accepted by node", submit_hash);
                                self_ref.accounting.settle_block(
                                    finder_pubkey,
                                    payout_wallet,
                                    block_height,
                                    submit_hash.to_string(),
                                    block_reward,
                                    block_total_fee,
                                    block_difficulty,
                                );
                                match tp.get_template().await {
                                    Ok(tpl) => {
                                        info!(
                                            "Refreshed template after block accept: height={}",
                                            tpl.height
                                        );
                                        self_ref.apply_template(&tpl);
                                    }
                                    Err(e) => {
                                        warn!("Failed to refresh template after block: {e}");
                                        self_ref.job_manager.finish_block_submission(job_id, true);
                                    }
                                }
                            } else {
                                warn!("Block rejected by node: {}", result.error);
                                self_ref.job_manager.finish_block_submission(job_id, false);
                            }
                        }
                        Err(e) => {
                            self_ref.job_manager.finish_block_submission(job_id, false);
                            error!("Failed to submit block to node: {e}");
                        }
                    }
                });

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

            ShareVerdict::ValidShare => {
                self.accounting.record_valid_share(
                    *miner_pk,
                    wallet_address,
                    effective_share_diff,
                    effective_header.difficulty,
                    effective_header.reward,
                    effective_header.total_fee,
                );
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
}
