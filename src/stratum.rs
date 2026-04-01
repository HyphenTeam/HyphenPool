use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::accounting::PoolAccounting;
use crate::job::{ActiveJob, JobManager};
use crate::pow::EpochArena;
use crate::primitives::{Block, ChainConfig, Hash256};
use crate::share::{verify_share, ShareVerdict};
use crate::tp::TemplateProvider;

#[derive(Deserialize, Debug)]
struct JsonRpcRequest {
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    id: serde_json::Value,
    result: serde_json::Value,
    error: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcNotify {
    id: serde_json::Value,
    method: String,
    params: serde_json::Value,
}

struct StratumSession {
    worker: String,
    extranonce1: [u8; 4],
    wallet_address: [u8; 32],
    authorized: bool,
    shares: u64,
    invalid: u64,
}

pub struct StratumServer<T: TemplateProvider + Send + Sync + 'static> {
    job_manager: Arc<JobManager>,
    tp_client: Arc<T>,
    accounting: Arc<PoolAccounting>,
    cfg: ChainConfig,
    bind_addr: SocketAddr,
    job_tx: broadcast::Sender<()>,
    sessions: Arc<RwLock<HashMap<u64, StratumSession>>>,
    #[allow(clippy::type_complexity)]
    arena: Arc<RwLock<Option<(Hash256, Arc<EpochArena>)>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl<T: TemplateProvider + Send + Sync + 'static> StratumServer<T> {
    pub fn new(
        job_manager: Arc<JobManager>,
        tp_client: Arc<T>,
        accounting: Arc<PoolAccounting>,
        cfg: ChainConfig,
        bind_addr: SocketAddr,
    ) -> Self {
        let (job_tx, _) = broadcast::channel(256);
        Self {
            job_manager,
            tp_client,
            accounting,
            cfg,
            bind_addr,
            job_tx,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            arena: Arc::new(RwLock::new(None)),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn get_arena(&self, seed: Hash256) -> Arc<EpochArena> {
        {
            let g = self.arena.read();
            if let Some((s, ref a)) = *g {
                if s == seed {
                    return Arc::clone(a);
                }
            }
        }
        let a = Arc::new(EpochArena::generate(
            seed,
            self.cfg.arena_size,
            self.cfg.page_size,
        ));
        *self.arena.write() = Some((seed, Arc::clone(&a)));
        a
    }

    pub async fn run(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        info!("Stratum V1 server listening on {}", self.bind_addr);

        let srv = Arc::clone(&self);
        tokio::spawn(async move {
            srv.job_poll_loop().await;
        });

        loop {
            let (stream, addr) = listener.accept().await?;
            info!("Stratum client connected from {addr}");
            let srv = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = srv.handle(stream, addr).await {
                    if Self::is_expected_disconnect(e.as_ref()) {
                        info!("Stratum {addr} disconnected: {e}");
                    } else {
                        warn!("Stratum {addr} disconnected: {e}");
                    }
                }
            });
        }
    }

    fn is_expected_disconnect(error: &(dyn std::error::Error + Send + Sync + 'static)) -> bool {
        error
            .downcast_ref::<std::io::Error>()
            .map(|io_error| {
                matches!(
                    io_error.kind(),
                    ErrorKind::ConnectionReset
                        | ErrorKind::ConnectionAborted
                        | ErrorKind::BrokenPipe
                        | ErrorKind::UnexpectedEof
                )
            })
            .unwrap_or(false)
    }

    /// Poll the JobManager every 200ms; when a new job appears, broadcast it.
    async fn job_poll_loop(&self) {
        let mut last_id: Option<[u8; 32]> = None;
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(200));
        loop {
            interval.tick().await;
            if let Some(job) = self.job_manager.current_job() {
                let changed = match last_id {
                    Some(id) => id != job.job_id,
                    None => true,
                };
                if changed {
                    last_id = Some(job.job_id);
                    let _ = self.job_tx.send(());
                }
            }
        }
    }

    async fn handle(
        self: &Arc<Self>,
        stream: TcpStream,
        addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (rd, mut wr) = stream.into_split();
        let mut buf = BufReader::new(rd);

        let sid = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let en1 = (sid as u32).to_be_bytes();

        self.sessions.write().insert(
            sid,
            StratumSession {
                worker: String::new(),
                extranonce1: en1,
                wallet_address: [0u8; 32],
                authorized: false,
                shares: 0,
                invalid: 0,
            },
        );

        let mut job_rx = self.job_tx.subscribe();
        let mut line = String::new();

        let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = loop {
            line.clear();
            tokio::select! {
                n = buf.read_line(&mut line) => {
                    let n = n?;
                    if n == 0 { break Ok(()); }
                    let req: JsonRpcRequest = match serde_json::from_str(line.trim()) {
                        Ok(r) => r,
                        Err(e) => { warn!("Stratum {addr} bad json: {e}"); continue; }
                    };
                    if let Some(reply) = self.dispatch(&req, sid, &mut wr).await? {
                        let mut j = serde_json::to_string(&reply)?;
                        j.push('\n');
                        wr.write_all(j.as_bytes()).await?;
                    }
                }
                notif = job_rx.recv() => {
                    match notif {
                        Ok(()) => {
                            let wallet_address = self
                                .sessions
                                .read()
                                .get(&sid)
                                .map(|session| session.wallet_address)
                                .unwrap_or([0u8; 32]);
                            if wallet_address != [0u8; 32] {
                                if let Some(job) = self.job_manager.current_job() {
                                    let notify = self.build_notify_for_wallet(&job, true, wallet_address);
                                    let mut json = serde_json::to_string(&notify)?;
                                    json.push('\n');
                                    wr.write_all(json.as_bytes()).await?;
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!("Stratum {addr} lagged {n}");
                        }
                        Err(_) => break Ok(()),
                    }
                }
            }
        };

        if let Some(session) = self.sessions.write().remove(&sid) {
            if session.wallet_address != [0u8; 32] {
                self.accounting.note_disconnect(session.wallet_address);
            }
        }
        result
    }

    async fn dispatch(
        &self,
        req: &JsonRpcRequest,
        sid: u64,
        wr: &mut tokio::net::tcp::OwnedWriteHalf,
    ) -> Result<Option<JsonRpcResponse>, Box<dyn std::error::Error + Send + Sync>> {
        match req.method.as_str() {
            "mining.subscribe" => {
                let en1 = self
                    .sessions
                    .read()
                    .get(&sid)
                    .map(|s| hex::encode(s.extranonce1))
                    .unwrap_or_default();

                Ok(Some(JsonRpcResponse {
                    id: req.id.clone(),
                    result: serde_json::json!([
                        [["mining.notify", hex::encode(sid.to_be_bytes())]],
                        en1,
                        28
                    ]),
                    error: serde_json::Value::Null,
                }))
            }

            "mining.authorize" => {
                let worker = req
                    .params
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("anon")
                    .to_string();
                let wallet_spec = worker.split('.').next().unwrap_or("");
                let (view_public, wallet_address) = match PoolAccounting::parse_wallet_input(wallet_spec) {
                    Ok(keys) => keys,
                    Err(error) => {
                        return Ok(Some(JsonRpcResponse {
                            id: req.id.clone(),
                            result: serde_json::Value::Null,
                            error: serde_json::json!([24, error, null]),
                        }));
                    }
                };

                {
                    let mut s = self.sessions.write();
                    if let Some(ses) = s.get_mut(&sid) {
                        ses.worker = worker.clone();
                        ses.wallet_address = wallet_address;
                        ses.authorized = true;
                    }
                }
                self.accounting.register_view_key(wallet_address, view_public);
                self.accounting
                    .register_miner(wallet_address, wallet_address);
                info!("Stratum worker authorized: {worker}");

                let sd = JsonRpcNotify {
                    id: serde_json::Value::Null,
                    method: "mining.set_difficulty".into(),
                    params: serde_json::json!([self.job_manager.share_difficulty()]),
                };
                let mut j = serde_json::to_string(&sd)?;
                j.push('\n');
                wr.write_all(j.as_bytes()).await?;

                if let Some(job) = self.job_manager.current_job() {
                    let n = self.build_notify_for_wallet(&job, true, wallet_address);
                    let mut j = serde_json::to_string(&n)?;
                    j.push('\n');
                    wr.write_all(j.as_bytes()).await?;
                }

                Ok(Some(JsonRpcResponse {
                    id: req.id.clone(),
                    result: serde_json::json!(true),
                    error: serde_json::Value::Null,
                }))
            }

            "mining.submit" => Ok(Some(self.handle_submit(req, sid).await)),

            other => {
                warn!("Stratum unknown method: {other}");
                Ok(Some(JsonRpcResponse {
                    id: req.id.clone(),
                    result: serde_json::Value::Null,
                    error: serde_json::json!([20, "unknown method", null]),
                }))
            }
        }
    }

    async fn handle_submit(&self, req: &JsonRpcRequest, sid: u64) -> JsonRpcResponse {
        let fail = |code: u32, msg: &str| JsonRpcResponse {
            id: req.id.clone(),
            result: serde_json::Value::Null,
            error: serde_json::json!([code, msg, null]),
        };

        let arr = match req.params.as_array() {
            Some(a) if a.len() >= 4 => a,
            _ => return fail(20, "invalid params"),
        };

        let _worker = arr[0].as_str().unwrap_or("");
        let job_hex = arr[1].as_str().unwrap_or("");
        let nonce_hex = arr[2].as_str().unwrap_or("");
        let en2_hex = arr[3].as_str().unwrap_or("");

        let jb = match hex::decode(job_hex) {
            Ok(b) if b.len() == 32 => b,
            _ => return fail(21, "bad job_id"),
        };
        let mut job_id = [0u8; 32];
        job_id.copy_from_slice(&jb);

        let nonce = match hex::decode(nonce_hex) {
            Ok(b) if b.len() == 8 => u64::from_le_bytes(b.try_into().unwrap()),
            _ => return fail(20, "bad nonce"),
        };

        let en1 = self
            .sessions
            .read()
            .get(&sid)
            .map(|s| s.extranonce1)
            .unwrap_or([0; 4]);
        let wallet_address = self
            .sessions
            .read()
            .get(&sid)
            .map(|session| session.wallet_address)
            .unwrap_or([0u8; 32]);
        let en2 = hex::decode(en2_hex).unwrap_or_default();
        let mut extra_nonce = [0u8; 32];
        extra_nonce[..4].copy_from_slice(&en1);
        let n = en2.len().min(28);
        extra_nonce[4..4 + n].copy_from_slice(&en2[..n]);

        let job = match self.job_manager.get_job(&job_id) {
            Some(j) => j,
            None => return fail(21, "stale job"),
        };

        if let Some(current_job) = self.job_manager.current_job() {
            let chain_advanced = current_job.header.height != job.header.height
                || current_job.header.prev_hash != job.header.prev_hash;
            if chain_advanced && current_job.job_id != job.job_id {
                return fail(21, "stale job");
            }
        }

        if self.job_manager.is_blocked(&job_id) {
            return fail(21, "stale job");
        }

        let arena = self.get_arena(job.epoch_seed);
        let mut effective_header = job.header.clone();
        effective_header.miner_pubkey = self.accounting.reward_recipient_for_wallet(wallet_address);

        let verdict = verify_share(
            &effective_header,
            nonce,
            &extra_nonce,
            &arena,
            &self.cfg,
            job.share_difficulty,
        );

        match verdict {
            ShareVerdict::BlockFound { hash } => {
                if !self.job_manager.try_begin_block_submission(job.job_id) {
                    return fail(21, "stale job");
                }

                self.accounting.record_valid_share(
                    wallet_address,
                    wallet_address,
                    job.share_difficulty,
                    effective_header.difficulty,
                    effective_header.reward,
                    effective_header.total_fee,
                );

                info!(
                    "STRATUM BLOCK at height {} hash={}",
                    effective_header.height, hash
                );

                let mut h = effective_header.clone();
                h.nonce = nonce;
                h.extra_nonce = extra_nonce;
                let block_height = h.height;
                let block_reward = h.reward;
                let block_total_fee = h.total_fee;
                let block_difficulty = h.difficulty;

                let reward_recipient = h.miner_pubkey;
                let view_pub = self.accounting.get_view_public(&reward_recipient)
                    .unwrap_or([0u8; 32]);

                let block = Block {
                    header: h,
                    transactions: job.transactions.clone(),
                    uncle_headers: Vec::new(),
                    pq_signature: view_pub.to_vec(),
                };
                let data = bincode::serialize(&block).unwrap_or_default();
                let tp = Arc::clone(&self.tp_client);
                let job_manager = Arc::clone(&self.job_manager);
                let accounting = Arc::clone(&self.accounting);
                let job_id = job.job_id;
                let block_hash_hex = hash.to_string();
                tokio::spawn(async move {
                    match tp.submit_block(data).await {
                        Ok(r) if r.accepted => {
                            accounting.settle_block(
                                wallet_address,
                                wallet_address,
                                block_height,
                                block_hash_hex,
                                block_reward,
                                block_total_fee,
                                block_difficulty,
                            );
                            info!("Stratum block accepted");
                        }
                        Ok(r) => {
                            job_manager.finish_block_submission(job_id, false);
                            warn!("Stratum block rejected: {}", r.error);
                        }
                        Err(e) => {
                            job_manager.finish_block_submission(job_id, false);
                            error!("Stratum block submit failed: {e}");
                        }
                    }
                });

                if let Some(s) = self.sessions.write().get_mut(&sid) {
                    s.shares += 1;
                }

                JsonRpcResponse {
                    id: req.id.clone(),
                    result: serde_json::json!(true),
                    error: serde_json::Value::Null,
                }
            }

            ShareVerdict::ValidShare => {
                self.accounting.record_valid_share(
                    wallet_address,
                    wallet_address,
                    job.share_difficulty,
                    effective_header.difficulty,
                    effective_header.reward,
                    effective_header.total_fee,
                );
                if let Some(s) = self.sessions.write().get_mut(&sid) {
                    s.shares += 1;
                }

                JsonRpcResponse {
                    id: req.id.clone(),
                    result: serde_json::json!(true),
                    error: serde_json::Value::Null,
                }
            }

            ShareVerdict::Invalid(reason) => {
                self.accounting.record_invalid_share(wallet_address);
                if let Some(s) = self.sessions.write().get_mut(&sid) {
                    s.invalid += 1;
                }

                fail(23, &reason)
            }
        }
    }

    fn build_notify_for_wallet(
        &self,
        job: &ActiveJob,
        clean: bool,
        wallet_address: [u8; 32],
    ) -> JsonRpcNotify {
        let mut header = job.header.clone();
        header.miner_pubkey = self.accounting.reward_recipient_for_wallet(wallet_address);
        let header_data = bincode::serialize(&header).unwrap_or_default();
        let arena_params = bincode::serialize(&crate::server::ArenaParamsData {
            arena_size: job.arena_size as u64,
            page_size: job.page_size as u64,
        })
        .unwrap_or_default();

        JsonRpcNotify {
            id: serde_json::Value::Null,
            method: "mining.notify".into(),
            params: serde_json::json!([
                hex::encode(job.job_id),
                hex::encode(&header_data),
                header.height,
                header.difficulty,
                job.share_difficulty,
                hex::encode(job.epoch_seed.as_bytes()),
                hex::encode(header.prev_hash.as_bytes()),
                hex::encode(&arena_params),
                clean,
            ]),
        }
    }
}
