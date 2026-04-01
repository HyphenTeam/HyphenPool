use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use tracing::info;

use crate::primitives::{blake3_hash_many, BlockHeader, Hash256};
use crate::tp::BlockTemplate;

#[derive(Clone)]
pub struct ActiveJob {
    pub job_id: [u8; 32],
    pub header: BlockHeader,
    pub transactions: Vec<Vec<u8>>,
    pub epoch_seed: Hash256,
    pub share_difficulty: u64,
    pub created_at: u64,
    pub arena_size: usize,
    pub page_size: usize,
    pub clean_jobs: bool,
}

pub struct JobManager {
    share_difficulty: u64,
    current_job: RwLock<Option<ActiveJob>>,
    jobs: RwLock<HashMap<[u8; 32], ActiveJob>>,
    blocked_jobs: RwLock<HashSet<[u8; 32]>>,
}

impl JobManager {
    pub fn new(share_difficulty: u64) -> Self {
        Self {
            share_difficulty,
            current_job: RwLock::new(None),
            jobs: RwLock::new(HashMap::new()),
            blocked_jobs: RwLock::new(HashSet::new()),
        }
    }

    /// Backwards-compatible constructor retained for existing call sites.
    pub fn with_pool_pubkey(share_difficulty: u64, _pool_pubkey: [u8; 32]) -> Self {
        Self::new(share_difficulty)
    }

    pub fn ingest_template(&self, tpl: &BlockTemplate) -> Result<ActiveJob, String> {
        let header: BlockHeader = bincode::deserialize(&tpl.header_data)
            .map_err(|e| format!("header deserialise: {e}"))?;

        let mut template_id = [0u8; 32];
        if tpl.template_id.len() == 32 {
            template_id.copy_from_slice(&tpl.template_id);
        } else {
            let id = blake3_hash_many(&[
                &tpl.height.to_le_bytes(),
                &tpl.difficulty.to_le_bytes(),
                &tpl.prev_hash,
            ]);
            template_id = *id.as_bytes();
        }

        {
            let current = self.current_job.read();
            if let Some(ref current_job) = *current {
                if current_job.job_id == template_id {
                    return Ok(current_job.clone());
                }
            }
        }

        let epoch_seed = if tpl.epoch_seed.len() == 32 {
            Hash256::from_bytes(tpl.epoch_seed.clone().try_into().unwrap())
        } else {
            Hash256::ZERO
        };

        let job = ActiveJob {
            job_id: template_id,
            header,
            transactions: tpl.transactions.clone(),
            epoch_seed,
            share_difficulty: self.share_difficulty,
            created_at: chrono::Utc::now().timestamp() as u64,
            arena_size: tpl.arena_size as usize,
            page_size: tpl.page_size as usize,
            clean_jobs: tpl.clean,
        };

        {
            let mut jobs = self.jobs.write();
            let mut blocked = self.blocked_jobs.write();
            if tpl.clean {
                jobs.clear();
                blocked.clear();
            } else {
                jobs.retain(|_, existing| {
                    existing.header.height == job.header.height
                        && existing.header.prev_hash == job.header.prev_hash
                });
                blocked.retain(|job_id| jobs.contains_key(job_id));
            }
            jobs.insert(job.job_id, job.clone());
            if jobs.len() > 16 {
                let oldest_key = jobs
                    .iter()
                    .min_by_key(|(_, j)| j.created_at)
                    .map(|(k, _)| *k);
                if let Some(k) = oldest_key {
                    jobs.remove(&k);
                }
            }
        }

        *self.current_job.write() = Some(job.clone());

        info!(
            "New job from template: height={}, difficulty={}, txs={}",
            job.header.height,
            job.header.difficulty,
            job.transactions.len()
        );

        Ok(job)
    }

    pub fn get_job(&self, job_id: &[u8; 32]) -> Option<ActiveJob> {
        self.jobs.read().get(job_id).cloned()
    }

    pub fn current_job(&self) -> Option<ActiveJob> {
        self.current_job.read().clone()
    }

    pub fn try_begin_block_submission(&self, job_id: [u8; 32]) -> bool {
        let mut blocked = self.blocked_jobs.write();
        blocked.insert(job_id)
    }

    pub fn finish_block_submission(&self, job_id: [u8; 32], keep_blocked: bool) {
        if keep_blocked {
            return;
        }
        self.blocked_jobs.write().remove(&job_id);
    }

    pub fn is_blocked(&self, job_id: &[u8; 32]) -> bool {
        self.blocked_jobs.read().contains(job_id)
    }

    pub fn share_difficulty(&self) -> u64 {
        self.share_difficulty
    }

    pub fn set_share_difficulty(&mut self, d: u64) {
        self.share_difficulty = d;
    }
}
