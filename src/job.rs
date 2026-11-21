use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::info;

use crate::primitives::{BlockHeader, Hash256};
use crate::tp::BlockTemplate;

/// How long one candidate may hold the right to submit a block for a job.
///
/// A submission is a request to the node; if the pool stalls, crashes or loses
/// the node connection mid-flight, the claim must not outlive the attempt. Two
/// minutes is far longer than a submit takes and short enough that a wedged pool
/// recovers on its own.
const BLOCK_SUBMISSION_LEASE: Duration = Duration::from_secs(120);

#[derive(Clone)]
pub struct ActiveJob {
    pub job_id: [u8; 32],
    pub header: BlockHeader,
    pub transactions: Vec<Vec<u8>>,
    pub epoch_seed: Hash256,
    pub share_difficulty: u64,
    pub created_at: u64,
    /// Cunningham chain length every witness must satisfy.
    pub chain_length: u32,
    /// Parent work commitment the miner chains into `pow_commitment`.
    pub parent_work_commitment: Hash256,
    pub clean_jobs: bool,
}

pub struct JobManager {
    share_difficulty: u64,
    current_job: RwLock<Option<Arc<ActiveJob>>>,
    jobs: RwLock<HashMap<[u8; 32], Arc<ActiveJob>>>,
    blocked_jobs: RwLock<HashMap<[u8; 32], Arc<Instant>>>,
}

pub struct SubmissionLease {
    manager: Arc<JobManager>,
    job_id: [u8; 32],
    started: Arc<Instant>,
}

impl Drop for SubmissionLease {
    fn drop(&mut self) {
        let mut blocked = self.manager.blocked_jobs.write();
        if blocked
            .get(&self.job_id)
            .is_some_and(|owner| Arc::ptr_eq(owner, &self.started))
        {
            blocked.remove(&self.job_id);
        }
    }
}

impl JobManager {
    pub fn new(share_difficulty: u64) -> Self {
        Self {
            share_difficulty,
            current_job: RwLock::new(None),
            jobs: RwLock::new(HashMap::new()),
            blocked_jobs: RwLock::new(HashMap::new()),
        }
    }

    /// Backwards-compatible constructor retained for existing call sites.
    pub fn with_pool_pubkey(share_difficulty: u64, _pool_pubkey: [u8; 32]) -> Self {
        Self::new(share_difficulty)
    }

    pub fn ingest_template(&self, tpl: &BlockTemplate) -> Result<ActiveJob, String> {
        self.ingest_owned_template(tpl.clone())
            .map(Arc::unwrap_or_clone)
    }

    pub(crate) fn ingest_owned_template(
        &self,
        tpl: BlockTemplate,
    ) -> Result<Arc<ActiveJob>, String> {
        let header: BlockHeader = crate::wire_config(4096)
            .deserialize(&tpl.header_data)
            .map_err(|e| format!("header deserialise: {e}"))?;

        if tpl.template_id.len() != 32 {
            return Err("template id must be exactly 32 bytes".into());
        }
        if tpl.epoch_seed.len() != 32 {
            return Err("template epoch seed must be exactly 32 bytes".into());
        }
        let mut template_id = [0u8; 32];
        template_id.copy_from_slice(&tpl.template_id);

        {
            let current = self.current_job.read();
            if let Some(ref current_job) = *current
                && current_job.job_id == template_id
            {
                return Ok(current_job.clone());
            }
        }

        let epoch_seed = Hash256::from_bytes(
            tpl.epoch_seed
                .as_slice()
                .try_into()
                .map_err(|_| "template epoch seed must be exactly 32 bytes")?,
        );

        let job = Arc::new(ActiveJob {
            job_id: template_id,
            header,
            transactions: tpl.transactions,
            epoch_seed,
            share_difficulty: self.share_difficulty,
            created_at: hyphen_core::timestamp::ntp_adjusted_timestamp_secs(),
            chain_length: match u32::try_from(tpl.pouw_chain_length) {
                Ok(length) => length,
                Err(_) => return Err("template chain length exceeds u32".into()),
            },
            parent_work_commitment: Hash256::from_bytes(
                tpl.parent_work_commitment
                    .as_slice()
                    .try_into()
                    .map_err(|_| "template parent work commitment must be exactly 32 bytes")?,
            ),
            clean_jobs: tpl.clean,
        });

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
                blocked.retain(|job_id, _| jobs.contains_key(job_id));
            }
            jobs.insert(job.job_id, job.clone());
            if jobs.len() > 16 {
                let oldest_key = jobs
                    .iter()
                    .filter(|(key, _)| **key != job.job_id)
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
        self.shared_job(job_id).map(Arc::unwrap_or_clone)
    }

    pub(crate) fn shared_job(&self, job_id: &[u8; 32]) -> Option<Arc<ActiveJob>> {
        self.jobs.read().get(job_id).cloned()
    }

    pub fn current_job(&self) -> Option<ActiveJob> {
        self.shared_current_job().map(Arc::unwrap_or_clone)
    }

    pub(crate) fn shared_current_job(&self) -> Option<Arc<ActiveJob>> {
        self.current_job.read().clone()
    }

    /// Claim the right to submit a block for this job.
    ///
    /// Only one candidate per job may be in flight, otherwise two miners race
    /// the node with the same height. The claim expires: every caller must
    /// release it, and a process that dies or stalls mid-submit must not wedge
    /// the pool, because a wedged job cannot produce a block and no new template
    /// arrives while the chain is stuck.
    pub fn try_begin_block_submission(
        self: &Arc<Self>,
        job_id: [u8; 32],
    ) -> Option<SubmissionLease> {
        self.claim_at(job_id, Instant::now())
    }

    fn claim_at(self: &Arc<Self>, job_id: [u8; 32], now: Instant) -> Option<SubmissionLease> {
        let mut blocked = self.blocked_jobs.write();
        if blocked
            .get(&job_id)
            .is_some_and(|owner| now.duration_since(**owner) < BLOCK_SUBMISSION_LEASE)
        {
            return None;
        }
        let started = Arc::new(now);
        blocked.insert(job_id, Arc::clone(&started));
        Some(SubmissionLease {
            manager: Arc::clone(self),
            job_id,
            started,
        })
    }

    pub fn is_blocked(&self, job_id: &[u8; 32]) -> bool {
        let now = Instant::now();
        self.blocked_jobs
            .read()
            .get(job_id)
            .is_some_and(|claimed_at| now.duration_since(**claimed_at) < BLOCK_SUBMISSION_LEASE)
    }

    pub fn share_difficulty(&self) -> u64 {
        self.share_difficulty
    }

    pub fn set_share_difficulty(&mut self, d: u64) {
        self.share_difficulty = d;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn template_churn_bounds_history_and_shares_transaction_buffers() {
        let manager = JobManager::new(1);
        let header = crate::primitives::build_genesis_block(
            &crate::primitives::ChainConfig::archived_devnet_v2(),
        )
        .header;
        let header_data = crate::wire_config(4096).serialize(&header).unwrap();
        let mut observers = Vec::new();
        for id in 0..128 {
            let payload = vec![id; 256 * 1024];
            let original = payload.as_ptr();
            let template = BlockTemplate {
                template_id: job_id(id).into(),
                header_data: header_data.clone(),
                epoch_seed: vec![0; 32],
                parent_work_commitment: vec![0; 32],
                transactions: vec![payload],
                ..Default::default()
            };
            let job = manager.ingest_owned_template(template).unwrap();
            assert_eq!(job.transactions[0].as_ptr(), original);
            assert!(Arc::ptr_eq(&job, &manager.shared_current_job().unwrap()));
            assert!(Arc::ptr_eq(&job, &manager.shared_job(&job.job_id).unwrap()));
            observers.push(Arc::downgrade(&job));
        }
        assert_eq!(
            observers
                .iter()
                .filter(|job| job.strong_count() > 0)
                .count(),
            16
        );
    }

    #[test]
    fn only_one_candidate_may_submit_a_block_for_a_job() {
        let manager = Arc::new(JobManager::new(10));
        let lease = manager.try_begin_block_submission(job_id(1)).unwrap();
        assert!(
            manager.try_begin_block_submission(job_id(1)).is_none(),
            "a second miner must not race the node with the same height"
        );
        assert!(manager.is_blocked(&job_id(1)));

        drop(lease);
        assert!(!manager.is_blocked(&job_id(1)));
        assert!(
            manager.try_begin_block_submission(job_id(1)).is_some(),
            "the claim must be reusable once released"
        );
    }

    #[test]
    fn a_claim_expires_so_a_stalled_submit_cannot_wedge_the_pool() {
        let manager = Arc::new(JobManager::new(10));
        let start = Instant::now();
        let id = job_id(2);
        let expired = manager.claim_at(id, start).unwrap();
        assert!(
            manager
                .claim_at(id, start + BLOCK_SUBMISSION_LEASE / 2)
                .is_none()
        );
        let replacement = manager
            .claim_at(id, start + BLOCK_SUBMISSION_LEASE)
            .unwrap();
        drop(expired);
        assert!(manager.is_blocked(&id));
        drop(replacement);
        assert!(!manager.is_blocked(&id));
    }
}
