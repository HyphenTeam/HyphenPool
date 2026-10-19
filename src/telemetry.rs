//! Live mining telemetry.
//!
//! The accounting ledger answers "what has been earned". It cannot answer "why
//! is no block appearing", which is a question about the running loop: how many
//! miners are attached, which job is outstanding, whether candidates are being
//! refused and why. That state is kept here — counters in atomics the share path
//! can bump without taking a lock, plus guarded snapshots for the two structured
//! facts (the outstanding job and the last settlement).
//!
//! Nothing here influences consensus, accounting or the payout ledger. It is
//! observation only: the mining path pays one relaxed atomic increment per event
//! and a reader never blocks it by more than an uncontended lock.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::Serialize;

use crate::job::ActiveJob;
use crate::primitives::hex_encode;

/// Longest rejection reason retained for `/api/pool/status`. The text can carry
/// miner-supplied fragments, so it is truncated and reduced to printable ASCII
/// before it is ever stored or served.
const MAX_REJECTION_CHARS: usize = 160;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn sanitize(reason: &str) -> String {
    reason
        .chars()
        .take(MAX_REJECTION_CHARS)
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect()
}

fn age_secs(at: u64, now: u64) -> u64 {
    now.saturating_sub(at)
}

#[derive(Clone, Debug, Serialize)]
pub struct JobReport {
    job_id: String,
    /// Height the job mines into; the chain tip is `height - 1`.
    height: u64,
    block_difficulty: u64,
    share_difficulty: u64,
    transactions: u32,
    issued_at: u64,
    age_secs: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SettlementReport {
    height: u64,
    hash: String,
    accepted: bool,
    at: u64,
    age_secs: u64,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShareReport {
    accepted: u64,
    rejected: u64,
    last_rejection: Option<String>,
    last_rejection_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockReport {
    submitted: u64,
    accepted: u64,
    rejected: u64,
}

/// Everything `/api/pool/status` returns, as one consistent read.
#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub status: &'static str,
    pub uptime_secs: u64,
    pub connected_miners: u64,
    pub claimed_witnesses: u64,
    pub template_refresh_failures: u64,
    pub job: Option<JobReport>,
    pub shares: ShareReport,
    pub blocks: BlockReport,
    pub last_block: Option<SettlementReport>,
}

#[derive(Debug)]
struct JobSnapshot {
    job_id: String,
    height: u64,
    block_difficulty: u64,
    share_difficulty: u64,
    transactions: u32,
    issued_at: u64,
}

#[derive(Debug)]
struct SettlementSnapshot {
    height: u64,
    hash: String,
    accepted: bool,
    at: u64,
    detail: String,
}

#[derive(Debug)]
struct RejectionSnapshot {
    reason: String,
    at: u64,
}

pub struct PoolTelemetry {
    started_at: Instant,
    connected_miners: AtomicU64,
    accepted_shares: AtomicU64,
    rejected_shares: AtomicU64,
    submitted_blocks: AtomicU64,
    accepted_blocks: AtomicU64,
    rejected_blocks: AtomicU64,
    template_refresh_failures: AtomicU64,
    claimed_witnesses: AtomicU64,
    job: RwLock<Option<JobSnapshot>>,
    last_settlement: RwLock<Option<SettlementSnapshot>>,
    last_rejection: RwLock<Option<RejectionSnapshot>>,
}

impl Default for PoolTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

impl PoolTelemetry {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            connected_miners: AtomicU64::new(0),
            accepted_shares: AtomicU64::new(0),
            rejected_shares: AtomicU64::new(0),
            submitted_blocks: AtomicU64::new(0),
            accepted_blocks: AtomicU64::new(0),
            rejected_blocks: AtomicU64::new(0),
            template_refresh_failures: AtomicU64::new(0),
            claimed_witnesses: AtomicU64::new(0),
            job: RwLock::new(None),
            last_settlement: RwLock::new(None),
            last_rejection: RwLock::new(None),
        }
    }

    /// Published by the server rather than counted here: the session map is the
    /// authority on who is attached, so the number cannot drift from it.
    pub fn set_connected_miners(&self, attached: usize) {
        self.connected_miners
            .store(attached as u64, Ordering::Relaxed);
    }

    pub fn record_job(&self, job: &ActiveJob) {
        *self.job.write() = Some(JobSnapshot {
            job_id: hex_encode(job.job_id),
            height: job.header.height,
            block_difficulty: job.header.difficulty,
            share_difficulty: job.share_difficulty,
            transactions: job.transactions.len() as u32,
            issued_at: unix_now(),
        });
    }

    pub fn record_share_accepted(&self) {
        self.accepted_shares.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_share_rejected(&self, reason: &str) {
        self.rejected_shares.fetch_add(1, Ordering::Relaxed);
        *self.last_rejection.write() = Some(RejectionSnapshot {
            reason: sanitize(reason),
            at: unix_now(),
        });
    }

    pub fn record_block_submitted(&self) {
        self.submitted_blocks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_block_settled(&self, height: u64, hash: String, accepted: bool, detail: &str) {
        if accepted {
            self.accepted_blocks.fetch_add(1, Ordering::Relaxed);
        } else {
            self.rejected_blocks.fetch_add(1, Ordering::Relaxed);
        }
        *self.last_settlement.write() = Some(SettlementSnapshot {
            height,
            hash,
            accepted,
            at: unix_now(),
            detail: sanitize(detail),
        });
    }

    pub fn record_template_refresh_failure(&self) {
        self.template_refresh_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_claimed_witnesses(&self, claimed: usize) {
        self.claimed_witnesses
            .store(claimed as u64, Ordering::Relaxed);
    }

    pub fn report(&self) -> StatusReport {
        let now = unix_now();
        let job = self.job.read().as_ref().map(|job| JobReport {
            job_id: job.job_id.clone(),
            height: job.height,
            block_difficulty: job.block_difficulty,
            share_difficulty: job.share_difficulty,
            transactions: job.transactions,
            issued_at: job.issued_at,
            age_secs: age_secs(job.issued_at, now),
        });
        let last_block = self
            .last_settlement
            .read()
            .as_ref()
            .map(|settled| SettlementReport {
                height: settled.height,
                hash: settled.hash.clone(),
                accepted: settled.accepted,
                at: settled.at,
                age_secs: age_secs(settled.at, now),
                detail: settled.detail.clone(),
            });
        let rejection = self.last_rejection.read();
        StatusReport {
            status: "ok",
            uptime_secs: self.started_at.elapsed().as_secs(),
            connected_miners: self.connected_miners.load(Ordering::Relaxed),
            claimed_witnesses: self.claimed_witnesses.load(Ordering::Relaxed),
            template_refresh_failures: self.template_refresh_failures.load(Ordering::Relaxed),
            job,
            shares: ShareReport {
                accepted: self.accepted_shares.load(Ordering::Relaxed),
                rejected: self.rejected_shares.load(Ordering::Relaxed),
                last_rejection: rejection.as_ref().map(|last| last.reason.clone()),
                last_rejection_age_secs: rejection.as_ref().map(|last| age_secs(last.at, now)),
            },
            blocks: BlockReport {
                submitted: self.submitted_blocks.load(Ordering::Relaxed),
                accepted: self.accepted_blocks.load(Ordering::Relaxed),
                rejected: self.rejected_blocks.load(Ordering::Relaxed),
            },
            last_block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_rejections_are_bounded() {
        let telemetry = PoolTelemetry::new();
        telemetry.record_share_accepted();
        telemetry.record_share_rejected(&"x".repeat(4_096));
        telemetry.record_share_rejected("stale\u{0}job");
        telemetry.record_block_submitted();
        telemetry.record_block_settled(9, "ab".repeat(32), false, "rejected: stale job");
        telemetry.record_template_refresh_failure();
        telemetry.set_claimed_witnesses(12);
        telemetry.set_connected_miners(3);

        let report = telemetry.report();
        assert_eq!(report.shares.accepted, 1);
        assert_eq!(report.shares.rejected, 2);
        assert_eq!(report.blocks.submitted, 1);
        assert_eq!(report.blocks.rejected, 1);
        assert_eq!(report.blocks.accepted, 0);
        assert_eq!(report.claimed_witnesses, 12);
        assert_eq!(report.connected_miners, 3);
        assert_eq!(report.template_refresh_failures, 1);

        // The newest rejection wins, and it carries no control characters.
        let reason = report
            .shares
            .last_rejection
            .expect("a rejection is retained");
        assert_eq!(reason, "stale?job");

        let settled = report.last_block.expect("a settlement is retained");
        assert_eq!(settled.height, 9);
        assert!(!settled.accepted);
        assert_eq!(settled.detail, "rejected: stale job");
    }

    #[test]
    fn reason_truncation_keeps_ascii_only() {
        let sanitized = sanitize(&"aé\n".repeat(200));
        assert!(sanitized.len() <= MAX_REJECTION_CHARS);
        assert!(sanitized.chars().all(|c| c.is_ascii_graphic() || c == '?'));
    }
}
