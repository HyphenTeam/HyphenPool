//! Hyphen mining pool. Consensus types, hashing, keys and the Template
//! Protocol are canonical base-chain crates reached by path dependency; this
//! crate owns only pool policy and accounting.

/// Fresh randomness for test identities and salts.
#[cfg(test)]
pub(crate) fn random_u64() -> u64 {
    let mut bytes = [0u8; 8];
    hyphen_crypto::fill_system_random(&mut bytes);
    u64::from_le_bytes(bytes)
}

pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;

pub mod accounting;
pub mod api;
pub mod chain;
pub mod job;
pub mod payout;
pub mod primitives;
pub mod protocol;
pub mod server;
pub mod share;
pub mod template;
pub mod tp;

pub use accounting::{
    AccountingError, PayoutRecord, PayoutStatus, PoolAccounting, PoolAccountingConfig, PoolMode,
};
pub use api::start_pool_api;
pub use chain::StandaloneProvider;
pub use job::JobManager;
pub use payout::{PayoutAgentClient, PayoutWorker, PayoutWorkerConfig};
pub use primitives::wire_config;
pub use protocol::{PoolCodec, PoolMessage};
pub use server::PoolServer;
pub use template::TemplateProviderClient;
pub use tp::{BlockTemplate, TPError, TemplateProvider};
