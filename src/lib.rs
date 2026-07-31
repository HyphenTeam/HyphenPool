pub(crate) const DEFAULT_WIRE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_WIRE_COLLECTION_ITEMS: usize = 1_000_000;

pub(crate) fn wire_config(max_bytes: usize) -> rustbinary::Config {
    rustbinary::legacy_options()
        .with_little_endian()
        .with_fixint_encoding()
        .with_limit(max_bytes as u64)
        .with_collection_limit(max_bytes.min(MAX_WIRE_COLLECTION_ITEMS) as u64)
        .reject_trailing_bytes()
}

pub mod accounting;
pub mod api;
pub mod chain;
pub mod job;
pub mod payout;
pub mod pow;
pub mod primitives;
pub mod protocol;
pub mod server;
pub mod share;
pub mod stratum;
pub mod template;
pub mod tp;

pub use accounting::{
    AccountingError, PayoutRecord, PayoutStatus, PoolAccounting, PoolAccountingConfig, PoolMode,
};
pub use api::start_pool_api;
pub use chain::StandaloneProvider;
pub use job::JobManager;
pub use payout::{PayoutAgentClient, PayoutWorker, PayoutWorkerConfig};
pub use protocol::{PoolCodec, PoolMessage};
pub use server::{ArenaParamsData, PoolServer};
pub use template::TemplateProviderClient;
pub use tp::{BlockTemplate, TPError, TemplateProvider};
