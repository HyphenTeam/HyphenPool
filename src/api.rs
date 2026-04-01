use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use crate::accounting::{
    BlockSettlement, PoolAccounting, PoolMode, RewardEventKind, WalletLedgerSummary,
    WalletRewardEvent,
};

const ATOMIC_UNITS: u128 = 1_000_000_000_000;

#[derive(Clone)]
struct PoolApiState {
    accounting: Arc<PoolAccounting>,
}

#[derive(Serialize)]
struct PoolInfoResponse {
    mode: PoolMode,
    pool_fee_bps: u16,
    pool_wallet: String,
    direct_coinbase: bool,
}

#[derive(Serialize)]
struct WalletBalanceResponse {
    wallet_address: String,
    mode: PoolMode,
    pool_wallet: String,
    is_pool_wallet: bool,
    direct_coinbase_mode: bool,
    pool_fee_bps: u16,
    active_miners: u64,
    valid_shares: u64,
    invalid_shares: u64,
    accumulated_share_difficulty: String,
    pending_payout: String,
    pending_payout_atomic: String,
    direct_reward: String,
    direct_reward_atomic: String,
    total_paid: String,
    total_paid_atomic: String,
    total_earned: String,
    total_earned_atomic: String,
    total_blocks_found: u64,
    last_share_timestamp: Option<u64>,
    last_disconnect_timestamp: Option<u64>,
    recent_blocks: Vec<WalletBlockSettlement>,
    recent_reward_events: Vec<WalletRewardEventResponse>,
}

#[derive(Serialize)]
struct WalletBlockSettlement {
    height: u64,
    block_hash_hex: String,
    reward_recipient: String,
    direct_coinbase: bool,
    gross_reward_atomic: u64,
    total_fee_atomic: u64,
    distributed_atomic: String,
    pool_fee_atomic: String,
    timestamp: u64,
    finder_pubkey: String,
}

#[derive(Serialize)]
struct WalletRewardEventResponse {
    height: u64,
    block_hash_hex: String,
    wallet_address: String,
    finder_pubkey: String,
    reward_recipient: String,
    amount: String,
    amount_atomic: String,
    mode: PoolMode,
    kind: RewardEventKind,
    direct_coinbase: bool,
    timestamp: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, Default)]
struct WalletBalanceQuery {
    limit: Option<usize>,
}

fn format_hpn_128(atomic: u128) -> String {
    let whole = atomic / ATOMIC_UNITS;
    let frac = atomic % ATOMIC_UNITS;
    if frac == 0 {
        format!("{whole}.000000000000")
    } else {
        format!("{whole}.{frac:012}")
    }
}

fn error_json(status: StatusCode, message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
}

fn map_summary(summary: WalletLedgerSummary) -> WalletBalanceResponse {
    let total_earned_atomic = summary
        .pending_payout_atomic
        .saturating_add(summary.direct_reward_atomic)
        .saturating_add(summary.total_paid_atomic);

    WalletBalanceResponse {
        wallet_address: hex::encode(summary.wallet_address),
        mode: summary.mode,
        pool_wallet: hex::encode(summary.pool_wallet),
        is_pool_wallet: summary.is_pool_wallet,
        direct_coinbase_mode: summary.direct_coinbase_mode,
        pool_fee_bps: summary.pool_fee_bps,
        active_miners: summary.active_miners,
        valid_shares: summary.valid_shares,
        invalid_shares: summary.invalid_shares,
        accumulated_share_difficulty: summary.accumulated_share_difficulty.to_string(),
        pending_payout: format_hpn_128(summary.pending_payout_atomic),
        pending_payout_atomic: summary.pending_payout_atomic.to_string(),
        direct_reward: format_hpn_128(summary.direct_reward_atomic),
        direct_reward_atomic: summary.direct_reward_atomic.to_string(),
        total_paid: format_hpn_128(summary.total_paid_atomic),
        total_paid_atomic: summary.total_paid_atomic.to_string(),
        total_earned: format_hpn_128(total_earned_atomic),
        total_earned_atomic: total_earned_atomic.to_string(),
        total_blocks_found: summary.total_blocks_found,
        last_share_timestamp: summary.last_share_timestamp,
        last_disconnect_timestamp: summary.last_disconnect_timestamp,
        recent_blocks: summary.recent_blocks.into_iter().map(map_block).collect(),
        recent_reward_events: summary
            .recent_reward_events
            .into_iter()
            .map(map_reward_event)
            .collect(),
    }
}

fn map_block(block: BlockSettlement) -> WalletBlockSettlement {
    WalletBlockSettlement {
        height: block.height,
        block_hash_hex: block.block_hash_hex,
        reward_recipient: hex::encode(block.reward_recipient),
        direct_coinbase: block.direct_coinbase,
        gross_reward_atomic: block.gross_reward_atomic,
        total_fee_atomic: block.total_fee_atomic,
        distributed_atomic: block.distributed_atomic.to_string(),
        pool_fee_atomic: block.pool_fee_atomic.to_string(),
        timestamp: block.timestamp,
        finder_pubkey: hex::encode(block.finder_pubkey),
    }
}

fn map_reward_event(event: WalletRewardEvent) -> WalletRewardEventResponse {
    WalletRewardEventResponse {
        height: event.height,
        block_hash_hex: event.block_hash_hex,
        wallet_address: hex::encode(event.wallet_address),
        finder_pubkey: hex::encode(event.finder_pubkey),
        reward_recipient: hex::encode(event.reward_recipient),
        amount: format_hpn_128(event.amount_atomic),
        amount_atomic: event.amount_atomic.to_string(),
        mode: event.mode,
        kind: event.kind,
        direct_coinbase: event.direct_coinbase,
        timestamp: event.timestamp,
    }
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

async fn pool_info(State(state): State<PoolApiState>) -> impl IntoResponse {
    let mode = state.accounting.mode();
    (
        StatusCode::OK,
        Json(PoolInfoResponse {
            mode,
            pool_fee_bps: state.accounting.pool_fee_bps(),
            pool_wallet: hex::encode(state.accounting.pool_wallet()),
            direct_coinbase: mode.uses_direct_coinbase(),
        }),
    )
}

async fn wallet_balance(
    State(state): State<PoolApiState>,
    Path(wallet): Path<String>,
    Query(query): Query<WalletBalanceQuery>,
) -> impl IntoResponse {
    let wallet_address = match PoolAccounting::parse_wallet_input(wallet.trim()) {
        Ok((_view, spend)) => spend,
        Err(error) => return error_json(StatusCode::BAD_REQUEST, error).into_response(),
    };

    let limit = query.limit.unwrap_or(16).clamp(1, 128);
    let summary = state.accounting.wallet_summary(wallet_address, limit);
    (StatusCode::OK, Json(map_summary(summary))).into_response()
}

pub fn pool_api_router(accounting: Arc<PoolAccounting>) -> Router {
    let state = PoolApiState { accounting };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/healthz", get(health))
        .route("/api/pool/info", get(pool_info))
        .route("/api/pool/wallet/{wallet}/balance", get(wallet_balance))
        .layer(cors)
        .with_state(state)
}

pub async fn start_pool_api(
    bind_addr: SocketAddr,
    accounting: Arc<PoolAccounting>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("Pool accounting API listening on http://{}", bind_addr);
    axum::serve(listener, pool_api_router(accounting)).await?;
    Ok(())
}
