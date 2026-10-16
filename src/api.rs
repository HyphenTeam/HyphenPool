//! Accounting HTTP(S) API.
//!
//! Served by Courierust's own server: a bound listener, one closure handler and
//! optional TLS — no router framework on top, which is why the whole API is
//! three routes and four functions.
//!
//! ```text
//! GET /healthz                                    liveness for supervisors
//! GET /api/pool/info                              mode, fee, pool wallet
//! GET /api/pool/wallet/{wallet}/balance?limit=16  one wallet's ledger
//! ```
//!
//! The payload shapes are the ones the explorer and operator dashboards already
//! consume: this is a transport swap, not a protocol change. Reads are open —
//! every number here is already public on chain or derivable from it — but each
//! request is bounded (`max_body`, `max_header_list`, a header deadline and an
//! idle timeout) so a status endpoint cannot be turned into a resource sink.
//!
//! Supply `--api-tls-cert`/`--api-tls-key` and the same routes are served over
//! HTTPS with HTTP/2 negotiated by ALPN.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use courierust::courierust_body::Body;
use courierust::courierust_http::request::Request;
use courierust::courierust_http::response::Response;
use courierust::courierust_http::{Method, StatusCode};
use courierust::courierust_server::{Server, ServerConfig, ServerHandle, TlsSettings};
use serde::Serialize;
use tracing::{info, warn};

use crate::accounting::{
    BlockSettlement, PayoutRecord, PayoutStatus, PoolAccounting, PoolMode, RewardEventKind,
    WalletLedgerSummary, WalletRewardEvent,
};
use crate::primitives::hex_encode;

const ATOMIC_UNITS: u128 = 1_000_000_000_000;

/// Largest request body accepted. Every route is a `GET`; anything larger than
/// a stray header fragment is a client that has misunderstood the API.
const API_MAX_BODY_BYTES: usize = 8 * 1024;

/// Largest request header list accepted.
const API_MAX_HEADER_BYTES: usize = 32 * 1024;

/// Deadline for a complete request head — an absolute one, so trickling bytes
/// cannot extend it.
const API_HEADER_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-connection read budget.
const API_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Close a connection that has been parked this long.
const API_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Concurrent connections kept open.
const API_MAX_CONNECTIONS: usize = 512;

/// Ledger entries returned when the caller does not ask for a count.
const SUMMARY_LIMIT_DEFAULT: usize = 16;

/// Bounds on the requested ledger depth, so a single call cannot ask the
/// accounting lock for an unbounded copy.
const SUMMARY_LIMIT_RANGE: std::ops::RangeInclusive<usize> = 1..=128;

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
    reserved_payout: String,
    reserved_payout_atomic: String,
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
    recent_payouts: Vec<WalletPayoutResponse>,
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
struct WalletPayoutResponse {
    intent_id: String,
    amount: String,
    amount_atomic: u64,
    created_at: u64,
    status: PayoutStatus,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// A request this API will not serve, with what the caller should be told.
struct ApiRejection {
    status: StatusCode,
    message: String,
}

impl ApiRejection {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
}

/// The route a request names.
enum Endpoint {
    Health,
    PoolInfo,
    WalletBalance {
        wallet: String,
        limit: Option<usize>,
    },
}

impl Endpoint {
    /// Resolves a request target, or `None` when no route matches.
    ///
    /// The wallet segment is the only part of a target that can be anything, so
    /// it is the only part that is decoded — and a malformed escape is answered
    /// with `400` rather than a silently different address.
    fn resolve(path: &str, query: Option<&str>) -> Result<Option<Self>, ApiRejection> {
        let endpoint = match path {
            "/healthz" => Endpoint::Health,
            "/api/pool/info" => Endpoint::PoolInfo,
            _ => match wallet_segment(path) {
                None => return Ok(None),
                Some(segment) => Endpoint::WalletBalance {
                    wallet: percent_decode(segment)?,
                    limit: parse_limit(query)?,
                },
            },
        };
        Ok(Some(endpoint))
    }
}

/// `{wallet}` from `/api/pool/wallet/{wallet}/balance`.
fn wallet_segment(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/api/pool/wallet/")?;
    let wallet = rest.strip_suffix("/balance")?;
    if wallet.is_empty() || wallet.contains('/') {
        return None;
    }
    Some(wallet)
}

/// `limit` from a query string; unknown parameters are ignored.
fn parse_limit(query: Option<&str>) -> Result<Option<usize>, ApiRejection> {
    let Some(query) = query else {
        return Ok(None);
    };
    let mut limit = None;
    for pair in query.split('&') {
        let (name, value) = match pair.split_once('=') {
            Some((name, value)) => (name, value),
            None => (pair, ""),
        };
        if name != "limit" {
            continue;
        }
        let value = percent_decode(value)?;
        let parsed = value.trim().parse::<usize>().map_err(|_| {
            ApiRejection::bad_request(format!(
                "invalid limit '{value}': expected an integer between {} and {}",
                SUMMARY_LIMIT_RANGE.start(),
                SUMMARY_LIMIT_RANGE.end()
            ))
        })?;
        limit = Some(parsed);
    }
    Ok(limit)
}

/// Decodes `%XX` escapes, which is all a path or query parameter may contain.
fn percent_decode(input: &str) -> Result<String, ApiRejection> {
    if !input.contains('%') {
        return Ok(input.to_string());
    }
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let escape = bytes.get(index + 1..index + 3).ok_or_else(|| {
            ApiRejection::bad_request("percent-encoding is truncated in the request target")
        })?;
        let text = std::str::from_utf8(escape).map_err(|_| {
            ApiRejection::bad_request("percent-encoding is not valid ASCII in the request target")
        })?;
        decoded.push(u8::from_str_radix(text, 16).map_err(|_| {
            ApiRejection::bad_request(format!("'%{text}' is not a valid percent-encoding"))
        })?);
        index += 3;
    }
    String::from_utf8(decoded)
        .map_err(|_| ApiRejection::bad_request("request target is not valid UTF-8 once decoded"))
}

/// Answers one request; the whole API surface lives here.
struct PoolApiRouter {
    accounting: Arc<PoolAccounting>,
}

impl PoolApiRouter {
    fn respond(&self, req: &Request<Body>) -> Response<Body> {
        // A preflight is answered for any target: the browser is asking what
        // this origin may do, and that answer does not depend on the route.
        if req.method == Method::OPTIONS {
            return preflight();
        }

        let endpoint = match Endpoint::resolve(req.uri.path(), req.uri.query()) {
            Ok(Some(endpoint)) => endpoint,
            Ok(None) => return error_response(StatusCode::NOT_FOUND, "no such endpoint"),
            Err(rejection) => return error_response(rejection.status, rejection.message),
        };

        // `HEAD` is served like `GET`; the server suppresses the body.
        if req.method != Method::GET && req.method != Method::HEAD {
            let mut response = error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                format!("{} is not allowed here", req.method.as_str()),
            );
            response
                .headers
                .insert("allow".into(), "GET, HEAD, OPTIONS".into());
            return response;
        }

        match endpoint {
            Endpoint::Health => json_response(StatusCode::OK, &HealthResponse { status: "ok" }),
            Endpoint::PoolInfo => self.pool_info(),
            Endpoint::WalletBalance { wallet, limit } => self.wallet_balance(&wallet, limit),
        }
    }

    fn pool_info(&self) -> Response<Body> {
        let mode = self.accounting.mode();
        json_response(
            StatusCode::OK,
            &PoolInfoResponse {
                mode,
                pool_fee_bps: self.accounting.pool_fee_bps(),
                pool_wallet: hex_encode(self.accounting.pool_wallet()),
                direct_coinbase: mode.uses_direct_coinbase(),
            },
        )
    }

    fn wallet_balance(&self, wallet: &str, limit: Option<usize>) -> Response<Body> {
        let wallet_address = match self.accounting.decode_wallet(wallet.trim()) {
            Ok((_view, spend)) => spend,
            Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
        };

        let limit = limit
            .unwrap_or(SUMMARY_LIMIT_DEFAULT)
            .clamp(*SUMMARY_LIMIT_RANGE.start(), *SUMMARY_LIMIT_RANGE.end());
        json_response(
            StatusCode::OK,
            &map_summary(self.accounting.wallet_summary(wallet_address, limit)),
        )
    }
}

/// Response shared by every answer: uncacheable accounting data, a media type
/// that cannot be sniffed into something else, and the CORS grant the explorer
/// needs to read it from its own origin.
fn base_response(status: StatusCode) -> Response<Body> {
    Response::with_status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("access-control-allow-origin", "*")
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Body> {
    match serde_json::to_vec(payload) {
        Ok(bytes) => base_response(status).with_body(Body::from(bytes)),
        Err(error) => {
            warn!("Encoding an accounting API payload failed: {error}");
            internal_error()
        }
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response<Body> {
    json_response(
        status,
        &ErrorResponse {
            error: message.into(),
        },
    )
}

/// The last resort for a response that could not be built. Says nothing about
/// the failure beyond the fact of it, and logs the reason instead.
fn internal_error() -> Response<Body> {
    Response::<Body>::with_status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .header("access-control-allow-origin", "*")
        .with_body(Body::from(&b"{\"error\":\"internal error\"}"[..]))
}

fn preflight() -> Response<Body> {
    base_response(StatusCode::NO_CONTENT)
        .header("access-control-allow-methods", "GET, HEAD, OPTIONS")
        .header("access-control-allow-headers", "*")
        .header("access-control-max-age", "600")
        .with_body(Body::from(Vec::new()))
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

fn map_summary(summary: WalletLedgerSummary) -> WalletBalanceResponse {
    let total_earned_atomic = summary
        .pending_payout_atomic
        .saturating_add(summary.reserved_payout_atomic)
        .saturating_add(summary.direct_reward_atomic)
        .saturating_add(summary.total_paid_atomic);

    WalletBalanceResponse {
        wallet_address: hex_encode(summary.wallet_address),
        mode: summary.mode,
        pool_wallet: hex_encode(summary.pool_wallet),
        is_pool_wallet: summary.is_pool_wallet,
        direct_coinbase_mode: summary.direct_coinbase_mode,
        pool_fee_bps: summary.pool_fee_bps,
        active_miners: summary.active_miners,
        valid_shares: summary.valid_shares,
        invalid_shares: summary.invalid_shares,
        accumulated_share_difficulty: summary.accumulated_share_difficulty.to_string(),
        pending_payout: format_hpn_128(summary.pending_payout_atomic),
        pending_payout_atomic: summary.pending_payout_atomic.to_string(),
        reserved_payout: format_hpn_128(summary.reserved_payout_atomic),
        reserved_payout_atomic: summary.reserved_payout_atomic.to_string(),
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
        recent_payouts: summary.recent_payouts.into_iter().map(map_payout).collect(),
    }
}

fn map_payout(payout: PayoutRecord) -> WalletPayoutResponse {
    WalletPayoutResponse {
        intent_id: payout.intent_id,
        amount: format_hpn_128(payout.amount_atomic as u128),
        amount_atomic: payout.amount_atomic,
        created_at: payout.created_at,
        status: payout.status,
    }
}

fn map_block(block: BlockSettlement) -> WalletBlockSettlement {
    WalletBlockSettlement {
        height: block.height,
        block_hash_hex: block.block_hash_hex,
        reward_recipient: hex_encode(block.reward_recipient),
        direct_coinbase: block.direct_coinbase,
        gross_reward_atomic: block.gross_reward_atomic,
        total_fee_atomic: block.total_fee_atomic,
        distributed_atomic: block.distributed_atomic.to_string(),
        pool_fee_atomic: block.pool_fee_atomic.to_string(),
        timestamp: block.timestamp,
        finder_pubkey: hex_encode(block.finder_pubkey),
    }
}

fn map_reward_event(event: WalletRewardEvent) -> WalletRewardEventResponse {
    WalletRewardEventResponse {
        height: event.height,
        block_hash_hex: event.block_hash_hex,
        wallet_address: hex_encode(event.wallet_address),
        finder_pubkey: hex_encode(event.finder_pubkey),
        reward_recipient: hex_encode(event.reward_recipient),
        amount: format_hpn_128(event.amount_atomic),
        amount_atomic: event.amount_atomic.to_string(),
        mode: event.mode,
        kind: event.kind,
        direct_coinbase: event.direct_coinbase,
        timestamp: event.timestamp,
    }
}

/// Why the accounting API did not start.
#[derive(Debug, thiserror::Error)]
pub enum PoolApiError {
    #[error("the accounting API could not listen on {addr}: {source}")]
    Listen {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "the accounting API certificate pair is unusable (cert {cert:?}, key {key:?}): {reason}; \
         pass a PEM certificate chain and its matching private key, or neither"
    )]
    Tls {
        cert: String,
        key: String,
        reason: String,
    },
}

/// A running accounting API: the listener, its worker threads and the promise
/// that dropping this value leaves neither behind.
pub struct PoolApi {
    handle: Option<ServerHandle>,
    local_addr: SocketAddr,
    secure: bool,
}

impl PoolApi {
    /// The address actually bound — the resolved port when `:0` was requested.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Base URL clients should use.
    pub fn base_url(&self) -> String {
        let scheme = if self.secure { "https" } else { "http" };
        format!("{scheme}://{}", self.local_addr)
    }

    /// Stops serving and waits for the listener and its workers to be gone.
    ///
    /// Dropping does the same thing and swallows nothing that matters, but a
    /// caller that wants to know whether shutdown was clean calls this.
    pub fn shutdown(mut self) -> std::io::Result<()> {
        match self.handle.take() {
            Some(handle) => {
                handle.stop();
                handle.join()
            }
            None => Ok(()),
        }
    }
}

impl Drop for PoolApi {
    fn drop(&mut self) {
        // Stopping is asynchronous in Courierust — it signals the accept loop —
        // so joining is what makes "the API is gone" true when this returns
        // rather than merely likely. A pool process that shut down must not
        // leave a port bound.
        if let Some(handle) = self.handle.take() {
            handle.stop();
            if let Err(error) = handle.join() {
                warn!("The accounting API stopped with an error: {error}");
            }
        }
    }
}

/// Loads a server identity from a PEM certificate chain and its private key.
///
/// Both halves are required together. A server that quietly served plaintext
/// where the operator asked for TLS would be a security defect, so half a pair
/// is a startup error, not a warning.
pub fn load_tls_identity(
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<Option<TlsSettings>, PoolApiError> {
    let (cert, key) = match (cert, key) {
        (None, None) => return Ok(None),
        (Some(cert), Some(key)) => (cert, key),
        (cert, key) => {
            return Err(PoolApiError::Tls {
                cert: cert.unwrap_or("<unset>").to_string(),
                key: key.unwrap_or("<unset>").to_string(),
                reason: "a certificate and a key must be given together".to_string(),
            })
        }
    };

    TlsSettings::from_pem_file(cert, key)
        .map(Some)
        .map_err(|error| PoolApiError::Tls {
            cert: cert.to_string(),
            key: key.to_string(),
            reason: error.to_string(),
        })
}

/// Binds the accounting API and serves it on background worker threads.
///
/// The returned [`PoolApi`] owns the listener: keep it alive for as long as the
/// API should answer, and drop it to stop accepting.
pub fn start_pool_api(
    bind_addr: SocketAddr,
    accounting: Arc<PoolAccounting>,
    tls: Option<TlsSettings>,
) -> Result<PoolApi, PoolApiError> {
    let secure = tls.is_some();
    let config = ServerConfig {
        // One port serves HTTP/1.1 and HTTP/2 — and HTTPS with ALPN when a
        // certificate is configured — so a dashboard needs no second endpoint.
        http2: true,
        tls,
        max_body: API_MAX_BODY_BYTES,
        max_header_list: API_MAX_HEADER_BYTES,
        request_header_timeout: Some(API_HEADER_TIMEOUT),
        read_timeout: Some(API_READ_TIMEOUT),
        idle_timeout: Some(API_IDLE_TIMEOUT),
        max_connections: API_MAX_CONNECTIONS,
        ..ServerConfig::default()
    };

    let server =
        Server::bind_with_config(bind_addr, config).map_err(|source| PoolApiError::Listen {
            addr: bind_addr,
            source,
        })?;
    let local_addr = server.local_addr().map_err(|source| PoolApiError::Listen {
        addr: bind_addr,
        source,
    })?;

    let router = Arc::new(PoolApiRouter { accounting });
    let handle = server
        .serve_background(move |request: Request<Body>| router.respond(&request))
        .map_err(|source| PoolApiError::Listen {
            addr: bind_addr,
            source,
        })?;

    let scheme = if secure { "https" } else { "http" };
    info!("Pool accounting API listening on {scheme}://{local_addr}");
    Ok(PoolApi {
        handle: Some(handle),
        local_addr,
        secure,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounting::PoolAccountingConfig;
    use crate::primitives::{base58, blake3_hash};
    use courierust::courierust_client::{Client, ClientConfig};
    use serde_json::Value;

    const DEVNET_MAGIC: [u8; 4] = [0x48, 0x59, 0x44, 0x56];

    fn accounting() -> Arc<PoolAccounting> {
        Arc::new(PoolAccounting::new(PoolAccountingConfig {
            mode: PoolMode::Prop,
            pool_fee_bps: 100,
            pool_wallet: [9u8; 32],
            pool_view_public: [0u8; 32],
            network_magic: DEVNET_MAGIC,
            pplns_window_factor: 2,
            state_dir: None,
        }))
    }

    /// `hy1…` for `view`/`spend`, in the layout the pool accepts.
    fn address(view: [u8; 32], spend: [u8; 32]) -> String {
        address_on(0x02, view, spend)
    }

    /// `hy1…` with an explicit network version byte.
    fn address_on(version: u8, view: [u8; 32], spend: [u8; 32]) -> String {
        let mut payload = Vec::with_capacity(69);
        payload.push(version);
        payload.extend_from_slice(&view);
        payload.extend_from_slice(&spend);
        let checksum = blake3_hash(&payload);
        payload.extend_from_slice(&checksum.as_bytes()[..4]);
        format!("hy1{}", base58::encode(&payload))
    }

    fn api() -> PoolApi {
        start_pool_api(
            "127.0.0.1:0".parse().expect("loopback address"),
            accounting(),
            None,
        )
        .expect("the accounting API binds")
    }

    fn client() -> Client {
        Client::with_config(ClientConfig::default())
    }

    fn body_json(response: Response<Body>) -> Value {
        let text = response.text().expect("the response body is text");
        serde_json::from_str(&text).expect("the response body is JSON")
    }

    #[test]
    fn health_and_pool_info_are_served() {
        let api = api();
        let client = client();

        let health = client
            .get(&format!("{}/healthz", api.base_url()))
            .expect("healthz answers");
        assert_eq!(health.status.as_u16(), 200);
        assert_eq!(body_json(health)["status"], "ok");

        let info = client
            .get(&format!("{}/api/pool/info", api.base_url()))
            .expect("pool info answers");
        let info = body_json(info);
        assert_eq!(info["mode"], "prop");
        assert_eq!(info["pool_fee_bps"], 100);
        assert_eq!(info["pool_wallet"], hex_encode([9u8; 32]));
        assert_eq!(info["direct_coinbase"], false);
    }

    #[test]
    fn wallet_balance_reports_the_ledger_of_a_registered_miner() {
        let accounting = accounting();
        let wallet = [7u8; 32];
        accounting.register_miner([1u8; 32], wallet);
        accounting.record_valid_share([1u8; 32], wallet, 100, 1_000, 500, 0);

        let api = start_pool_api(
            "127.0.0.1:0".parse().expect("loopback address"),
            Arc::clone(&accounting),
            None,
        )
        .expect("the accounting API binds");

        let response = client()
            .get(&format!(
                "{}/api/pool/wallet/{}/balance?limit=4",
                api.base_url(),
                address([7u8; 32], wallet)
            ))
            .expect("the balance endpoint answers");
        assert_eq!(response.status.as_u16(), 200);

        let balance = body_json(response);
        assert_eq!(balance["wallet_address"], hex_encode(wallet));
        assert_eq!(balance["active_miners"], 1);
        assert_eq!(balance["valid_shares"], 1);
        assert_eq!(balance["total_blocks_found"], 0);
        assert!(
            balance["pending_payout"]
                .as_str()
                .expect("pending payout is a string")
                .contains('.'),
            "amounts render as HPN, not raw atomic units"
        );
    }

    #[test]
    fn a_wallet_from_another_network_is_a_bad_request() {
        let api = api();
        // Version 0x01 is a mainnet address; this pool runs on devnet.
        let response = client()
            .get(&format!(
                "{}/api/pool/wallet/{}/balance",
                api.base_url(),
                address_on(0x01, [7u8; 32], [8u8; 32])
            ))
            .expect("the balance endpoint answers");
        assert_eq!(response.status.as_u16(), 400);
        assert!(body_json(response)["error"]
            .as_str()
            .expect("an error message")
            .contains("network"));
    }

    #[test]
    fn an_out_of_range_limit_is_clamped_not_rejected() {
        let accounting = accounting();
        let wallet = [7u8; 32];
        accounting.register_miner([1u8; 32], wallet);

        let api = start_pool_api(
            "127.0.0.1:0".parse().expect("loopback address"),
            accounting,
            None,
        )
        .expect("the accounting API binds");

        let response = client()
            .get(&format!(
                "{}/api/pool/wallet/{}/balance?limit=100000",
                api.base_url(),
                address([7u8; 32], wallet)
            ))
            .expect("the balance endpoint answers");
        assert_eq!(response.status.as_u16(), 200);
    }

    #[test]
    fn malformed_targets_are_answered_with_four_xx() {
        let api = api();
        let client = client();
        let base = api.base_url();

        let cases = [
            (format!("{base}/nope"), 404),
            (format!("{base}/api/pool/wallet//balance"), 404),
            (format!("{base}/api/pool/wallet/ab%2Fcd/balance"), 400),
            (format!("{base}/api/pool/wallet/ab%zz/balance"), 400),
            (
                format!(
                    "{base}/api/pool/wallet/{}/balance?limit=many",
                    address([7u8; 32], [8u8; 32])
                ),
                400,
            ),
        ];
        for (url, expected) in cases {
            let response = client.get(&url).expect("the server answers");
            assert_eq!(
                response.status.as_u16(),
                expected,
                "unexpected status for {url}"
            );
            // Every answer is a JSON object with either data or an error, so a
            // client never has to branch on the media type.
            assert!(
                body_json(response).is_object(),
                "every answer is a JSON object: {url}"
            );
        }
    }

    #[test]
    fn wrong_methods_are_refused_with_allow() {
        let api = api();
        let response = client()
            .post(&format!("{}/healthz", api.base_url()), "spurious")
            .expect("the server answers");
        assert_eq!(response.status.as_u16(), 405);
        assert_eq!(
            response.headers.get("allow").map(|value| value.as_bytes()),
            Some(&b"GET, HEAD, OPTIONS"[..])
        );
    }

    #[test]
    fn head_answers_without_a_body_and_preflight_carries_cors() {
        let api = api();
        let client = client();
        let base = api.base_url();

        let head = client
            .head(&format!("{base}/api/pool/info"))
            .expect("the server answers");
        assert_eq!(head.status.as_u16(), 200);

        let preflight = client
            .options(&format!("{base}/api/pool/wallet/hy1abc/balance"))
            .expect("the server answers");
        assert_eq!(preflight.status.as_u16(), 204);
        assert_eq!(
            preflight
                .headers
                .get("access-control-allow-origin")
                .map(|value| value.as_bytes()),
            Some(&b"*"[..])
        );
        assert!(preflight
            .headers
            .get("access-control-allow-methods")
            .is_some());
    }

    #[test]
    fn a_plain_json_read_is_uncacheable_and_not_sniffable() {
        let api = api();
        let response = client()
            .get(&format!("{}/healthz", api.base_url()))
            .expect("healthz answers");

        let header = |name: &str| {
            response
                .headers
                .get(name)
                .map(|value| value.as_bytes().to_vec())
        };
        assert_eq!(header("content-type"), Some(b"application/json".to_vec()));
        assert_eq!(header("cache-control"), Some(b"no-store".to_vec()));
        assert_eq!(header("x-content-type-options"), Some(b"nosniff".to_vec()));
    }

    #[test]
    fn a_tls_pair_must_be_complete_and_valid() {
        assert!(load_tls_identity(None, None)
            .expect("no certificate is not an error")
            .is_none());

        let incomplete =
            load_tls_identity(Some("cert.pem"), None).expect_err("half a pair must be refused");
        assert!(incomplete.to_string().contains("together"));

        let missing = load_tls_identity(Some("does-not-exist.pem"), Some("does-not-exist.key"))
            .expect_err("a certificate that cannot be read must be refused");
        assert!(missing.to_string().contains("does-not-exist.pem"));
    }

    #[test]
    fn the_api_stops_when_it_is_dropped() {
        let api = api();
        let addr = api.local_addr();
        let client = client();
        client
            .get(&format!("http://{addr}/healthz"))
            .expect("the API answers while it is held");

        drop(api);

        // The listener is gone; a fresh connection cannot be established. This
        // is the property the pool process relies on at shutdown.
        assert!(
            std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_err(),
            "a dropped API must leave no listener behind"
        );
    }
}
