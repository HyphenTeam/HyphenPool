use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;

use hyphen_pool::accounting::{PoolAccounting, PoolAccountingConfig, PoolMode};
use hyphen_pool::api::start_pool_api;
use hyphen_pool::job::JobManager;
use hyphen_pool::payout::{load_token_file, PayoutAgentClient, PayoutWorker, PayoutWorkerConfig};
use hyphen_pool::primitives::{hex_encode, ChainConfig, SecretKey};
use hyphen_pool::server::PoolServer;
use hyphen_pool::template::TemplateProviderClient;
use hyphen_pool::tp::TemplateProvider;

#[derive(Parser, Debug)]
#[command(
    name = "hyphen-pool-server",
    about = "Mining pool server for the Hyphen blockchain"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Node TP address (ignored in standalone mode)
    #[arg(long, default_value = "127.0.0.1:3350")]
    node: String,

    /// Pool protocol listen address (protobuf miners)
    #[arg(long, default_value = "0.0.0.0:3340")]
    bind: String,

    /// HTTP listen address for pool accounting API
    #[arg(long, default_value = "0.0.0.0:8081")]
    api_bind: String,

    /// Share difficulty for miners
    #[arg(long, default_value = "100")]
    share_difficulty: u64,

    /// Network selection (mainnet | testnet | devnet)
    #[arg(long, value_parser = ["mainnet", "testnet", "devnet"], default_value = "devnet")]
    network: String,

    /// Pool identifier
    #[arg(long, default_value = "hyphen-pool/0.1")]
    pool_id: String,

    /// Path to 32-byte Ed25519 secret key file
    #[arg(long, default_value = "")]
    key_file: String,

    /// Retired compatibility flag. Standalone consensus is intentionally rejected.
    #[arg(long)]
    standalone: bool,

    /// Retained for CLI compatibility; standalone consensus is no longer executable.
    #[arg(long, default_value = "data")]
    data_dir: String,

    /// Data directory for pool accounting persistence
    #[arg(long, default_value = "pool_state")]
    pool_state_dir: String,

    /// Disable pool accounting HTTP API
    #[arg(long)]
    no_api: bool,

    /// Pool payout mode
    #[arg(long, value_enum, default_value_t = PoolMode::Solo)]
    payout_mode: PoolMode,

    /// Pool fee in basis points. If omitted, SOLO uses 0 and all other modes use 100 (1%).
    #[arg(long)]
    pool_fee_bps: Option<u16>,

    /// PPLNS window factor, measured as a multiple of the current block difficulty.
    #[arg(long, default_value_t = 2)]
    pplns_window_factor: u32,

    /// A network-correct hy1... wallet address for shared-pool rewards.
    /// In SOLO mode the miner's authorized address receives the coinbase.
    #[arg(long, default_value = "")]
    pool_wallet: String,

    /// Loopback endpoint of hyphen-payout-agent. Required for shared modes.
    #[arg(long, default_value = "")]
    payout_agent: String,

    /// Authentication token file shared with hyphen-payout-agent.
    #[arg(long, default_value = "")]
    payout_token_file: String,

    /// Smallest wallet balance eligible for an automatic payout.
    #[arg(long, default_value_t = 1_000_000u64)]
    minimum_payout_atomic: u64,

    /// Maximum amount placed in one automatic payout transaction.
    #[arg(long, default_value_t = u64::MAX)]
    maximum_payout_atomic: u64,

    /// Canonical confirmations required before reserved credit becomes paid.
    #[arg(long, default_value_t = 20u64)]
    payout_confirmations: u64,

    /// Automatic payout reconciliation interval in seconds.
    #[arg(long, default_value_t = 30u64)]
    payout_interval_secs: u64,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new Ed25519 key pair and save to file
    Keygen {
        /// Output file path for the 32-byte secret key
        #[arg(long, default_value = "pool.key")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();

    if let Some(Commands::Keygen { output }) = &cli.command {
        let sk = SecretKey::generate();
        std::fs::write(output, sk.0)?;
        println!("Key generated successfully:");
        println!("  Secret key file : {output}");
        println!("  Public key (hex): {}", sk.public_key());
        println!("\nKeep the secret key file safe. Never share it.");
        return Ok(());
    }

    let cfg = match cli.network.as_str() {
        "mainnet" => ChainConfig::mainnet(),
        "testnet" => ChainConfig::testnet(),
        "devnet" => ChainConfig::devnet(),
        _ => unreachable!("clap validates network"),
    };

    if cli.share_difficulty == 0 {
        return Err("--share-difficulty must be greater than zero".into());
    }
    if cli.standalone {
        return Err(
            "--standalone is disabled because its historical internal chain is not consensus-compatible; run a Hyphen node Template Provider instead"
                .into(),
        );
    }
    if cli.pool_fee_bps.unwrap_or(0) > 10_000 {
        return Err("--pool-fee-bps cannot exceed 10000".into());
    }
    if cli.pplns_window_factor == 0 {
        return Err("--pplns-window-factor must be greater than zero".into());
    }
    if cli.network == "mainnet" {
        if cli.standalone {
            return Err("standalone pool mode is a test harness and is disabled on mainnet".into());
        }
        if cli.key_file.is_empty() || cli.pool_wallet.is_empty() {
            return Err("mainnet pools require both --key-file and --pool-wallet".into());
        }
    }
    if cli.payout_mode != PoolMode::Solo
        && (cli.payout_agent.is_empty() || cli.payout_token_file.is_empty())
    {
        return Err("shared payout modes require --payout-agent and --payout-token-file".into());
    }
    if cli.minimum_payout_atomic == 0
        || cli.maximum_payout_atomic < cli.minimum_payout_atomic
        || cli.payout_confirmations == 0
        || cli.payout_interval_secs == 0
    {
        return Err("automatic payout bounds, confirmations and interval are invalid".into());
    }

    let sk = if cli.key_file.is_empty() {
        let sk = SecretKey::generate();
        info!("Generated ephemeral pool key: {}", sk.public_key());
        sk
    } else {
        let data = std::fs::read(&cli.key_file)?;
        if data.len() != 32 {
            return Err("key file must be exactly 32 bytes".into());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&data);
        SecretKey(bytes)
    };

    info!("Pool public key: {}", sk.public_key());

    let bind_addr: SocketAddr = cli
        .bind
        .parse()
        .map_err(|e| format!("invalid bind address: {e}"))?;

    let api_addr: SocketAddr = cli
        .api_bind
        .parse()
        .map_err(|e| format!("invalid API bind address: {e}"))?;

    let (pool_view_public, pool_pubkey) = if cli.pool_wallet.is_empty() {
        ([0u8; 32], *sk.public_key().as_bytes())
    } else {
        PoolAccounting::parse_wallet_input(&cli.pool_wallet, cfg.network_magic)?
    };
    let pool_fee_bps = cli
        .pool_fee_bps
        .unwrap_or_else(|| cli.payout_mode.default_fee_bps());
    info!("Pool reward wallet: {}", hex_encode(pool_pubkey));
    info!(
        "Pool payout mode: mode={}, fee_bps={}, pplns_window_factor={}",
        cli.payout_mode, pool_fee_bps, cli.pplns_window_factor,
    );

    let accounting = Arc::new(PoolAccounting::try_new(PoolAccountingConfig {
        mode: cli.payout_mode,
        pool_fee_bps,
        pool_wallet: pool_pubkey,
        pool_view_public,
        network_magic: cfg.network_magic,
        pplns_window_factor: cli.pplns_window_factor,
        state_dir: Some(PathBuf::from(&cli.pool_state_dir)),
    })?);
    let job_manager = Arc::new(JobManager::with_pool_pubkey(
        cli.share_difficulty,
        pool_pubkey,
    ));

    run_with_node(cli, cfg, sk, bind_addr, api_addr, job_manager, accounting).await
}

#[allow(clippy::too_many_arguments)]
async fn run_with_node(
    cli: Cli,
    cfg: ChainConfig,
    sk: SecretKey,
    bind_addr: SocketAddr,
    api_addr: SocketAddr,
    job_manager: Arc<JobManager>,
    accounting: Arc<PoolAccounting>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Connecting to node TP at {} …", cli.node);

    let tp = Arc::new(
        TemplateProviderClient::connect(&cli.node, &sk, &cfg)
            .await
            .map_err(|e| format!("Failed to connect to node TP: {e}"))?,
    );

    info!("Connected to node Template Provider");

    start_pool(
        cli,
        cfg,
        sk,
        bind_addr,
        api_addr,
        job_manager,
        accounting,
        tp,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_pool<T: TemplateProvider + Send + Sync + 'static>(
    cli: Cli,
    cfg: ChainConfig,
    sk: SecretKey,
    bind_addr: SocketAddr,
    api_addr: SocketAddr,
    job_manager: Arc<JobManager>,
    accounting: Arc<PoolAccounting>,
    tp: Arc<T>,
) -> Result<(), Box<dyn std::error::Error>> {
    let payout_handle = if cli.payout_mode != PoolMode::Solo {
        let endpoint: SocketAddr = cli
            .payout_agent
            .parse()
            .map_err(|error| format!("invalid payout-agent endpoint: {error}"))?;
        let token = load_token_file(PathBuf::from(&cli.payout_token_file).as_path())?;
        let expected_wallet = accounting.pool_wallet_address()?;
        let client = PayoutAgentClient::new(endpoint, token, expected_wallet)?;
        let worker = PayoutWorker::new(
            Arc::clone(&accounting),
            client,
            PayoutWorkerConfig {
                minimum_payout_atomic: cli.minimum_payout_atomic,
                maximum_payout_atomic: cli.maximum_payout_atomic,
                required_confirmations: cli.payout_confirmations,
                interval: std::time::Duration::from_secs(cli.payout_interval_secs),
            },
        )?;
        worker.verify_agent().await?;
        Some(tokio::spawn(worker.run()))
    } else {
        None
    };

    let pool = Arc::new(PoolServer::new(
        Arc::clone(&job_manager),
        Arc::clone(&tp),
        Arc::clone(&accounting),
        sk,
        cli.pool_id.clone(),
        cfg.clone(),
        bind_addr,
    ));

    info!(
        "Pool: pool_id={}, bind={}, share_diff={}, network={}",
        cli.pool_id, bind_addr, cli.share_difficulty, cli.network
    );

    let pool_handle = {
        let p = Arc::clone(&pool);
        tokio::spawn(async move { p.run().await })
    };

    let api_handle = if !cli.no_api {
        info!("Pool API: bind={}", api_addr);
        let accounting = Arc::clone(&accounting);
        Some(tokio::spawn(async move {
            start_pool_api(api_addr, accounting).await
        }))
    } else {
        None
    };

    pool_handle.await??;
    if let Some(h) = api_handle {
        let _ = h.await?;
    }
    if let Some(h) = payout_handle {
        h.abort();
        let _ = h.await;
    }

    Ok(())
}
