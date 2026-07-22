use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::info;

use hyphen_pool::accounting::{PoolAccounting, PoolAccountingConfig, PoolMode};
use hyphen_pool::api::start_pool_api;
use hyphen_pool::chain::StandaloneProvider;
use hyphen_pool::job::JobManager;
use hyphen_pool::primitives::{ChainConfig, SecretKey};
use hyphen_pool::server::PoolServer;
use hyphen_pool::stratum::StratumServer;
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

    /// Stratum V1 listen address (JSON-RPC miners)
    #[arg(long, default_value = "0.0.0.0:3333")]
    stratum_bind: String,

    /// HTTP listen address for pool accounting API
    #[arg(long, default_value = "0.0.0.0:8081")]
    api_bind: String,

    /// Share difficulty for miners
    #[arg(long, default_value = "100")]
    share_difficulty: u64,

    /// Network selection (mainnet | testnet | devnet)
    #[arg(long, value_parser = ["mainnet", "testnet", "devnet"], default_value = "devnet")]
    network: String,

    /// Confirms that non-SOLO mainnet balances require an external payout process.
    #[arg(long)]
    acknowledge_manual_payouts: bool,

    /// Pool identifier
    #[arg(long, default_value = "hyphen-pool/0.1")]
    pool_id: String,

    /// Path to 32-byte Ed25519 secret key file
    #[arg(long, default_value = "")]
    key_file: String,

    /// Run in standalone mode (internal chain state, no external node)
    #[arg(long)]
    standalone: bool,

    /// Data directory for chain state persistence (standalone mode)
    #[arg(long, default_value = "data")]
    data_dir: String,

    /// Data directory for pool accounting persistence
    #[arg(long, default_value = "pool_state")]
    pool_state_dir: String,

    /// Enable the legacy share-only Stratum V1 test adapter. It cannot submit
    /// frozen-v2 blocks and is forbidden on mainnet.
    #[arg(long)]
    enable_legacy_stratum: bool,

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
        if cli.payout_mode != PoolMode::Solo && !cli.acknowledge_manual_payouts {
            return Err(
                "shared mainnet payout modes require --acknowledge-manual-payouts because automatic on-chain settlement is not implemented"
                    .into(),
            );
        }
        if cli.enable_legacy_stratum {
            return Err("legacy Stratum is disabled on mainnet because it cannot carry miner block authorization".into());
        }
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

    let stratum_addr: SocketAddr = cli
        .stratum_bind
        .parse()
        .map_err(|e| format!("invalid stratum bind address: {e}"))?;

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
    info!("Pool reward wallet: {}", hex::encode(pool_pubkey));
    info!(
        "Pool payout mode: mode={}, fee_bps={}, pplns_window_factor={}",
        cli.payout_mode, pool_fee_bps, cli.pplns_window_factor,
    );

    let accounting = Arc::new(PoolAccounting::new(PoolAccountingConfig {
        mode: cli.payout_mode,
        pool_fee_bps,
        pool_wallet: pool_pubkey,
        pool_view_public,
        network_magic: cfg.network_magic,
        pplns_window_factor: cli.pplns_window_factor,
        state_dir: Some(PathBuf::from(&cli.pool_state_dir)),
    }));
    let job_manager = Arc::new(JobManager::with_pool_pubkey(
        cli.share_difficulty,
        pool_pubkey,
    ));

    if cli.standalone {
        run_standalone(
            cli,
            cfg,
            sk,
            bind_addr,
            stratum_addr,
            api_addr,
            job_manager,
            accounting,
        )
        .await
    } else {
        run_with_node(
            cli,
            cfg,
            sk,
            bind_addr,
            stratum_addr,
            api_addr,
            job_manager,
            accounting,
        )
        .await
    }
}

async fn run_standalone(
    cli: Cli,
    cfg: ChainConfig,
    sk: SecretKey,
    bind_addr: SocketAddr,
    stratum_addr: SocketAddr,
    api_addr: SocketAddr,
    job_manager: Arc<JobManager>,
    accounting: Arc<PoolAccounting>,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting in STANDALONE mode (internal chain state)");

    let data_dir = PathBuf::from(&cli.data_dir);
    let tp = Arc::new(StandaloneProvider::new(
        cfg.clone(),
        Some(data_dir),
        sk.clone(),
    ));

    info!(
        "Chain tip: height={}, difficulty={}",
        tp.chain().tip_height(),
        tp.chain().current_difficulty()
    );

    start_pool_and_stratum(
        cli,
        cfg,
        sk,
        bind_addr,
        stratum_addr,
        api_addr,
        job_manager,
        accounting,
        tp,
    )
    .await
}

async fn run_with_node(
    cli: Cli,
    cfg: ChainConfig,
    sk: SecretKey,
    bind_addr: SocketAddr,
    stratum_addr: SocketAddr,
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

    start_pool_and_stratum(
        cli,
        cfg,
        sk,
        bind_addr,
        stratum_addr,
        api_addr,
        job_manager,
        accounting,
        tp,
    )
    .await
}

async fn start_pool_and_stratum<T: TemplateProvider + Send + Sync + 'static>(
    cli: Cli,
    cfg: ChainConfig,
    sk: SecretKey,
    bind_addr: SocketAddr,
    stratum_addr: SocketAddr,
    api_addr: SocketAddr,
    job_manager: Arc<JobManager>,
    accounting: Arc<PoolAccounting>,
    tp: Arc<T>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let stratum_handle = if cli.enable_legacy_stratum {
        let stratum = Arc::new(StratumServer::new(
            Arc::clone(&job_manager),
            Arc::clone(&tp),
            Arc::clone(&accounting),
            cfg,
            stratum_addr,
        ));
        Some(tokio::spawn(async move { stratum.run().await }))
    } else {
        None
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
    if let Some(h) = stratum_handle {
        let _ = h.await?;
    }
    if let Some(h) = api_handle {
        let _ = h.await?;
    }

    Ok(())
}
