mod config;
mod ip;
mod provider;

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();
    let config_path = cli.config.clone();

    let config = config::load_config(&config_path).with_context(|| {
        format!(
            "failed to load configuration from {}",
            config_path.display()
        )
    })?;

    let client = build_client(&config)?;

    match cli.command {
        None | Some(Command::Ddns) => run_ddns(&config, &client),
        Some(Command::Glesys { command }) => run_glesys_command(&config.provider, &client, command),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "douteki-dns",
    version,
    about = "Dynamic DNS updater",
    propagate_version = true
)]
struct Cli {
    /// Path to the configuration TOML file
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,
    /// Command to execute. Defaults to `ddns`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Run the dynamic DNS updater loop
    Ddns,
    /// GleSYS provider specific operations
    Glesys {
        #[command(subcommand)]
        command: GlesysCommand,
    },
}

#[derive(Subcommand, Debug, Clone)]
enum GlesysCommand {
    /// List DNS records via the GleSYS API
    ListRecords,
}

fn build_client(config: &config::Config) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(config.user_agent())
        .build()
        .context("failed to construct HTTP client")
}

fn run_ddns(config: &config::Config, client: &reqwest::blocking::Client) -> Result<()> {
    let interval_secs = determine_interval_seconds(config);
    let interval = Duration::from_secs(interval_secs);

    if let Some(min_ttl) = config.provider.min_ttl() {
        info!(
            records = config.provider.record_count(),
            min_ttl,
            interval = interval_secs,
            "Starting dynamic DNS loop"
        );
    } else {
        info!(
            records = config.provider.record_count(),
            interval = interval_secs,
            "Starting dynamic DNS loop"
        );
    }

    let mut previous_ips: Option<ip::ResolvedIps> = None;

    loop {
        let ip::ResolveReport {
            ips: resolved,
            errors,
        } = ip::resolve_all(&config.ip_sources, client);

        for error in &errors {
            warn!(error = %error, "Failed to determine current IP address");
        }

        if resolved.ipv4.is_none() && resolved.ipv6.is_none() {
            warn!(
                interval = interval_secs,
                "No IP addresses resolved; skipping update cycle"
            );
            thread::sleep(interval);
            continue;
        }

        debug!(?resolved, "Resolved IP addresses");

        let changed = previous_ips.as_ref() != Some(&resolved);

        if changed {
            match config.provider.update(client, &resolved) {
                Ok(updates) => {
                    for update in updates {
                        info!(
                            fqdn = update.fqdn,
                            record_type = %update.record_type,
                            ip = %update.ip,
                            outcome = update.outcome.as_str(),
                            record_id = update.record_id.as_deref(),
                            "DNS record change applied"
                        );
                    }
                    previous_ips = Some(resolved);
                }
                Err(err) => {
                    warn!(error = %err, "Failed to push DNS update");
                }
            }
        } else {
            debug!(interval = interval_secs, "No IP change detected");
        }

        thread::sleep(interval);
    }
}

fn run_glesys_command(
    provider: &config::DnsProvider,
    client: &reqwest::blocking::Client,
    command: GlesysCommand,
) -> Result<()> {
    match provider {
        config::DnsProvider::Glesys(cfg) => match command {
            GlesysCommand::ListRecords => {
                let records = cfg.list_records(client)?;
                if records.is_empty() {
                    info!("No records returned by GleSYS");
                } else {
                    for record in records {
                        debug!(
                            record_id = %record.record_id,
                            fqdn = %record.fqdn(),
                            record_type = %record.record_type,
                            data = %record.data,
                            ttl = record.ttl,
                            "Record from GleSYS"
                        );
                        println!(
                            "{}\t{}\t{}\t{}\tTTL {}",
                            record.record_id,
                            record.fqdn(),
                            record.record_type,
                            record.data,
                            record.ttl
                        );
                    }
                }
                Ok(())
            }
        },
    }
}

fn determine_interval_seconds(config: &config::Config) -> u64 {
    if let Some(explicit) = config.check_interval_seconds() {
        return explicit.max(1);
    }

    let ttl = config.provider.min_ttl().unwrap_or(300);
    derive_interval_from_ttl(ttl)
}

fn derive_interval_from_ttl(ttl: u32) -> u64 {
    let ttl = u64::from(ttl);
    if ttl == 0 {
        return 30;
    }

    if ttl > 30 {
        ttl - 30
    } else if ttl > 1 {
        ttl - 1
    } else {
        1
    }
}

fn init_tracing() -> Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .context("failed to build tracing filter")?;

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize tracing subscriber: {err}"))?;
    Ok(())
}
