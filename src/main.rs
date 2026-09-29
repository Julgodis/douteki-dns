mod config;
mod desired;
mod ip;
mod provider;
mod scheduler;
mod state;
#[cfg(test)]
mod test_support;
mod updater;

use std::path::PathBuf;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    init_tracing()?;
    let cli = Cli::parse();
    let config = config::load_config(&cli.config).context("failed to load configuration")?;

    match &cli.command {
        None | Some(Command::Ddns) => config.validate()?,
        Some(Command::Glesys { .. }) => config.validate_provider()?,
    }
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
    /// Configuration TOML file; repeat to overlay files in order
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: Vec<PathBuf>,
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
    ListRecords {
        /// DNS zone to list; repeat for several zones. Defaults to all account zones.
        #[arg(long = "domain", value_name = "ZONE")]
        domains: Vec<String>,
    },
}

fn build_client(config: &config::Config) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(config.user_agent())
        .build()
        .context("failed to construct HTTP client")
}

fn run_ddns(config: &config::Config, client: &reqwest::blocking::Client) -> Result<()> {
    let interval_secs = determine_interval_seconds(config);

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

    let mut scheduler = scheduler::Scheduler::new(config.provider.records(), interval_secs);
    let started = Instant::now();
    loop {
        let cycle = updater::cycle(config, client, &mut scheduler, || started.elapsed());
        for error in cycle.source_errors {
            warn!(error = %error, "Failed to determine current IP address");
        }
        let report = cycle.updates;
        for update in report.updates {
            info!(fqdn = update.fqdn, record_type = %update.record_type,
                data = %update.data, outcome = update.outcome.as_str(),
                record_id = update.record_id.as_deref(), "DNS record change applied");
        }
        for (index, error) in &report.errors {
            warn!(record = index, error = %error, "Failed to push DNS update");
        }
        thread::sleep(scheduler.delay(started.elapsed()));
    }
}

fn run_glesys_command(
    provider: &config::DnsProvider,
    client: &reqwest::blocking::Client,
    command: GlesysCommand,
) -> Result<()> {
    match provider {
        config::DnsProvider::Glesys(cfg) => match command {
            GlesysCommand::ListRecords { domains } => {
                let records = cfg.list_records(client, &domains)?;
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
        .with_writer(std::io::stderr)
        .try_init()
        .map_err(|err| anyhow!("failed to initialize tracing subscriber: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_flags_preserve_input_order_and_default_only_when_absent() {
        let cli = Cli::try_parse_from([
            "douteki-dns",
            "--config",
            "base.toml",
            "--config",
            "local.toml",
            "ddns",
        ])
        .unwrap();
        assert_eq!(
            cli.config,
            [PathBuf::from("base.toml"), PathBuf::from("local.toml")]
        );
        assert_eq!(
            Cli::try_parse_from(["douteki-dns"]).unwrap().config,
            [PathBuf::from("config.toml")]
        );
    }
    #[test]
    fn list_records_accepts_credentials_only_and_explicit_zones() {
        let api = crate::test_support::MockApi::new(vec![(
            200,
            serde_json::json!({"response":{"records":[]}}),
        )]);
        let config: config::Config = toml::from_str(&format!(
            r#"
[provider]
type="glesys"
api_user="test"
api_key="test"
list_endpoint="{}/list"
"#,
            api.url
        ))
        .unwrap();
        config.validate_provider().unwrap();
        assert!(config.validate().is_err());
        let cli = Cli::try_parse_from([
            "douteki-dns",
            "glesys",
            "list-records",
            "--domain",
            "example.com",
        ])
        .unwrap();
        let Some(Command::Glesys { command }) = cli.command else {
            panic!("missing command")
        };
        run_glesys_command(&config.provider, &build_client(&config).unwrap(), command).unwrap();
        assert_eq!(api.requests()[0].1["domainname"], "example.com");
    }
}
