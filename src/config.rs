use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::net::IpAddr;

pub fn load_config(path: &Path) -> Result<Config> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read configuration file: {}", path.display()))?;
    let config: Config = toml::from_str(&raw)
        .with_context(|| format!("failed to parse configuration TOML: {}", path.display()))?;
    config.validate()?;
    Ok(config)
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default = "default_user_agent")]
    user_agent: String,
    #[serde(default)]
    check_interval_seconds: Option<u64>,
    #[serde(default)]
    pub ip_sources: IpSources,
    pub provider: DnsProvider,
}

impl Config {
    pub fn user_agent(&self) -> &str {
        &self.user_agent
    }

    pub fn check_interval_seconds(&self) -> Option<u64> {
        self.check_interval_seconds
    }

    fn validate(&self) -> Result<()> {
        self.provider.validate(&self.ip_sources)
    }
}

fn default_user_agent() -> String {
    format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Deserialize)]
pub struct IpSources {
    #[serde(default = "default_ipv4_source")]
    pub ipv4: Option<IpSource>,
    #[serde(default)]
    pub ipv6: Option<IpSource>,
}

impl Default for IpSources {
    fn default() -> Self {
        Self {
            ipv4: default_ipv4_source(),
            ipv6: None,
        }
    }
}

fn default_ipv4_source() -> Option<IpSource> {
    Some(IpSource::default_http())
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IpSource {
    Http {
        #[serde(default = "default_public_ip_service")]
        url: String,
    },
    Static {
        address: IpAddr,
    },
}

impl IpSource {
    pub fn default_http() -> Self {
        IpSource::Http {
            url: default_public_ip_service(),
        }
    }
}

fn default_public_ip_service() -> String {
    "https://api.ipify.org".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DnsProvider {
    Glesys(GlesysProvider),
}

impl DnsProvider {
    pub fn validate(&self, sources: &IpSources) -> Result<()> {
        match self {
            DnsProvider::Glesys(provider) => provider.validate(sources),
        }
    }

    pub fn min_ttl(&self) -> Option<u32> {
        match self {
            DnsProvider::Glesys(provider) => provider.min_ttl(),
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            DnsProvider::Glesys(provider) => provider.records.len(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GlesysProvider {
    pub api_user: String,
    pub api_key: String,
    #[serde(default = "default_glesys_update_endpoint")]
    pub update_endpoint: String,
    #[serde(default = "default_glesys_add_endpoint")]
    pub add_endpoint: String,
    #[serde(default = "default_glesys_list_endpoint")]
    pub list_endpoint: String,
    #[serde(default)]
    pub records: Vec<GlesysRecord>,
}

impl GlesysProvider {
    fn validate(&self, sources: &IpSources) -> Result<()> {
        ensure!(
            !self.records.is_empty(),
            "GleSYS provider requires at least one record entry"
        );

        for record in &self.records {
            ensure!(
                !record.domain.is_empty(),
                "Record '{}' must specify a domain",
                record.hostname
            );
            match record.record_type {
                RecordType::A => ensure!(
                    sources.ipv4.is_some(),
                    "Record '{}' of type A requires an ipv4 ip_source",
                    record.hostname
                ),
                RecordType::AAAA => ensure!(
                    sources.ipv6.is_some(),
                    "Record '{}' of type AAAA requires an ipv6 ip_source",
                    record.hostname
                ),
            }
        }

        Ok(())
    }

    pub fn min_ttl(&self) -> Option<u32> {
        self.records.iter().map(|record| record.ttl).min()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct GlesysRecord {
    #[serde(default)]
    pub record_id: Option<String>,
    pub domain: String,
    pub hostname: String,
    #[serde(default)]
    pub record_type: RecordType,
    #[serde(default = "default_glesys_ttl")]
    pub ttl: u32,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
}

impl Default for RecordType {
    fn default() -> Self {
        RecordType::A
    }
}

impl RecordType {
    pub fn as_api_value(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_api_value())
    }
}

fn default_glesys_ttl() -> u32 {
    300
}

fn default_glesys_update_endpoint() -> String {
    "https://api.glesys.com/domain/updaterecord".to_string()
}

fn default_glesys_add_endpoint() -> String {
    "https://api.glesys.com/domain/addrecord".to_string()
}

fn default_glesys_list_endpoint() -> String {
    "https://api.glesys.com/domain/listrecords".to_string()
}
