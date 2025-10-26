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
    #[serde(default = "default_glesys_delete_endpoint")]
    pub delete_endpoint: String,
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

            if record.data.requires_ipv4() {
                ensure!(
                    sources.ipv4.is_some(),
                    "Record '{}' with dynamic-ipv4 requires an ipv4 ip_source",
                    record.hostname
                );
            }

            if record.data.requires_ipv6() {
                ensure!(
                    sources.ipv6.is_some(),
                    "Record '{}' with dynamic-ipv6 requires an ipv6 ip_source",
                    record.hostname
                );
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
    #[serde(flatten)]
    pub data: RecordData,
    #[serde(default = "default_glesys_ttl")]
    pub ttl: u32,
    /// Optional interval in seconds for this specific record.
    /// If not set, uses the global check_interval_seconds.
    /// Static records without an interval are set once at startup.
    #[serde(default)]
    pub interval_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum RecordData {
    /// Dynamic IPv4 address record (A)
    DynamicIpv4,
    /// Dynamic IPv6 address record (AAAA)
    DynamicIpv6,
    /// Dynamic PTR record for IPv4 reverse DNS
    DynamicPtrV4 {
        /// The value/hostname to point to (e.g., "host.example.com")
        value: String,
    },
    /// Dynamic PTR record for IPv6 reverse DNS
    DynamicPtrV6 {
        /// The value/hostname to point to (e.g., "host.example.com")
        value: String,
    },
    /// Static text record (TXT, MX, etc.)
    Text { record_type: String, value: String },
    /// Static address record (A or AAAA)
    Static {
        record_type: DnsRecordType,
        address: IpAddr,
    },
}

impl RecordData {
    pub fn dns_record_type(&self) -> &str {
        match self {
            RecordData::DynamicIpv4 => "A",
            RecordData::DynamicIpv6 => "AAAA",
            RecordData::DynamicPtrV4 { .. } => "PTR",
            RecordData::DynamicPtrV6 { .. } => "PTR",
            RecordData::Text { record_type, .. } => record_type,
            RecordData::Static { record_type, .. } => record_type.as_str(),
        }
    }

    pub fn is_dynamic(&self) -> bool {
        matches!(
            self,
            RecordData::DynamicIpv4
                | RecordData::DynamicIpv6
                | RecordData::DynamicPtrV4 { .. }
                | RecordData::DynamicPtrV6 { .. }
        )
    }

    pub fn requires_ipv4(&self) -> bool {
        matches!(
            self,
            RecordData::DynamicIpv4 | RecordData::DynamicPtrV4 { .. }
        )
    }

    pub fn requires_ipv6(&self) -> bool {
        matches!(
            self,
            RecordData::DynamicIpv6 | RecordData::DynamicPtrV6 { .. }
        )
    }

    /// Check if this record type needs dynamic IP substitution in its value
    pub fn needs_ip_substitution(&self) -> bool {
        match self {
            RecordData::Text { value, .. } => value.contains("{ipv4}") || value.contains("{ipv6}"),
            _ => false,
        }
    }

    /// Generate the reverse DNS domain for an IP address
    pub fn reverse_dns_domain(ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!(
                    "{}.{}.{}.{}.in-addr.arpa",
                    octets[3], octets[2], octets[1], octets[0]
                )
            }
            IpAddr::V6(ipv6) => {
                let hex = format!("{:032x}", ipv6.to_bits());
                let mut result = String::new();
                for ch in hex.chars().rev() {
                    if !result.is_empty() {
                        result.push('.');
                    }
                    result.push(ch);
                }
                result.push_str(".ip6.arpa");
                result
            }
        }
    }
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    A,
    AAAA,
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Legacy type alias for backwards compatibility during transition
pub type RecordType = DnsRecordType;

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

fn default_glesys_delete_endpoint() -> String {
    "https://api.glesys.com/domain/deleterecord".to_string()
}
