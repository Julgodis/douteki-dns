use std::fmt;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use std::net::IpAddr;

pub fn load_config(paths: &[impl AsRef<Path>]) -> Result<Config> {
    ensure!(
        !paths.is_empty(),
        "at least one configuration file is required"
    );
    let mut merged = toml::Value::Table(toml::map::Map::new());
    for path in paths {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read configuration file: {}", path.display()))?;
        let value: toml::Value = toml::from_str(&raw)
            .with_context(|| format!("failed to parse configuration TOML: {}", path.display()))?;
        merge_value(&mut merged, value);
    }
    let config: Config = merged
        .try_into()
        .context("failed to decode merged configuration")?;
    Ok(config)
}

fn merge_value(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base), toml::Value::Table(overlay)) => {
            for (key, value) in overlay {
                if let Some(existing) = base.get_mut(&key) {
                    merge_value(existing, value);
                } else {
                    base.insert(key, value);
                }
            }
        }
        (base, overlay) => *base = overlay,
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

    pub fn validate_provider(&self) -> Result<()> {
        match &self.provider {
            DnsProvider::Glesys(provider) => provider.validate_connection(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.check_interval_seconds != Some(0),
            "check_interval_seconds must be greater than zero"
        );
        for (family, source) in [
            ("ipv4", &self.ip_sources.ipv4),
            ("ipv6", &self.ip_sources.ipv6),
        ] {
            match source {
                Some(IpSource::Static { address }) => ensure!(
                    address.is_ipv4() == (family == "ipv4"),
                    "ip_sources.{family} has the wrong address family"
                ),
                Some(IpSource::Http { url }) => {
                    validate_url(url, &format!("ip_sources.{family}.url"))?
                }
                None => {}
            }
        }
        self.provider.validate(&self.ip_sources)
    }
}

fn validate_url(url: &str, name: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).with_context(|| format!("invalid URL for {name}"))?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https") && parsed.host_str().is_some(),
        "{name} must be an HTTP or HTTPS URL"
    );
    Ok(())
}

fn default_user_agent() -> String {
    format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
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

    pub fn records(&self) -> &[GlesysRecord] {
        match self {
            Self::Glesys(provider) => &provider.records,
        }
    }

    pub fn record_count(&self) -> usize {
        match self {
            DnsProvider::Glesys(provider) => provider.records.len(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlesysProvider {
    #[serde(default = "default_domains_endpoint")]
    pub domains_endpoint: String,
    #[serde(default = "default_ptr_state_file")]
    pub ptr_state_file: std::path::PathBuf,
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
    #[serde(default, deserialize_with = "deserialize_records")]
    pub records: Vec<GlesysRecord>,
}

impl GlesysProvider {
    fn validate_connection(&self) -> Result<()> {
        ensure!(
            !self.api_user.trim().is_empty() && !self.api_key.trim().is_empty(),
            "GleSYS api_user and api_key must not be empty"
        );
        for (name, url) in [
            ("update_endpoint", &self.update_endpoint),
            ("add_endpoint", &self.add_endpoint),
            ("list_endpoint", &self.list_endpoint),
            ("delete_endpoint", &self.delete_endpoint),
            ("domains_endpoint", &self.domains_endpoint),
        ] {
            validate_url(url, name)?;
        }
        ensure!(
            !self.ptr_state_file.as_os_str().is_empty(),
            "ptr_state_file must not be empty"
        );
        Ok(())
    }

    fn validate(&self, sources: &IpSources) -> Result<()> {
        self.validate_connection()?;
        let mut ids = std::collections::HashSet::new();
        let mut definitions = std::collections::HashSet::new();
        let mut ptr_families = std::collections::HashSet::new();
        ensure!(
            !self.records.is_empty(),
            "GleSYS provider requires at least one record entry"
        );

        for record in &self.records {
            ensure!(
                record.interval_seconds != Some(0),
                "interval_seconds for {} must be greater than zero",
                record.hostname
            );
            if let Some(id) = &record.record_id {
                ensure!(!id.trim().is_empty(), "record_id must not be empty");
                ensure!(
                    ids.insert(id),
                    "record_id {id} is used by more than one record"
                );
            }
            ensure!(
                definitions.insert(format!(
                    "{}|{}|{:?}",
                    record.domain, record.hostname, record.data
                )),
                "duplicate record definition for {}.{}",
                record.hostname,
                record.domain
            );
            if matches!(
                record.data,
                RecordData::DynamicPtrV4 { .. } | RecordData::DynamicPtrV6 { .. }
            ) {
                ensure!(
                    ptr_families.insert(record.data.requires_ipv4()),
                    "only one dynamic PTR entry per address family is supported"
                );
            }
            if let RecordData::Static {
                record_type,
                address,
            } = record.data
            {
                ensure!(
                    matches!(
                        (record_type, address),
                        (DnsRecordType::A, IpAddr::V4(_)) | (DnsRecordType::Aaaa, IpAddr::V6(_))
                    ),
                    "static record {} has an address incompatible with {record_type}",
                    record.hostname
                );
            }
            let kind = record.data.dns_record_type();
            ensure!(
                !kind.is_empty()
                    && kind
                        .chars()
                        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()),
                "record_type must be an uppercase DNS type for {}",
                record.hostname
            );
            ensure!(
                !record.domain.chars().any(char::is_whitespace)
                    && !record.hostname.chars().any(char::is_whitespace),
                "record domain and hostname must not contain whitespace"
            );
            ensure!(
                !record.domain.is_empty(),
                "Record '{}' must specify a domain",
                record.hostname
            );
            ensure!(
                !record.hostname.is_empty(),
                "Record in domain '{}' must specify a hostname",
                record.domain
            );

            if record.data.requires_ipv4() {
                ensure!(
                    sources.ipv4.is_some(),
                    "Record '{}' requires an ipv4 ip_source",
                    record.hostname
                );
            }

            if record.data.requires_ipv6() {
                ensure!(
                    sources.ipv6.is_some(),
                    "Record '{}' requires an ipv6 ip_source",
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

#[derive(Deserialize)]
struct GlesysRecordInput {
    #[serde(default)]
    record_id: Option<String>,
    domain: Option<String>,
    domains: Option<Vec<String>>,
    hostname: Option<String>,
    hostnames: Option<Vec<String>>,
    #[serde(flatten)]
    data: RecordData,
    #[serde(default = "default_glesys_ttl")]
    ttl: u32,
    #[serde(default)]
    interval_seconds: Option<u64>,
}

fn deserialize_records<'de, D>(deserializer: D) -> Result<Vec<GlesysRecord>, D::Error>
where
    D: Deserializer<'de>,
{
    let inputs = Vec::<toml::Value>::deserialize(deserializer)?;
    let mut records = Vec::new();
    for value in inputs {
        let table = value
            .as_table()
            .ok_or_else(|| de::Error::custom("record must be a table"))?;
        let kind = table
            .get("type")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        let common = [
            "record_id",
            "domain",
            "domains",
            "hostname",
            "hostnames",
            "type",
            "ttl",
            "interval_seconds",
        ];
        let specific: &[&str] = match kind {
            "text" => &["record_type", "value"],
            "static" => &["record_type", "address"],
            "dynamic-ptr-v4" | "dynamic-ptr-v6" => &["value"],
            _ => &[],
        };
        for key in table.keys() {
            if !common.contains(&key.as_str()) && !specific.contains(&key.as_str()) {
                return Err(de::Error::custom(format!(
                    "unknown field `{key}` in {kind} record"
                )));
            }
        }
        let input: GlesysRecordInput = value.try_into().map_err(de::Error::custom)?;
        let domains = match (input.domain, input.domains) {
            (Some(domain), None) => vec![domain],
            (None, Some(domains)) if !domains.is_empty() => domains,
            (None, Some(_)) => return Err(de::Error::custom("domains must not be empty")),
            (None, None) => return Err(de::Error::custom("record requires domain or domains")),
            _ => return Err(de::Error::custom("use either domain or domains")),
        };
        let hostnames = match (input.hostname, input.hostnames) {
            (Some(hostname), None) => vec![hostname],
            (None, Some(hostnames)) if !hostnames.is_empty() => hostnames,
            (None, Some(_)) => return Err(de::Error::custom("hostnames must not be empty")),
            (None, None) => return Err(de::Error::custom("record requires hostname or hostnames")),
            _ => return Err(de::Error::custom("use either hostname or hostnames")),
        };
        if input.record_id.is_some() && (domains.len() > 1 || hostnames.len() > 1) {
            return Err(de::Error::custom(
                "record_id cannot be shared by multiple domains or hostnames",
            ));
        }
        for domain in domains {
            for hostname in &hostnames {
                records.push(GlesysRecord {
                    record_id: input.record_id.clone(),
                    domain: domain.trim_end_matches('.').to_ascii_lowercase(),
                    hostname: hostname.trim_end_matches('.').to_ascii_lowercase(),
                    data: input.data.clone(),
                    ttl: input.ttl,
                    interval_seconds: input.interval_seconds,
                });
            }
        }
    }
    Ok(records)
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

    pub fn requires_ipv4(&self) -> bool {
        matches!(
            self,
            RecordData::DynamicIpv4 | RecordData::DynamicPtrV4 { .. }
        ) || matches!(self, RecordData::Text { value, .. } if value.contains("{ipv4}"))
    }

    pub fn requires_ipv6(&self) -> bool {
        matches!(
            self,
            RecordData::DynamicIpv6 | RecordData::DynamicPtrV6 { .. }
        ) || matches!(self, RecordData::Text { value, .. } if value.contains("{ipv6}"))
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
    Aaaa,
}

impl DnsRecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::Aaaa => "AAAA",
        }
    }
}

impl fmt::Display for DnsRecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn default_glesys_ttl() -> u32 {
    300
}

fn default_domains_endpoint() -> String {
    "https://api.glesys.com/domain/list".into()
}

fn default_ptr_state_file() -> std::path::PathBuf {
    "ptr-state.json".into()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn later_files_override_scalars_and_arrays_but_keep_other_table_keys() {
        let directory = std::env::temp_dir().join(format!(
            "douteki-dns-config-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let first = directory.join("first.toml");
        let second = directory.join("second.toml");
        fs::write(
            &first,
            r#"
user_agent = "first"
[ip_sources.ipv4]
type = "static"
address = "192.0.2.1"
[provider]
type = "glesys"
api_user = "user"
api_key = "old-key"
[[provider.records]]
domain = "old.example"
hostname = "old"
type = "dynamic-ipv4"
"#,
        )
        .unwrap();
        fs::write(
            &second,
            r#"
user_agent = "second"
[provider]
api_key = "new-key"
[[provider.records]]
domain = "example.com"
hostnames = ["a", "b", "*"]
type = "dynamic-ipv4"
ttl = 120
"#,
        )
        .unwrap();

        let config = load_config(&[&first, &second]).unwrap();
        assert_eq!(config.user_agent(), "second");
        assert!(matches!(
            config.ip_sources.ipv4,
            Some(IpSource::Static { .. })
        ));
        let DnsProvider::Glesys(provider) = config.provider;
        assert_eq!(provider.api_user, "user");
        assert_eq!(provider.api_key, "new-key");
        assert_eq!(provider.records.len(), 3);
        assert_eq!(provider.records[0].hostname, "a");
        assert_eq!(provider.records[1].hostname, "b");
        assert_eq!(provider.records[2].hostname, "*");
        assert!(provider.records.iter().all(|record| record.ttl == 120));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn plural_domains_expand_and_shared_record_id_is_rejected() {
        let raw = r#"
[provider]
type = "glesys"
api_user = "user"
api_key = "key"
[[provider.records]]
domains = ["example.com", "example.net"]
hostnames = ["a", "b"]
type = "dynamic-ipv4"
"#;
        let config: Config = toml::from_str(raw).unwrap();
        let DnsProvider::Glesys(provider) = config.provider;
        let names: Vec<_> = provider
            .records
            .iter()
            .map(|r| (r.domain.as_str(), r.hostname.as_str()))
            .collect();
        assert_eq!(
            names,
            [
                ("example.com", "a"),
                ("example.com", "b"),
                ("example.net", "a"),
                ("example.net", "b")
            ]
        );
        assert!(
            toml::from_str::<Config>(&raw.replace(
                "type = \"dynamic-ipv4\"",
                "type = \"dynamic-ipv4\"\nrecord_id = \"123\""
            ))
            .is_err()
        );
    }
    fn checked_config(extra: &str) -> Result<Config> {
        let config: Config = toml::from_str(&format!(
            r#"
[provider]
type="glesys"
api_user="test"
api_key="test"
[[provider.records]]
domain="example.com"
hostname="home"
{extra}
"#
        ))?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn rejects_wrong_families_missing_template_sources_and_unknown_fields() {
        assert!(
            checked_config("type=\"static\"\nrecord_type=\"A\"\naddress=\"2001:db8::1\"").is_err()
        );
        assert!(
            checked_config("type=\"text\"\nrecord_type=\"TXT\"\nvalue=\"ip6:{ipv6}\"").is_err()
        );
        assert!(checked_config("type=\"dynamic-ipv4\"\nrecordid=\"123\"").is_err());
        assert!(checked_config("type=\"dynamic-ipv4\"\ninterval_seconds=0").is_err());
        assert!(checked_config("type=\"dynamic-ipv4\"").is_ok());
    }
}
