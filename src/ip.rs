use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};

use crate::config::{IpSource, IpSources, RecordType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIps {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

impl ResolvedIps {
    pub fn ip_for(&self, record_type: RecordType) -> Option<IpAddr> {
        match record_type {
            RecordType::A => self.ipv4.map(IpAddr::V4),
            RecordType::AAAA => self.ipv6.map(IpAddr::V6),
        }
    }
}

pub struct ResolveReport {
    pub ips: ResolvedIps,
    pub errors: Vec<String>,
}

pub fn resolve_all(sources: &IpSources, client: &reqwest::blocking::Client) -> ResolveReport {
    let mut errors = Vec::new();

    let ipv4 = match &sources.ipv4 {
        Some(source) => match source.resolve(client) {
            Ok(addr) => match ensure_ipv4(addr) {
                Ok(v4) => Some(v4),
                Err(err) => {
                    errors.push(format!("{err:#}"));
                    None
                }
            },
            Err(err) => {
                errors.push(format!("{err:#}"));
                None
            }
        },
        None => None,
    };

    let ipv6 = match &sources.ipv6 {
        Some(source) => match source.resolve(client) {
            Ok(addr) => match ensure_ipv6(addr) {
                Ok(v6) => Some(v6),
                Err(err) => {
                    errors.push(format!("{err:#}"));
                    None
                }
            },
            Err(err) => {
                errors.push(format!("{err:#}"));
                None
            }
        },
        None => None,
    };

    ResolveReport {
        ips: ResolvedIps { ipv4, ipv6 },
        errors,
    }
}

impl IpSource {
    pub fn resolve(&self, client: &reqwest::blocking::Client) -> Result<IpAddr> {
        match self {
            IpSource::Http { url } => resolve_http(url, client),
            IpSource::Static { address } => Ok(*address),
        }
    }
}

fn resolve_http(url: &str, client: &reqwest::blocking::Client) -> Result<IpAddr> {
    let response = client
        .get(url)
        .send()
        .with_context(|| format!("failed to fetch public IP from {}", url))?;

    let status = response.status();
    let body = response.text().context("failed to read IP response body")?;

    anyhow::ensure!(
        status.is_success(),
        "HTTP {} when fetching IP from {}: {}",
        status,
        url,
        body
    );

    let trimmed = body.trim();
    trimmed
        .parse()
        .with_context(|| format!("failed to parse '{}' as an IP address", trimmed))
}

fn ensure_ipv4(addr: IpAddr) -> Result<Ipv4Addr> {
    match addr {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(v6) => bail!("expected IPv4 address but received IPv6 {}", v6),
    }
}

fn ensure_ipv6(addr: IpAddr) -> Result<Ipv6Addr> {
    match addr {
        IpAddr::V6(v6) => Ok(v6),
        IpAddr::V4(v4) => bail!("expected IPv6 address but received IPv4 {}", v4),
    }
}
