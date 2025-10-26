use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::config::{DnsProvider, GlesysProvider, GlesysRecord, RecordType};
use crate::ip::ResolvedIps;

#[derive(Debug, Clone)]
pub struct RecordUpdate {
    pub fqdn: String,
    pub record_type: RecordType,
    pub ip: IpAddr,
    pub outcome: UpdateOutcome,
    pub record_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOutcome {
    Created,
    Updated,
}

impl UpdateOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateOutcome::Created => "created",
            UpdateOutcome::Updated => "updated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RecordKey {
    domain: String,
    host: String,
    record_type: String,
}

impl RecordKey {
    fn from_config(record: &GlesysRecord) -> Self {
        Self {
            domain: record.domain.clone(),
            host: record.hostname.clone(),
            record_type: record.record_type.as_api_value().to_string(),
        }
    }

    fn from_listed(record: &GlesysListedRecord) -> Self {
        Self {
            domain: record.domain.clone(),
            host: record.host.clone(),
            record_type: record.record_type.clone(),
        }
    }
}

impl RecordUpdate {
    fn new(
        record: &GlesysRecord,
        ip: IpAddr,
        outcome: UpdateOutcome,
        record_id: Option<String>,
    ) -> Self {
        Self {
            fqdn: record.fqdn(),
            record_type: record.record_type,
            ip,
            outcome,
            record_id,
        }
    }

    fn updated(record: &GlesysRecord, ip: IpAddr, record_id: Option<String>) -> Self {
        Self::new(record, ip, UpdateOutcome::Updated, record_id)
    }

    fn created(record: &GlesysRecord, ip: IpAddr, record_id: Option<String>) -> Self {
        Self::new(record, ip, UpdateOutcome::Created, record_id)
    }
}

impl DnsProvider {
    pub fn update(
        &self,
        client: &reqwest::blocking::Client,
        ips: &ResolvedIps,
    ) -> Result<Vec<RecordUpdate>> {
        match self {
            DnsProvider::Glesys(config) => config.update(client, ips),
        }
    }
}

impl GlesysProvider {
    pub fn list_records(
        &self,
        client: &reqwest::blocking::Client,
    ) -> Result<Vec<GlesysListedRecord>> {
        let mut aggregated = Vec::new();
        for domain in self.unique_domains() {
            let payload = json!({ "domainname": domain });

            debug!(
                endpoint = %self.list_endpoint,
                domain,
                ?payload,
                "Sending GleSYS listrecords request"
            );

            let response = client
                .post(&self.list_endpoint)
                .basic_auth(&self.api_user, Some(&self.api_key))
                .json(&payload)
                .send()
                .with_context(|| {
                    format!("failed to send listrecords request for domain {domain}")
                })?;

            let status = response.status();
            let body = response
                .text()
                .context("failed to read response from GleSYS listrecords API")?;

            debug!(
                endpoint = %self.list_endpoint,
                domain,
                status = %status,
                body = %body,
                "Received GleSYS listrecords response"
            );

            ensure!(
                status.is_success(),
                "GleSYS listrecords error ({}): {}",
                status,
                body
            );

            let parsed: GlesysListResponse = serde_json::from_str(&body)
                .context("failed to parse GleSYS listrecords response as JSON")?;

            debug!(
                domain,
                count = parsed.response.records.len(),
                "Parsed GleSYS listrecords payload"
            );

            aggregated.extend(parsed.response.records.into_iter());
        }

        Ok(aggregated)
    }

    fn update(
        &self,
        client: &reqwest::blocking::Client,
        ips: &ResolvedIps,
    ) -> Result<Vec<RecordUpdate>> {
        let mut results = Vec::with_capacity(self.records.len());
        let mut existing_ids = self.fetch_existing_record_ids(client)?;

        for record in &self.records {
            let Some(ip) = ips.ip_for(record.record_type) else {
                warn!(
                    record_id = record.record_id.as_deref(),
                    fqdn = %record.fqdn(),
                    record_type = %record.record_type,
                    "Skipping GleSYS update; no resolved IP"
                );
                continue;
            };

            let key = RecordKey::from_config(record);
            let record_id = record
                .record_id
                .clone()
                .or_else(|| existing_ids.get(&key).cloned());

            match record_id {
                Some(ref record_id) => {
                    debug!(
                        record_id = %record_id,
                        fqdn = %record.fqdn(),
                        record_type = %record.record_type,
                        ip = %ip,
                        "Preparing GleSYS update"
                    );

                    self.update_record(client, record_id, record, ip)?;
                    existing_ids.insert(key, record_id.clone());

                    results.push(RecordUpdate::updated(record, ip, Some(record_id.clone())));
                }
                None => {
                    debug!(
                        fqdn = %record.fqdn(),
                        record_type = %record.record_type,
                        ip = %ip,
                        "Preparing GleSYS addrecord"
                    );

                    let created_id = self.create_record(client, record, ip)?;
                    existing_ids.insert(key, created_id.clone());

                    results.push(RecordUpdate::created(record, ip, Some(created_id)));
                }
            }
        }

        Ok(results)
    }

    fn fetch_existing_record_ids(
        &self,
        client: &reqwest::blocking::Client,
    ) -> Result<HashMap<RecordKey, String>> {
        let mut map = HashMap::new();
        for record in self.list_records(client)? {
            map.insert(RecordKey::from_listed(&record), record.record_id.clone());
        }
        Ok(map)
    }

    fn update_record(
        &self,
        client: &reqwest::blocking::Client,
        record_id: &str,
        record: &GlesysRecord,
        ip: IpAddr,
    ) -> Result<()> {
        let payload = json!({
            "recordid": record_id,
            "domainname": record.domain,
            "host": record.hostname,
            "recordtype": record.record_type.as_api_value(),
            "ttl": record.ttl,
            "data": ip.to_string(),
        });

        debug!(
            endpoint = %self.update_endpoint,
            record_id = %record_id,
            fqdn = %record.fqdn(),
            record_type = %record.record_type,
            ttl = record.ttl,
            ip = %ip,
            ?payload,
            "Sending GleSYS update request"
        );

        let response = client
            .post(&self.update_endpoint)
            .basic_auth(&self.api_user, Some(&self.api_key))
            .json(&payload)
            .send()
            .context("failed to send request to GleSYS API")?;

        let status = response.status();
        let body = response
            .text()
            .context("failed to read response from GleSYS API")?;

        debug!(
            endpoint = %self.update_endpoint,
            record_id = %record_id,
            status = %status,
            body = %body,
            "Received GleSYS update response"
        );

        ensure!(
            status.is_success(),
            "GleSYS API error ({}): {}",
            status,
            body
        );

        Ok(())
    }

    fn create_record(
        &self,
        client: &reqwest::blocking::Client,
        record: &GlesysRecord,
        ip: IpAddr,
    ) -> Result<String> {
        let payload = json!({
            "domainname": record.domain,
            "host": record.hostname,
            "recordtype": record.record_type.as_api_value(),
            "ttl": record.ttl,
            "data": ip.to_string(),
        });

        debug!(
            endpoint = %self.add_endpoint,
            fqdn = %record.fqdn(),
            record_type = %record.record_type,
            ttl = record.ttl,
            ip = %ip,
            ?payload,
            "Sending GleSYS addrecord request"
        );

        let response = client
            .post(&self.add_endpoint)
            .basic_auth(&self.api_user, Some(&self.api_key))
            .json(&payload)
            .send()
            .context("failed to send request to GleSYS addrecord API")?;

        let status = response.status();
        let body = response
            .text()
            .context("failed to read response from GleSYS addrecord API")?;

        debug!(
            endpoint = %self.add_endpoint,
            status = %status,
            body = %body,
            "Received GleSYS addrecord response"
        );

        ensure!(
            status.is_success(),
            "GleSYS addrecord error ({}): {}",
            status,
            body
        );

        let parsed: GlesysAddResponse = serde_json::from_str(&body)
            .context("failed to parse GleSYS addrecord response as JSON")?;

        Ok(parsed.response.record.record_id)
    }

    fn unique_domains(&self) -> BTreeSet<&str> {
        self.records
            .iter()
            .map(|record| record.domain.as_str())
            .collect()
    }
}

impl GlesysRecord {
    fn fqdn(&self) -> String {
        if self.hostname == "@" {
            self.domain.clone()
        } else {
            format!("{}.{}", self.hostname, self.domain)
        }
    }
}

#[derive(Debug, Deserialize)]
struct GlesysListResponse {
    response: GlesysListResponseBody,
}

#[derive(Debug, Deserialize)]
struct GlesysListResponseBody {
    records: Vec<GlesysListedRecord>,
}

#[derive(Debug, Deserialize)]
pub struct GlesysListedRecord {
    #[serde(rename = "recordid", deserialize_with = "deserialize_stringlike")]
    pub record_id: String,
    #[serde(rename = "domainname")]
    pub domain: String,
    pub host: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

impl GlesysListedRecord {
    pub fn fqdn(&self) -> String {
        if self.host == "@" {
            self.domain.clone()
        } else {
            format!("{}.{}", self.host, self.domain)
        }
    }
}

#[derive(Debug, Deserialize)]
struct GlesysAddResponse {
    response: GlesysAddResponseBody,
}

#[derive(Debug, Deserialize)]
struct GlesysAddResponseBody {
    record: GlesysAddResponseRecord,
}

#[derive(Debug, Deserialize)]
struct GlesysAddResponseRecord {
    #[serde(rename = "recordid", deserialize_with = "deserialize_stringlike")]
    record_id: String,
}

fn deserialize_stringlike<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    match value {
        Value::String(s) => Ok(s),
        Value::Number(num) => Ok(num.to_string()),
        other => Err(de::Error::custom(format!(
            "expected string or number, got {}",
            other
        ))),
    }
}
