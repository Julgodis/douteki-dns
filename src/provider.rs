use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use serde_json::{Value, json};
use tracing::{debug, warn};

use crate::config::{DnsProvider, GlesysProvider, GlesysRecord};
use crate::ip::ResolvedIps;

#[derive(Debug, Clone)]
pub struct RecordUpdate {
    pub fqdn: String,
    pub record_type: String,
    pub data: String,
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
            record_type: record.data.dns_record_type().to_string(),
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
        data: String,
        outcome: UpdateOutcome,
        record_id: Option<String>,
    ) -> Self {
        Self {
            fqdn: record.fqdn(),
            record_type: record.data.dns_record_type().to_string(),
            data,
            outcome,
            record_id,
        }
    }

    fn updated(record: &GlesysRecord, data: String, record_id: Option<String>) -> Self {
        Self::new(record, data, UpdateOutcome::Updated, record_id)
    }

    fn created(record: &GlesysRecord, data: String, record_id: Option<String>) -> Self {
        Self::new(record, data, UpdateOutcome::Created, record_id)
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
            use crate::config::RecordData;

            // Determine the data value and handle PTR records specially
            let (data, ptr_info) = match &record.data {
                RecordData::DynamicIpv4 => {
                    let Some(ip) = ips.ipv4 else {
                        warn!(
                            record_id = record.record_id.as_deref(),
                            fqdn = %record.fqdn(),
                            "Skipping dynamic-ipv4 record; no resolved IPv4"
                        );
                        continue;
                    };
                    (ip.to_string(), None)
                }
                RecordData::DynamicIpv6 => {
                    let Some(ip) = ips.ipv6 else {
                        warn!(
                            record_id = record.record_id.as_deref(),
                            fqdn = %record.fqdn(),
                            "Skipping dynamic-ipv6 record; no resolved IPv6"
                        );
                        continue;
                    };
                    (ip.to_string(), None)
                }
                RecordData::DynamicPtrV4 { value } => {
                    let Some(ip) = ips.ipv4 else {
                        warn!(
                            record_id = record.record_id.as_deref(),
                            hostname = %record.hostname,
                            "Skipping dynamic-ptr-v4 record; no resolved IPv4"
                        );
                        continue;
                    };
                    (value.clone(), Some((IpAddr::V4(ip), value.clone())))
                }
                RecordData::DynamicPtrV6 { value } => {
                    let Some(ip) = ips.ipv6 else {
                        warn!(
                            record_id = record.record_id.as_deref(),
                            hostname = %record.hostname,
                            "Skipping dynamic-ptr-v6 record; no resolved IPv6"
                        );
                        continue;
                    };
                    (value.clone(), Some((IpAddr::V6(ip), value.clone())))
                }
                RecordData::Text { value, .. } => (value.clone(), None),
                RecordData::Static { address, .. } => (address.to_string(), None),
            };

            // For PTR records, we need to handle them differently
            if let Some((ip, hostname)) = ptr_info {
                self.handle_ptr_record(
                    client,
                    record,
                    ip,
                    &hostname,
                    &mut existing_ids,
                    &mut results,
                )?;
                continue;
            }

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
                        record_type = %record.data.dns_record_type(),
                        data = %data,
                        "Preparing GleSYS update"
                    );

                    self.update_record(client, record_id, record, &data)?;
                    existing_ids.insert(key, record_id.clone());

                    results.push(RecordUpdate::updated(
                        record,
                        data.clone(),
                        Some(record_id.clone()),
                    ));
                }
                None => {
                    debug!(
                        fqdn = %record.fqdn(),
                        record_type = %record.data.dns_record_type(),
                        data = %data,
                        "Preparing GleSYS addrecord"
                    );

                    let created_id = self.create_record(client, record, &data)?;
                    existing_ids.insert(key, created_id.clone());

                    results.push(RecordUpdate::created(record, data, Some(created_id)));
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
        data: &str,
    ) -> Result<()> {
        let payload = json!({
            "recordid": record_id,
            "host": record.hostname,
            "type": record.data.dns_record_type(),
            "ttl": record.ttl,
            "data": data,
        });

        debug!(
            endpoint = %self.update_endpoint,
            record_id = %record_id,
            fqdn = %record.fqdn(),
            record_type = %record.data.dns_record_type(),
            ttl = record.ttl,
            data = %data,
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
        data: &str,
    ) -> Result<String> {
        let payload = json!({
            "domainname": record.domain,
            "host": record.hostname,
            "type": record.data.dns_record_type(),
            "ttl": record.ttl,
            "data": data,
        });

        debug!(
            endpoint = %self.add_endpoint,
            fqdn = %record.fqdn(),
            record_type = %record.data.dns_record_type(),
            ttl = record.ttl,
            data = %data,
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

    fn delete_record(&self, client: &reqwest::blocking::Client, record_id: &str) -> Result<()> {
        let payload = json!({
            "recordid": record_id,
        });

        debug!(
            endpoint = %self.delete_endpoint,
            record_id = %record_id,
            ?payload,
            "Sending GleSYS deleterecord request"
        );

        let response = client
            .post(&self.delete_endpoint)
            .basic_auth(&self.api_user, Some(&self.api_key))
            .json(&payload)
            .send()
            .context("failed to send request to GleSYS deleterecord API")?;

        let status = response.status();
        let body = response
            .text()
            .context("failed to read response from GleSYS deleterecord API")?;

        debug!(
            endpoint = %self.delete_endpoint,
            record_id = %record_id,
            status = %status,
            body = %body,
            "Received GleSYS deleterecord response"
        );

        ensure!(
            status.is_success(),
            "GleSYS deleterecord error ({}): {}",
            status,
            body
        );

        Ok(())
    }

    fn handle_ptr_record(
        &self,
        client: &reqwest::blocking::Client,
        record: &GlesysRecord,
        ip: IpAddr,
        hostname: &str,
        existing_ids: &mut HashMap<RecordKey, String>,
        results: &mut Vec<RecordUpdate>,
    ) -> Result<()> {
        use crate::config::RecordData;

        // Generate the reverse DNS domain from the IP
        let reverse_domain = RecordData::reverse_dns_domain(ip);

        // Extract the hostname part (first label) and domain part
        let (ptr_host, ptr_domain) = if let Some(pos) = reverse_domain.find('.') {
            let (h, d) = reverse_domain.split_at(pos);
            (h.to_string(), d[1..].to_string()) // Skip the leading '.'
        } else {
            (reverse_domain.clone(), String::new())
        };

        // Create a modified record for PTR with the computed domain
        let ptr_key = RecordKey {
            domain: ptr_domain.clone(),
            host: ptr_host.clone(),
            record_type: "PTR".to_string(),
        };

        // Check if we already have a PTR record for this IP
        let existing_id = existing_ids.get(&ptr_key).cloned();

        // Also check if we have PTR records for the original hostname/domain
        // (from before the IP changed) and delete them
        let original_key = RecordKey::from_config(record);
        if let Some(old_id) = existing_ids.get(&original_key) {
            if original_key != ptr_key {
                debug!(
                    record_id = %old_id,
                    old_domain = %original_key.domain,
                    old_host = %original_key.host,
                    new_domain = %ptr_domain,
                    new_host = %ptr_host,
                    "Deleting old PTR record after IP change"
                );
                self.delete_record(client, old_id)?;
                existing_ids.remove(&original_key);
            }
        }

        match existing_id {
            Some(ref record_id) => {
                debug!(
                    record_id = %record_id,
                    reverse_domain = %reverse_domain,
                    hostname = %hostname,
                    ip = %ip,
                    "Updating PTR record"
                );

                // Create a temporary record with the PTR domain info
                let mut ptr_record = record.clone();
                ptr_record.domain = ptr_domain.clone();
                ptr_record.hostname = ptr_host.clone();

                self.update_record(client, record_id, &ptr_record, hostname)?;
                existing_ids.insert(ptr_key, record_id.clone());

                results.push(RecordUpdate {
                    fqdn: reverse_domain,
                    record_type: "PTR".to_string(),
                    data: hostname.to_string(),
                    outcome: UpdateOutcome::Updated,
                    record_id: Some(record_id.clone()),
                });
            }
            None => {
                debug!(
                    reverse_domain = %reverse_domain,
                    hostname = %hostname,
                    ip = %ip,
                    "Creating PTR record"
                );

                // Create a temporary record with the PTR domain info
                let mut ptr_record = record.clone();
                ptr_record.domain = ptr_domain.clone();
                ptr_record.hostname = ptr_host.clone();

                let created_id = self.create_record(client, &ptr_record, hostname)?;
                existing_ids.insert(ptr_key, created_id.clone());

                results.push(RecordUpdate {
                    fqdn: reverse_domain,
                    record_type: "PTR".to_string(),
                    data: hostname.to_string(),
                    outcome: UpdateOutcome::Created,
                    record_id: Some(created_id),
                });
            }
        }

        Ok(())
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
