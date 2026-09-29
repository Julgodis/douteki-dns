use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use serde_json::{Value, json};
use tracing::debug;

use crate::config::{DnsProvider, GlesysProvider, GlesysRecord};
use crate::ip::ResolvedIps;

#[derive(Debug, Default)]
pub struct UpdateReport {
    pub updates: Vec<RecordUpdate>,
    pub errors: Vec<(usize, String)>,
    pub applied: Vec<usize>,
}

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
            domain: record.domain.trim_end_matches('.').to_ascii_lowercase(),
            host: record.hostname.to_ascii_lowercase(),
            record_type: record.data.dns_record_type().to_string(),
        }
    }

    fn from_listed(record: &GlesysListedRecord) -> Self {
        Self {
            domain: record.domain.trim_end_matches('.').to_ascii_lowercase(),
            host: record.host.to_ascii_lowercase(),
            record_type: record.record_type.to_ascii_uppercase(),
        }
    }
}

// Never guess which member of a record set the user intends to manage.
fn select_record(
    record: &GlesysRecord,
    data: &str,
    existing: &[GlesysListedRecord],
    claimed: &HashSet<String>,
    shared_key: bool,
) -> Result<Option<String>> {
    if let Some(id) = &record.record_id {
        ensure!(
            existing.iter().any(|r| &r.record_id == id),
            "record_id {id} does not match {} ({})",
            record.fqdn(),
            record.data.dns_record_type()
        );
        return Ok(Some(id.clone()));
    }
    let candidates: Vec<_> = existing
        .iter()
        .filter(|r| !claimed.contains(&r.record_id))
        .collect();
    let exact: Vec<_> = candidates.iter().filter(|r| r.data == data).collect();
    if exact.len() == 1 {
        return Ok(Some(exact[0].record_id.clone()));
    }
    if candidates.is_empty() {
        return Ok(None);
    }
    ensure!(
        !shared_key && candidates.len() == 1,
        "ambiguous records for {} ({}); set record_id explicitly",
        record.fqdn(),
        record.data.dns_record_type()
    );
    Ok(Some(candidates[0].record_id.clone()))
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
        selected: &[usize],
    ) -> UpdateReport {
        match self {
            DnsProvider::Glesys(config) => config.update_selected(client, ips, selected),
        }
    }
}

impl GlesysProvider {
    pub fn list_records(
        &self,
        client: &reqwest::blocking::Client,
        domains: &[String],
    ) -> Result<Vec<GlesysListedRecord>> {
        let discovered;
        let domains = if domains.is_empty() {
            discovered = self.list_domains(client)?;
            &discovered
        } else {
            domains
        };
        self.list_domains_records(client, domains.iter().map(String::as_str))
    }

    fn list_domains_records<'a>(
        &self,
        client: &reqwest::blocking::Client,
        domains: impl IntoIterator<Item = &'a str>,
    ) -> Result<Vec<GlesysListedRecord>> {
        let mut aggregated = Vec::new();
        for domain in domains {
            let parsed: GlesysListResponse = self.request(
                client,
                reqwest::Method::POST,
                &self.list_endpoint,
                Some(json!({"domainname": domain})),
            )?;
            aggregated.extend(parsed.response.records);
        }
        Ok(aggregated)
    }

    #[cfg(test)]
    fn update(&self, client: &reqwest::blocking::Client, ips: &ResolvedIps) -> UpdateReport {
        self.update_selected(client, ips, &(0..self.records.len()).collect::<Vec<_>>())
    }

    fn update_selected(
        &self,
        client: &reqwest::blocking::Client,
        ips: &ResolvedIps,
        selected: &[usize],
    ) -> UpdateReport {
        let mut report = UpdateReport::default();
        let mut existing: HashMap<String, Result<Vec<GlesysListedRecord>>> = HashMap::new();
        let mut claimed: HashSet<String> = self
            .records
            .iter()
            .filter_map(|r| r.record_id.clone())
            .collect();

        for &index in selected {
            let record = &self.records[index];
            let mut results = Vec::new();
            let outcome = (|| -> Result<bool> {
                let Some(desired) = crate::desired::resolve(&record.data, ips) else {
                    return Ok(false);
                };
                let data = desired.value;
                if let Some(ip) = desired.ptr_ip {
                    self.handle_ptr_record(client, record, ip, &data, &mut results)?;
                    return Ok(true);
                }

                let key = RecordKey::from_config(record);
                let shared_key = self
                    .records
                    .iter()
                    .filter(|r| RecordKey::from_config(r) == key)
                    .count()
                    > 1;
                let records = existing
                    .entry(record.domain.clone())
                    .or_insert_with(|| self.list_domains_records(client, [record.domain.as_str()]));
                let records = records
                    .as_ref()
                    .map_err(|error| anyhow::anyhow!("{error:#}"))?;
                let candidates: Vec<_> = records
                    .iter()
                    .filter(|r| RecordKey::from_listed(r) == key)
                    .cloned()
                    .collect();
                let record_id = select_record(record, &data, &candidates, &claimed, shared_key)?;

                match record_id {
                    Some(ref record_id) => {
                        debug!(
                            record_id = %record_id,
                            fqdn = %record.fqdn(),
                            record_type = %record.data.dns_record_type(),
                            data = %data,
                            "Preparing GleSYS update"
                        );

                        claimed.insert(record_id.clone());
                        self.update_record(client, record_id, record, &data)?;

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
                        claimed.insert(created_id.clone());

                        results.push(RecordUpdate::created(record, data, Some(created_id)));
                    }
                }
                Ok(true)
            })();
            report.updates.extend(results);
            match outcome {
                Ok(true) => report.applied.push(index),
                Ok(false) => {}
                Err(error) => report
                    .errors
                    .push((index, format!("{}: {error:#}", record.fqdn()))),
            }
        }
        report
    }

    fn request<T: serde::de::DeserializeOwned>(
        &self,
        client: &reqwest::blocking::Client,
        method: reqwest::Method,
        endpoint: &str,
        payload: Option<Value>,
    ) -> Result<T> {
        debug!(%endpoint, %method, "Sending GleSYS request");
        let mut request = client
            .request(method, endpoint)
            .basic_auth(&self.api_user, Some(&self.api_key));
        if let Some(payload) = payload {
            request = request.json(&payload);
        }
        let response = request
            .send()
            .with_context(|| format!("failed to call {endpoint}"))?;
        let status = response.status();
        let body = response
            .text()
            .with_context(|| format!("failed to read {endpoint}"))?;
        ensure!(
            status.is_success(),
            "GleSYS API error at {endpoint} ({status}): {body}"
        );
        serde_json::from_str(if body.trim().is_empty() {
            "null"
        } else {
            &body
        })
        .with_context(|| format!("invalid JSON response from {endpoint}"))
    }

    fn update_record(
        &self,
        client: &reqwest::blocking::Client,
        record_id: &str,
        record: &GlesysRecord,
        data: &str,
    ) -> Result<()> {
        let _: Value = self.request(client, reqwest::Method::POST, &self.update_endpoint, Some(json!({
            "recordid": record_id, "host": record.hostname, "type": record.data.dns_record_type(), "ttl": record.ttl, "data": data,
        })))?;
        Ok(())
    }

    fn create_record(
        &self,
        client: &reqwest::blocking::Client,
        record: &GlesysRecord,
        data: &str,
    ) -> Result<String> {
        let parsed: GlesysAddResponse = self.request(client, reqwest::Method::POST, &self.add_endpoint, Some(json!({
            "domainname": record.domain, "host": record.hostname, "type": record.data.dns_record_type(), "ttl": record.ttl, "data": data,
        })))?;
        Ok(parsed.response.record.record_id)
    }

    fn delete_record(&self, client: &reqwest::blocking::Client, record_id: &str) -> Result<()> {
        let _: Value = self.request(
            client,
            reqwest::Method::POST,
            &self.delete_endpoint,
            Some(json!({"recordid": record_id})),
        )?;
        Ok(())
    }

    pub fn list_domains(&self, client: &reqwest::blocking::Client) -> Result<Vec<String>> {
        let parsed: GlesysDomainsResponse =
            self.request(client, reqwest::Method::GET, &self.domains_endpoint, None)?;
        Ok(parsed
            .response
            .domains
            .into_iter()
            .map(|d| d.domainname.trim_end_matches('.').to_ascii_lowercase())
            .collect())
    }

    fn handle_ptr_record(
        &self,
        client: &reqwest::blocking::Client,
        record: &GlesysRecord,
        ip: IpAddr,
        hostname: &str,
        results: &mut Vec<RecordUpdate>,
    ) -> Result<()> {
        use crate::state::{OwnedPtr, PtrJournal};
        let reverse = crate::config::RecordData::reverse_dns_domain(ip);
        let domains = self.list_domains(client)?;
        let (host, domain) = reverse_location(&reverse, &domains)?;
        let mut desired = record.clone();
        desired.hostname = host.clone();
        desired.domain = domain.clone();
        let identity = serde_json::to_string(&(
            &self.api_user,
            &self.list_endpoint,
            RecordKey::from_config(record).domain,
            &record.hostname,
            record.data.dns_record_type(),
            record.data.requires_ipv4(),
        ))?;
        let mut journal = PtrJournal::open(&self.ptr_state_file)?;
        let previous = journal.records.get(&identity).cloned().unwrap_or_default();
        let listed = self.list_domains_records(client, [domain.as_str()])?;
        let key = RecordKey::from_config(&desired);
        let candidates: Vec<_> = listed
            .into_iter()
            .filter(|r| RecordKey::from_listed(r) == key)
            .collect();
        // An explicit ID bootstraps ownership. Later migrations must use the new reverse name.
        if !previous.is_empty() {
            desired.record_id = None;
        }
        if let Some(owned) = previous
            .iter()
            .find(|r| r.domain == domain && r.host == host)
            && let Some(id) = &owned.id
            && candidates.iter().any(|r| &r.record_id == id)
        {
            desired.record_id = Some(id.clone());
        }
        let id = select_record(&desired, hostname, &candidates, &HashSet::new(), false)?;
        // Save intent before creating: a restart can rediscover an interrupted successful add.
        let mut owned = OwnedPtr {
            domain,
            host,
            data: hostname.into(),
            id: id.clone(),
        };
        let mut pending = previous.clone();
        pending.retain(|r| !(r.domain == owned.domain && r.host == owned.host));
        pending.push(owned.clone());
        journal.records.insert(identity.clone(), pending);
        journal.save()?;
        let update = match id {
            Some(id) => {
                self.update_record(client, &id, &desired, hostname)?;
                RecordUpdate::updated(&desired, hostname.into(), Some(id))
            }
            None => {
                let id = self.create_record(client, &desired, hostname)?;
                RecordUpdate::created(&desired, hostname.into(), Some(id))
            }
        };
        owned.id = update.record_id.clone();
        let pending = journal.records.get_mut(&identity).unwrap();
        *pending.last_mut().unwrap() = owned.clone();
        journal.save()?;
        results.push(update);
        // Create the replacement first. Delete only records whose stored identity still matches.
        for old in previous {
            if old.domain == owned.domain && old.host == owned.host {
                continue;
            }
            let records = self.list_domains_records(client, [old.domain.as_str()])?;
            let matches: Vec<_> = records
                .iter()
                .filter(|r| {
                    if let Some(id) = &old.id {
                        &r.record_id == id
                    } else {
                        r.host == old.host && r.record_type == "PTR" && r.data == old.data
                    }
                })
                .collect();
            ensure!(
                matches.len() <= 1,
                "ambiguous interrupted PTR creation; refusing cleanup"
            );
            if let Some(existing) = matches.first() {
                ensure!(
                    existing.domain == old.domain
                        && existing.host == old.host
                        && existing.record_type == "PTR"
                        && existing.data == old.data,
                    "previous PTR was changed externally; refusing to delete {}",
                    existing.record_id
                );
                self.delete_record(client, &existing.record_id)?;
            }
            journal
                .records
                .get_mut(&identity)
                .unwrap()
                .retain(|r| r != &old);
            journal.save()?;
        }
        Ok(())
    }
}

fn reverse_location(reverse: &str, domains: &[String]) -> Result<(String, String)> {
    let domain = domains
        .iter()
        .filter(|domain| reverse == domain.as_str() || reverse.ends_with(&format!(".{domain}")))
        .max_by_key(|domain| domain.len())
        .with_context(|| format!("no delegated GleSYS reverse zone found for {reverse}"))?;
    let host = if reverse == domain {
        "@"
    } else {
        &reverse[..reverse.len() - domain.len() - 1]
    };
    Ok((host.into(), domain.clone()))
}

#[derive(Deserialize)]
struct GlesysDomainsResponse {
    response: GlesysDomainsBody,
}
#[derive(Deserialize)]
struct GlesysDomainsBody {
    domains: Vec<GlesysDomain>,
}
#[derive(Deserialize)]
struct GlesysDomain {
    domainname: String,
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

#[derive(Debug, Deserialize, Clone)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn txt() -> GlesysRecord {
        toml::from_str(
            r#"domain="example.com"
hostname="@"
type="text"
record_type="TXT"
value="one"
"#,
        )
        .unwrap()
    }

    fn listed(id: &str, data: &str) -> GlesysListedRecord {
        GlesysListedRecord {
            record_id: id.into(),
            domain: "example.com".into(),
            host: "@".into(),
            record_type: "TXT".into(),
            data: data.into(),
            ttl: 300,
        }
    }

    #[test]
    fn record_sets_match_by_value_or_require_an_explicit_id() {
        let existing = vec![listed("1", "one"), listed("2", "two")];
        assert_eq!(
            select_record(&txt(), "two", &existing, &HashSet::new(), true).unwrap(),
            Some("2".into())
        );
        assert!(select_record(&txt(), "new", &existing, &HashSet::new(), false).is_err());
        let mut record = txt();
        record.record_id = Some("1".into());
        assert_eq!(
            select_record(&record, "new", &existing, &HashSet::new(), true).unwrap(),
            Some("1".into())
        );
        record.record_id = Some("unknown".into());
        assert!(select_record(&record, "new", &existing, &HashSet::new(), true).is_err());
    }

    #[test]
    fn claimed_records_are_never_reused() {
        let existing = vec![listed("1", "one")];
        let claimed = HashSet::from(["1".into()]);
        assert_eq!(
            select_record(&txt(), "two", &existing, &claimed, true).unwrap(),
            None
        );
        assert_eq!(
            select_record(&txt(), "one", &[], &claimed, true).unwrap(),
            None
        );
    }

    fn ptr_provider(api: &crate::test_support::MockApi, state: &std::path::Path) -> GlesysProvider {
        toml::from_str(&format!(
            r#"
api_user="test"
api_key="test"
domains_endpoint="{0}/domains"
list_endpoint="{0}/list"
add_endpoint="{0}/add"
update_endpoint="{0}/update"
delete_endpoint="{0}/delete"
ptr_state_file={1}
[[records]]
domain="ignored-for-ptr"
hostname="ptr"
type="dynamic-ptr-v4"
value="home.example.com"
"#,
            api.url,
            serde_json::to_string(&state).unwrap()
        ))
        .unwrap()
    }

    #[test]
    fn ptr_failure_is_returned_to_the_retry_loop() {
        let api = crate::test_support::MockApi::new(vec![
            (
                200,
                json!({"response":{"domains":[{"domainname":"2.0.192.in-addr.arpa"}]}}),
            ),
            (200, json!({"response":{"records":[]}})),
            (503, json!({"error":"retry"})),
        ]);
        let dir = std::env::temp_dir().join(format!("ptr-failure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let provider = ptr_provider(&api, &dir.join("state.json"));
        let ips = ResolvedIps {
            ipv4: Some("192.0.2.1".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(
            provider
                .update(&reqwest::blocking::Client::new(), &ips)
                .errors
                .len(),
            1
        );
        assert_eq!(api.requests().len(), 3);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reverse_zone_uses_longest_delegated_suffix() {
        let zones = vec!["0.192.in-addr.arpa".into(), "2.0.192.in-addr.arpa".into()];
        assert_eq!(
            reverse_location("1.2.0.192.in-addr.arpa", &zones).unwrap(),
            ("1".into(), zones[1].clone())
        );
        assert!(reverse_location("1.2.0.193.in-addr.arpa", &zones).is_err());
        assert_eq!(
            reverse_location("a.b.c.ip6.arpa", &["c.ip6.arpa".into()])
                .unwrap()
                .0,
            "a.b"
        );
    }

    #[test]
    fn ptr_restart_discovers_existing_record_and_ip_change_cleans_owned_record() {
        let domains = json!({"response":{"domains":[{"domainname":"2.0.192.in-addr.arpa"}]}});
        let old = json!({"recordid":"1","domainname":"2.0.192.in-addr.arpa","host":"1","type":"PTR","data":"home.example.com","ttl":300});
        let api = crate::test_support::MockApi::new(vec![
            (200, domains.clone()),
            (200, json!({"response":{"records":[old.clone()]}})),
            (200, json!({})),
            (200, domains),
            (200, json!({"response":{"records":[old.clone()]}})),
            (200, json!({"response":{"record":{"recordid":"2"}}})),
            (200, json!({"response":{"records":[old]}})),
            (200, json!({})),
        ]);
        let dir = std::env::temp_dir().join(format!("ptr-restart-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("state.json");
        let client = reqwest::blocking::Client::new();
        let first = ResolvedIps {
            ipv4: Some("192.0.2.1".parse().unwrap()),
            ipv6: None,
        };
        assert!(
            ptr_provider(&api, &state)
                .update(&client, &first)
                .errors
                .is_empty()
        );
        let second = ResolvedIps {
            ipv4: Some("192.0.2.2".parse().unwrap()),
            ipv6: None,
        };
        assert!(
            ptr_provider(&api, &state)
                .update(&client, &second)
                .errors
                .is_empty()
        );
        let requests = api.requests();
        assert_eq!(requests.iter().filter(|(p, _)| p == "/add").count(), 1);
        assert_eq!(requests.last().unwrap().1["recordid"], "1");
        let journal = crate::state::PtrJournal::open(&state).unwrap();
        let owned = journal.records.values().next().unwrap();
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].id.as_deref(), Some("2"));
        drop(journal);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn failed_record_does_not_hide_successes_or_block_later_records() {
        let api = crate::test_support::MockApi::new(vec![
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"1"}}})),
            (503, json!({"error":"broken"})),
            (200, json!({"response":{"record":{"recordid":"3"}}})),
        ]);
        let provider: GlesysProvider = toml::from_str(&format!(
            r#"
api_user="test"
api_key="test"
list_endpoint="{0}/list"
add_endpoint="{0}/add"
[[records]]
domain="example.com"
hostnames=["first","broken","last"]
type="dynamic-ipv4"
"#,
            api.url
        ))
        .unwrap();
        let report = provider.update(
            &reqwest::blocking::Client::new(),
            &ResolvedIps {
                ipv4: Some("192.0.2.1".parse().unwrap()),
                ipv6: None,
            },
        );
        assert_eq!(report.applied, vec![0, 2]);
        assert_eq!(report.updates.len(), 2);
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].0, 1);
        assert_eq!(api.requests().last().unwrap().1["host"], "last");
    }
    #[test]
    fn missing_ips_only_skip_dependent_records() {
        let api = crate::test_support::MockApi::new(vec![
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"1"}}})),
        ]);
        let provider: GlesysProvider = toml::from_str(&format!(
            r#"
api_user="test"
api_key="test"
list_endpoint="{0}/list"
add_endpoint="{0}/add"
[[records]]
domain="example.com"
hostname="dynamic"
type="dynamic-ipv4"
[[records]]
domain="example.com"
hostname="static"
type="static"
record_type="A"
address="192.0.2.5"
"#,
            api.url
        ))
        .unwrap();
        let report = provider.update(
            &reqwest::blocking::Client::new(),
            &ResolvedIps {
                ipv4: None,
                ipv6: None,
            },
        );
        assert!(report.errors.is_empty());
        assert_eq!(report.applied, vec![1]);
        assert_eq!(api.requests().last().unwrap().1["data"], "192.0.2.5");
    }
}
