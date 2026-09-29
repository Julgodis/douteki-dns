//! One update cycle. The caller supplies the clock and handles sleeping/logging.
use std::time::Duration;

use crate::{config::Config, ip, provider::UpdateReport, scheduler::Scheduler};

pub struct CycleReport {
    pub source_errors: Vec<String>,
    pub updates: UpdateReport,
}

pub fn cycle(
    config: &Config,
    client: &reqwest::blocking::Client,
    scheduler: &mut Scheduler,
    now: impl Fn() -> Duration,
) -> CycleReport {
    let due = scheduler.due(now());
    let (ipv4, ipv6) = scheduler.required_ips(&due);
    let resolved = ip::resolve_required(&config.ip_sources, client, ipv4, ipv6);
    let selected: Vec<_> = due
        .iter()
        .copied()
        .filter(|i| scheduler.needs_update(*i, &resolved.ips))
        .collect();
    let updates = config.provider.update(client, &resolved.ips, &selected);
    for (index, _) in &updates.errors {
        scheduler.failed(*index);
    }
    scheduler.finish(&due, &updates.applied, &resolved.ips, now());
    CycleReport {
        source_errors: resolved.errors,
        updates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{MockApi, TempDir};
    use serde_json::json;

    fn config(api: &MockApi, dir: &TempDir, source: &str, records: &str) -> Config {
        let config: Config = toml::from_str(&format!(
            r#"
check_interval_seconds=1
[ip_sources.ipv4]
{source}
[provider]
type="glesys"
api_user="test"
api_key="test"
list_endpoint="{0}/list"
add_endpoint="{0}/add"
update_endpoint="{0}/update"
delete_endpoint="{0}/delete"
domains_endpoint="{0}/domains"
ptr_state_file={1}
{records}
"#,
            api.url,
            serde_json::to_string(&dir.path().join("state.json")).unwrap()
        ))
        .unwrap();
        config.validate().unwrap();
        config
    }

    fn tick(config: &Config, scheduler: &mut Scheduler, seconds: u64) -> CycleReport {
        cycle(config, &reqwest::blocking::Client::new(), scheduler, || {
            Duration::from_secs(seconds)
        })
    }

    #[test]
    fn two_txt_records_survive_creation_and_a_fresh_process_schedule() {
        let rows = json!({"response":{"records":[
            {"recordid":"1","domainname":"example.com","host":"@","type":"TXT","ttl":300,"data":"one"},
            {"recordid":"2","domainname":"example.com","host":"@","type":"TXT","ttl":300,"data":"two"}
        ]}});
        let api = MockApi::new(vec![
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"1"}}})),
            (200, json!({"response":{"record":{"recordid":"2"}}})),
            (200, rows),
            (200, json!({})),
            (200, json!({})),
        ]);
        let dir = TempDir::new();
        let cfg = config(
            &api,
            &dir,
            "type=\"static\"\naddress=\"192.0.2.1\"",
            r#"
[[provider.records]]
domain="example.com"
hostname="@"
type="text"
record_type="TXT"
value="one"
[[provider.records]]
domain="example.com"
hostname="@"
type="text"
record_type="TXT"
value="two"
"#,
        );
        let mut scheduler = Scheduler::new(cfg.provider.records(), 1);
        assert_eq!(tick(&cfg, &mut scheduler, 0).updates.applied, [0, 1]);
        assert!(tick(&cfg, &mut scheduler, 1).updates.updates.is_empty());
        assert_eq!(api.requests().len(), 3);
        let mut restarted = Scheduler::new(cfg.provider.records(), 1);
        assert_eq!(tick(&cfg, &mut restarted, 0).updates.applied, [0, 1]);
        let requests = api.requests();
        assert_eq!(requests[4].1["recordid"], "1");
        assert_eq!(requests[5].1["recordid"], "2");
    }

    #[test]
    fn source_outage_applies_static_then_recovers_dynamic_without_rewriting_static() {
        let api = MockApi::new(vec![
            (503, json!({"error":"offline"})),
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"static"}}})),
            (200, json!("192.0.2.1")),
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"dynamic"}}})),
            (200, json!("192.0.2.1")),
        ]);
        let dir = TempDir::new();
        let cfg = config(
            &api,
            &dir,
            &format!("type=\"http\"\nurl=\"{}/ip\"", api.url),
            r#"
[[provider.records]]
domain="example.com"
hostname="dynamic"
type="dynamic-ipv4"
[[provider.records]]
domain="example.com"
hostname="static"
type="static"
record_type="A"
address="192.0.2.5"
"#,
        );
        let mut scheduler = Scheduler::new(cfg.provider.records(), 1);
        let first = tick(&cfg, &mut scheduler, 0);
        assert_eq!(first.source_errors.len(), 1);
        assert_eq!(first.updates.applied, [1]);
        assert_eq!(tick(&cfg, &mut scheduler, 1).updates.applied, [0]);
        assert!(tick(&cfg, &mut scheduler, 2).updates.updates.is_empty());
        let requests = api.requests();
        assert_eq!(requests.len(), 7);
        assert_eq!(
            requests
                .iter()
                .filter(|(_, p)| p["host"] == "static")
                .count(),
            1
        );
    }

    #[test]
    fn failed_record_retries_while_successful_sibling_stays_untouched() {
        let api = MockApi::new(vec![
            (200, json!({"response":{"records":[]}})),
            (503, json!({"error":"retry"})),
            (200, json!({"response":{"record":{"recordid":"healthy"}}})),
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"recovered"}}})),
        ]);
        let dir = TempDir::new();
        let cfg = config(
            &api,
            &dir,
            "type=\"static\"\naddress=\"192.0.2.1\"",
            r#"
[[provider.records]]
domain="example.com"
hostnames=["broken","healthy"]
type="dynamic-ipv4"
"#,
        );
        let mut scheduler = Scheduler::new(cfg.provider.records(), 1);
        let first = tick(&cfg, &mut scheduler, 0).updates;
        assert_eq!(first.errors.len(), 1);
        assert_eq!(first.applied, [1]);
        assert_eq!(tick(&cfg, &mut scheduler, 1).updates.applied, [0]);
        assert!(tick(&cfg, &mut scheduler, 2).updates.updates.is_empty());
        assert_eq!(api.requests().len(), 5);
    }

    #[test]
    fn record_interval_controls_source_polling_and_updates() {
        let api = MockApi::new(vec![
            (200, json!("192.0.2.1")),
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"1"}}})),
            (200, json!("192.0.2.2")),
            (
                200,
                json!({"response":{"records":[{"recordid":"1","domainname":"example.com","host":"home","type":"A","ttl":300,"data":"192.0.2.1"}]}}),
            ),
            (200, json!({})),
        ]);
        let dir = TempDir::new();
        let cfg = config(
            &api,
            &dir,
            &format!("type=\"http\"\nurl=\"{}/ip\"", api.url),
            r#"
[[provider.records]]
domain="example.com"
hostname="home"
type="dynamic-ipv4"
interval_seconds=3600
"#,
        );
        let mut scheduler = Scheduler::new(cfg.provider.records(), 1);
        assert_eq!(tick(&cfg, &mut scheduler, 0).updates.applied, [0]);
        assert!(tick(&cfg, &mut scheduler, 1).updates.updates.is_empty());
        assert_eq!(api.requests().len(), 3);
        assert_eq!(tick(&cfg, &mut scheduler, 3600).updates.applied, [0]);
        assert_eq!(api.requests().last().unwrap().1["data"], "192.0.2.2");
    }

    #[test]
    fn ptr_failure_retries_with_unchanged_ip() {
        let domains = json!({"response":{"domains":[{"domainname":"2.0.192.in-addr.arpa"}]}});
        let api = MockApi::new(vec![
            (200, domains.clone()),
            (200, json!({"response":{"records":[]}})),
            (503, json!({"error":"retry"})),
            (200, domains),
            (200, json!({"response":{"records":[]}})),
            (200, json!({"response":{"record":{"recordid":"1"}}})),
        ]);
        let dir = TempDir::new();
        let cfg = config(
            &api,
            &dir,
            "type=\"static\"\naddress=\"192.0.2.1\"",
            r#"
[[provider.records]]
domain="ptr"
hostname="v4"
type="dynamic-ptr-v4"
value="home.example.com"
"#,
        );
        let mut scheduler = Scheduler::new(cfg.provider.records(), 1);
        assert_eq!(tick(&cfg, &mut scheduler, 0).updates.errors.len(), 1);
        assert_eq!(tick(&cfg, &mut scheduler, 1).updates.applied, [0]);
        assert!(tick(&cfg, &mut scheduler, 2).updates.updates.is_empty());
        assert_eq!(api.requests().len(), 6);
    }
}
