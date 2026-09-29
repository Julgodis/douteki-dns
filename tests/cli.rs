#[path = "../src/test_support.rs"]
mod test_support;

use serde_json::json;
use std::process::Command;
use test_support::{MockApi, TempDir};

#[test]
fn credentials_only_listing_discovers_zones_and_keeps_stdout_machine_readable() {
    let api = MockApi::new(vec![
        (
            200,
            json!({"response":{"domains":[{"domainname":"example.com"}]}}),
        ),
        (
            200,
            json!({"response":{"records":[{"recordid":42,"domainname":"example.com","host":"@","type":"A","data":"192.0.2.1","ttl":300}]}}),
        ),
    ]);
    let dir = TempDir::new();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        format!(
            r#"
[provider]
type="glesys"
api_user="test"
api_key="test"
domains_endpoint="{0}/domains"
list_endpoint="{0}/list"
"#,
            api.url
        ),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_douteki-dns"))
        .args(["--config", path.to_str().unwrap(), "glesys", "list-records"])
        .env("RUST_LOG", "debug")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "42\texample.com\tA\t192.0.2.1\tTTL 300\n"
    );
    assert_eq!(api.requests().len(), 2);
}

#[test]
fn invalid_configuration_exits_before_any_api_call() {
    let api = MockApi::new(vec![]);
    let dir = TempDir::new();
    let path = dir.path().join("config.toml");
    let cases = [
        (
            "type=\"static\"\nrecord_type=\"A\"\naddress=\"2001:db8::1\"",
            "incompatible",
        ),
        ("type=\"dynamic-ipv4\"\nrecordid=\"42\"", "unknown field"),
        (
            "type=\"text\"\nrecord_type=\"TXT\"\nvalue=\"ip6:{ipv6}\"",
            "requires an ipv6",
        ),
    ];
    for (record, error) in cases {
        std::fs::write(
            &path,
            format!(
                r#"
[provider]
type="glesys"
api_user="test"
api_key="test"
list_endpoint="{}/list"
[[provider.records]]
domain="example.com"
hostname="home"
{record}
"#,
                api.url
            ),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_douteki-dns"))
            .args(["--config", path.to_str().unwrap(), "ddns"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(api.requests().is_empty());
}
