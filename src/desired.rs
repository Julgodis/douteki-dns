//! Pure calculation of record data, separate from scheduling and provider I/O.
use std::net::IpAddr;

use crate::config::RecordData;
use crate::ip::ResolvedIps;

pub struct DesiredData {
    pub value: String,
    pub ptr_ip: Option<IpAddr>,
}

pub fn resolve(data: &RecordData, ips: &ResolvedIps) -> Option<DesiredData> {
    let (value, ptr_ip) = match data {
        RecordData::DynamicIpv4 => (ips.ipv4?.to_string(), None),
        RecordData::DynamicIpv6 => (ips.ipv6?.to_string(), None),
        RecordData::DynamicPtrV4 { value } => (value.clone(), Some(IpAddr::V4(ips.ipv4?))),
        RecordData::DynamicPtrV6 { value } => (value.clone(), Some(IpAddr::V6(ips.ipv6?))),
        RecordData::Static { address, .. } => (address.to_string(), None),
        RecordData::Text { value, .. } => {
            let mut value = value.clone();
            if value.contains("{ipv4}") {
                value = value.replace("{ipv4}", &ips.ipv4?.to_string());
            }
            if value.contains("{ipv6}") {
                value = value.replace("{ipv6}", &ips.ipv6?.to_string());
            }
            (value, None)
        }
    };
    Some(DesiredData { value, ptr_ip })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_require_all_referenced_families_and_replace_every_occurrence() {
        let data = RecordData::Text {
            record_type: "TXT".into(),
            value: "{ipv4} {ipv6} {ipv4}".into(),
        };
        let mut ips = ResolvedIps {
            ipv4: Some("192.0.2.1".parse().unwrap()),
            ipv6: None,
        };
        assert!(resolve(&data, &ips).is_none());
        ips.ipv6 = Some("2001:db8::1".parse().unwrap());
        assert_eq!(
            resolve(&data, &ips).unwrap().value,
            "192.0.2.1 2001:db8::1 192.0.2.1"
        );
    }
}
