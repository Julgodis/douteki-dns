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
