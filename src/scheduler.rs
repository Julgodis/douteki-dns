use std::time::Duration;

use crate::config::GlesysRecord;
use crate::ip::ResolvedIps;

struct Entry {
    interval: Duration,
    next: Option<Duration>,
    last_applied: Option<ResolvedIps>,
    ipv4: bool,
    ipv6: bool,
    once: bool,
}

pub struct Scheduler {
    entries: Vec<Entry>,
}

impl Scheduler {
    pub fn new(records: &[GlesysRecord], default_interval: u64) -> Self {
        Self {
            entries: records
                .iter()
                .map(|record| {
                    let ipv4 = record.data.requires_ipv4();
                    let ipv6 = record.data.requires_ipv6();
                    Entry {
                        interval: Duration::from_secs(
                            record.interval_seconds.unwrap_or(default_interval).max(1),
                        ),
                        next: Some(Duration::ZERO),
                        last_applied: None,
                        ipv4,
                        ipv6,
                        once: !ipv4 && !ipv6 && record.interval_seconds.is_none(),
                    }
                })
                .collect(),
        }
    }

    pub fn due(&self, now: Duration) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.next.filter(|next| *next <= now).map(|_| i))
            .collect()
    }

    pub fn required_ips(&self, due: &[usize]) -> (bool, bool) {
        (
            due.iter().any(|i| self.entries[*i].ipv4),
            due.iter().any(|i| self.entries[*i].ipv6),
        )
    }

    pub fn needs_update(&self, index: usize, ips: &ResolvedIps) -> bool {
        let entry = &self.entries[index];
        if (entry.ipv4 && ips.ipv4.is_none()) || (entry.ipv6 && ips.ipv6.is_none()) {
            return false;
        }
        let relevant = entry.relevant(ips);
        // Static records with explicit intervals are periodically reconciled.
        (!entry.ipv4 && !entry.ipv6) || entry.last_applied.as_ref() != Some(&relevant)
    }

    pub fn finish(&mut self, due: &[usize], applied: &[usize], ips: &ResolvedIps, now: Duration) {
        for index in due {
            let entry = &mut self.entries[*index];
            if applied.contains(index) {
                entry.last_applied = Some(entry.relevant(ips));
            }
            entry.next = if entry.once && entry.last_applied.is_some() {
                None
            } else {
                Some(now.saturating_add(entry.interval))
            };
        }
    }

    pub fn delay(&self, now: Duration) -> Duration {
        self.entries
            .iter()
            .filter_map(|e| e.next)
            .min()
            .map(|next| next.saturating_sub(now))
            .unwrap_or(Duration::from_secs(60))
    }
}

impl Entry {
    fn relevant(&self, ips: &ResolvedIps) -> ResolvedIps {
        ResolvedIps {
            ipv4: ips.ipv4.filter(|_| self.ipv4),
            ipv6: ips.ipv6.filter(|_| self.ipv6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(kind: &str, interval: Option<u64>) -> GlesysRecord {
        let extra = if kind == "static" {
            "record_type=\"A\"\naddress=\"192.0.2.5\""
        } else {
            ""
        };
        toml::from_str(&format!(
            "domain=\"example.com\"\nhostname=\"home\"\ntype=\"{kind}\"\n{extra}\n{}",
            interval
                .map(|n| format!("interval_seconds={n}"))
                .unwrap_or_default()
        ))
        .unwrap()
    }

    #[test]
    fn schedules_records_independently_and_retries_only_failed_entries() {
        let mut scheduler = Scheduler::new(
            &[
                record("dynamic-ipv4", Some(3600)),
                record("dynamic-ipv4", Some(1)),
                record("static", None),
            ],
            300,
        );
        let ips = ResolvedIps {
            ipv4: Some("192.0.2.1".parse().unwrap()),
            ipv6: None,
        };
        assert_eq!(scheduler.due(Duration::ZERO), vec![0, 1, 2]);
        scheduler.finish(&[0, 1, 2], &[0, 2], &ips, Duration::ZERO);
        assert_eq!(scheduler.due(Duration::from_secs(1)), vec![1]);
        assert!(scheduler.needs_update(1, &ips));
        assert!(!scheduler.needs_update(0, &ips));
        assert_eq!(scheduler.due(Duration::from_secs(3600)), vec![0, 1]);
    }

    #[test]
    fn ipv6_changes_do_not_rewrite_ipv4_and_static_intervals_repeat() {
        let mut scheduler = Scheduler::new(
            &[record("dynamic-ipv4", None), record("static", Some(5))],
            10,
        );
        let mut ips = ResolvedIps {
            ipv4: Some("192.0.2.1".parse().unwrap()),
            ipv6: None,
        };
        scheduler.finish(&[0, 1], &[0, 1], &ips, Duration::ZERO);
        ips.ipv6 = Some("2001:db8::1".parse().unwrap());
        assert!(!scheduler.needs_update(0, &ips));
        assert!(scheduler.needs_update(1, &ips));
        assert_eq!(scheduler.due(Duration::from_secs(5)), vec![1]);
    }
}
