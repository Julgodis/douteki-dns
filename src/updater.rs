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
