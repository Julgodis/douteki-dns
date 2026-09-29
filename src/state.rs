//! Durable ownership journal for PTR migration. Never infer old ownership from a target name.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OwnedPtr {
    pub domain: String,
    pub host: String,
    pub data: String,
    pub id: Option<String>,
}

pub struct PtrJournal {
    path: PathBuf,
    _lock: File,
    pub records: BTreeMap<String, Vec<OwnedPtr>>,
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    name.into()
}

impl PtrJournal {
    pub fn open(path: &Path) -> Result<Self> {
        let lock_path = sidecar(path, ".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("cannot open PTR state lock {}", lock_path.display()))?;
        lock.try_lock()
            .context("PTR state is in use by another updater")?;
        let records = match fs::read(path) {
            Ok(data) => serde_json::from_slice(&data).context("invalid PTR ownership state")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error).context("cannot read PTR ownership state"),
        };
        Ok(Self {
            path: path.into(),
            _lock: lock,
            records,
        })
    }

    pub fn save(&self) -> Result<()> {
        // The lock serializes writers; rename keeps a failed write from corrupting the journal.
        let temporary = sidecar(&self.path, ".tmp");
        let mut file = File::create(&temporary).context("cannot write PTR ownership state")?;
        file.write_all(&serde_json::to_vec_pretty(&self.records)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path).context("cannot replace PTR ownership state")?;
        File::open(
            self.path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?
        .sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trips_and_excludes_concurrent_writers() {
        let dir = crate::test_support::TempDir::new();
        let path = dir.path().join("state.json");
        let mut journal = PtrJournal::open(&path).unwrap();
        assert!(PtrJournal::open(&path).is_err());
        journal.records.insert(
            "entry".into(),
            vec![OwnedPtr {
                domain: "2.0.192.in-addr.arpa".into(),
                host: "1".into(),
                data: "home.example.com".into(),
                id: Some("1".into()),
            }],
        );
        journal.save().unwrap();
        let expected = journal.records.clone();
        drop(journal);
        assert_eq!(PtrJournal::open(&path).unwrap().records, expected);
        fs::write(&path, "corrupt state").unwrap();
        assert!(PtrJournal::open(&path).is_err());
    }
}
