use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

type Subdomain = String;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Record {
    pub subdomain: Subdomain,
    pub txt: String,
}

pub struct RecordStore {
    records: HashMap<Subdomain, (Record, Instant)>,
    threshold: Duration,
    verbose: bool,
}

impl RecordStore {
    pub fn new(threshold: Duration, verbose: bool) -> Self {
        Self {
            records: HashMap::new(),
            threshold,
            verbose,
        }
    }

    /// Adds the given record or refreshes an existing entry. Returns true if it was not present before
    pub fn add(&mut self, record: Record) -> bool {
        let changed = self
            .records
            .get(&record.subdomain)
            .map(|v| v.0 != record)
            .unwrap_or_default();

        let added = self
            .records
            .insert(record.subdomain.clone(), (record.clone(), Instant::now()))
            .is_none();

        if self.verbose && added {
            println!("+ TXT {}", record.subdomain);
        } else if self.verbose && changed {
            println!("~ TXT {}", record.subdomain);
        }

        added || changed
    }

    /// Removes stale entries from the store
    pub fn purge_old(&mut self) -> usize {
        // Find expired records
        let expired_keys = self
            .records
            .iter()
            .filter(|(_, (_, time))| (Instant::now() - *time) > self.threshold)
            .map(|(key, _)| key.clone())
            .collect::<Vec<_>>();

        // Remove expired entries
        for key in expired_keys.iter() {
            println!("- TXT {}", key);
            self.records.remove(key);
        }

        expired_keys.len()
    }

    /// Lists all currently stored entries. Note that some might be stale if you did not call `purge_old` recently.
    pub fn entries(&self) -> Vec<&Record> {
        self.records.values().map(|(r, _)| r).collect()
    }
}
