//! In-memory entry cache: DN → LDAP entry, thread-safe.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub dn: String,
    pub attrs: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct MatchResult {
    pub category: MatchCategory,
    pub dn: String,
    pub attr_name: String,
    pub attr_value: String,
    pub value_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchCategory {
    Dn,
    AttrName,
    AttrValue,
}

#[derive(Debug, Clone, Default)]
pub struct EntryCache {
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
}

impl EntryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, dn: String, attrs: HashMap<String, Vec<String>>) {
        let entry = CacheEntry {
            dn: dn.clone(),
            attrs,
        };
        self.inner
            .lock()
            .expect("cache lock poisoned")
            .insert(dn, entry);
    }

    pub fn get(&self, dn: &str) -> Option<CacheEntry> {
        self.inner
            .lock()
            .expect("cache lock poisoned")
            .get(dn)
            .cloned()
    }

    pub fn delete(&self, dn: &str) {
        self.inner.lock().expect("cache lock poisoned").remove(dn);
    }

    pub fn clear(&self) {
        self.inner.lock().expect("cache lock poisoned").clear();
    }

    pub fn len(&self) -> usize {
        self.inner.lock().expect("cache lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn find_with_regexp(&self, pattern: &str) -> anyhow::Result<Vec<MatchResult>> {
        let re = Regex::new(pattern)?;
        let guard = self.inner.lock().expect("cache lock poisoned");
        let mut results = Vec::new();

        for entry in guard.values() {
            if re.is_match(&entry.dn) {
                results.push(MatchResult {
                    category: MatchCategory::Dn,
                    dn: entry.dn.clone(),
                    attr_name: String::new(),
                    attr_value: String::new(),
                    value_index: 0,
                });
            }
            for (name, values) in &entry.attrs {
                if re.is_match(name) {
                    results.push(MatchResult {
                        category: MatchCategory::AttrName,
                        dn: entry.dn.clone(),
                        attr_name: name.clone(),
                        attr_value: String::new(),
                        value_index: 0,
                    });
                }
                for (idx, val) in values.iter().enumerate() {
                    if re.is_match(val) {
                        results.push(MatchResult {
                            category: MatchCategory::AttrValue,
                            dn: entry.dn.clone(),
                            attr_name: name.clone(),
                            attr_value: val.clone(),
                            value_index: idx,
                        });
                    }
                }
            }
        }

        Ok(results)
    }
}
