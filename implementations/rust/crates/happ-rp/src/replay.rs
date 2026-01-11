use dashmap::DashMap;
use std::sync::Arc;

/// Very small in-memory replay cache.
/// Production systems should use a persistent store with TTL eviction.
#[derive(Clone, Default)]
pub struct ReplayCache {
    used: Arc<DashMap<String, i64>>,
}

impl ReplayCache {
    pub fn new() -> Self {
        ReplayCache::default()
    }

    /// Returns true if the jti was newly inserted (i.e. not a replay).
    pub fn check_and_mark(&self, jti: &str, exp: i64) -> bool {
        if self.used.contains_key(jti) {
            return false;
        }
        self.used.insert(jti.to_string(), exp);
        true
    }
}
