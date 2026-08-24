use crate::clock::{Clock, SystemClock};
use crate::findings::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

#[must_use]
pub fn lockfile_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    stored_at: u64,
    findings: Vec<Finding>,
}

/// Filesystem cache of parsed advisory findings, keyed by lockfile digest.
///
/// Owns its TTL and its clock: callers used to pass the TTL on every `get`,
/// which had exactly one legal value in production.
pub struct AdvisoryCache {
    dir: PathBuf,
    ttl_secs: u64,
    clock: Arc<dyn Clock>,
}

impl AdvisoryCache {
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            ttl_secs: DEFAULT_TTL_SECS,
            clock: Arc::new(SystemClock),
        }
    }

    #[must_use]
    pub const fn with_ttl(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<Vec<Finding>> {
        let raw = std::fs::read_to_string(self.entry_path(key)).ok()?;
        let envelope: Envelope = serde_json::from_str(&raw).ok()?;
        if self.clock.now_secs().saturating_sub(envelope.stored_at) >= self.ttl_secs {
            return None;
        }
        Some(envelope.findings)
    }

    /// Store advisories under `key`, stamped with the current time.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error if the cache directory cannot be
    /// created or the entry cannot be written.
    pub fn put(&self, key: &str, findings: &[Finding]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let envelope = Envelope {
            stored_at: self.clock.now_secs(),
            findings: findings.to_vec(),
        };
        std::fs::write(self.entry_path(key), serde_json::to_string(&envelope)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::{Finding, FindingKind, Severity};

    fn sample_finding() -> Finding {
        Finding {
            kind: FindingKind::Advisory,
            code: "GHSA-x".into(),
            message: "m".into(),
            severity: Severity::High,
            path: "/p/package-lock.json".into(),
            fixable: false,
            manager: None,
            package: Some("left-pad".into()),
            current_version: None,
            fix_version: None,
            fix: None,
        }
    }

    #[test]
    fn lockfile_digest_is_sha256_hex() {
        assert_eq!(
            lockfile_digest(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn put_then_get_roundtrips() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        cache.put("key1", &[sample_finding()]).unwrap();
        let got = cache.get("key1").unwrap();
        assert_eq!(got, vec![sample_finding()]);
    }

    #[test]
    fn missing_key_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        assert!(cache.get("nope").is_none());
    }

    #[test]
    fn expired_entry_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        cache.put("key1", &[sample_finding()]).unwrap();
        assert!(AdvisoryCache::new(tmp.path().to_path_buf())
            .with_ttl(0)
            .get("key1")
            .is_none());
    }

    #[test]
    fn corrupt_entry_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        cache.put("key1", &[sample_finding()]).unwrap();
        let file = std::fs::read_dir(tmp.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap();
        std::fs::write(file.path(), "not json").unwrap();
        assert!(cache.get("key1").is_none());
    }

    #[test]
    fn an_entry_expires_once_the_ttl_has_passed() {
        let tmp = tempfile::tempdir().unwrap();
        let stored_at = 1_700_000_000;
        let cache = AdvisoryCache::new(tmp.path().to_path_buf()).with_clock(std::sync::Arc::new(
            crate::clock::FixedClock::at_secs(stored_at),
        ));
        cache.put("key", &[sample_finding()]).unwrap();

        // Still inside the 24h window.
        let fresh = AdvisoryCache::new(tmp.path().to_path_buf()).with_clock(std::sync::Arc::new(
            crate::clock::FixedClock::at_secs(stored_at + DEFAULT_TTL_SECS - 1),
        ));
        assert!(fresh.get("key").is_some());

        // Exactly at the TTL, and beyond it, the entry is gone.
        let expired = AdvisoryCache::new(tmp.path().to_path_buf()).with_clock(std::sync::Arc::new(
            crate::clock::FixedClock::at_secs(stored_at + DEFAULT_TTL_SECS),
        ));
        assert!(expired.get("key").is_none());
    }
}
