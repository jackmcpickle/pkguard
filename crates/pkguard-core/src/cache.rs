use crate::findings::Finding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;

pub fn lockfile_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    stored_at: u64,
    findings: Vec<Finding>,
}

/// Filesystem cache of parsed advisory findings, keyed by lockfile digest.
pub struct AdvisoryCache {
    dir: PathBuf,
}

impl AdvisoryCache {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn get(&self, key: &str, ttl_secs: u64) -> Option<Vec<Finding>> {
        let raw = std::fs::read_to_string(self.entry_path(key)).ok()?;
        let envelope: Envelope = serde_json::from_str(&raw).ok()?;
        if Self::now().saturating_sub(envelope.stored_at) >= ttl_secs {
            return None;
        }
        Some(envelope.findings)
    }

    pub fn put(&self, key: &str, findings: &[Finding]) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let envelope = Envelope {
            stored_at: Self::now(),
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
        let got = cache.get("key1", DEFAULT_TTL_SECS).unwrap();
        assert_eq!(got, vec![sample_finding()]);
    }

    #[test]
    fn missing_key_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        assert!(cache.get("nope", DEFAULT_TTL_SECS).is_none());
    }

    #[test]
    fn expired_entry_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = AdvisoryCache::new(tmp.path().to_path_buf());
        cache.put("key1", &[sample_finding()]).unwrap();
        assert!(cache.get("key1", 0).is_none());
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
        assert!(cache.get("key1", DEFAULT_TTL_SECS).is_none());
    }
}
