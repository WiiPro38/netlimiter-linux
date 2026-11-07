use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::protocol::{Rule, RuleAction};

pub struct RuleStore {
    path: PathBuf,
    pub rules: Vec<Rule>,
    /// Runtime-only: never loaded from or saved to disk, so a reboot during a
    /// network lock cannot leave the machine offline.
    pub lock_all: bool,
}

/// Snap apps run from /snap/<name>/<revision>/..., and the revision changes on
/// every update. Rules are keyed by path, so map the revision to `current`
/// (a symlink to the active revision) to keep rules valid across updates.
pub fn normalize_exe(path: &str) -> String {
    for prefix in ["/snap/", "/var/lib/snapd/snap/"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            let mut parts = rest.splitn(3, '/');
            if let (Some(name), Some(rev)) = (parts.next(), parts.next()) {
                let digits = rev.strip_prefix('x').unwrap_or(rev);
                if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
                    let tail = parts.next().map(|t| format!("/{t}")).unwrap_or_default();
                    return format!("{prefix}{name}/current{tail}");
                }
            }
            break;
        }
    }
    path.to_string()
}

impl RuleStore {
    pub fn load() -> Self {
        let path = store_path();
        let mut rules = Vec::new();
        match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<StoreFile>(&text) {
                Ok(file) => rules = file.rules,
                Err(err) => {
                    // Keep the broken file for inspection instead of silently
                    // starting empty and overwriting it later.
                    let bad = path.with_extension("json.bad");
                    eprintln!("rules: cannot parse {}: {err}; saved copy as {}", path.display(), bad.display());
                    let _ = fs::rename(&path, &bad);
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => eprintln!("rules: cannot read {}: {err}", path.display()),
        }
        // Migrate rules saved with a snap revision in their path.
        let mut changed = false;
        for rule in rules.iter_mut() {
            let norm = normalize_exe(&rule.exe);
            if norm != rule.exe {
                rule.exe = norm;
                changed = true;
            }
        }
        let before = rules.len();
        let mut seen = std::collections::HashSet::new();
        rules.retain(|r| seen.insert(r.exe.clone()));
        let mut store = Self {
            path,
            rules,
            lock_all: false,
        };
        if changed || store.rules.len() != before {
            store.persist();
        }
        store
    }

    /// Atomic save: write a temp file, fsync, then rename over the real one.
    pub fn persist(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let file = StoreFile {
            rules: self.rules.clone(),
        };
        let text = match serde_json::to_string_pretty(&file) {
            Ok(t) => t,
            Err(err) => {
                eprintln!("rules: serialize failed: {err}");
                return;
            }
        };
        let tmp = self.path.with_extension("json.tmp");
        let result = (|| -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)
        })();
        if let Err(err) = result {
            eprintln!("rules: save to {} failed: {err}", self.path.display());
            let _ = fs::remove_file(&tmp);
        }
    }

    pub fn upsert(
        &mut self,
        exe: String,
        action: RuleAction,
        down_kbps: Option<u32>,
        up_kbps: Option<u32>,
        enabled: Option<bool>,
    ) {
        if let Some(existing) = self.rules.iter_mut().find(|r| r.exe == exe) {
            existing.action = action;
            existing.down_kbps = down_kbps;
            existing.up_kbps = up_kbps;
            if let Some(enabled) = enabled {
                existing.enabled = enabled;
            }
        } else {
            self.rules.push(Rule {
                id: format!("{:x}", simple_hash(&exe)),
                            exe,
                            action,
                            down_kbps,
                            up_kbps,
                            enabled: enabled.unwrap_or(true),
            });
        }
        self.persist();
    }

    pub fn delete(&mut self, exe: &str) {
        self.rules.retain(|r| r.exe != exe);
        self.persist();
    }

    pub fn clear(&mut self) {
        self.rules.clear();
        self.lock_all = false;
        self.persist();
    }
}

// Old files may still contain "lock_all"; serde ignores unknown fields.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoreFile {
    #[serde(default)]
    rules: Vec<Rule>,
}

fn store_path() -> PathBuf {
    if Path::new("/var/lib/netlimiter").is_dir() || unsafe { libc::geteuid() == 0 } {
        PathBuf::from("/var/lib/netlimiter/rules.json")
    } else {
        let fallback = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(fallback).join(".config/netlimiter/rules.json")
    }
}

fn simple_hash(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::normalize_exe;

    #[test]
    fn snap_revision_is_normalized() {
        assert_eq!(
            normalize_exe("/snap/firefox/8763/usr/lib/firefox/firefox"),
                   "/snap/firefox/current/usr/lib/firefox/firefox"
        );
        assert_eq!(normalize_exe("/snap/core22/x12/usr/bin/x"), "/snap/core22/current/usr/bin/x");
        assert_eq!(
            normalize_exe("/snap/firefox/current/usr/bin/f"),
                   "/snap/firefox/current/usr/bin/f"
        );
        assert_eq!(normalize_exe("/opt/brave.com/brave/brave"), "/opt/brave.com/brave/brave");
        assert_eq!(normalize_exe("/snap/bin/firefox"), "/snap/bin/firefox");
    }
}
