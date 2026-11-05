use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::protocol::{ConnectionRow, Rule, RuleAction};

/// How long a remote address stays in an app's rule after its last connection
/// disappeared. Keeps the ruleset stable (no flapping) while an app retries.
const STICKY: Duration = Duration::from_secs(120);

#[derive(Default)]
pub struct NftState {
    last_script: String,
    seen: HashMap<String, HashMap<IpAddr, Instant>>,
}

impl NftState {
    fn remember(&mut self, rules: &[Rule], connections: &[ConnectionRow], now: Instant) {
        // Drop state of apps that no longer have an enabled rule.
        self.seen
            .retain(|exe, _| rules.iter().any(|r| r.enabled && &r.exe == exe));

        for rule in rules.iter().filter(|r| r.enabled) {
            let map = self.seen.entry(rule.exe.clone()).or_default();
            for conn in connections.iter().filter(|c| c.exe == rule.exe) {
                if let Some(ip) = remote_ip(&conn.remote) {
                    map.insert(ip, now);
                }
            }
            map.retain(|_, last| now.duration_since(*last) <= STICKY);
        }
    }
}

/// Applies the ruleset. The nft script is only reloaded when its text changed,
/// so `limit rate` counters are not reset every second.
pub fn apply(
    state: &mut NftState,
    lock_all: bool,
    rules: &[Rule],
    connections: &[ConnectionRow],
) -> Result<(), String> {
    state.remember(rules, connections, Instant::now());
    let script = render(lock_all, rules, &state.seen);
    if script == state.last_script {
        return Ok(());
    }
    match run_nft(&script) {
        Ok(()) => {
            state.last_script = script;
            Ok(())
        }
        Err(err) => {
            state.last_script.clear();
            Err(err)
        }
    }
}

/// Removes our table (used on shutdown).
pub fn cleanup() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "netlimiter"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn run_nft(script: &str) -> Result<(), String> {
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("nft: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("nft stdin: {e}"))?;
    }
    let output = child.wait_with_output().map_err(|e| format!("nft wait: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Direction {
    Down,
    Up,
}

fn render(lock_all: bool, rules: &[Rule], seen: &HashMap<String, HashMap<IpAddr, Instant>>) -> String {
    let mut s = String::from("table inet netlimiter\ndelete table inet netlimiter\ntable inet netlimiter {\n");

    // البحث عن القاعدة العامة (إن وجدت ومفعلة)
    let global_rule = rules.iter().find(|r| (r.exe.is_empty() || r.exe == "global") && r.enabled);

    for (chain, ifkw, dir) in [("input", "iif", Direction::Down), ("output", "oif", Direction::Up)] {
        s.push_str(&format!(
            "  chain {chain} {{\n    type filter hook {chain} priority 10; policy accept;\n    {ifkw} \"lo\" accept\n"
        ));

        if lock_all {
            s.push_str("    meta l4proto ipv6-icmp accept\n    drop\n");
        } else {
            // 1. تطبيق الحد العام أولاً (إن وجد) على كافة الحزم//
            if let Some(rule) = global_rule {
                match rule.action {
                    RuleAction::Block => {
                        s.push_str("    drop\n");
                    }
                    RuleAction::Limit => {
                        let down_kbps = if dir == Direction::Down { rule.down_kbps } else { None };
                        let up_kbps = if dir == Direction::Up { rule.up_kbps } else { None };
                        let kbps = match dir {
                            Direction::Down => rule.down_kbps,
                            Direction::Up => rule.up_kbps,
                        };
                        if let Some(kbps) = kbps.filter(|v| *v > 0) {
                            // تحويل الكيلوبايت إلى بايت في الثانية لتحديد دقيق جداً
                            let bytes_per_sec = kbps * 1024;
                            // ضبط الـ burst ليكون ضيقاً جداً لفرض الحد بصرامة
                            let burst = 8192; // 8KB burst صارم
                            s.push_str(&format!(
                                "    limit rate over {} bytes/second burst {} bytes drop\n",
                                bytes_per_sec, burst
                            ));
                        }
                    }
                    RuleAction::Allow => {}
                }
            }

            // 2. تطبيق قواعد التطبيقات الفردية بعدها
            for rule in rules.iter().filter(|r| r.enabled && !r.exe.is_empty() && r.exe != "global") {
                let ips: BTreeSet<IpAddr> = seen
                .get(&rule.exe)
                .map(|m| m.keys().copied().collect())
                .unwrap_or_default();
                append_rule(&mut s, rule, &ips, dir);
            }
        }
        s.push_str("  }\n");
    }
    s.push_str("}\n");
    s
}

fn append_rule(s: &mut String, rule: &Rule, ips: &BTreeSet<IpAddr>, dir: Direction) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(ip) => v4.push(ip.to_string()),
            IpAddr::V6(ip) => v6.push(ip.to_string()),
        }
    }
    if v4.is_empty() && v6.is_empty() {
        return;
    }

    match rule.action {
        RuleAction::Allow => {}
        RuleAction::Block => emit_match(s, dir, &v4, &v6, "drop"),
        RuleAction::Limit => {
            let kbps = match dir {
                Direction::Down => rule.down_kbps,
                Direction::Up => rule.up_kbps,
            };
            if let Some(kbps) = kbps.filter(|v| *v > 0) {
                let burst = (kbps / 4).max(32);
                let action = format!("limit rate over {kbps} kbytes/second burst {burst} kbytes drop");
                emit_match(s, dir, &v4, &v6, &action);
            }
        }
    }
}

fn emit_match(s: &mut String, dir: Direction, v4: &[String], v6: &[String], action: &str) {
    let (v4_key, v6_key) = match dir {
        Direction::Down => ("ip saddr", "ip6 saddr"),
        Direction::Up => ("ip daddr", "ip6 daddr"),
    };
    if !v4.is_empty() {
        s.push_str(&format!("    {v4_key} {{ {} }} {action}\n", v4.join(", ")));
    }
    if !v6.is_empty() {
        s.push_str(&format!("    {v6_key} {{ {} }} {action}\n", v6.join(", ")));
    }
}

/// Remote address of a connection, with IPv4-mapped IPv6 (::ffff:a.b.c.d)
/// converted to plain IPv4 so it matches `ip` rules. Loopback and unspecified
/// addresses are ignored.
fn remote_ip(remote: &str) -> Option<IpAddr> {
    let ip = remote.parse::<std::net::SocketAddr>().ok()?.ip().to_canonical();
    if ip.is_loopback() || ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}
