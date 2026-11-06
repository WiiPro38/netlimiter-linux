//! Strict bandwidth shaping with Linux traffic control.
//!
//! nftables `limit rate ... drop` only *polices*: it drops whatever exceeds
//! the rate, so TCP keeps probing and the real throughput oscillates far above
//! the configured value. A shaper queues and paces packets instead:
//!
//!   * upload   : HTB on the default-route interface(s) (egress).
//!   * download : ingress traffic is redirected (mirred) to an IFB device and
//!                shaped by HTB on its egress side.
//!
//! Every limited app gets its own HTB class; packets are assigned to it by
//! u32 filters on the app's remote addresses (the same "seen IPs" the nft
//! module tracks). Everything else falls into the default class, which is only
//! limited by the optional global rule.
//!
//! The `tc` and `ip` binaries are used (package `iproute-tc` on Fedora). If
//! anything fails, `apply` returns an error and the caller falls back to the
//! nft policer, so a limit is never silently lost.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::protocol::{Rule, RuleAction};

/// Name of the IFB device used for download shaping.
pub const IFB: &str = "nlifb0";
/// "No limit" rate of the HTB root (kept below 2^32 bytes/s for old iproute2).
const UNLIMITED: &str = "10gbit";
/// After a failed setup wait this long before trying again.
const RETRY: Duration = Duration::from_secs(30);
/// How often the installed qdiscs are verified (somebody may have removed them).
const HEALTH_EVERY: Duration = Duration::from_secs(10);
const MAX_IPS_PER_APP: usize = 512;
const FIRST_APP_MINOR: u32 = 0x20;
const MAX_APPS: usize = 4000;

/// One direction of shaping.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Shape {
    /// Rate of the whole direction in bits/s (global rule); `None` = unlimited.
    root_bps: Option<u64>,
    /// (exe, bits/s) sorted by exe. Index + FIRST_APP_MINOR is the class id.
    apps: Vec<(String, u64)>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Structure {
    ifaces: Vec<String>,
    down: Option<Shape>,
    up: Option<Shape>,
}

/// (is_download, class minor, remote address)
type FilterSet = BTreeSet<(bool, u32, IpAddr)>;

struct Inner {
    structure: Option<Structure>,
    filters: FilterSet,
    failed_at: Option<Instant>,
    last_err: String,
    last_check: Option<Instant>,
    logged: String,
}

static STATE: Mutex<Inner> = Mutex::new(Inner {
    structure: None,
    filters: BTreeSet::new(),
    failed_at: None,
    last_err: String::new(),
    last_check: None,
    logged: String::new(),
});

/// ifindexes of interfaces whose ingress is currently redirected to the IFB.
static SHAPED_DOWN: Mutex<Vec<i32>> = Mutex::new(Vec::new());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Interfaces whose download goes through the IFB. The packet capture uses it
/// to avoid counting the same bytes several times (see capture.rs).
pub fn shaped_down() -> Vec<i32> {
    lock(&SHAPED_DOWN).clone()
}

pub fn ifb_index() -> i32 {
    ifindex(IFB)
}

fn ifindex(name: &str) -> i32 {
    match CString::new(name) {
        Ok(c) => unsafe { libc::if_nametoindex(c.as_ptr()) as i32 },
        Err(_) => 0,
    }
}

fn rate(bps: u64) -> String {
    format!("{}bit", bps.max(8))
}

fn is_global(rule: &Rule) -> bool {
    rule.exe.is_empty() || rule.exe == "global"
}

fn build_shape(rules: &[Rule], down: bool) -> Option<Shape> {
    let pick = |r: &Rule| if down { r.down_kbps } else { r.up_kbps };
    let to_bps = |kbps: u32| kbps as u64 * 1024 * 8;

    let root_bps = rules
        .iter()
        .find(|r| r.enabled && is_global(r) && r.action == RuleAction::Limit)
        .and_then(pick)
        .filter(|v| *v > 0)
        .map(to_bps);

    let mut apps: Vec<(String, u64)> = rules
        .iter()
        .filter(|r| r.enabled && !is_global(r) && r.action == RuleAction::Limit)
        .filter_map(|r| pick(r).filter(|v| *v > 0).map(|v| (r.exe.clone(), to_bps(v))))
        .collect();
    apps.sort();
    apps.dedup_by(|a, b| a.0 == b.0);
    apps.truncate(MAX_APPS);

    if root_bps.is_none() && apps.is_empty() {
        None
    } else {
        Some(Shape { root_bps, apps })
    }
}

/// Interfaces that carry the default routes (IPv4 and IPv6).
fn default_ifaces() -> Vec<String> {
    let mut set = BTreeSet::new();
    if let Ok(text) = fs::read_to_string("/proc/net/route") {
        for line in text.lines().skip(1) {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() > 7 && c[1] == "00000000" && c[7] == "00000000" {
                set.insert(c[0].to_string());
            }
        }
    }
    if let Ok(text) = fs::read_to_string("/proc/net/ipv6_route") {
        for line in text.lines() {
            let c: Vec<&str> = line.split_whitespace().collect();
            if c.len() > 9 && c[0] == "0".repeat(32) && c[1] == "00" {
                set.insert(c[9].to_string());
            }
        }
    }
    set.into_iter()
        .filter(|n| n != "lo" && !n.starts_with("nlifb") && ifindex(n) > 0)
        .collect()
}

fn run_cmd(prog: &str, args: &[&str]) -> Result<(), String> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{prog}: {e} (is iproute-tc installed?)"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{prog} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Feeds a script to `tc -batch -`. With `force` errors do not abort the batch
/// (used for teardown, where missing qdiscs are expected).
fn tc_batch(script: &str, force: bool) -> Result<(), String> {
    if script.trim().is_empty() {
        return Ok(());
    }
    let mut cmd = Command::new("tc");
    if force {
        cmd.arg("-force");
    }
    let mut child = cmd
        .args(["-batch", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("tc: {e} (is iproute-tc installed?)"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| format!("tc stdin: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("tc wait: {e}"))?;
    if force || out.status.success() {
        Ok(())
    } else {
        Err(format!("tc: {}", String::from_utf8_lossy(&out.stderr).trim()))
    }
}

fn ensure_ifb() -> Result<(), String> {
    if ifindex(IFB) == 0 {
        // numifbs=0: do not auto-create ifb0/ifb1; ignore failure (built-in / already loaded).
        let _ = run_cmd("modprobe", &["ifb", "numifbs=0"]);
        run_cmd("ip", &["link", "add", IFB, "type", "ifb"])?;
    }
    run_cmd("ip", &["link", "set", IFB, "up"])
}

fn teardown_script(ifaces: &[String], with_ifb: bool) -> String {
    let mut s = String::new();
    for dev in ifaces {
        s.push_str(&format!("qdisc del dev {dev} root\n"));
        s.push_str(&format!("qdisc del dev {dev} ingress\n"));
    }
    if with_ifb && ifindex(IFB) > 0 {
        s.push_str(&format!("qdisc del dev {IFB} root\n"));
    }
    s
}

fn filter_line(dev: &str, down: bool, minor: u32, ip: &IpAddr) -> String {
    let side = if down { "src" } else { "dst" };
    match ip {
        IpAddr::V4(v4) => format!(
            "filter add dev {dev} parent 1: protocol ip prio 1 u32 match ip {side} {v4}/32 flowid 1:{minor:x}\n"
        ),
        IpAddr::V6(v6) => format!(
            "filter add dev {dev} parent 1: protocol ipv6 prio 2 u32 match ip6 {side} {v6}/128 flowid 1:{minor:x}\n"
        ),
    }
}

fn shaper_script(s: &mut String, dev: &str, shape: &Shape) {
    let root = shape.root_bps.map(rate).unwrap_or_else(|| UNLIMITED.to_string());
    s.push_str(&format!("qdisc add dev {dev} root handle 1: htb default 10\n"));
    s.push_str(&format!("class add dev {dev} parent 1: classid 1:1 htb rate {root} ceil {root}\n"));
    s.push_str(&format!(
        "class add dev {dev} parent 1:1 classid 1:10 htb rate {root} ceil {root} prio 1\n"
    ));
    s.push_str(&format!("qdisc add dev {dev} parent 1:10 handle 10: fq_codel\n"));
    for (i, (_, bps)) in shape.apps.iter().enumerate() {
        let minor = FIRST_APP_MINOR + i as u32;
        let r = rate(*bps);
        s.push_str(&format!(
            "class add dev {dev} parent 1:1 classid 1:{minor:x} htb rate {r} ceil {r} prio 1\n"
        ));
        s.push_str(&format!("qdisc add dev {dev} parent 1:{minor:x} handle {minor:x}: fq_codel\n"));
    }
}

fn desired_filters(
    st: &Structure,
    ips_for: &dyn Fn(&str) -> BTreeSet<IpAddr>,
) -> FilterSet {
    let mut set = FilterSet::new();
    for (down, shape) in [(true, &st.down), (false, &st.up)] {
        let Some(shape) = shape else { continue };
        for (i, (exe, _)) in shape.apps.iter().enumerate() {
            let minor = FIRST_APP_MINOR + i as u32;
            for ip in ips_for(exe).into_iter().take(MAX_IPS_PER_APP) {
                set.insert((down, minor, ip));
            }
        }
    }
    set
}

fn filter_devs(st: &Structure, down: bool) -> Vec<String> {
    if down {
        vec![IFB.to_string()]
    } else {
        st.ifaces.clone()
    }
}

fn filter_script(st: &Structure, filters: &FilterSet) -> String {
    let mut s = String::new();
    for (down, minor, ip) in filters {
        for dev in filter_devs(st, *down) {
            s.push_str(&filter_line(&dev, *down, *minor, ip));
        }
    }
    s
}

fn full_script(st: &Structure, filters: &FilterSet) -> String {
    let mut s = String::new();
    if let Some(shape) = &st.up {
        for dev in &st.ifaces {
            shaper_script(&mut s, dev, shape);
        }
    }
    if let Some(shape) = &st.down {
        shaper_script(&mut s, IFB, shape);
        for dev in &st.ifaces {
            s.push_str(&format!("qdisc add dev {dev} handle ffff: ingress\n"));
            s.push_str(&format!(
                "filter add dev {dev} parent ffff: protocol ip prio 10 u32 match u32 0 0 \
                 action mirred egress redirect dev {IFB}\n"
            ));
            s.push_str(&format!(
                "filter add dev {dev} parent ffff: protocol ipv6 prio 11 u32 match u32 0 0 \
                 action mirred egress redirect dev {IFB}\n"
            ));
        }
    }
    s.push_str(&filter_script(st, filters));
    s
}

fn publish_taps(st: Option<&Structure>) {
    let list = match st {
        Some(st) if st.down.is_some() => st.ifaces.iter().map(|n| ifindex(n)).filter(|i| *i > 0).collect(),
        _ => Vec::new(),
    };
    *lock(&SHAPED_DOWN) = list;
}

/// Installs / updates the shaping that corresponds to `rules`.
/// `Ok(())` means every Limit rule is enforced by tc (or there is none).
pub fn apply(
    lock_all: bool,
    rules: &[Rule],
    ips_for: &dyn Fn(&str) -> BTreeSet<IpAddr>,
) -> Result<(), String> {
    let (down, up) = if lock_all {
        (None, None)
    } else {
        (build_shape(rules, true), build_shape(rules, false))
    };

    let mut inner = lock(&STATE);

    if down.is_none() && up.is_none() {
        if inner.structure.is_some() {
            teardown_locked(&mut inner);
        }
        inner.failed_at = None;
        return Ok(());
    }

    let ifaces = default_ifaces();
    let wanted = Structure { ifaces, down, up };

    if let Some(at) = inner.failed_at {
        if at.elapsed() < RETRY && inner.structure.is_none() {
            return Err(inner.last_err.clone());
        }
    }

    match apply_locked(&mut inner, wanted, ips_for) {
        Ok(()) => {
            inner.failed_at = None;
            inner.logged.clear();
            Ok(())
        }
        Err(err) => {
            if inner.logged != err {
                eprintln!("tc: {err}; falling back to nft rate limiting");
                inner.logged = err.clone();
            }
            // Leave nothing half-configured behind.
            teardown_locked(&mut inner);
            inner.failed_at = Some(Instant::now());
            inner.last_err = err.clone();
            Err(err)
        }
    }
}

fn apply_locked(
    inner: &mut Inner,
    wanted: Structure,
    ips_for: &dyn Fn(&str) -> BTreeSet<IpAddr>,
) -> Result<(), String> {
    if wanted.ifaces.is_empty() {
        return Err("no default-route interface found".into());
    }
    let desired = desired_filters(&wanted, ips_for);

    // Somebody (NetworkManager, an interface reset) may have removed our qdiscs.
    let mut healthy = true;
    if inner.structure.as_ref() == Some(&wanted)
        && inner.last_check.map_or(true, |t| t.elapsed() >= HEALTH_EVERY)
    {
        inner.last_check = Some(Instant::now());
        healthy = is_installed(&wanted);
    }

    if inner.structure.as_ref() != Some(&wanted) || !healthy {
        // Full rebuild.
        let mut old: Vec<String> = inner
            .structure
            .as_ref()
            .map(|s| s.ifaces.clone())
            .unwrap_or_default();
        old.extend(wanted.ifaces.iter().cloned());
        old.sort();
        old.dedup();
        tc_batch(&teardown_script(&old, true), true)?;

        if wanted.down.is_some() {
            ensure_ifb()?;
        }
        tc_batch(&full_script(&wanted, &desired), false)?;
        inner.structure = Some(wanted);
        inner.filters = desired;
        inner.last_check = Some(Instant::now());
        publish_taps(inner.structure.as_ref());
        return Ok(());
    }

    if inner.filters == desired {
        return Ok(());
    }

    let st = wanted;
    if inner.filters.is_subset(&desired) {
        // Only new addresses: add their filters, nothing is interrupted.
        let added: FilterSet = desired.difference(&inner.filters).cloned().collect();
        tc_batch(&filter_script(&st, &added), false)?;
    } else {
        // Addresses disappeared: flush all filters and re-add the current ones.
        let mut s = String::new();
        for (down, shape) in [(true, &st.down), (false, &st.up)] {
            if shape.is_none() {
                continue;
            }
            for dev in filter_devs(&st, down) {
                s.push_str(&format!("filter del dev {dev} parent 1: prio 1\n"));
                s.push_str(&format!("filter del dev {dev} parent 1: prio 2\n"));
            }
        }
        tc_batch(&s, true)?;
        tc_batch(&filter_script(&st, &desired), false)?;
    }
    inner.filters = desired;
    Ok(())
}

/// True when the root HTB (and ingress redirect) we installed is still present.
fn is_installed(st: &Structure) -> bool {
    let Ok(out) = Command::new("tc")
        .args(["qdisc", "show"])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let has = |kind: &str, handle: &str, dev: &str| {
        text.lines().any(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            c.len() > 4 && c[1] == kind && c[2] == handle && c[3] == "dev" && c[4] == dev
        })
    };
    if st.up.is_some() && !st.ifaces.iter().all(|d| has("htb", "1:", d)) {
        return false;
    }
    if st.down.is_some() {
        if !has("htb", "1:", IFB) {
            return false;
        }
        if !st.ifaces.iter().all(|d| has("ingress", "ffff:", d)) {
            return false;
        }
    }
    true
}

fn teardown_locked(inner: &mut Inner) {
    let ifaces = inner
        .structure
        .as_ref()
        .map(|s| s.ifaces.clone())
        .unwrap_or_default();
    let _ = tc_batch(&teardown_script(&ifaces, true), true);
    inner.structure = None;
    inner.filters.clear();
    inner.last_check = None;
    publish_taps(None);
}

/// Removes every shaper this module installed (also leftovers of a previous
/// daemon run that did not shut down cleanly) and deletes the IFB device.
pub fn cleanup() {
    let mut inner = lock(&STATE);
    let mut ifaces: Vec<String> = inner
        .structure
        .as_ref()
        .map(|s| s.ifaces.clone())
        .unwrap_or_default();

    // The IFB device only exists if we created it, so its presence is the
    // marker that qdiscs on other interfaces may be ours too.
    if ifindex(IFB) > 0 {
        if let Ok(out) = Command::new("tc")
            .args(["qdisc", "show"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
        {
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let c: Vec<&str> = line.split_whitespace().collect();
                if c.len() > 4 && c[3] == "dev" {
                    let ours = (c[1] == "htb" && c[2] == "1:" && line.contains(" root "))
                        || (c[1] == "ingress" && c[2] == "ffff:");
                    if ours && c[4] != IFB {
                        ifaces.push(c[4].to_string());
                    }
                }
            }
        }
    }
    ifaces.sort();
    ifaces.dedup();
    let _ = tc_batch(&teardown_script(&ifaces, true), true);
    if ifindex(IFB) > 0 {
        let _ = run_cmd("ip", &["link", "del", IFB]);
    }
    inner.structure = None;
    inner.filters.clear();
    inner.last_check = None;
    inner.failed_at = None;
    publish_taps(None);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Rule, RuleAction};

    fn rule(exe: &str, down: Option<u32>, up: Option<u32>) -> Rule {
        Rule {
            id: exe.into(),
            exe: exe.into(),
            action: RuleAction::Limit,
            down_kbps: down,
            up_kbps: up,
            enabled: true,
        }
    }

    #[test]
    fn script_shape() {
        let rules = vec![rule("global", Some(600), Some(100)), rule("/usr/bin/curl", Some(50), None)];
        let down = build_shape(&rules, true).unwrap();
        let up = build_shape(&rules, false).unwrap();
        assert_eq!(down.root_bps, Some(600 * 1024 * 8));
        assert_eq!(down.apps.len(), 1);
        assert_eq!(up.apps.len(), 0);
        let st = Structure { ifaces: vec!["eth0".into()], down: Some(down), up: Some(up) };
        let mut f = FilterSet::new();
        f.insert((true, FIRST_APP_MINOR, "1.2.3.4".parse().unwrap()));
        f.insert((true, FIRST_APP_MINOR, "2001:db8::1".parse().unwrap()));
        let s = full_script(&st, &f);
        println!("{s}");
        assert!(s.contains("qdisc add dev eth0 root handle 1: htb default 10"));
        assert!(s.contains("htb rate 4915200bit ceil 4915200bit"));
        assert!(s.contains("htb rate 819200bit ceil 819200bit"));
        assert!(s.contains("redirect dev nlifb0"));
        assert!(s.contains("dev nlifb0 parent 1: protocol ip prio 1 u32 match ip src 1.2.3.4/32 flowid 1:20"));
        assert!(s.contains("match ip6 src 2001:db8::1/128 flowid 1:20"));
    }
}
