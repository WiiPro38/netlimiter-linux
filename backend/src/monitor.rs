use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::netlink::{dump_sockets, tcp_state_name, SockInfo};
use crate::protocol::{ConnectionRow, ProcessRow};

#[derive(Clone, Debug)]
pub struct ProcOwner {
    pub pid: i32,
    pub uid: u32,
    pub exe: String,
    pub name: String,
}

#[derive(Default)]
struct ByteSample {
    sent: u64,
    recv: u64,
}

/// تطبيق ظهر سابقاً ونبقيه في القائمة حتى لو أُغلق.
#[derive(Clone)]
struct KnownApp {
    name: String,
    uid: u32,
    pids: Vec<i32>,
}

pub struct Monitor {
    prev_sock: HashMap<u64, ByteSample>,
    /// None until the first sample, so the first interface rate is 0 instead
    /// of "all bytes since boot / dt".
    prev_iface: Option<(u64, u64)>,
    prev_at: Instant,
    /// Cumulative (down, up) bytes per executable since the daemon started.
    /// Built from per-socket deltas, so closed sockets do not make it shrink.
    totals: HashMap<String, (u64, u64)>,
    /// كل التطبيقات التي ظهرت سابقاً — تبقى في القائمة حتى لو أُغلقت.
    known_apps: HashMap<String, KnownApp>,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            prev_sock: HashMap::new(),
            prev_iface: None,
            prev_at: Instant::now(),
            totals: HashMap::new(),
            known_apps: HashMap::new(),
        }
    }

    pub fn sample(&mut self) -> Sample {
        let owners = inode_owners();
        let socks = dump_sockets().unwrap_or_default();
        let now = Instant::now();
        let dt = now
        .saturating_duration_since(self.prev_at)
        .as_secs_f64()
        .max(0.2);
        self.prev_at = now;

        let mut connections = Vec::new();
        let mut next_sock: HashMap<u64, ByteSample> = HashMap::new();
        let mut proc_acc: HashMap<String, ProcessAcc> = HashMap::new();

        for sock in &socks {
            // inode 0 = TIME_WAIT / orphaned sockets: no owner, no counters, and
            // they would all collide on the same key.
            if sock.inode == 0 {
                continue;
            }
            let owner = owners.get(&sock.inode).cloned().unwrap_or(ProcOwner {
                pid: 0,
                uid: sock.uid,
                exe: String::from("unknown"),
                                                                   name: String::from("unknown"),
            });

            // سجّل التطبيق كمعروف (حتى لو أُغلق لاحقاً)
            self.known_apps
            .entry(owner.exe.clone())
            .and_modify(|k| {
                if owner.pid > 0 && !k.pids.contains(&owner.pid) {
                    k.pids.push(owner.pid);
                }
                if !owner.name.is_empty() && owner.name != "unknown" {
                    k.name = owner.name.clone();
                }
            })
            .or_insert_with(|| KnownApp {
                name: owner.name.clone(),
                            uid: owner.uid,
                            pids: if owner.pid > 0 { vec![owner.pid] } else { Vec::new() },
            });

            let sample = ByteSample {
                sent: sock.bytes_sent,
                recv: sock.bytes_recv,
            };
            let (d_up, d_down) = match self.prev_sock.get(&sock.inode) {
                Some(prev) => (
                    sample.sent.saturating_sub(prev.sent),
                               sample.recv.saturating_sub(prev.recv),
                ),
                None => (0, 0),
            };
            let up_bps = per_sec(d_up, dt);
            let down_bps = per_sec(d_down, dt);
            next_sock.insert(sock.inode, sample);

            let total = self.totals.entry(owner.exe.clone()).or_insert((0, 0));
            total.0 += d_down;
            total.1 += d_up;
            let (down_total, up_total) = *total;

            let acc = proc_acc
            .entry(owner.exe.clone())
            .or_insert_with(|| ProcessAcc {
                exe: owner.exe.clone(),
                            name: owner.name.clone(),
                            uid: owner.uid,
                            pids: Vec::new(),
                            connections: 0,
                            down_bps: 0,
                            up_bps: 0,
                            down_total: 0,
                            up_total: 0,
            });
            if !acc.pids.contains(&owner.pid) && owner.pid > 0 {
                acc.pids.push(owner.pid);
            }
            acc.connections += 1;
            acc.down_bps += down_bps;
            acc.up_bps += up_bps;
            acc.down_total = down_total;
            acc.up_total = up_total;

            connections.push(to_row(sock, &owner, down_bps, up_bps));
        }
        self.prev_sock = next_sock;

        // ✅ التطبيقات المعروفة التي لم تظهر في هذه الدورة (أُغلقت الآن)
        //    تُضاف بصفر سرعة حتى تبقى ظاهرة في الواجهة.
        for (exe, known) in &self.known_apps {
            if !proc_acc.contains_key(exe) {
                let (down_total, up_total) = self.totals.get(exe).copied().unwrap_or((0, 0));
                proc_acc.insert(
                    exe.clone(),
                                ProcessAcc {
                                    exe: exe.clone(),
                                name: known.name.clone(),
                                uid: known.uid,
                                pids: known.pids.clone(),
                                connections: 0,
                                down_bps: 0,
                                up_bps: 0,
                                down_total,
                                up_total,
                                },
                );
            }
        }

        let (rx, tx) = iface_bytes();
        let (iface_down, iface_up) = match self.prev_iface {
            Some((prx, ptx)) => (rate(rx, prx, dt), rate(tx, ptx, dt)),
            None => (0, 0),
        };
        self.prev_iface = Some((rx, tx));

        let mut processes: Vec<ProcessRow> = proc_acc.into_values().map(|a| a.into_row()).collect();
        processes.sort_by(|a, b| b.down_bps.cmp(&a.down_bps).then(b.up_bps.cmp(&a.up_bps)));
        connections.sort_by(|a, b| b.down_bps.cmp(&a.down_bps));

        Sample {
            processes,
            connections,
            iface_down_bps: iface_down,
            iface_up_bps: iface_up,
        }
    }
}

pub struct Sample {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub iface_down_bps: u64,
    pub iface_up_bps: u64,
}

struct ProcessAcc {
    exe: String,
    name: String,
    uid: u32,
    pids: Vec<i32>,
    connections: u32,
    down_bps: u64,
    up_bps: u64,
    down_total: u64,
    up_total: u64,
}

impl ProcessAcc {
    fn into_row(mut self) -> ProcessRow {
        self.pids.sort_unstable();
        ProcessRow {
            exe: self.exe,
            name: self.name,
            pids: self.pids,
            uid: self.uid,
            connections: self.connections,
            down_bps: self.down_bps,
            up_bps: self.up_bps,
            down_total: self.down_total,
            up_total: self.up_total,
        }
    }
}

fn per_sec(delta: u64, dt: f64) -> u64 {
    (delta as f64 / dt) as u64
}

fn rate(now: u64, prev: u64, dt: f64) -> u64 {
    per_sec(now.saturating_sub(prev), dt)
}

fn to_row(sock: &SockInfo, owner: &ProcOwner, down_bps: u64, up_bps: u64) -> ConnectionRow {
    ConnectionRow {
        proto: sock.proto.to_string(),
        family: if sock.family == 10 { "ipv6".into() } else { "ipv4".into() },
        local: sock.local.to_string(),
        remote: sock.remote.to_string(),
        state: if sock.proto == "tcp" {
            tcp_state_name(sock.state).into()
        } else {
            "UDP".into()
        },
        inode: sock.inode,
        pid: owner.pid,
        exe: owner.exe.clone(),
        name: owner.name.clone(),
        uid: owner.uid,
        down_bps,
        up_bps,
    }
}

fn inode_owners() -> HashMap<u64, ProcOwner> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let pid: i32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        let meta = match fs::metadata(format!("/proc/{pid}")) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string();
        let exe_path = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| comm.clone())
        .trim_end_matches(" (deleted)")
        .to_string();
        let (exe, name) = identify(pid, exe_path, &comm);
        let owner = ProcOwner {
            pid,
            uid: meta.uid(),
            exe,
            name,
        };
        let fd_path = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_path) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(link) = fs::read_link(fd.path()) else {
                continue;
            };
            if let Some(inode) = parse_socket_inode(&link) {
                map.insert(inode, owner.clone());
            }
        }
    }
    map
}

const INTERPRETERS: &[&str] = &[
    "python", "node", "java", "bash", "sh", "dash", "zsh", "perl", "ruby", "php", "lua",
];

fn is_interpreter(base: &str) -> bool {
    INTERPRETERS.iter().any(|i| {
        base == *i
        || base
        .strip_prefix(i)
        .map(|rest| {
            !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit() || c == '.')
        })
        .unwrap_or(false)
    })
}

/// First non-option argument of the process (the script / jar it runs).
fn script_arg(pid: i32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    raw.split(|b| *b == 0)
    .skip(1)
    .filter_map(|a| std::str::from_utf8(a).ok())
    .find(|a| !a.is_empty() && !a.starts_with('-') && !a.contains(' '))
    .map(|s| s.to_string())
}

fn file_name(path: &str) -> Option<String> {
    Path::new(path)
    .file_name()
    .and_then(|s| s.to_str())
    .map(|s| s.to_string())
}

/// Returns (rule key, display name). The name is the executable's file name
/// (not the 15-char thread name from /proc/<pid>/comm). Interpreters such as
/// python or node are keyed per script so different scripts are not merged.
fn identify(pid: i32, exe_path: String, comm: &str) -> (String, String) {
    let base = file_name(&exe_path).unwrap_or_else(|| comm.to_string());
    if is_interpreter(&base) {
        if let Some(script) = script_arg(pid) {
            let name = file_name(&script).unwrap_or_else(|| base.clone());
            return (format!("{exe_path} {script}"), name);
        }
    }
    (exe_path, base)
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let s = path.to_str()?;
    let rest = s.strip_prefix("socket:[")?;
    let rest = rest.strip_suffix(']')?;
    rest.parse().ok()
}

fn iface_bytes() -> (u64, u64) {
    let Ok(text) = fs::read_to_string("/proc/net/dev") else {
        return (0, 0);
    };
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        if name.trim() == "lo" {
            continue;
        }
        let cols: Vec<&str> = rest.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        rx += cols[0].parse().unwrap_or(0);
        tx += cols[8].parse().unwrap_or(0);
    }
    (rx, tx)
}

pub fn privileged() -> bool {
    unsafe { libc::geteuid() == 0 }
}

pub fn tick_interval() -> Duration {
    Duration::from_millis(1000)
}
