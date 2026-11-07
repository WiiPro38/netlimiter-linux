use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::capture::{Capture, FlowBytes, FlowKey, PROTO_TCP, PROTO_UDP};
use crate::netlink::{dump_sockets, tcp_state_name, SockInfo};
use crate::protocol::{ConnectionRow, ProcessRow};

/// How long a flow -> executable mapping is remembered after its socket is
/// gone, so the last packets of a closing connection are still attributed.
const FLOW_TTL: Duration = Duration::from_secs(90);
/// Packets of a flow whose owner is not known yet wait this long for the
/// next socket-table refresh.
const PENDING_TTL: Duration = Duration::from_secs(4);

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
    /// Per-packet byte counters (preferred source for per-app numbers).
    capture: Capture,
    /// Fallback only (used when the packet socket cannot be opened):
    /// per-socket tcp_info samples.
    prev_sock: HashMap<u64, ByteSample>,
    /// None until the first sample, so the first interface rate is 0 instead
    /// of "all bytes since boot / dt".
    prev_iface: Option<(u64, u64)>,
    prev_at: Instant,
    /// Cumulative (down, up) bytes of all non-loopback interfaces since start.
    iface_total: (u64, u64),
    /// Cumulative (down, up) bytes per executable since the daemon started.
    totals: HashMap<String, (u64, u64)>,
    /// كل التطبيقات التي ظهرت سابقاً — تبقى في القائمة حتى لو أُغلقت.
    known_apps: HashMap<String, KnownApp>,
    /// flow (4-tuple) -> (executable, last time it was seen).
    flows: HashMap<FlowKey, (String, Instant)>,
    /// Counted packets whose owner is not known yet: (down, up, first seen).
    pending: HashMap<FlowKey, (u64, u64, Instant)>,
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            capture: Capture::start(),
            prev_sock: HashMap::new(),
            prev_iface: None,
            prev_at: Instant::now(),
            iface_total: (0, 0),
            totals: HashMap::new(),
            known_apps: HashMap::new(),
            flows: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    pub fn sample(&mut self) -> Sample {
        // Packets are drained BEFORE the socket table is read: every flow that
        // produced packets and is still open is then guaranteed to be listed.
        let captured = self.capture.drain();
        let use_capture = self.capture.is_active();

        let owners = inode_owners();
        let socks = dump_sockets().unwrap_or_default();
        let now = Instant::now();
        let dt = now
        .saturating_duration_since(self.prev_at)
        .as_secs_f64()
        .max(0.2);
        self.prev_at = now;

        let mut proc_acc: HashMap<String, ProcessAcc> = HashMap::new();
        let mut live: Vec<(usize, ProcOwner, Option<FlowKey>)> = Vec::new();
        let mut live_keys: HashSet<FlowKey> = HashSet::new();
        // Sockets that are not connected (UDP/QUIC, listeners): matched by
        // local address + port, or by port alone when bound to 0.0.0.0 / ::.
        let mut bound: HashMap<(u8, IpAddr, u16), String> = HashMap::new();
        let mut wild: HashMap<(u8, u16), String> = HashMap::new();
        let mut next_sock: HashMap<u64, ByteSample> = HashMap::new();
        let mut exe_delta: HashMap<String, (u64, u64)> = HashMap::new();
        let mut flow_delta: FlowBytes = HashMap::new();

        for (i, sock) in socks.iter().enumerate() {
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

            let proto = proto_num(sock.proto);
            let local = sock.local.ip().to_canonical();
            let remote = sock.remote.ip().to_canonical();
            let unconnected = remote.is_unspecified() && sock.remote.port() == 0;
            let key = FlowKey {
                proto,
                local,
                lport: sock.local.port(),
                remote,
                rport: sock.remote.port(),
            };
            let flow_key = if unconnected {
                if local.is_unspecified() {
                    wild.insert((proto, key.lport), owner.exe.clone());
                } else {
                    bound.insert((proto, local, key.lport), owner.exe.clone());
                }
                None
            } else {
                self.flows.insert(key, (owner.exe.clone(), now));
                live_keys.insert(key);
                Some(key)
            };

            if !use_capture {
                // Fallback: per-socket tcp_info deltas (TCP only, approximate).
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
                next_sock.insert(sock.inode, sample);
                let e = exe_delta.entry(owner.exe.clone()).or_insert((0, 0));
                e.0 += d_down;
                e.1 += d_up;
                if let Some(k) = flow_key {
                    let f = flow_delta.entry(k).or_insert((0, 0));
                    f.0 += d_down;
                    f.1 += d_up;
                }
            }

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
            live.push((i, owner, flow_key));
        }
        self.prev_sock = next_sock;

        // Attribute the counted packets to executables.
        // Flows with traffic but without a live connected socket (QUIC, DNS,
        // closing TCP) get a synthetic connection row below.
        let mut extra_rows: Vec<(FlowKey, String)> = Vec::new();
        if use_capture {
            let mut work: Vec<(FlowKey, u64, u64, Instant)> = Vec::new();
            for (k, (d, u, t)) in std::mem::take(&mut self.pending) {
                work.push((k, d, u, t));
            }
            for (k, (d, u)) in captured {
                work.push((k, d, u, now));
            }
            for (k, d, u, first_seen) in work {
                let exe = if let Some(ent) = self.flows.get_mut(&k) {
                    ent.1 = now;
                    Some(ent.0.clone())
                } else {
                    let found = bound
                    .get(&(k.proto, k.local, k.lport))
                    .or_else(|| wild.get(&(k.proto, k.lport)))
                    .cloned();
                    if let Some(e) = &found {
                        self.flows.insert(k, (e.clone(), now));
                    }
                    found
                };
                match exe {
                    Some(exe) => {
                        let e = exe_delta.entry(exe.clone()).or_insert((0, 0));
                        e.0 += d;
                        e.1 += u;
                        let f = flow_delta.entry(k).or_insert((0, 0));
                        f.0 += d;
                        f.1 += u;
                        if !live_keys.contains(&k) {
                            extra_rows.push((k, exe));
                        }
                    }
                    None => {
                        if now.duration_since(first_seen) <= PENDING_TTL {
                            let p = self.pending.entry(k).or_insert((0, 0, first_seen));
                            p.0 += d;
                            p.1 += u;
                            if first_seen < p.2 {
                                p.2 = first_seen;
                            }
                        }
                    }
                }
            }
        }
        self.flows
        .retain(|_, (_, seen)| now.duration_since(*seen) <= FLOW_TTL);

        for (exe, (d, u)) in &exe_delta {
            let t = self.totals.entry(exe.clone()).or_insert((0, 0));
            t.0 += d;
            t.1 += u;
        }

        // ✅ التطبيقات المعروفة التي لم تظهر في هذه الدورة (أُغلقت الآن)
        //    تُضاف حتى تبقى ظاهرة في الواجهة (وبإجمالياتها).
        for (exe, known) in &self.known_apps {
            if !proc_acc.contains_key(exe) {
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
                                down_total: 0,
                                up_total: 0,
                                },
                );
            }
        }
        for (exe, acc) in proc_acc.iter_mut() {
            let (d, u) = exe_delta.get(exe).copied().unwrap_or((0, 0));
            acc.down_bps = per_sec(d, dt);
            acc.up_bps = per_sec(u, dt);
            let (td, tu) = self.totals.get(exe).copied().unwrap_or((0, 0));
            acc.down_total = td;
            acc.up_total = tu;
        }

        let mut connections: Vec<ConnectionRow> = Vec::new();
        for (i, owner, key) in &live {
            let (d, u) = (*key)
            .and_then(|k| flow_delta.get(&k).copied())
            .unwrap_or((0, 0));
            connections.push(to_row(&socks[*i], owner, per_sec(d, dt), per_sec(u, dt)));
        }
        for (k, exe) in &extra_rows {
            let (d, u) = flow_delta.get(k).copied().unwrap_or((0, 0));
            let known = self.known_apps.get(exe);
            let is_tcp = k.proto == PROTO_TCP;
            connections.push(ConnectionRow {
                proto: if is_tcp { "tcp" } else { "udp" }.to_string(),
                             family: if k.remote.is_ipv6() { "ipv6" } else { "ipv4" }.to_string(),
                             local: SocketAddr::new(k.local, k.lport).to_string(),
                             remote: SocketAddr::new(k.remote, k.rport).to_string(),
                             state: if is_tcp { "CLOSED" } else { "UDP" }.to_string(),
                             inode: 0,
                             pid: known.and_then(|a| a.pids.first().copied()).unwrap_or(0),
                             exe: exe.clone(),
                             name: known.map(|a| a.name.clone()).unwrap_or_else(|| exe.clone()),
                             uid: known.map(|a| a.uid).unwrap_or(0),
                             down_bps: per_sec(d, dt),
                             up_bps: per_sec(u, dt),
            });
        }

        let (rx, tx) = iface_bytes();
        let (iface_down, iface_up) = match self.prev_iface {
            Some((prx, ptx)) => {
                self.iface_total.0 += rx.saturating_sub(prx);
                self.iface_total.1 += tx.saturating_sub(ptx);
                (rate(rx, prx, dt), rate(tx, ptx, dt))
            }
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
            iface_down_total: self.iface_total.0,
            iface_up_total: self.iface_total.1,
            capture_ok: use_capture,
        }
    }
}

pub struct Sample {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub iface_down_bps: u64,
    pub iface_up_bps: u64,
    pub iface_down_total: u64,
    pub iface_up_total: u64,
    pub capture_ok: bool,
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

fn proto_num(proto: &str) -> u8 {
    if proto == "tcp" {
        PROTO_TCP
    } else {
        PROTO_UDP
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
        let exe_path = crate::rules::normalize_exe(&exe_path);
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
