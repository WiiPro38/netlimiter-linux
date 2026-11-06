//! Packet-level byte counting.
//!
//! `tcp_info` counters only exist for live TCP sockets: UDP/QUIC is invisible,
//! short-lived connections are missed and the bytes of a socket that closes
//! between two samples are lost. Here every IP packet is seen once through an
//! AF_PACKET socket and its bytes are accumulated per flow (4-tuple). The
//! monitor later maps each flow to the owning executable.

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const PKT_OTHERHOST: u8 = 3;
const PKT_OUTGOING: u8 = 4;
const FLUSH_EVERY: Duration = Duration::from_millis(100);
/// Safety valve: never keep more than this many distinct flows between drains.
const MAX_FLOWS: usize = 200_000;

/// A flow seen from this machine's point of view (`local` is always us).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: u8,
    pub local: IpAddr,
    pub lport: u16,
    pub remote: IpAddr,
    pub rport: u16,
}

/// (download bytes, upload bytes) per flow.
pub type FlowBytes = HashMap<FlowKey, (u64, u64)>;

/// Snapshot of the tc/IFB state, refreshed every flush.
#[derive(Default)]
struct Taps {
    ifb: i32,
    shaped: Vec<i32>,
}

impl Taps {
    fn current() -> Self {
        Self {
            ifb: crate::tc::ifb_index(),
            shaped: crate::tc::shaped_down(),
        }
    }
}

pub struct Capture {
    shared: Arc<Mutex<FlowBytes>>,
    active: Arc<AtomicBool>,
}

impl Capture {
    pub fn start() -> Self {
        let shared = Arc::new(Mutex::new(HashMap::new()));
        let active = Arc::new(AtomicBool::new(false));
        let (s, a) = (Arc::clone(&shared), Arc::clone(&active));
        if let Err(err) = thread::Builder::new()
            .name("capture".into())
            .spawn(move || run(s, a))
        {
            eprintln!("capture: cannot spawn thread: {err}");
        }
        Self { shared, active }
    }

    /// True once the packet socket is open and counting.
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }

    /// Takes everything counted since the previous call.
    pub fn drain(&self) -> FlowBytes {
        let mut guard = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        mem::take(&mut *guard)
    }
}

fn setsockopt_int(fd: libc::c_int, opt: libc::c_int, value: libc::c_int) {
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

fn run(shared: Arc<Mutex<FlowBytes>>, active: Arc<AtomicBool>) {
    // SOCK_DGRAM: the kernel strips the link-layer header, so Ethernet, Wi-Fi,
    // PPP, WireGuard/tun (no header) are all handled the same way.
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
        )
    };
    if fd < 0 {
        eprintln!(
            "capture: cannot open AF_PACKET socket: {} (needs root / CAP_NET_RAW); \
             falling back to tcp_info counters",
            io::Error::last_os_error()
        );
        return;
    }
    setsockopt_int(fd, libc::SO_RCVBUF, 4 * 1024 * 1024);
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const libc::timeval as *const libc::c_void,
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let lo_index = unsafe { libc::if_nametoindex(b"lo\0".as_ptr() as *const libc::c_char) } as i32;
    // Download shaping (tc.rs) redirects ingress to an IFB device. Every such
    // packet then shows up three times: on the NIC (before tc), on the IFB
    // (after shaping, as "outgoing") and again on the NIC (re-injected). We
    // count it once, on the IFB, which also makes the GUI show the shaped rate.
    let mut taps = Taps::default();

    active.store(true, Ordering::Relaxed);
    eprintln!("capture: packet counting active");

    let mut local: FlowBytes = HashMap::new();
    let mut last_flush = Instant::now();
    let mut buf = [0u8; 256];

    loop {
        let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
        let mut slen = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // MSG_TRUNC: the return value is the real packet length even though we
        // only copy the first bytes (headers). It also covers GRO/TSO packets
        // whose IP total-length field cannot be trusted.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
                &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut slen,
            )
        };
        if n > 0 {
            let real_len = n as u64;
            let have = (n as usize).min(buf.len());
            handle_packet(&sll, &buf[..have], real_len, lo_index, &taps, &mut local);
        } else if n < 0 {
            let err = io::Error::last_os_error();
            match err.kind() {
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {}
                _ => {
                    eprintln!("capture: recv failed: {err}");
                    thread::sleep(Duration::from_millis(200));
                }
            }
        }

        if last_flush.elapsed() >= FLUSH_EVERY {
            last_flush = Instant::now();
            taps = Taps::current();
            if !local.is_empty() {
                let mut guard = shared.lock().unwrap_or_else(|e| e.into_inner());
                if guard.len() > MAX_FLOWS {
                    guard.clear();
                }
                for (key, (down, up)) in local.drain() {
                    let entry = guard.entry(key).or_insert((0, 0));
                    entry.0 += down;
                    entry.1 += up;
                }
            }
        }
    }
}

fn handle_packet(
    sll: &libc::sockaddr_ll,
    data: &[u8],
    real_len: u64,
    lo_index: i32,
    taps: &Taps,
    out: &mut FlowBytes,
) {
    if sll.sll_pkttype == PKT_OTHERHOST || sll.sll_ifindex == lo_index {
        return;
    }
    let mut outgoing = sll.sll_pkttype == PKT_OUTGOING;
    if sll.sll_ifindex == taps.ifb {
        if taps.shaped.is_empty() {
            return;
        }
        outgoing = false; // leaving the IFB = download
    } else if !outgoing && taps.shaped.contains(&sll.sll_ifindex) {
        return; // counted on the IFB instead
    }
    let eth = u16::from_be(sll.sll_protocol);
    let Some((proto, src, sport, dst, dport)) = parse_ip(eth, data) else {
        return;
    };
    let (local, lport, remote, rport) = if outgoing {
        (src, sport, dst, dport)
    } else {
        (dst, dport, src, sport)
    };
    let local = local.to_canonical();
    let remote = remote.to_canonical();
    if local.is_loopback() || remote.is_loopback() || remote.is_unspecified() {
        return;
    }
    let key = FlowKey {
        proto,
        local,
        lport,
        remote,
        rport,
    };
    let entry = out.entry(key).or_insert((0, 0));
    if outgoing {
        entry.1 += real_len;
    } else {
        entry.0 += real_len;
    }
}

type Parsed = (u8, IpAddr, u16, IpAddr, u16);

fn parse_ip(eth: u16, data: &[u8]) -> Option<Parsed> {
    match eth {
        ETH_P_IP => {
            if data.len() < 20 || data[0] >> 4 != 4 {
                return None;
            }
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if ihl < 20 {
                return None;
            }
            // Only the first fragment carries the ports.
            if u16::from_be_bytes([data[6], data[7]]) & 0x1fff != 0 {
                return None;
            }
            let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
            let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
            ports(data[9], src, dst, data.get(ihl..)?)
        }
        ETH_P_IPV6 => {
            if data.len() < 40 || data[0] >> 4 != 6 {
                return None;
            }
            let mut next = data[6];
            let mut off = 40usize;
            // Skip hop-by-hop / routing / destination-options headers.
            while matches!(next, 0 | 43 | 60) {
                if data.len() < off + 8 {
                    return None;
                }
                let len = (data[off + 1] as usize + 1) * 8;
                next = data[off];
                off += len;
            }
            let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
            let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
            ports(next, src, dst, data.get(off..)?)
        }
        _ => None,
    }
}

fn ports(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8]) -> Option<Parsed> {
    if proto != PROTO_TCP && proto != PROTO_UDP {
        return None;
    }
    if l4.len() < 4 {
        return None;
    }
    let sport = u16::from_be_bytes([l4[0], l4[1]]);
    let dport = u16::from_be_bytes([l4[2], l4[3]]);
    Some((proto, src, sport, dst, dport))
}
