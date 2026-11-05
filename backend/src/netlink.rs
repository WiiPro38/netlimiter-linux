use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;

use libc::{
    c_int, c_void, nlmsghdr, recv, send, socket, AF_INET, AF_INET6, AF_NETLINK, IPPROTO_TCP,
    IPPROTO_UDP, NETLINK_SOCK_DIAG, SOCK_CLOEXEC, SOCK_RAW,
};

const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_DONE: u16 = 3;
const NLMSG_ERROR: u16 = 2;
const NLMSG_ALIGNTO: usize = 4;
const INET_DIAG_INFO: u8 = 2;
const INET_DIAG_NOCOOKIE: u32 = !0;

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagSockId {
    sport: u16,
    dport: u16,
    src: [u32; 4],
    dst: [u32; 4],
    ifindex: u32,
    cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagReqV2 {
    family: u8,
    protocol: u8,
    ext: u8,
    pad: u8,
    states: u32,
    id: InetDiagSockId,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InetDiagMsg {
    family: u8,
    state: u8,
    timer: u8,
    retrans: u8,
    id: InetDiagSockId,
    expires: u32,
    rqueue: u32,
    wqueue: u32,
    uid: u32,
    inode: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

fn nlmsg_align(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

/// Reads a `T` from `buf` at `offset` without requiring alignment.
/// Returns None if the buffer is too short.
fn read_at<T: Copy>(buf: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(mem::size_of::<T>())?;
    if end > buf.len() {
        return None;
    }
    // SAFETY: bounds checked above; T is plain-old-data (repr(C), Copy) and
    // read_unaligned has no alignment requirement.
    Some(unsafe { ptr::read_unaligned(buf.as_ptr().add(offset) as *const T) })
}

#[derive(Debug, Clone)]
pub struct SockInfo {
    pub proto: &'static str,
    pub family: u8,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u64,
    pub uid: u32,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

pub fn dump_sockets() -> io::Result<Vec<SockInfo>> {
    let mut out = Vec::new();
    for family in [AF_INET as u8, AF_INET6 as u8] {
        for proto in [IPPROTO_TCP as u8, IPPROTO_UDP as u8] {
            // UDP diag can be unavailable on some kernels; keep going on any error.
            let _ = dump_family_proto(family, proto, &mut out);
        }
    }
    Ok(out)
}

fn dump_family_proto(family: u8, proto: u8, out: &mut Vec<SockInfo>) -> io::Result<()> {
    // SAFETY: plain libc calls; fd is closed on every path below.
    let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = dump_on_fd(fd, family, proto, out);
    unsafe { libc::close(fd) };
    result
}

fn build_request(family: u8, proto: u8) -> Vec<u8> {
    let hdr_len = mem::size_of::<nlmsghdr>();
    let total = hdr_len + mem::size_of::<InetDiagReqV2>();
    let mut buf = vec![0u8; total];

    let hdr = nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: SOCK_DIAG_BY_FAMILY,
        nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
        nlmsg_seq: 1,
        nlmsg_pid: 0,
    };
    let req = InetDiagReqV2 {
        family,
        protocol: proto,
        ext: 1 << (INET_DIAG_INFO - 1),
        pad: 0,
        states: !0,
        id: InetDiagSockId {
            sport: 0,
            dport: 0,
            src: [0; 4],
            dst: [0; 4],
            ifindex: 0,
            cookie: [INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE],
        },
    };
    // SAFETY: buf has exactly hdr_len + size_of::<InetDiagReqV2>() bytes.
    unsafe {
        ptr::write_unaligned(buf.as_mut_ptr() as *mut nlmsghdr, hdr);
        ptr::write_unaligned(buf.as_mut_ptr().add(hdr_len) as *mut InetDiagReqV2, req);
    }
    buf
}

fn dump_on_fd(fd: c_int, family: u8, proto: u8, out: &mut Vec<SockInfo>) -> io::Result<()> {
    let req_buf = build_request(family, proto);
    let sent = unsafe { send(fd, req_buf.as_ptr() as *const c_void, req_buf.len(), 0) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let hdr_size = mem::size_of::<nlmsghdr>();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe { recv(fd, buf.as_mut_ptr() as *mut c_void, buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let n = n as usize;
        if n == 0 {
            break;
        }

        let mut offset = 0usize;
        let mut done = false;
        while offset + hdr_size <= n {
            let Some(nlh) = read_at::<nlmsghdr>(&buf[..n], offset) else {
                break;
            };
            let len = nlh.nlmsg_len as usize;
            if len < hdr_size || offset + len > n {
                break;
            }
            match nlh.nlmsg_type {
                NLMSG_DONE => done = true,
                NLMSG_ERROR => {
                    return Err(io::Error::new(io::ErrorKind::Other, "netlink error"));
                }
                SOCK_DIAG_BY_FAMILY => {
                    parse_diag(&buf[offset + hdr_size..offset + len], proto, out);
                }
                _ => {}
            }
            offset += nlmsg_align(len);
        }
        if done {
            break;
        }
    }
    Ok(())
}

fn parse_diag(payload: &[u8], proto: u8, out: &mut Vec<SockInfo>) {
    let Some(msg) = read_at::<InetDiagMsg>(payload, 0) else {
        return;
    };
    let local = addr_from(msg.family, &msg.id.src, msg.id.sport);
    let remote = addr_from(msg.family, &msg.id.dst, msg.id.dport);
    let (Some(local), Some(remote)) = (local, remote) else {
        return;
    };

    let mut bytes_sent = 0u64;
    let mut bytes_recv = 0u64;
    let nla_size = mem::size_of::<NlAttr>();
    let mut attr_off = nlmsg_align(mem::size_of::<InetDiagMsg>());
    while attr_off + nla_size <= payload.len() {
        let Some(nla) = read_at::<NlAttr>(payload, attr_off) else {
            break;
        };
        let nla_len = nla.nla_len as usize;
        if nla_len < nla_size || attr_off + nla_len > payload.len() {
            break;
        }
        if (nla.nla_type & 0x3fff) == INET_DIAG_INFO as u16 {
            let data = &payload[attr_off + nla_size..attr_off + nla_len];
            parse_tcp_info(data, &mut bytes_sent, &mut bytes_recv);
        }
        attr_off += nlmsg_align(nla_len);
    }

    out.push(SockInfo {
        proto: if proto == IPPROTO_TCP as u8 { "tcp" } else { "udp" },
        family: msg.family,
        local,
        remote,
        state: msg.state,
        inode: msg.inode as u64,
        uid: msg.uid,
        bytes_sent,
        bytes_recv,
    });
}

fn read_u64(data: &[u8], at: usize) -> u64 {
    data.get(at..at + 8)
    .and_then(|s| s.try_into().ok())
    .map(u64::from_ne_bytes)
    .unwrap_or(0)
}

fn parse_tcp_info(data: &[u8], sent: &mut u64, recv: &mut u64) {
    // offsetof(struct tcp_info, ...) on current kernels:
    // tcpi_bytes_acked=120, tcpi_bytes_received=128, tcpi_bytes_sent=200
    if data.len() >= 136 {
        *sent = sane_counter(read_u64(data, 120));
        *recv = sane_counter(read_u64(data, 128));
    }
    if data.len() >= 208 {
        let bytes_sent = sane_counter(read_u64(data, 200));
        if bytes_sent > 0 {
            *sent = bytes_sent;
        }
    }
}

fn sane_counter(value: u64) -> u64 {
    if value > (1u64 << 60) {
        0
    } else {
        value
    }
}

fn addr_from(family: u8, words: &[u32; 4], port_be: u16) -> Option<SocketAddr> {
    let port = u16::from_be(port_be);
    if family == AF_INET as u8 {
        // The kernel stores the address in network byte order inside a native u32.
        let ip = Ipv4Addr::from(u32::from_be(words[0]));
        Some(SocketAddr::from((ip, port)))
    } else if family == AF_INET6 as u8 {
        // Each word already holds 4 raw network-order bytes: copy them back
        // unchanged (to_ne_bytes), NOT to_be_bytes, which swaps them on x86.
        let mut octets = [0u8; 16];
        for (i, w) in words.iter().enumerate() {
            octets[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        Some(SocketAddr::from((Ipv6Addr::from(octets), port)))
    } else {
        None
    }
}

pub fn tcp_state_name(state: u8) -> &'static str {
    match state {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}
