use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CString;
use std::fs;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::monitor::Monitor;
use crate::nft::{self, NftState};
use crate::protocol::{ConnectionRow, Request, Response, Rule, RuleAction, Snapshot};
use crate::rules::RuleStore;
use crate::tc;

/// Longest accepted request line (a request is a few hundred bytes).
const MAX_LINE: u64 = 64 * 1024;

/// لا نُشعر نفس التطبيق أكثر من مرة خلال هذه المدة.
/// بعد انقضائها، إذا لم تكن هناك قاعدة، نُشعر مرة أخرى.
const NOTIFY_COOLDOWN: Duration = Duration::from_secs(30);

pub struct AppState {
    pub monitor: Mutex<Monitor>,
    pub rules: Mutex<RuleStore>,
    pub last: Mutex<Snapshot>,
    pub nft: Mutex<NftState>,
    pub paused: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl AppState {
    pub fn new() -> Arc<Self> {
        let mut rules = RuleStore::load();
        if !AUTO_BLOCK_NEW_APPS {
            // قواعد حظر تلقائي قديمة محفوظة من إصدارات سابقة: تُحذف.
            let before = rules.rules.len();
            rules.rules.retain(|r| !r.id.starts_with("auto-"));
            if rules.rules.len() != before {
                rules.persist();
            }
        }
        let snapshot = Snapshot {
            processes: Vec::new(),
            connections: Vec::new(),
            rules: rules.rules.clone(),
            lock_all: rules.lock_all,
            iface_down_bps: 0,
            iface_up_bps: 0,
            privileged: crate::monitor::privileged(),
            nft_ok: false,
            paused: false,
            iface_down_total: 0,
            iface_up_total: 0,
            capture_ok: false,
        };
        Arc::new(Self {
            monitor: Mutex::new(Monitor::new()),
                 rules: Mutex::new(rules),
                 last: Mutex::new(snapshot),
                 nft: Mutex::new(NftState::default()),
                 paused: AtomicBool::new(false),
        })
    }
}

pub fn socket_path() -> String {
    if crate::monitor::privileged() {
        "/run/netlimiter/netlimiter.sock".to_string()
    } else if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{dir}/netlimiter.sock")
    } else {
        "/tmp/netlimiter.sock".to_string()
    }
}

pub fn shutdown() {
    nft::cleanup();
    tc::cleanup();
    {
        let mut guard = lock(notifier_cell());
        *guard = None;
    }
    let _ = fs::remove_file(socket_path());
}

pub fn serve(state: Arc<AppState>) -> Result<(), String> {
    let path = socket_path();
    if let Some(parent) = Path::new(&path).parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path).map_err(|e| format!("bind {path}: {e}"))?;

    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o666));

    eprintln!("netlimiterd listening on {path}");
    for incoming in listener.incoming() {
        let Ok(stream) = incoming else {
            continue;
        };
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(err) = handle_client(state, stream) {
                eprintln!("client: {err}");
            }
        });
    }
    Ok(())
}

#[allow(dead_code)]
fn apply_socket_perms(path: &str) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o666));
}

/// true = كل تطبيق جديد يتصل بالشبكة يُحظر حتى يقرر المستخدم.
const AUTO_BLOCK_NEW_APPS: bool = true;

static NSS_LOCK: Mutex<()> = Mutex::new(());
/// wheel = Fedora/RHEL/Arch admins, sudo/admin = Debian/Ubuntu/Kubuntu admins.
const ALLOWED_GROUPS: [&str; 5] = ["wheel", "sudo", "admin", "adm", "netlimiter"];

/// آخر مرة أُرسل فيها إشعار لكل تطبيق (cooldown).
static LAST_NOTIFIED: Mutex<Option<HashMap<String, Instant>>> = Mutex::new(None);

/// تطبيقات قرر المستخدم فك حظرها يدوياً — لا إشعار لها أبداً.
static USER_OVERRIDES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

fn is_user_override(exe: &str) -> bool {
    let guard = lock(&USER_OVERRIDES);
    guard.as_ref().map(|s| s.contains(exe)).unwrap_or(false)
}

fn mark_user_override(exe: &str) {
    let mut guard = lock(&USER_OVERRIDES);
    guard.get_or_insert_with(HashSet::new).insert(exe.to_string());
}

fn clear_user_override(exe: &str) {
    let mut guard = lock(&USER_OVERRIDES);
    if let Some(set) = guard.as_mut() {
        set.remove(exe);
    }
}

fn clear_all_user_overrides() {
    let mut guard = lock(&USER_OVERRIDES);
    if let Some(set) = guard.as_mut() {
        set.clear();
    }
}

fn forget_all_notified() {
    let mut guard = lock(&LAST_NOTIFIED);
    if let Some(map) = guard.as_mut() {
        map.clear();
    }
}

/// يعيد true إذا كان مسموحاً بإرسال إشعار لهذا التطبيق الآن.
fn should_notify(exe: &str) -> bool {
    let now = Instant::now();
    let mut guard = lock(&LAST_NOTIFIED);
    let map = guard.get_or_insert_with(HashMap::new);
    if let Some(last) = map.get(exe) {
        if now.duration_since(*last) < NOTIFY_COOLDOWN {
            return false;
        }
    }
    map.insert(exe.to_string(), now);
    true
}

/// FNV-1a hash — يُستخدم لتوليد id ثابت لقاعدة auto-block.
fn simple_hash(s: &str) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// id قاعدة الحظر التلقائي (auto-block) لتطبيق ما.
fn auto_block_id(exe: &str) -> String {
    format!("auto-{}", simple_hash(exe))
}

/// هل التطبيق لديه قاعدة "يدوية" (قرار مستخدم، ليست auto-block)؟
fn has_manual_rule(store: &RuleStore, exe: &str) -> bool {
    store
    .rules
    .iter()
    .any(|r| r.exe == exe && !r.id.starts_with("auto-"))
}

/// احذف قاعدة auto-block إن وُجدت. يعيد true إذا حُذف شيء.
fn remove_auto_block(store: &mut RuleStore, exe: &str) -> bool {
    let before = store.rules.len();
    store.rules.retain(|r| !(r.exe == exe && r.id.starts_with("auto-")));
    let removed = store.rules.len() != before;
    if removed {
        store.persist();
    }
    removed
}

// =====================================================================
// Notifier
// =====================================================================

struct NotifierHandle {
    child: Child,
    stdin: BufWriter<ChildStdin>,
}

static NOTIFIER: OnceLock<Mutex<Option<NotifierHandle>>> = OnceLock::new();

fn notifier_cell() -> &'static Mutex<Option<NotifierHandle>> {
    NOTIFIER.get_or_init(|| Mutex::new(None))
}

fn spawn_notifier() -> Option<NotifierHandle> {
    let (user, uid) = get_active_gui_user()?;
    let bus = format!("unix:path=/run/user/{}/bus", uid);
    let runtime = format!("/run/user/{}", uid);

    // runuser بدل su (su فشل بـ "cannot set groups")
    let mut child = Command::new("runuser")
    .arg("-u")
    .arg(&user)
    .arg("--")
    .arg("/usr/bin/env")
    .arg(format!("DBUS_SESSION_BUS_ADDRESS={}", bus))
    .arg(format!("XDG_RUNTIME_DIR={}", runtime))
    .arg("/usr/bin/python3")
    .arg("/usr/libexec/netlimiter/netlimiter_notifier.py")
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::inherit())
    .spawn()
    .ok()?;

    let stdin = child.stdin.take()?;
    Some(NotifierHandle {
        child,
         stdin: BufWriter::new(stdin),
    })
}

fn ensure_notifier() -> MutexGuard<'static, Option<NotifierHandle>> {
    let mut guard = lock(notifier_cell());
    let dead = guard
    .as_mut()
    .map(|h| h.child.try_wait().map(|s| s.is_some()).unwrap_or(true))
    .unwrap_or(true);
    if dead {
        *guard = spawn_notifier();
        if guard.is_some() {
            eprintln!("notifier: started");
        } else {
            eprintln!("notifier: unavailable (no GUI user or script missing)");
        }
    }
    guard
}

fn notify_new_app(exe: &str, name: &str) {
    let mut guard = ensure_notifier();
    let Some(handle) = guard.as_mut() else {
        return;
    };
    let payload = serde_json::json!({
        "type": "new_app",
        "exe": exe,
        "name": name,
    });
    let line = match serde_json::to_string(&payload) {
        Ok(s) => s,
        Err(_) => return,
    };
    if handle.stdin.write_all(line.as_bytes()).is_err()
        || handle.stdin.write_all(b"\n").is_err()
        || handle.stdin.flush().is_err()
        {
            *guard = None;
        }
}

fn notify_and_block_new_app(state: &AppState, exe: &str, name: &str) {
    if state.paused.load(Ordering::SeqCst) {
        return;
    }
    if exe.is_empty() || exe == "global" {
        return;
    }
    if is_user_override(exe) {
        return;
    }

    // إذا كانت هناك قاعدة يدوية (قرار المستخدم) → لا حظر تلقائي ولا إشعار
    {
        let store = lock(&state.rules);
        if has_manual_rule(&store, exe) {
            return;
        }
    }

    // الحظر التلقائي للتطبيقات الجديدة مفعّل (AUTO_BLOCK_NEW_APPS).
    if AUTO_BLOCK_NEW_APPS {
        let mut store = lock(&state.rules);
        let auto_id = auto_block_id(exe);
        if !store.rules.iter().any(|r| r.id == auto_id) {
            store.rules.push(Rule {
                id: auto_id,
                exe: exe.to_string(),
                action: RuleAction::Block,
                down_kbps: None,
                up_kbps: None,
                enabled: true,
            });
            store.persist();
            eprintln!("auto-block: {exe}");
        }
    }

    // إشعار (مرة كل 30 ثانية)
    if !should_notify(exe) {
        return;
    }
    notify_new_app(exe, name);
}

/// Active graphical user. logind is authoritative (utmp, which `who` reads,
/// is no longer written on recent Debian/Ubuntu); `who` stays as a fallback.
fn get_active_gui_user() -> Option<(String, String)> {
    if let Some(found) = gui_user_from_logind() {
        return Some(found);
    }
    let output = Command::new("who").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && (parts[1].starts_with("tty") || parts[1].starts_with(":")) {
            let user = parts[0].to_string();
            let uid_out = Command::new("id").arg("-u").arg(&user).output().ok()?;
            let uid = String::from_utf8_lossy(&uid_out.stdout).trim().to_string();
            return Some((user, uid));
        }
    }
    None
}

fn gui_user_from_logind() -> Option<(String, String)> {
    let list = Command::new("loginctl")
        .args(["list-sessions", "--no-legend"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&list.stdout);
    for line in text.lines() {
        let Some(id) = line.split_whitespace().next() else {
            continue;
        };
        let show = Command::new("loginctl")
            .args(["show-session", id, "-p", "Name", "-p", "User", "-p", "Type", "-p", "Active", "-p", "Class"])
            .output()
            .ok()?;
        let info = String::from_utf8_lossy(&show.stdout);
        let get = |key: &str| {
            info.lines()
                .find_map(|l| l.strip_prefix(&format!("{key}=")))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        let graphical = matches!(get("Type").as_str(), "x11" | "wayland" | "mir");
        if get("Active") == "yes" && get("Class") == "user" && graphical {
            let (name, uid) = (get("Name"), get("User"));
            if !name.is_empty() && !uid.is_empty() {
                return Some((name, uid));
            }
        }
    }
    None
}

fn peer_cred(stream: &std::os::unix::net::UnixStream) -> Option<(u32, u32)> {
    use std::os::unix::io::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
                         libc::SOL_SOCKET,
                         libc::SO_PEERCRED,
                         &mut cred as *mut libc::ucred as *mut libc::c_void,
                         &mut len,
        )
    };
    if rc == 0 {
        Some((cred.uid, cred.gid))
    } else {
        None
    }
}

fn user_groups(uid: u32, gid: u32) -> Vec<u32> {
    let _guard = NSS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return vec![gid];
        }
        let name = (*pw).pw_name;
        let mut capacity: libc::c_int = 32;
        loop {
            let mut buf: Vec<libc::gid_t> = vec![0; capacity as usize];
            let mut count = capacity;
            if libc::getgrouplist(name, gid, buf.as_mut_ptr(), &mut count) >= 0 {
                buf.truncate(count as usize);
                return buf;
            }
            capacity = count.max(capacity * 2);
        }
    }
}

fn group_id(name: &str) -> Option<u32> {
    let _guard = NSS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cname = CString::new(name).ok()?;
    unsafe {
        let grp = libc::getgrnam(cname.as_ptr());
        if grp.is_null() {
            None
        } else {
            Some((*grp).gr_gid)
        }
    }
}

fn is_authorized(uid: u32, gid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let groups = user_groups(uid, gid);
    ALLOWED_GROUPS
    .iter()
    .filter_map(|g| group_id(g))
    .any(|allowed| groups.contains(&allowed))
}

fn handle_client(
    state: Arc<AppState>,
    stream: std::os::unix::net::UnixStream,
) -> Result<(), String> {
    let authorized = match peer_cred(&stream) {
        Some((uid, gid)) => is_authorized(uid, gid),
        None => false,
    };
    let mut reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = (&mut reader)
        .take(MAX_LINE)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if n as u64 >= MAX_LINE && !line.ends_with('\n') {
            let _ = write_resp(&mut writer, &Response::err("request too long"));
            return Err("request too long".into());
        }
        let req: Request = match serde_json::from_str(line.trim()) {
            Ok(req) => req,
            Err(err) => {
                write_resp(&mut writer, &Response::err(format!("bad json: {err}")))?;
                continue;
            }
        };
        let resp = if authorized || matches!(req, Request::Ping) {
            dispatch(&state, req)
        } else {
            Response::err("not authorized")
        };
        write_resp(&mut writer, &resp)?;
    }
    Ok(())
}

fn write_resp(writer: &mut impl Write, resp: &Response) -> Result<(), String> {
    let mut text = serde_json::to_string(resp).map_err(|e| e.to_string())?;
    text.push('\n');
    writer
    .write_all(text.as_bytes())
    .map_err(|e| e.to_string())
}

fn dispatch(state: &AppState, req: Request) -> Response {
    match req {
        Request::Ping => Response::ok(),
        Request::Snapshot => Response::snapshot(lock(&state.last).clone()),
        Request::SetLock { enabled } => {
            lock(&state.rules).lock_all = enabled;
            apply_rules(state);
            Response::ok()
        }
        Request::SetPaused { enabled } => {
            state.paused.store(enabled, Ordering::SeqCst);
            if enabled {
                nft::cleanup();
                tc::cleanup();
            } else {
                apply_rules(state);
            }
            {
                let mut last = lock(&state.last);
                last.paused = enabled;
            }
            Response::ok()
        }
        Request::SetRule {
            exe,
            action,
            down_kbps,
            up_kbps,
            enabled,
        } => {
            if action == RuleAction::Block {
                clear_user_override(&exe);
            }
            let mut store = lock(&state.rules);
            // ✅ احذف قاعدة auto-block إن وُجدت (المستخدم قرر الآن)
            remove_auto_block(&mut store, &exe);
            store.upsert(exe, action, down_kbps, up_kbps, enabled);
            drop(store);
            apply_rules(state);
            Response::ok()
        }
        Request::DeleteRule { exe } => {
            mark_user_override(&exe);
            {
                let mut guard = lock(&LAST_NOTIFIED);
                if let Some(map) = guard.as_mut() {
                    map.remove(&exe);
                }
            }
            let mut store = lock(&state.rules);
            // احذف كل شيء (auto + يدوي)
            store.rules.retain(|r| r.exe != exe);
            store.persist();
            drop(store);
            apply_rules(state);
            Response::ok()
        }
        Request::ClearRules => {
            {
                let mut store = lock(&state.rules);
                store.clear();
                drop(store);
            }
            forget_all_notified();
            clear_all_user_overrides();
            apply_rules(state);
            Response::ok()
        }
    }
}

pub fn sampler_loop(state: Arc<AppState>) {
    loop {
        sample_once(&state);
        thread::sleep(crate::monitor::tick_interval());
    }
}

/// اتصال بعنوان بعيد حقيقي (ليس loopback ولا 0.0.0.0 ولا LISTEN).
fn talks_to_network(conn: &ConnectionRow) -> bool {
    conn.remote
    .parse::<std::net::SocketAddr>()
    .map(|a| {
        let ip = a.ip().to_canonical();
        !ip.is_loopback() && !ip.is_unspecified()
    })
    .unwrap_or(false)
}

fn sample_once(state: &AppState) {
    let sample = lock(&state.monitor).sample();

    // لا نُشعر إلا عن التطبيقات التي لها اتصال فعلي خارج الجهاز الآن.
    let talking: HashSet<&str> = sample
    .connections
    .iter()
    .filter(|c| talks_to_network(c))
    .map(|c| c.exe.as_str())
    .collect();
    for proc in &sample.processes {
        if proc.exe != "unknown" && talking.contains(proc.exe.as_str()) {
            notify_and_block_new_app(state, &proc.exe, &proc.name);
        }
    }

    {
        let mut last = lock(&state.last);
        last.processes = sample.processes;
        last.connections = sample.connections;
        last.iface_down_bps = sample.iface_down_bps;
        last.iface_up_bps = sample.iface_up_bps;
        last.iface_down_total = sample.iface_down_total;
        last.iface_up_total = sample.iface_up_total;
        last.capture_ok = sample.capture_ok;
        last.privileged = crate::monitor::privileged();
        last.paused = state.paused.load(Ordering::SeqCst);
    }
    apply_rules(state);
}

fn apply_rules(state: &AppState) {
    if state.paused.load(Ordering::SeqCst) {
        let (rules, lock_all) = {
            let store = lock(&state.rules);
            (store.rules.clone(), store.lock_all)
        };
        let mut last = lock(&state.last);
        last.rules = rules;
        last.lock_all = lock_all;
        last.paused = true;
        return;
    }

    let connections = lock(&state.last).connections.clone();
    let (rules, lock_all) = {
        let store = lock(&state.rules);
        (store.rules.clone(), store.lock_all)
    };
    let nft_ok = if crate::monitor::privileged() {
        let mut nft_state = lock(&state.nft);
        nft_state.refresh(&rules, &connections);
        // Strict shaping first; the nft policer is only a fallback.
        let tc_ok = tc::apply(lock_all, &rules, &|exe| nft_state.ips_for(exe)).is_ok();
        match nft::apply(&mut nft_state, lock_all, !tc_ok, &rules, &connections) {
            Ok(()) => true,
            Err(err) => {
                eprintln!("nft: {err}");
                false
            }
        }
    } else {
        false
    };
    let mut last = lock(&state.last);
    last.rules = rules;
    last.lock_all = lock_all;
    last.nft_ok = nft_ok;
    last.paused = false;
}
