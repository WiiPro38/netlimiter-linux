use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessRow {
    pub exe: String,
    pub name: String,
    pub pids: Vec<i32>,
    pub uid: u32,
    pub connections: u32,
    pub down_bps: u64,
    pub up_bps: u64,
    pub down_total: u64,
    pub up_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRow {
    pub proto: String,
    pub family: String,
    pub local: String,
    pub remote: String,
    pub state: String,
    pub inode: u64,
    pub pid: i32,
    pub exe: String,
    pub name: String,
    pub uid: u32,
    pub down_bps: u64,
    pub up_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Block,
    Limit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub exe: String,
    pub action: RuleAction,
    pub down_kbps: Option<u32>,
    pub up_kbps: Option<u32>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub processes: Vec<ProcessRow>,
    pub connections: Vec<ConnectionRow>,
    pub rules: Vec<Rule>,
    pub lock_all: bool,
    pub iface_down_bps: u64,
    pub iface_up_bps: u64,
    pub privileged: bool,
    pub nft_ok: bool,
    #[serde(default)]
    pub paused: bool,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Snapshot,
    SetLock {
        enabled: bool,
    },
    /// إيقاف/استئناف تطبيق القواعد مؤقتاً (لا يمسح rules.json).
    SetPaused {
        enabled: bool,
    },
    SetRule {
        exe: String,
        action: RuleAction,
        down_kbps: Option<u32>,
        up_kbps: Option<u32>,
        enabled: Option<bool>,
    },
    DeleteRule {
        exe: String,
    },
    ClearRules,
}

#[derive(Debug, Serialize)]
pub struct Response {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Snapshot>,
}

impl Response {
    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            snapshot: None,
        }
    }

    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            snapshot: None,
        }
    }

    pub fn snapshot(snapshot: Snapshot) -> Self {
        Self {
            ok: true,
            error: None,
            snapshot: Some(snapshot),
        }
    }
}
