// Erpis access control.
//
// hbbs: when ERPIS_INITIATOR_CIDRS is set, only peers whose TCP source address
// is inside one of those networks may start a session (PunchHoleRequest,
// RequestRelay) or query online status. Everyone may still register, so
// controlled devices keep working from any network. WebSocket initiators are
// refused because their address comes from an unauthenticated header.
//
// hbbr: when ERPIS_RELAY_GATE=Y, two connections are paired only if hbbs
// announced their uuid for an authorized initiator, so the relay cannot be
// used by clients that talk to hbbr directly.
#![allow(dead_code)]

use crate::common::get_arg;
use hbb_common::{
    bail, log,
    tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
        sync::Mutex,
        time::sleep,
    },
    timeout, try_into_v4, ResultType,
};
use ipnetwork::IpNetwork;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

pub const REFUSED: &str = "Erpis: unauthorized initiator";
pub const CONSOLE_ALLOW_CMD: &str = "erpis-allow";

const AUTHORIZED_TTL: Duration = Duration::from_secs(120);
const ALLOWED_UUID_TTL: Duration = Duration::from_secs(60);
const REFUSED_LOG_INTERVAL: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 10_000;
const MAX_UUID_LEN: usize = 64;
const ANNOUNCE_TIMEOUT_MS: u64 = 1_000;
const PAIR_WAIT: Duration = Duration::from_secs(3);
const PAIR_POLL: Duration = Duration::from_millis(50);
const DEFAULT_RELAY_CONSOLE: &str = "127.0.0.1:21117";

static INITIATOR_NETS: Lazy<Result<Option<Vec<IpNetwork>>, String>> =
    Lazy::new(|| parse_nets(&get_arg("ERPIS_INITIATOR_CIDRS")));
static RELAY_CONSOLE: Lazy<String> = Lazy::new(|| {
    let v = get_arg("ERPIS_RELAY_CONSOLE");
    if v.is_empty() {
        DEFAULT_RELAY_CONSOLE.to_owned()
    } else {
        v
    }
});
static RELAY_GATE: Lazy<bool> =
    Lazy::new(|| get_arg("ERPIS_RELAY_GATE").eq_ignore_ascii_case("Y"));

static AUTHORIZED: Lazy<Mutex<HashMap<SocketAddr, Instant>>> = Lazy::new(Default::default);
static ALLOWED_UUIDS: Lazy<Mutex<HashMap<String, Instant>>> = Lazy::new(Default::default);
static REFUSED_LOG: Lazy<Mutex<HashMap<IpAddr, Instant>>> = Lazy::new(Default::default);

/// Empty input disables the gate; any invalid entry is an error (fail closed at startup).
pub fn parse_nets(s: &str) -> Result<Option<Vec<IpNetwork>>, String> {
    let entries: Vec<&str> = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .collect();
    if entries.is_empty() {
        return Ok(None);
    }
    let mut nets = Vec::with_capacity(entries.len());
    for e in entries {
        match e.parse::<IpNetwork>() {
            Ok(net) => nets.push(net),
            Err(err) => return Err(format!("invalid ERPIS_INITIATOR_CIDRS entry {e:?}: {err}")),
        }
    }
    Ok(Some(nets))
}

/// hbbs startup check: refuses to start with a malformed allowlist.
pub fn init() -> ResultType<()> {
    match &*INITIATOR_NETS {
        Err(err) => bail!("{}", err),
        Ok(None) => log::info!("Erpis access control: disabled (ERPIS_INITIATOR_CIDRS not set)"),
        Ok(Some(nets)) => log::info!(
            "Erpis access control: initiators limited to {:?}, relay console {}",
            nets,
            *RELAY_CONSOLE
        ),
    }
    Ok(())
}

pub fn enabled() -> bool {
    matches!(&*INITIATOR_NETS, Ok(Some(_)))
}

fn nets_allow(nets: &[IpNetwork], addr: SocketAddr, ws: bool) -> bool {
    if ws {
        return false;
    }
    let ip = try_into_v4(addr).ip();
    nets.iter().any(|net| net.contains(ip))
}

pub fn is_initiator_allowed(addr: SocketAddr, ws: bool) -> bool {
    match &*INITIATOR_NETS {
        Ok(None) => true,
        Ok(Some(nets)) => nets_allow(nets, addr, ws),
        Err(_) => false,
    }
}

pub async fn log_refused(addr: SocketAddr, what: &str, peer_id: &str) {
    let ip = try_into_v4(addr).ip();
    let mut lock = REFUSED_LOG.lock().await;
    if let Some(tm) = lock.get(&ip) {
        if tm.elapsed() < REFUSED_LOG_INTERVAL {
            return;
        }
    }
    if lock.len() >= MAX_ENTRIES {
        lock.clear();
    }
    lock.insert(ip, Instant::now());
    drop(lock);
    log::warn!("Erpis: refused {} from {} for peer {}", what, ip, peer_id);
}

fn insert_with_ttl<K: std::hash::Hash + Eq>(map: &mut HashMap<K, Instant>, k: K, ttl: Duration) {
    if map.len() >= MAX_ENTRIES {
        map.retain(|_, tm| tm.elapsed() < ttl);
        if map.len() >= MAX_ENTRIES {
            map.clear();
        }
    }
    map.insert(k, Instant::now());
}

/// Remembers the exact TCP address of an authorized initiator, so a later
/// RelayResponse addressed to it can be trusted to belong to its session.
pub async fn record_authorized(addr: SocketAddr) {
    if !enabled() {
        return;
    }
    let mut lock = AUTHORIZED.lock().await;
    insert_with_ttl(&mut lock, try_into_v4(addr), AUTHORIZED_TTL);
}

pub async fn is_authorized(addr: SocketAddr) -> bool {
    let lock = AUTHORIZED.lock().await;
    matches!(lock.get(&try_into_v4(addr)), Some(tm) if tm.elapsed() < AUTHORIZED_TTL)
}

pub fn valid_uuid(uuid: &str) -> bool {
    !uuid.is_empty()
        && uuid.len() <= MAX_UUID_LEN
        && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Tells hbbr (via its loopback console) that this relay uuid belongs to an
/// authorized session. Awaited before the message that reveals the uuid to
/// the other side is forwarded, so the announcement always arrives first.
pub async fn announce_uuid(uuid: &str) {
    if !enabled() {
        return;
    }
    if !valid_uuid(uuid) {
        log::warn!("Erpis: not announcing malformed relay uuid {:?}", uuid);
        return;
    }
    if let Err(err) = send_announce(uuid).await {
        log::error!(
            "Erpis: failed to announce relay uuid to hbbr at {}: {}",
            *RELAY_CONSOLE,
            err
        );
    }
}

async fn send_announce(uuid: &str) -> ResultType<()> {
    let mut stream = timeout(ANNOUNCE_TIMEOUT_MS, TcpStream::connect(RELAY_CONSOLE.as_str())).await??;
    stream
        .write_all(format!("{} {}", CONSOLE_ALLOW_CMD, uuid).as_bytes())
        .await?;
    let mut buf = [0u8; 16];
    let n = timeout(ANNOUNCE_TIMEOUT_MS, stream.read(&mut buf)).await??;
    if &buf[..n] != b"ok\n" {
        bail!("unexpected reply {:?}", String::from_utf8_lossy(&buf[..n]));
    }
    Ok(())
}

// ---- hbbr side ----

pub fn relay_gate_enabled() -> bool {
    *RELAY_GATE
}

pub fn log_relay_gate() {
    if relay_gate_enabled() {
        log::info!("Erpis relay gate: enabled, only uuids announced by hbbs are paired");
    } else {
        log::info!("Erpis relay gate: disabled (ERPIS_RELAY_GATE not Y)");
    }
}

/// Console handler; returns the reply line.
pub async fn console_allow(uuid: Option<&str>) -> String {
    match uuid {
        Some(uuid) if valid_uuid(uuid) => {
            let mut lock = ALLOWED_UUIDS.lock().await;
            insert_with_ttl(&mut lock, uuid.to_owned(), ALLOWED_UUID_TTL);
            "ok\n".to_owned()
        }
        _ => "invalid\n".to_owned(),
    }
}

async fn take_allowed_now(uuid: &str) -> bool {
    let mut lock = ALLOWED_UUIDS.lock().await;
    match lock.remove(uuid) {
        Some(tm) => tm.elapsed() < ALLOWED_UUID_TTL,
        None => false,
    }
}

/// Called when the second side of a relay arrives. Waits briefly in case the
/// announcement is still in flight; the uuid can be used for one pairing only.
pub async fn take_allowed_uuid(uuid: &str) -> bool {
    let deadline = Instant::now() + PAIR_WAIT;
    loop {
        if take_allowed_now(uuid).await {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        sleep(PAIR_POLL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn empty_allowlist_disables_gate() {
        assert_eq!(parse_nets("").unwrap(), None);
        assert_eq!(parse_nets("  , ").unwrap(), None);
    }

    #[test]
    fn malformed_allowlist_is_an_error() {
        assert!(parse_nets("10.8.0.0/24,nonsense").is_err());
        assert!(parse_nets("10.8.0.0/33").is_err());
    }

    #[test]
    fn allowlist_matches_v4_and_mapped_v4_but_never_ws() {
        let nets = parse_nets("10.8.0.0/24, 203.0.113.7/32").unwrap().unwrap();
        assert!(nets_allow(&nets, sa("10.8.0.2:5000"), false));
        assert!(nets_allow(&nets, sa("203.0.113.7:1"), false));
        assert!(nets_allow(&nets, sa("[::ffff:10.8.0.9]:5000"), false));
        assert!(!nets_allow(&nets, sa("10.8.1.2:5000"), false));
        assert!(!nets_allow(&nets, sa("198.51.100.1:5000"), false));
        assert!(!nets_allow(&nets, sa("10.8.0.2:5000"), true));
    }

    #[test]
    fn uuid_validation_blocks_console_injection() {
        assert!(valid_uuid("3f2b8c1e-6a4d-4e0f-9b7a-1c2d3e4f5a6b"));
        assert!(!valid_uuid(""));
        assert!(!valid_uuid("abc def"));
        assert!(!valid_uuid("abc\nba 1.2.3.4"));
        assert!(!valid_uuid(&"a".repeat(65)));
    }

    #[hbb_common::tokio::test]
    async fn announced_uuid_pairs_once() {
        let u = "11111111-2222-3333-4444-555555555555";
        assert_eq!(console_allow(Some(u)).await, "ok\n");
        assert!(take_allowed_now(u).await);
        assert!(!take_allowed_now(u).await);
        assert_eq!(console_allow(Some("bad uuid")).await, "invalid\n");
    }
}
