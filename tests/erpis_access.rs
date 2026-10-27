// End-to-end checks of the Erpis access gate against the real hbbs/hbbr binaries.
// Distinct source addresses stand in for the technician (allowed), strangers and
// the controlled device. They must not be 127.x: hbbs/hbbr treat loopback peers
// as their admin console. Add them to `lo` first (CI does this):
//   for a in 10.97.0.1 10.97.0.2 198.51.100.3 198.51.100.4 198.51.100.5 198.51.100.6 198.51.100.7; do
//     sudo ip addr add $a/32 dev lo; done
use hbb_common::{
    protobuf::Message as _, rendezvous_proto::*, tcp::FramedStream, tokio, udp::FramedSocket,
};
use std::{
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const REFUSED: &str = "Erpis: unauthorized initiator";
const SERVER: &str = "10.97.0.1";
const TECH: &str = "10.97.0.2";
const STRANGER: &str = "198.51.100.3";
const DEVICE: &str = "198.51.100.4";
const DEVICE_ID: &str = "123456789";

struct Servers {
    children: Vec<Child>,
    _dir: tempfile::TempDir,
    key: String,
    hbbs: SocketAddr,
    nat: SocketAddr,
    hbbr: SocketAddr,
}

impl Drop for Servers {
    fn drop(&mut self) {
        for c in self.children.iter_mut() {
            c.kill().ok();
            c.wait().ok();
        }
    }
}

fn wait_for(path: &Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "{path:?} not created");
        std::thread::sleep(Duration::from_millis(50));
    }
}

async fn wait_port(addr: SocketAddr) {
    let start = Instant::now();
    while tokio::net::TcpStream::connect(addr).await.is_err() {
        assert!(start.elapsed() < Duration::from_secs(10), "{addr} not listening");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn start(base: u16, gated: bool) -> Servers {
    let dir = tempfile::tempdir().unwrap();
    let hbbs_port = base + 1;
    let hbbr_port = base + 2;
    let relay = format!("{SERVER}:{hbbr_port}");
    let console = format!("127.0.0.1:{hbbr_port}");
    let mut hbbs = Command::new(env!("CARGO_BIN_EXE_hbbs"));
    hbbs.current_dir(dir.path())
        .args(["-p", &hbbs_port.to_string(), "-k", "_", "-r", &relay])
        .env("TEST_HBBS", "no")
        .env("ALWAYS_USE_RELAY", "Y")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if gated {
        hbbs.env("ERPIS_INITIATOR_CIDRS", format!("{TECH}/32"))
            .env("ERPIS_RELAY_CONSOLE", &console);
    }
    let hbbs = hbbs.spawn().unwrap();
    wait_for(&dir.path().join("id_ed25519.pub"));
    let key = std::fs::read_to_string(dir.path().join("id_ed25519.pub"))
        .unwrap()
        .trim()
        .to_owned();
    let mut hbbr = Command::new(env!("CARGO_BIN_EXE_hbbr"));
    hbbr.current_dir(dir.path())
        .args(["-p", &hbbr_port.to_string(), "-k", "_"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if gated {
        hbbr.env("ERPIS_RELAY_GATE", "Y");
    }
    let hbbr = hbbr.spawn().unwrap();
    let s = Servers {
        children: vec![hbbs, hbbr],
        _dir: dir,
        key,
        hbbs: format!("{SERVER}:{hbbs_port}").parse().unwrap(),
        nat: format!("{SERVER}:{}", hbbs_port - 1).parse().unwrap(),
        hbbr: relay.parse().unwrap(),
    };
    wait_port(s.hbbs).await;
    wait_port(s.hbbr).await;
    s
}

fn local(ip: &str) -> Option<SocketAddr> {
    Some(format!("{ip}:0").parse().unwrap())
}

async fn tcp(to: SocketAddr, from: &str) -> FramedStream {
    FramedStream::new(to, local(from), 3_000)
        .await
        .unwrap_or_else(|e| panic!("connect {to} from {from} (test addresses on lo?): {e}"))
}

async fn recv(s: &mut FramedStream, ms: u64) -> Option<RendezvousMessage> {
    match s.next_timeout(ms).await {
        Some(Ok(bytes)) => RendezvousMessage::parse_from_bytes(&bytes).ok(),
        _ => None,
    }
}

async fn udp_recv(s: &mut FramedSocket, ms: u64) -> Option<RendezvousMessage> {
    match s.next_timeout(ms).await {
        Some(Ok((bytes, _))) => RendezvousMessage::parse_from_bytes(&bytes).ok(),
        _ => None,
    }
}

async fn register_device(s: &Servers) -> FramedSocket {
    let mut udp = FramedSocket::new(local(DEVICE).unwrap()).await.unwrap();
    let mut msg = RendezvousMessage::new();
    msg.set_register_pk(RegisterPk {
        id: DEVICE_ID.to_owned(),
        uuid: b"device-uuid".to_vec().into(),
        pk: vec![7u8; 32].into(),
        ..Default::default()
    });
    udp.send(&msg, s.hbbs).await.unwrap();
    let res = udp_recv(&mut udp, 3_000).await.expect("register_pk response");
    assert!(res.has_register_pk_response());
    let mut msg = RendezvousMessage::new();
    msg.set_register_peer(RegisterPeer {
        id: DEVICE_ID.to_owned(),
        ..Default::default()
    });
    udp.send(&msg, s.hbbs).await.unwrap();
    assert!(udp_recv(&mut udp, 3_000).await.is_some());
    udp
}

fn punch_request(key: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_punch_hole_request(PunchHoleRequest {
        id: DEVICE_ID.to_owned(),
        licence_key: key.to_owned(),
        nat_type: NatType::ASYMMETRIC.into(),
        ..Default::default()
    });
    msg
}

fn relay_request(uuid: &str, key: &str, id: &str) -> RendezvousMessage {
    let mut msg = RendezvousMessage::new();
    msg.set_request_relay(RequestRelay {
        id: id.to_owned(),
        uuid: uuid.to_owned(),
        licence_key: key.to_owned(),
        ..Default::default()
    });
    msg
}

/// Controlled side of a relay: tells hbbs where it relays (RelayResponse) and parks on hbbr.
async fn device_relays(
    s: &Servers,
    socket_addr: hbb_common::bytes::Bytes,
    uuid: &str,
    initiate: bool,
) -> FramedStream {
    let mut to_hbbs = tcp(s.hbbs, DEVICE).await;
    let mut rr = RelayResponse {
        socket_addr,
        version: "1.5.0".to_owned(),
        ..Default::default()
    };
    if initiate {
        rr.uuid = uuid.to_owned();
        rr.relay_server = s.hbbr.to_string();
        rr.set_id(DEVICE_ID.to_owned());
    }
    let mut msg = RendezvousMessage::new();
    msg.set_relay_response(rr);
    to_hbbs.send(&msg).await.unwrap();
    let mut relay = tcp(s.hbbr, DEVICE).await;
    relay.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    relay
}

async fn assert_relayed(a: &mut FramedStream, b: &mut FramedStream) {
    a.send_raw(b"hello-from-a".to_vec()).await.unwrap();
    let got = b.next_timeout(5_000).await;
    assert!(
        matches!(&got, Some(Ok(bytes)) if &bytes[..] == b"hello-from-a"),
        "relay did not carry data: {got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_on_only_allowed_initiators_get_sessions() {
    let s = start(32100, true).await;
    let mut device = register_device(&s).await;

    // Stranger with the right key: refused fast, the device hears nothing.
    let mut stranger = tcp(s.hbbs, STRANGER).await;
    stranger.send(&punch_request(&s.key)).await.unwrap();
    let res = recv(&mut stranger, 3_000).await.expect("refusal");
    assert_eq!(res.punch_hole_response().other_failure, REFUSED);
    assert!(udp_recv(&mut device, 1_000).await.is_none());

    let mut stranger = tcp(s.hbbs, STRANGER).await;
    stranger
        .send(&relay_request("00000000-0000-0000-0000-000000000001", &s.key, DEVICE_ID))
        .await
        .unwrap();
    let res = recv(&mut stranger, 3_000).await.expect("refusal");
    assert_eq!(res.relay_response().refuse_reason, REFUSED);
    assert!(udp_recv(&mut device, 1_000).await.is_none());

    // Online status is only answered for allowed initiators.
    let mut online = RendezvousMessage::new();
    online.set_online_request(OnlineRequest {
        id: "x".to_owned(),
        peers: vec![DEVICE_ID.to_owned()],
        ..Default::default()
    });
    let mut q = tcp(s.nat, STRANGER).await;
    q.send(&online).await.unwrap();
    assert!(recv(&mut q, 1_500).await.is_none());
    let mut q = tcp(s.nat, TECH).await;
    q.send(&online).await.unwrap();
    let res = recv(&mut q, 3_000).await.expect("online response");
    assert_eq!(res.online_response().states[0] & 0x80, 0x80);

    // Technician, device-initiated relay (what ALWAYS_USE_RELAY produces).
    let mut tech = tcp(s.hbbs, TECH).await;
    tech.send(&punch_request(&s.key)).await.unwrap();
    let ph = udp_recv(&mut device, 3_000).await.expect("punch hole to device");
    let ph = ph.punch_hole().clone();
    assert_eq!(ph.nat_type.enum_value(), Ok(NatType::SYMMETRIC));
    let uuid = "3f2b8c1e-6a4d-4e0f-9b7a-1c2d3e4f5a6b";
    let mut device_relay = device_relays(&s, ph.socket_addr.clone(), uuid, true).await;
    let res = recv(&mut tech, 3_000).await.expect("relay response to technician");
    assert_eq!(res.relay_response().uuid, uuid);
    let mut tech_relay = tcp(s.hbbr, TECH).await;
    tech_relay.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    assert_relayed(&mut tech_relay, &mut device_relay).await;
    assert_relayed(&mut device_relay, &mut tech_relay).await;

    // Technician-initiated relay request.
    let uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let mut tech = tcp(s.hbbs, TECH).await;
    tech.send(&relay_request(uuid, "", DEVICE_ID)).await.unwrap();
    let rr = udp_recv(&mut device, 3_000).await.expect("relay request to device");
    let rr = rr.request_relay().clone();
    assert_eq!(rr.uuid, uuid);
    let mut device_relay = device_relays(&s, rr.socket_addr.clone(), uuid, false).await;
    assert!(recv(&mut tech, 3_000).await.unwrap().has_relay_response());
    let mut tech_relay = tcp(s.hbbr, TECH).await;
    tech_relay.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    assert_relayed(&mut tech_relay, &mut device_relay).await;

    // Clients talking to hbbr directly with an unannounced uuid are never paired.
    let uuid = "deadbeef-0000-4000-8000-000000000000";
    let mut x1 = tcp(s.hbbr, "198.51.100.5").await;
    x1.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut x2 = tcp(s.hbbr, "198.51.100.6").await;
    x2.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    x2.send_raw(b"abuse".to_vec()).await.ok();
    let got = x1.next_timeout(5_000).await;
    assert!(
        !matches!(&got, Some(Ok(bytes)) if &bytes[..] == b"abuse"),
        "unannounced uuid was relayed"
    );

    // A stranger cannot announce by forging a RelayResponse for a fake initiator.
    let uuid = "cafebabe-0000-4000-8000-000000000000";
    let fake: SocketAddr = format!("{TECH}:40000").parse().unwrap();
    let mut forged = device_relays(
        &s,
        hbb_common::AddrMangle::encode(fake).into(),
        uuid,
        true,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut x = tcp(s.hbbr, "198.51.100.7").await;
    x.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    x.send_raw(b"abuse".to_vec()).await.ok();
    let got = forged.next_timeout(5_000).await;
    assert!(
        !matches!(&got, Some(Ok(bytes)) if &bytes[..] == b"abuse"),
        "forged announcement was relayed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn gate_off_keeps_upstream_behaviour() {
    let s = start(32200, false).await;
    let mut device = register_device(&s).await;

    let mut anyone = tcp(s.hbbs, STRANGER).await;
    anyone.send(&punch_request(&s.key)).await.unwrap();
    assert!(udp_recv(&mut device, 3_000).await.unwrap().has_punch_hole());

    let uuid = "deadbeef-0000-4000-8000-000000000001";
    let mut x1 = tcp(s.hbbr, "198.51.100.5").await;
    x1.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut x2 = tcp(s.hbbr, "198.51.100.6").await;
    x2.send(&relay_request(uuid, &s.key, "")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_relayed(&mut x2, &mut x1).await;
}
