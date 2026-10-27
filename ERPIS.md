# Erpis patch for rustdesk-server

This fork adds one thing to upstream rustdesk-server: only **authorized
initiators** can start remote sessions through the server. Everything else is
upstream code, unchanged.

Upstream RustDesk Server OSS lets anyone who knows the public key use the server
to start sessions, and the key is public by design: it ships with every client.
This patch closes that gap without changing the RustDesk client.

- Base: upstream `master` at `873230e` (1.1.17, unreleased; includes the
  post-1.1.16 UDP reflection, punch-request bound and key-file permission fixes).
- License: AGPL-3.0, same as upstream. This repository at the release tag is the
  Corresponding Source of the binaries in the release (§13).

## Behaviour

| Who | What they can do |
|---|---|
| A client whose TCP source address is in `ERPIS_INITIATOR_CIDRS` (for example technicians on a WireGuard tunnel) | Everything, as upstream |
| Any other client | Register its ID, be connected to. Cannot start a session, request a relay or query online status |
| Clients on the WebSocket ports (21118/21119) | Cannot start sessions when the gate is on, because their address comes from an unauthenticated header |
| A client talking to hbbr directly | Paired only if hbbs announced that relay uuid for an authorized session (`ERPIS_RELAY_GATE=Y`) |

A refused initiator gets an immediate, explicit error (`Erpis: unauthorized
initiator`). The controlled device receives nothing, and the refusal happens
before the ID lookup, so it does not reveal whether an ID exists or is online.

## Configuration

| Variable | Process | Meaning |
|---|---|---|
| `ERPIS_INITIATOR_CIDRS` | hbbs | Comma-separated networks allowed to initiate, e.g. `10.97.0.0/24`. Unset means the gate is off (upstream behaviour). A malformed entry stops hbbs from starting. |
| `ERPIS_RELAY_CONSOLE` | hbbs | hbbr console address for uuid announcements. Default `127.0.0.1:21117`. |
| `ERPIS_RELAY_GATE` | hbbr | `Y` pairs only announced uuids. Use it together with `ERPIS_INITIATOR_CIDRS`. |
| `ALWAYS_USE_RELAY` | hbbs | Upstream option. Set it to `Y` when initiators are on a tunnel: the controlled side cannot reach the tunnel address, so a direct attempt would only add delay. |

hbbs and hbbr must run on the same host so hbbs can reach the hbbr console on
loopback (`network_mode: host` in Docker).

## How it works

All of the policy code is in `src/access_control.rs`. Upstream files only get
thin hooks:

- `rendezvous_server.rs`
  - `PunchHoleRequest`: refused unless the initiator is allowed.
  - `RequestRelay`: refused unless the initiator is allowed; otherwise the
    initiator is recorded and its uuid announced to hbbr.
  - `RelayResponse`: when the controlled side opens the relay, the uuid is
    announced only if the response is addressed to a recorded initiator
    connection (exact address, 120 s).
  - `OnlineRequest`: answered only for allowed initiators.
- `relay_server.rs`
  - New console command `erpis-allow <uuid>` (loopback only, like the other
    console commands).
  - `make_pair_`: the second side is paired only if the uuid was announced.
    It waits up to 3 s for an in-flight announcement. Each uuid pairs once and
    expires after 60 s.

The announcement is awaited before the message that reveals the uuid to the
other side is forwarded, so it always arrives at hbbr first.

## Tests

```sh
cargo test --lib --test erpis_access
```

`tests/erpis_access.rs` runs the real hbbs/hbbr binaries. It uses separate
127.0.0.x source addresses for the technician, strangers and the device, and
covers:

- a refused punch and a refused relay request;
- online status answered only for allowed initiators;
- both relay paths for an allowed technician, carrying data;
- an unannounced uuid that is never paired;
- a forged `RelayResponse` that cannot announce;
- with the gate off, upstream behaviour unchanged.

## Known limits

- The gate is network based. Anyone who controls an allowed address can
  initiate. With WireGuard, that means anyone holding a technician's peer key.
  Revoke a technician by removing their peer.
- An unannounced first side still waits in hbbr for up to 30 s, as upstream. It
  is never paired and no data flows.
- Controlled devices still connect to the server from anywhere. That is
  required for them to be reachable.

## Watch and maintenance

`.github/workflows/erpis-watch.yml` runs on GitHub's schedule (free for a public
repository) and e-mails the repository owner when a run turns red:

- **hourly**: 21115, 21116 and 21117 on `rd.erpyazilim.com` answer from the
  internet (three tries each, 20 s apart);
- **weekly**: `cargo audit` against RustSec, failing only on advisories that are
  not in the reviewed baseline `.cargo/audit.toml`; and an issue when upstream
  rustdesk-server releases past the version in `Cargo.toml`;
- **monthly**: an issue reminding to refresh the image, and a call that keeps
  GitHub from disabling the scheduled runs after 60 days without commits.

Updating the server is done from ErpisRustDeskAdmin → Bakım: *update* moves to
a newer `erpis-v*` release (download, SHA256SUMS check, image build, switch),
*refresh* rebuilds the running release on the current Ubuntu base. Both check
that the new containers are up on the expected image, report the same server
key and the access gate, and switch back by themselves when they do not.
The host itself takes Ubuntu and Docker security updates unattended, rebooting
at 04:30 Istanbul time when a kernel update asks for it.
