### Documentation map

* [README](../../README.md) — Project home
* [Crates overview](../01-architecture/crates-overview.md)
* **This document** — `mssq-net`: libp2p swarm and gossip topics

---

# `mssq-net` — libp2p swarm and gossip topics

Crate: `crates/mssq-net`. Library name: `mssq_net` (`src/lib.rs`).

## Role

Tokio-driven **libp2p** swarm: multi-transport listeners, mesh behaviours (Gossipsub, Kademlia, mDNS, AutoNAT, DCUtR, relay client, Identify, Ping), **heartbeat gossip** with `qssm-he` density checks, **`qssm-governor`** peer policy, and optional **rollup** updates via `mssq_batcher::apply_batch` on validated pulses.

## Transports and swarm build

`crates/mssq-net/src/transport.rs` — **`build_swarm`**: Tokio `SwarmBuilder` with TCP + Noise + Yamux, **QUIC**, **DNS**, **WebSocket** (+ Noise + Yamux), **relay client**. Default listen addresses include QUIC, TCP, and WS ports; additional **webrtc-direct** / **webtransport** multiaddrs are included in `TransportPlan` for operator visibility per code comments.

## NetworkBehaviour

`crates/mssq-net/src/behaviour.rs` — **`MeshBehaviour`**: `gossipsub`, `kademlia` (memory store, server mode), `mdns`, `autonat`, `dcutr`, `relay_client`, `identify`, `ping`. Gossipsub uses **Strict** validation and a **BLAKE3-based** `message_id_fn` on message payload.

## Gossip topics (string names)

Defined in `crates/mssq-net/src/node.rs` (subscription) and `pulse.rs` (heartbeat):

| Topic | Format | Purpose |
|--------|--------|---------|
| Heartbeat | `qssm.he.heartbeat.v1.net-{network_id}` | `heartbeat_topic(network_id)` in `pulse.rs` |
| Merit query | `mssq/merit-query/net-{network_id}` | JSON `MeritMessage::Query` / `Response` for startup peer discovery |
| Merkle branch | `mssq/req-merkle-branch/net-{network_id}` | JSON `BranchMessage` — request/response for SMT branch repair |

**Identify** protocol string: `/mssq-net/net-{network_id}/1.0.0`.

## Heartbeat payload

`crates/mssq-net/src/pulse.rs`:

- **`HeartbeatEnvelope`** (JSON): `peer_id`, `timestamp_ns`, `seed_hex` (hex of `Heartbeat::to_seed()`), `raw_jitter`, `sensor_entropy`.
- **Local publish**: `collect_local_heartbeat()` → `qssm_he::harvest` → `qssm_he::verify_density(&hb.raw_jitter)` for local governor observation; envelope is gossip-published to the heartbeat topic.

## Inbound validation

On Gossipsub message (heartbeat topic), before accepting:

1. **`Governor::decision_for`** — if action is **`Drop`**, message is **rejected** (`MessageAcceptance::Reject`).
2. Decode **`HeartbeatEnvelope`**; validity requires **`verify_metabolic_gate(raw_jitter)`** (`qssm_governor`) **and** **`qssm_he::verify_density(raw_jitter)`**.
3. **`governor.observe_pulse(peer, valid, ...)`**; accepted messages get **`MessageAcceptance::Accept`**.
4. If valid, a synthetic **`L2Transaction`** may be built and **`apply_batch`** run with an **`AllowAllProofs`**-style verifier (see `node.rs`) to advance local `RollupState` / SMT snapshot.

## Config and timing

**`NodeConfig`** (`node.rs`): `network_id`, **`heartbeat_every`** (default **30s**), `startup_peer_cache_probe`, `startup_merit_query_size`, `history_archive`.

## Governor and snapshot

Runtime holds **`Governor::default()`**, **`ReputationStore`**, **`RollupState`**, and updates **`NodeSnapshot`** (peer counts, density milli fields, `current_t_min_milli`, governor state string, `smt_root_hex`, fraud/repair fields, etc.).

## Example dashboard

Feature **`dashboard`**: `examples/mssq_node.rs` (ratatui). Build with `--features dashboard`.

## Dependencies (workspace)

`qssm-he`, `qssm-governor`, `qssm-utils`, `qssm-common`, `mssq-batcher` — see `crates/mssq-net/Cargo.toml`.
