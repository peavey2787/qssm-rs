### Documentation map

* [README](../../README.md) — Project home
* [Crates overview](../01-architecture/crates-overview.md)
* **This document** — `mssq-net`: libp2p swarm and gossip topics

---

# `mssq-net` — libp2p swarm and gossip topics

Crate: `crates/mssq-net`. Library name: `mssq_net` (`src/lib.rs`).

## Role

Tokio-driven **libp2p** swarm: multi-transport listeners, mesh behaviours (Gossipsub, Kademlia, mDNS, AutoNAT, DCUtR, relay client, Identify, Ping), **heartbeat gossip** with `qssm-entropy` density checks, **`qssm-governor`** peer policy, and optional **rollup** updates via `mssq_batcher::apply_batch` on validated pulses.

## Crate source layout (`src/`)

| Directory | Responsibility |
|-----------|------------------|
| `stack/` | **`build_swarm`** (`transport.rs`), **`MeshBehaviour`** / **`MeshEvent`** (`behaviour.rs`), **`seed_bootstrap`** / **`on_mesh_event`** (`discovery.rs`). `stack/mod.rs` re-exports the public items for in-crate use. |
| `connectivity/` | **`RelayState`** / **`update_nat_state`** (`relay.rs`); **`peer_cache`** (`peer_cache.rs`) — JSON cache of seen multiaddrs. |
| `protocol/` | **`heartbeat_topic`**, **`HeartbeatEnvelope`**, **`collect_local_heartbeat`** (`pulse.rs`); **`ReputationStore`** (`reputation.rs`). |
| `common/` | **`NetError`** (`error.rs`); **`unix_timestamp_ns`** and other small helpers (`utils.rs`). |
| `node/` | Orchestrator: **`start_node`**, swarm loop, snapshot bridge (see table below). |

## Node source layout (`src/node/`)

| File | Responsibility |
|------|------------------|
| `node/mod.rs` | **`start_node`**, **`NodeHandle`**, Tokio `select!` loop (ticker, shutdown, control, swarm), **`publish_heartbeat`**, **`snapshot_to_json`**, governor snapshot refresh helpers |
| `node/types.rs` | **`NodeConfig`**, **`NodeSnapshot`**, wire enums **`MeritMessage`**, **`BranchMessage`**, **`NodeControl`**, **`network_label`** |
| `node/events.rs` | **`handle_swarm_event`** and **`process_*`** handlers (heartbeats, merit query, merkle branch); local **`AllowAllProofs`** batch verifier for synthetic txs |
| `node/archive.rs` | **`archive_branch`** — append-only `history_archive_merkle.jsonl` when `history_archive` is enabled |

## Transports and swarm build

`crates/mssq-net/src/stack/transport.rs` — **`build_swarm`**: Tokio `SwarmBuilder` with TCP + Noise + Yamux, **QUIC**, **DNS**, **WebSocket** (+ Noise + Yamux), **relay client**. Default listen addresses include QUIC, TCP, and WS ports; additional **webrtc-direct** / **webtransport** multiaddrs are included in `TransportPlan` for operator visibility per code comments.

## NetworkBehaviour

`crates/mssq-net/src/stack/behaviour.rs` — **`MeshBehaviour`**: `gossipsub`, `kademlia` (memory store, server mode), `mdns`, `autonat`, `dcutr`, `relay_client`, `identify`, `ping`. Gossipsub uses **Strict** validation and a **BLAKE3-based** `message_id_fn` on message payload.

## Gossip topics (string names)

Gossipsub **subscriptions** are created in **`start_node`** (`crates/mssq-net/src/node/mod.rs`); heartbeat **topic string** comes from `protocol/pulse.rs`:

| Topic | Format | Purpose |
|--------|--------|---------|
| Heartbeat | `qssm.he.heartbeat.v1.net-{network_id}` | `heartbeat_topic(network_id)` in `protocol/pulse.rs` |
| Merit query | `mssq/merit-query/net-{network_id}` | JSON `MeritMessage::Query` / `Response` for startup peer discovery |
| Merkle branch | `mssq/req-merkle-branch/net-{network_id}` | JSON `BranchMessage` — request/response for SMT branch repair |

**Identify** protocol string: `/mssq-net/net-{network_id}/1.0.0`.

## Heartbeat payload

`crates/mssq-net/src/protocol/pulse.rs`:

- **`HeartbeatEnvelope`** (JSON): `peer_id`, `timestamp_ns`, `seed_hex` (hex of `Heartbeat::to_seed()`), `raw_jitter`, `sensor_entropy`.
- **Local publish**: `collect_local_heartbeat()` → `qssm_entropy::harvest` → `qssm_entropy::verify_density(&hb.raw_jitter)` for local governor observation; envelope is gossip-published to the heartbeat topic.

## Inbound validation

On Gossipsub message (heartbeat topic), before accepting:

1. **`Governor::decision_for`** — if action is **`Drop`**, message is **rejected** (`MessageAcceptance::Reject`).
2. Decode **`HeartbeatEnvelope`**; validity requires **`verify_metabolic_gate(raw_jitter)`** (`qssm_governor`) **and** **`qssm_entropy::verify_density(raw_jitter)`**.
3. **`governor.observe_pulse(peer, valid, ...)`**; accepted messages get **`MessageAcceptance::Accept`**.
4. If valid, a synthetic **`L2Transaction`** may be built and **`apply_batch`** run with a local **`AllowAllProofs`**-style verifier in `node/events.rs` (`process_inbound_heartbeat`) to advance local `RollupState` / SMT snapshot.

## Config and timing

**`NodeConfig`** (`node/types.rs`): `network_id`, **`heartbeat_every`** (default **30s**), `startup_peer_cache_probe`, `startup_merit_query_size`, `history_archive`.

## Governor and snapshot

The node task in **`node/mod.rs`** holds **`Governor::default()`**, **`ReputationStore`** (from **`protocol/reputation.rs`**), **`RollupState`**, and updates **`NodeSnapshot`** (peer counts, density milli fields, `current_t_min_milli`, governor state string, `smt_root_hex`, fraud/repair fields, etc.); inbound Gossipsub paths refresh the same snapshot via **`node/events.rs`**.

## Example dashboard

Feature **`dashboard`**: `examples/mssq_node.rs` (ratatui). Build with `--features dashboard`.

## Dependencies (workspace)

`qssm-entropy`, `qssm-governor`, `qssm-utils`, `qssm-common`, `mssq-batcher` — see `crates/mssq-net/Cargo.toml`.
