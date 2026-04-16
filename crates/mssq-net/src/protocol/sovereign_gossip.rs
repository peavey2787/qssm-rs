//! Sovereign hybrid-wrapper gossip: one [`GossipMessage`] per new `StepEnvelope` JSONL line from the Lab.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Gossipsub topic for sovereign step fanout on a given MSSQ network id.
#[must_use]
pub fn sovereign_step_topic(network_id: u32) -> String {
    format!("mssq/sovereign-step/net-{network_id}")
}

/// Wire payload published on [`sovereign_step_topic`].
///
/// `primary_targets` records the Merit-query primary peer set **at emit time** (audit / routing hints).
/// libp2p gossipsub still delivers over the mesh; explicit peers may be grafted separately when connected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GossipMessage {
    SovereignStepV1 {
        /// One JSONL record (a canonical `StepEnvelope` line from `SovereignStreamManager`).
        jsonl_line: String,
        primary_targets: Vec<String>,
        emitted_unix_ms: u64,
        /// Optional predicate law: JSON array of [`qssm_gadget::PredicateBlock`] or `{ "predicates": [...] }`.
        /// When set, verifiers run these rules on **`jsonl_line`**; when absent, inbound uses [`crate::node::sovereign_verify::VERIFIER_TEMPLATE_ID_FIELD`] + standard library.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        template_script: Option<Value>,
    },
}
