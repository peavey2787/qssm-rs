/// L2 transaction as posted to / sequenced by MSSQ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2Transaction {
    pub id: [u8; 32],
    pub proof: Vec<u8>,
    pub payload: Vec<u8>,
}

/// Ordered batch of L2 transactions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub txs: Vec<L2Transaction>,
}

/// Rollup state commitment (placeholder Merkle accumulator root).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SmtRoot(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageLease {
    pub lease_id: [u8; 32],
    pub user_id: [u8; 32],
    pub provider_node_id: [u8; 32],
    pub rent_per_epoch: u64,
    pub user_leaf_key: [u8; 32],
    pub next_due_pulse: u64,
    pub active: bool,
    pub slashed: bool,
}
