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
