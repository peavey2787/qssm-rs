use qssm_traits::L2Transaction;

/// Deterministic MSSQ ordering: lexicographic sort on `tx.id`.
pub fn sort_lexicographical(txs: Vec<L2Transaction>) -> Vec<L2Transaction> {
    let mut v = txs;
    v.sort_by(|a, b| a.id.cmp(&b.id));
    v
}
