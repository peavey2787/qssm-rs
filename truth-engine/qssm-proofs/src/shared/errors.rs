#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("fiat-shamir oracle failure: {0}")]
    FiatShamir(String),
    #[error("simulation bounds failure: {0}")]
    Bounds(String),
}
