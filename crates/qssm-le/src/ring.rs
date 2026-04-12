//! Cyclotomic ring \(R_q = \mathbb{Z}_q[X]/(X^{64}+1)\) with negacyclic multiplication via length-128 NTT.
#![forbid(unsafe_code)]

use crate::params::{BETA, N, Q};
use crate::LeError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RqPoly(pub [u32; N]);

impl RqPoly {
    pub fn zero() -> Self {
        Self([0u32; N])
    }

    pub fn embed_constant(message: u64) -> Self {
        let mut c = [0u32; N];
        c[0] = (message % u64::from(Q)) as u32;
        Self(c)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut o = [0u32; N];
        for (i, slot) in o.iter_mut().enumerate() {
            *slot = (self.0[i] + other.0[i]) % Q;
        }
        Self(o)
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut o = [0u32; N];
        for (i, slot) in o.iter_mut().enumerate() {
            *slot = (self.0[i] + Q - other.0[i]) % Q;
        }
        Self(o)
    }

    /// Negacyclic multiplication (uses NTT internally).
    pub fn mul(&self, other: &Self) -> Result<Self, LeError> {
        Ok(RqPoly(crate::ntt::negacyclic_mul(&self.0, &other.0)))
    }

    pub fn scalar_mul_u32(&self, s: u32) -> Self {
        let mut o = [0u32; N];
        let s = (s % Q) as u64;
        for (i, slot) in o.iter_mut().enumerate() {
            *slot = ((self.0[i] as u64 * s) % u64::from(Q)) as u32;
        }
        Self(o)
    }
}

/// Map signed short coefficients into \(\mathbb{Z}_q\) (centered lift not applied; use \(r_i \ge 0\) small).
pub fn short_vec_to_rq(coeffs: &[i32; N]) -> Result<RqPoly, LeError> {
    let mut out = [0u32; N];
    for (i, &v) in coeffs.iter().enumerate() {
        if v.unsigned_abs() > BETA {
            return Err(LeError::RejectedSample);
        }
        let u = if v >= 0 {
            v as u32
        } else {
            Q - ((-v) as u32 % Q)
        };
        out[i] = u % Q;
    }
    Ok(RqPoly(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntt::negacyclic_mul;

    #[test]
    fn mul_by_one() {
        let mut a = [0u32; N];
        a[0] = 123;
        let mut b = [0u32; N];
        b[0] = 1;
        let pa = RqPoly(a);
        let pb = RqPoly(b);
        let out = negacyclic_mul(&pa.0, &pb.0);
        assert_eq!(out[0], 123);
    }
}
