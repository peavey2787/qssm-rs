//! Cyclotomic ring \(R_q = \mathbb{Z}_q[X]/(X^{256}+1)\) with negacyclic multiplication via length-512 NTT.
#![forbid(unsafe_code)]

use crate::protocol::params::{BETA, N, Q};
use crate::LeError;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RqPoly(pub [u32; N]);

/// Secret-bearing polynomial wrapper that guarantees drop-time zeroization.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ScrubbedPoly {
    coeffs: [u32; N],
}

impl ScrubbedPoly {
    #[must_use]
    pub fn from_public(poly: &RqPoly) -> Self {
        Self { coeffs: poly.0 }
    }

    #[must_use]
    pub fn into_public(self) -> RqPoly {
        RqPoly(self.coeffs)
    }

    #[must_use]
    pub fn as_public(&self) -> RqPoly {
        RqPoly(self.coeffs)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = self.as_public().add(&other.as_public()).0;
        let scrubbed = Self { coeffs: out };
        out.zeroize();
        scrubbed
    }

    pub fn sub_public(&self, other: &RqPoly) -> Self {
        let mut out = self.as_public().sub(other).0;
        let scrubbed = Self { coeffs: out };
        out.zeroize();
        scrubbed
    }

    pub fn mul_scrubbed(&self, other: &Self) -> Result<Self, LeError> {
        let mut out = self.as_public().mul(&other.as_public())?.0;
        let scrubbed = Self { coeffs: out };
        out.zeroize();
        Ok(scrubbed)
    }

    pub fn mul_public(&self, other: &RqPoly) -> Result<Self, LeError> {
        let mut out = self.as_public().mul(other)?.0;
        let scrubbed = Self { coeffs: out };
        out.zeroize();
        Ok(scrubbed)
    }

    #[must_use]
    pub fn inf_norm_centered(&self) -> u32 {
        self.as_public().inf_norm_centered()
    }
}

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
        Ok(RqPoly(crate::algebra::ntt::negacyclic_mul(&self.0, &other.0)))
    }

    pub fn scalar_mul_u32(&self, s: u32) -> Self {
        let mut o = [0u32; N];
        let s = (s % Q) as u64;
        for (i, slot) in o.iter_mut().enumerate() {
            *slot = ((self.0[i] as u64 * s) % u64::from(Q)) as u32;
        }
        Self(o)
    }

    /// Coefficient-wise scalar multiply with signed \(c\) (lift coeff to centered \(\mathbb{Z}\), scale, reduce mod \(q\)).
    pub fn scalar_mul_signed(&self, c: i32) -> Self {
        let c64 = i64::from(c);
        let q = i64::from(Q);
        let mut o = [0u32; N];
        for (i, slot) in o.iter_mut().enumerate() {
            let x = center_u32_mod(self.0[i]);
            let p = x * c64;
            *slot = reduce_i64_mod_q(p, q);
        }
        Self(o)
    }

    /// \(\ell_\infty\) norm of centered representatives in \((-q/2,q/2]\).
    #[must_use]
    pub fn inf_norm_centered(&self) -> u32 {
        let mut m = 0u32;
        for &c in &self.0 {
            let a = center_u32_mod(c).unsigned_abs();
            m = m.max(a as u32);
        }
        m
    }
}

#[inline]
fn center_u32_mod(x: u32) -> i64 {
    let x = i64::from(x);
    let q = i64::from(Q);
    if x > q / 2 { x - q } else { x }
}

#[inline]
fn reduce_i64_mod_q(v: i64, q: i64) -> u32 {
    let m = v.rem_euclid(q);
    m as u32
}

/// Concatenate coefficients (LE u32) for Fiat–Shamir binding.
#[must_use]
pub fn encode_rq_coeffs_le(p: &RqPoly) -> [u8; N * 4] {
    let mut out = [0u8; N * 4];
    for (i, c) in p.0.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&c.to_le_bytes());
    }
    out
}

/// Map signed coefficients with \(\ell_\infty \le \texttt{bound}\) into \(R_q\).
pub fn short_vec_to_rq_bound(coeffs: &[i32; N], bound: u32) -> Result<RqPoly, LeError> {
    let mut out = [0u32; N];
    for (i, &v) in coeffs.iter().enumerate() {
        if v.unsigned_abs() > bound {
            return Err(LeError::RejectedSample);
        }
        let u = if v >= 0 { v as u32 } else { Q - ((-v) as u32 % Q) };
        out[i] = u % Q;
    }
    Ok(RqPoly(out))
}

/// Map signed short coefficients into \(\mathbb{Z}_q\) (witness bound \(\beta\)).
pub fn short_vec_to_rq(coeffs: &[i32; N]) -> Result<RqPoly, LeError> {
    short_vec_to_rq_bound(coeffs, BETA)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::ntt::negacyclic_mul;

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

    #[test]
    fn scrubbed_poly_roundtrip() {
        let mut c = [0u32; N];
        c[1] = 42;
        let p = RqPoly(c);
        let s = ScrubbedPoly::from_public(&p);
        assert_eq!(s.as_public(), p);
    }
}
