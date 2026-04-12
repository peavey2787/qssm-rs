//! Length-128 NTT mod `Q` for negacyclic convolution mod \(X^{64}+1\).
#![forbid(unsafe_code)]

use crate::params::{N, Q};

fn pow_mod(mut a: u64, mut e: u32, m: u32) -> u32 {
    let m = m as u64;
    let mut r: u64 = 1;
    a %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * a) % m;
        }
        a = (a * a) % m;
        e >>= 1;
    }
    r as u32
}

fn inv_mod(a: u32) -> u32 {
    pow_mod(a as u64, Q - 2, Q)
}

/// Primitive 128-th root of unity \(\omega\) (computed as \(5^{(q-1)/128}\)).
fn omega_128() -> u32 {
    pow_mod(5, (Q - 1) / 128, Q)
}

fn ntt_inplace(a: &mut [u32], invert: bool) {
    let n = a.len();
    debug_assert!(n.is_power_of_two());
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let wlen = if invert {
            inv_mod(pow_mod(omega_128() as u64, (Q - 1) / (len as u32) * ((len as u32) / 2), Q))
        } else {
            pow_mod(omega_128() as u64, (Q - 1) / (len as u32) * ((len as u32) / 2), Q)
        };
        let mut i = 0usize;
        while i < n {
            let mut w = 1u32;
            for j in 0..len / 2 {
                let u = a[i + j];
                let v = ((a[i + j + len / 2] as u64 * w as u64) % Q as u64) as u32;
                a[i + j] = (u + v) % Q;
                a[i + j + len / 2] = (u + Q - v) % Q;
                w = ((w as u64 * wlen as u64) % Q as u64) as u32;
            }
            i += len;
        }
        len <<= 1;
    }
    if invert {
        let inv_n = inv_mod(n as u32);
        for x in a.iter_mut() {
            *x = ((*x as u64 * inv_n as u64) % Q as u64) as u32;
        }
    }
}

/// Negacyclic product mod \(X^N+1\), \(N=64\).
pub fn negacyclic_mul(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut fa = [0u32; 128];
    let mut fb = [0u32; 128];
    fa[..N].copy_from_slice(a);
    fb[..N].copy_from_slice(b);
    ntt_inplace(&mut fa, false);
    ntt_inplace(&mut fb, false);
    for i in 0..128 {
        fa[i] = ((fa[i] as u64 * fb[i] as u64) % Q as u64) as u32;
    }
    ntt_inplace(&mut fa, true);
    let mut out = [0u32; N];
    for i in 0..N {
        out[i] = (fa[i] + Q - fa[i + N]) % Q;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::N;

    #[test]
    fn ntt_roundtrip_delta() {
        let mut v = [0u32; 128];
        v[0] = 1;
        let orig = v;
        let mut a = orig;
        ntt_inplace(&mut a, false);
        ntt_inplace(&mut a, true);
        assert_eq!(a, orig);
    }

    #[test]
    fn negacyclic_associates_small() {
        let mut x = [0u32; N];
        let mut y = [0u32; N];
        x[0] = 3;
        y[0] = 4;
        let xy = negacyclic_mul(&x, &y);
        assert_eq!(xy[0], 12);
    }
}
