// Copyright (c) 2026 Peavey Koding. All rights reserved.
// Licensed under the Business Source License 1.1 (BSL-1.1).
// See the LICENSE file in the repository root for full license text.

//! Length-`2N` NTT mod `Q` for negacyclic convolution mod \(X^N+1\).
#![forbid(unsafe_code)]

use crate::protocol::params::{N, Q};

const TWO_N_U32: u32 = (2 * N) as u32;
const _: () = assert!(TWO_N_U32 > 0, "2N must be non-zero");
const _: () = assert!(Q > 2, "Q must be an odd prime > 2");
const _: () = assert!(
    (Q - 1) % TWO_N_U32 == 0,
    "invalid NTT parameters: 2N must divide Q-1"
);

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

fn prime_factors(mut n: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut p = 2u32;
    while p.saturating_mul(p) <= n {
        if n % p == 0 {
            out.push(p);
            while n % p == 0 {
                n /= p;
            }
        }
        p += if p == 2 { 1 } else { 2 };
    }
    if n > 1 {
        out.push(n);
    }
    out
}

fn find_primitive_root(q: u32) -> Option<u32> {
    if q < 3 {
        return None;
    }
    let phi = q - 1;
    let factors = prime_factors(phi);
    'outer: for g in 2..q {
        for &f in &factors {
            if pow_mod(g as u64, phi / f, q) == 1 {
                continue 'outer;
            }
        }
        return Some(g);
    }
    None
}

fn validate_ntt_parameters(q: u32, two_n: u32) {
    assert!(two_n > 0, "two_n must be non-zero");
    assert_eq!(
        (q - 1) % two_n,
        0,
        "invalid NTT parameters: 2N must divide Q-1"
    );
}

/// Primitive `2N`-th root of unity \(\omega\), derived from a discovered generator.
fn omega_2n() -> u32 {
    validate_ntt_parameters(Q, TWO_N_U32);
    let g = find_primitive_root(Q).expect("failed to find primitive root for Q");
    let exp = (Q - 1) / TWO_N_U32;
    let omega = pow_mod(g as u64, exp, Q);
    assert_eq!(pow_mod(omega as u64, TWO_N_U32, Q), 1);
    assert_ne!(pow_mod(omega as u64, N as u32, Q), 1);
    omega
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
            inv_mod(pow_mod(omega_2n() as u64, TWO_N_U32 / (len as u32), Q))
        } else {
            pow_mod(omega_2n() as u64, TWO_N_U32 / (len as u32), Q)
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

/// Negacyclic product mod \(X^N+1\).
pub(crate) fn negacyclic_mul(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut fa = [0u32; 2 * N];
    let mut fb = [0u32; 2 * N];
    fa[..N].copy_from_slice(a);
    fb[..N].copy_from_slice(b);
    ntt_inplace(&mut fa, false);
    ntt_inplace(&mut fb, false);
    for i in 0..(2 * N) {
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
    use crate::protocol::params::N;

    #[test]
    fn ntt_roundtrip_delta() {
        let mut v = [0u32; 2 * N];
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

    #[test]
    fn derived_omega_has_expected_order() {
        let omega = omega_2n();
        assert_eq!(pow_mod(omega as u64, TWO_N_U32, Q), 1);
        assert_ne!(pow_mod(omega as u64, N as u32, Q), 1);
    }

    #[test]
    fn invalid_parameter_pair_panics() {
        let got = std::panic::catch_unwind(|| validate_ntt_parameters(17, 8));
        assert!(got.is_ok(), "17-1 is divisible by 8");
        let bad = std::panic::catch_unwind(|| validate_ntt_parameters(17, 10));
        assert!(bad.is_err(), "17-1 is not divisible by 10");
    }
}
