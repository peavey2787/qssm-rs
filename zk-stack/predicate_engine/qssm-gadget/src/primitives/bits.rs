//! Unified Phase 1: degree‑2 bit algebra and LE decomposition.
//!
//! Witness-facing operations **do not** use Rust’s bitwise operators `^`, `|`, `&`, `!` on
//! boolean witnesses—only the algebraic identities below (and integer remainder/shift for
//! **canonical** `u32` ↔ bit decomposition).
//!
//! - XOR: \(x + y - 2xy\) · **AND:** \(xy\) · **OR (bits):** \(a + b - ab\)

/// Little-endian: `bits[i]` has weight \(2^i\). Extraction uses division only (no `&`).
#[must_use]
pub fn to_le_bits(val: u32) -> [bool; 32] {
    let mut bits = [false; 32];
    let mut v = val;
    for i in 0..32 {
        bits[i] = v % 2 != 0;
        v /= 2;
    }
    bits
}

/// Inverse of [`to_le_bits`] without `|=` / `|=`: only multiply‑accumulate.
#[must_use]
pub fn from_le_bits(bits: &[bool; 32]) -> u32 {
    let mut v = 0u32;
    for i in 0..32 {
        v += u32::from(bits[i]) * (1u32 << i);
    }
    v
}

/// XOR via \(x + y - 2xy\) on \(\{0,1\}\).
#[inline]
#[must_use]
pub fn constraint_xor(a: bool, b: bool) -> bool {
    let x = u8::from(a);
    let y = u8::from(b);
    let s = x + y;
    let p = 2u8.wrapping_mul(x.wrapping_mul(y));
    (s.wrapping_sub(p)) != 0
}

/// AND as multiplication \(xy\).
#[inline]
#[must_use]
pub fn constraint_and(a: bool, b: bool) -> bool {
    u8::from(a).wrapping_mul(u8::from(b)) != 0
}

/// OR on bits: \(a + b - ab\).
#[inline]
#[must_use]
pub fn constraint_or(a: bool, b: bool) -> bool {
    let x = u8::from(a);
    let y = u8::from(b);
    (x + y).wrapping_sub(x.wrapping_mul(y)) != 0
}

/// Full adder; all nonlinear gates go through [`constraint_xor`], [`constraint_and`], [`constraint_or`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FullAdder {
    pub a: bool,
    pub b: bool,
    pub cin: bool,
    pub sum: bool,
    pub carry_out: bool,
}

impl FullAdder {
    #[must_use]
    pub fn eval(a: bool, b: bool, cin: bool) -> Self {
        let a_xor_b = constraint_xor(a, b);
        let sum = constraint_xor(a_xor_b, cin);
        let and_ab = constraint_and(a, b);
        let and_axb_cin = constraint_and(a_xor_b, cin);
        let carry_out = constraint_or(and_ab, and_axb_cin);
        Self {
            a,
            b,
            cin,
            sum,
            carry_out,
        }
    }
}

/// Ripple-carry add; **no** single-instruction `u32` add for the witness semantics.
#[must_use]
pub fn ripple_carry_adder(a: [bool; 32], b: [bool; 32], cin: bool) -> ([bool; 32], bool) {
    let mut out = [false; 32];
    let mut c = cin;
    for i in 0..32 {
        let fa = FullAdder::eval(a[i], b[i], c);
        out[i] = fa.sum;
        c = fa.carry_out;
    }
    (out, c)
}

/// XOR witness: per-bit \(x+y-2xy\) wires and explicit AND lanes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XorWitness {
    pub bits_a: [bool; 32],
    pub bits_b: [bool; 32],
    pub and_bits: [bool; 32],
    pub output_bits: [bool; 32],
}

impl XorWitness {
    #[must_use]
    pub fn eval(a: u32, b: u32) -> Self {
        let bits_a = to_le_bits(a);
        let bits_b = to_le_bits(b);
        let mut and_bits = [false; 32];
        let mut output_bits = [false; 32];
        for i in 0..32 {
            and_bits[i] = constraint_and(bits_a[i], bits_b[i]);
            output_bits[i] = constraint_xor(bits_a[i], bits_b[i]);
        }
        Self {
            bits_a,
            bits_b,
            and_bits,
            output_bits,
        }
    }

    pub fn validate(&self) -> bool {
        for i in 0..32 {
            if self.and_bits[i] != constraint_and(self.bits_a[i], self.bits_b[i]) {
                return false;
            }
            if self.output_bits[i] != constraint_xor(self.bits_a[i], self.bits_b[i]) {
                return false;
            }
        }
        true
    }

    #[must_use]
    pub fn to_u32(&self) -> u32 {
        from_le_bits(&self.output_bits)
    }
}

/// Full 32-bit ripple witness (every [`FullAdder`] stage retained).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RippleCarryWitness {
    pub bits_a: [bool; 32],
    pub bits_b: [bool; 32],
    pub cin: bool,
    pub stages: [FullAdder; 32],
    pub sum_bits: [bool; 32],
    pub cout: bool,
}

impl RippleCarryWitness {
    #[must_use]
    pub fn eval(a: u32, b: u32, cin: bool) -> Self {
        let bits_a = to_le_bits(a);
        let bits_b = to_le_bits(b);
        let mut stages = [FullAdder::eval(false, false, false); 32];
        let mut c = cin;
        let mut sum_bits = [false; 32];
        for i in 0..32 {
            let fa = FullAdder::eval(bits_a[i], bits_b[i], c);
            sum_bits[i] = fa.sum;
            c = fa.carry_out;
            stages[i] = fa;
        }
        Self {
            bits_a,
            bits_b,
            cin,
            stages,
            sum_bits,
            cout: c,
        }
    }

    pub fn validate(&self) -> bool {
        let mut c = self.cin;
        for i in 0..32 {
            let fa = FullAdder::eval(self.bits_a[i], self.bits_b[i], c);
            if fa.sum != self.sum_bits[i]
                || fa.carry_out != self.stages[i].carry_out
                || fa.sum != self.stages[i].sum
                || self.stages[i].a != self.bits_a[i]
                || self.stages[i].b != self.bits_b[i]
                || self.stages[i].cin != c
            {
                return false;
            }
            c = self.stages[i].carry_out;
        }
        c == self.cout
    }

    #[must_use]
    pub fn sum_u32(&self) -> u32 {
        from_le_bits(&self.sum_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected XOR on bools without using `^` (inequality matches XOR on bits).
    fn xor_expected(a: bool, b: bool) -> bool {
        a != b
    }

    #[test]
    fn constraint_xor_algebraic_truth_table() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(constraint_xor(a, b), xor_expected(a, b));
            }
        }
    }

    #[test]
    fn constraint_and_truth_table() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(constraint_and(a, b), a && b);
            }
        }
    }

    #[test]
    fn constraint_or_truth_table() {
        for a in [false, true] {
            for b in [false, true] {
                assert_eq!(constraint_or(a, b), a || b);
            }
        }
    }

    #[test]
    fn to_le_bits_roundtrip() {
        for v in [0u32, 1, 0xFFFF_FFFF, 0x1234_5678, 1 << 31] {
            let bits = to_le_bits(v);
            assert_eq!(from_le_bits(&bits), v);
        }
    }

    #[test]
    fn le_bits_match_le_bytes() {
        let v = 0xAABBCCDDu32;
        let bits = to_le_bits(v);
        let le = v.to_le_bytes();
        for i in 0..32 {
            let byte_i = i / 8;
            let bit_in_byte = i % 8;
            let expected = (le[byte_i] >> bit_in_byte) & 1 != 0;
            assert_eq!(bits[i], expected, "bit {i}");
        }
    }

    #[test]
    fn xor_witness_matches_u32_bitpattern() {
        let a = 0xCAFEBABEu32;
        let b = 0xDEADBEEFu32;
        let w = XorWitness::eval(a, b);
        assert!(w.validate());
        assert_eq!(w.to_u32(), a ^ b);
    }

    #[test]
    fn ripple_carry_matches_wrapping_add() {
        let a = 0xFFFF_0000u32;
        let b = 0x0000_00FFu32;
        let w = RippleCarryWitness::eval(a, b, false);
        assert!(w.validate());
        assert_eq!(w.sum_u32(), a.wrapping_add(b));
    }

    #[test]
    fn ripple_carry_overflow() {
        let a = 0xFFFF_FFFFu32;
        let b = 1u32;
        let w = RippleCarryWitness::eval(a, b, false);
        assert!(w.validate());
        assert!(w.cout);
        assert_eq!(w.sum_u32(), 0);
    }

    #[test]
    fn full_adder_numeric_truth_table() {
        for a in [false, true] {
            for b in [false, true] {
                for cin in [false, true] {
                    let fa = FullAdder::eval(a, b, cin);
                    let s = u32::from(a) + u32::from(b) + u32::from(cin);
                    assert_eq!(u32::from(fa.sum), s % 2);
                    assert_eq!(u32::from(fa.carry_out), s / 2);
                }
            }
        }
    }
}
