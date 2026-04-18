//! Phase 2: BLAKE3 **G‑function** using only [`super::bits::XorWitness`] and
//! [`super::bits::RippleCarryWitness`], plus **index‑only** rotation wiring.
//!
//! The algorithm matches the portable **G** from the [BLAKE3 specification](https://github.com/BLAKE3-team/BLAKE3-specs)
//! (same ordering as the reference / `blake3` crate compress kernel):  
//! `a ← a+b+mx`, `d ← rotr(d⊕a,16)`, `c ← c+d`, `b ← rotr(b⊕c,12)`,  
//! `a ← a+b+my`, `d ← rotr(d⊕a,8)`, `c ← c+d`, `b ← rotr(b⊕c,7)`.

use super::bits::{from_le_bits, RippleCarryWitness, XorWitness};

/// **ROTR** on a 32‑bit **LE** lane: `out[i] = in[(i + r) mod 32]` (matches `u32::rotate_right(r)` with `to_le_bits`).
#[must_use]
pub fn bit_wire_rotate(bits: [bool; 32], rotr: u8) -> BitRotateWitness {
    let r = (rotr % 32) as usize;
    let mut out_bits = [false; 32];
    for i in 0usize..32 {
        let src = (i + r) % 32;
        out_bits[i] = bits[src];
    }
    BitRotateWitness {
        in_bits: bits,
        out_bits,
        offset: rotr % 32,
    }
}

/// Witness for a rotation: pure bit permutation (no `u32` shifts on the witness path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitRotateWitness {
    pub in_bits: [bool; 32],
    pub out_bits: [bool; 32],
    pub offset: u8,
}

impl BitRotateWitness {
    pub fn validate(&self) -> bool {
        let r = (self.offset % 32) as usize;
        for i in 0usize..32 {
            let src = (i + r) % 32;
            if self.out_bits[i] != self.in_bits[src] {
                return false;
            }
        }
        true
    }
}

/// `a + b + c (mod 2^32)` as **two** fresh [`RippleCarryWitness`] (no native `u32` add on witness path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Add32ChainedWitness {
    pub first: RippleCarryWitness,
    pub second: RippleCarryWitness,
}

impl Add32ChainedWitness {
    #[must_use]
    pub fn eval(a: u32, b: u32, c: u32) -> Self {
        let first = RippleCarryWitness::eval(a, b, false);
        let second = RippleCarryWitness::eval(first.sum_u32(), c, false);
        Self { first, second }
    }

    pub fn validate(&self) -> bool {
        self.first.validate() && self.second.validate()
    }

    #[must_use]
    pub fn sum_u32(&self) -> u32 {
        self.second.sum_u32()
    }
}

/// One BLAKE3 **G** application: chained adds, XORs, and **BitRotateWitness** steps (no in‑place reuse).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GWitness {
    pub add_ab_mx: Add32ChainedWitness,
    pub xor_d_a: XorWitness,
    pub rot16: BitRotateWitness,
    pub add_c_d: RippleCarryWitness,
    pub xor_b_c: XorWitness,
    pub rot12: BitRotateWitness,
    pub add_ab_my: Add32ChainedWitness,
    pub xor_d_a2: XorWitness,
    pub rot8: BitRotateWitness,
    pub add_c_d2: RippleCarryWitness,
    pub xor_b_c2: XorWitness,
    pub rot7: BitRotateWitness,
}

/// Public outputs of [`g_function`] plus the full **G** witness chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GFunctionResult {
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
    pub witness: GWitness,
}

/// BLAKE3 **G** on four lanes with message words **`mx`**, **`my`** — algebraic witness path only.
#[must_use]
pub fn g_function(a: u32, b: u32, c: u32, d: u32, mx: u32, my: u32) -> GFunctionResult {
    let add_ab_mx = Add32ChainedWitness::eval(a, b, mx);
    let a1 = add_ab_mx.sum_u32();

    let xor_d_a = XorWitness::eval(d, a1);
    let rot16 = bit_wire_rotate(xor_d_a.output_bits, 16);
    let d1 = from_le_bits(&rot16.out_bits);

    let add_c_d = RippleCarryWitness::eval(c, d1, false);
    let c1 = add_c_d.sum_u32();

    let xor_b_c = XorWitness::eval(b, c1);
    let rot12 = bit_wire_rotate(xor_b_c.output_bits, 12);
    let b1 = from_le_bits(&rot12.out_bits);

    let add_ab_my = Add32ChainedWitness::eval(a1, b1, my);
    let a2 = add_ab_my.sum_u32();

    let xor_d_a2 = XorWitness::eval(d1, a2);
    let rot8 = bit_wire_rotate(xor_d_a2.output_bits, 8);
    let d2 = from_le_bits(&rot8.out_bits);

    let add_c_d2 = RippleCarryWitness::eval(c1, d2, false);
    let c2 = add_c_d2.sum_u32();

    let xor_b_c2 = XorWitness::eval(b1, c2);
    let rot7 = bit_wire_rotate(xor_b_c2.output_bits, 7);
    let b2 = from_le_bits(&rot7.out_bits);

    let witness = GWitness {
        add_ab_mx,
        xor_d_a,
        rot16,
        add_c_d,
        xor_b_c,
        rot12,
        add_ab_my,
        xor_d_a2,
        rot8,
        add_c_d2,
        xor_b_c2,
        rot7,
    };

    GFunctionResult {
        a: a2,
        b: b2,
        c: c2,
        d: d2,
        witness,
    }
}

impl GWitness {
    pub fn validate(&self) -> bool {
        self.add_ab_mx.validate()
            && self.xor_d_a.validate()
            && self.rot16.validate()
            && self.add_c_d.validate()
            && self.xor_b_c.validate()
            && self.rot12.validate()
            && self.add_ab_my.validate()
            && self.xor_d_a2.validate()
            && self.rot8.validate()
            && self.add_c_d2.validate()
            && self.xor_b_c2.validate()
            && self.rot7.validate()
    }
}

/// Chains a single **G** mixer (BLAKE3 “quarter” block on four words + two schedule words).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarterRoundWitness {
    pub g: GWitness,
}

impl QuarterRoundWitness {
    #[must_use]
    pub fn eval(a: u32, b: u32, c: u32, d: u32, mx: u32, my: u32) -> Self {
        let r = g_function(a, b, c, d, mx, my);
        Self { g: r.witness }
    }

    pub fn validate(&self) -> bool {
        self.g.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Portable **G** exactly as in the [BLAKE3 spec](https://github.com/BLAKE3-team/BLAKE3-specs) and the
    /// `blake3` crate’s compress kernel (same step order as `blake3` v1.5 portable code path).
    fn blake3_reference_g(
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        mx: u32,
        my: u32,
    ) -> (u32, u32, u32, u32) {
        let mut a = a;
        let mut b = b;
        let mut c = c;
        let mut d = d;
        a = a.wrapping_add(b).wrapping_add(mx);
        d = (d ^ a).rotate_right(16);
        c = c.wrapping_add(d);
        b = (b ^ c).rotate_right(12);
        a = a.wrapping_add(b).wrapping_add(my);
        d = (d ^ a).rotate_right(8);
        c = c.wrapping_add(d);
        b = (b ^ c).rotate_right(7);
        (a, b, c, d)
    }

    #[test]
    fn bit_wire_rotate_matches_u32_rotate_right() {
        for v in [0u32, 1, 0xFFFF_FFFF, 0x00FF_00FF, 0x1234_5678, 0xDEAD_BEEF] {
            for r in [0u8, 1, 7, 8, 12, 16, 31] {
                let bits = crate::primitives::bits::to_le_bits(v);
                let w = bit_wire_rotate(bits, r);
                assert!(w.validate());
                let got = from_le_bits(&w.out_bits);
                let exp = v.rotate_right(r as u32);
                assert_eq!(got, exp, "v={v:#x} r={r}");
            }
        }
    }

    /// Golden vectors: algebraic **G** matches BLAKE3 reference **G** (spec ordering).
    #[test]
    fn g_function_golden_matches_blake3_reference() {
        let goldens: [(u32, u32, u32, u32, u32, u32); 12] = [
            (0, 0, 0, 0, 0, 0),
            (1, 2, 3, 4, 5, 6),
            (
                0x1111_1111,
                0x2222_2222,
                0x3333_3333,
                0x4444_4444,
                0xAAAA_AAAA,
                0xBBBB_BBBB,
            ),
            (
                0xFFFF_FFFF,
                0x0000_0001,
                0x8000_0000,
                0x7FFF_FFFF,
                0x5555_5555,
                0xAAAA_AAAA,
            ),
            (
                0x0123_4567,
                0x89AB_CDEF,
                0xFEDC_BA98,
                0x7654_3210,
                0x0F0F_0F0F,
                0xF0F0_F0F0,
            ),
            (0x0000_0001, 0x0000_0000, 0x0000_0000, 0x0000_0000, 0, 0),
            (0, 0x8000_0000, 0, 0, 0xFFFF_FFFF, 0),
            (
                0x9E37_79B9,
                0x9E37_79B9,
                0x9E37_79B9,
                0x9E37_79B9,
                0x243F_6A88,
                0x85A3_08D3,
            ),
            (
                0x6A09_E667,
                0xBB67_AE85,
                0x3C6E_F372,
                0xA54F_F53A,
                0x510E_527F,
                0x9B05_688C,
            ),
            (
                0x1000_0000,
                0x2000_0000,
                0x4000_0000,
                0x8000_0000,
                0x1111_1111,
                0x2222_2222,
            ),
            (
                0x0000_00FF,
                0x0000_FF00,
                0x00FF_0000,
                0xFF00_0000,
                0x00FF_00FF,
                0xFF00_FF00,
            ),
            (
                0xC2E1_2A01,
                0xA5A5_A5A5,
                0x5A5A_5A5A,
                0x1234_ABCD,
                0xDEAD_BEEF,
                0xCAFE_BABE,
            ),
        ];

        for (a, b, c, d, mx, my) in goldens {
            let r = g_function(a, b, c, d, mx, my);
            assert!(
                r.witness.validate(),
                "validate failed for ({a:#x},{b:#x},…)"
            );
            let (ea, eb, ec, ed) = blake3_reference_g(a, b, c, d, mx, my);
            assert_eq!((r.a, r.b, r.c, r.d), (ea, eb, ec, ed), "G mismatch");
        }
    }

    #[test]
    fn g_function_randomized_fuzz_against_reference() {
        let seeds: [u32; 32] = [
            0x243f_6a88,
            0x85a3_08d3,
            0x1319_8a2e,
            0x0370_7344,
            0xa409_3822,
            0x299f_31d0,
            0x082e_fa98,
            0xec4e_6c89,
            0x4528_21e6,
            0x38d0_1377,
            0xbe54_66cf,
            0x34e9_0c6c,
            0xc0ac_29b7,
            0xc97c_50dd,
            0x3f84_d5b5,
            0xb547_0917,
            0x9216_d5d9,
            0x8979_fb1b,
            0xd131_0ba6,
            0x98df_b5ac,
            0x2ffd_72db,
            0xd01a_dfb7,
            0xb8e1_afed,
            0x6a26_7e96,
            0xba7c_9045,
            0xf12c_7f99,
            0x24a1_9947,
            0xb391_6cf7,
            0x0801_f2e2,
            0x858e_fc16,
            0x6369_20d8,
            0x7157_4a69,
        ];
        for i in 0..256 {
            let a = seeds[i % 32].wrapping_mul(i as u32);
            let b = seeds[(i + 3) % 32].rotate_left((i % 17) as u32);
            let c = seeds[(i + 7) % 32] ^ (i as u32);
            let d = seeds[(i + 11) % 32].wrapping_add(i as u32);
            let mx = seeds[(i + 13) % 32].rotate_right((i % 5) as u32);
            let my = seeds[(i + 19) % 32].wrapping_sub(i as u32);
            let got = g_function(a, b, c, d, mx, my);
            assert!(got.witness.validate());
            let exp = blake3_reference_g(a, b, c, d, mx, my);
            assert_eq!(
                (got.a, got.b, got.c, got.d),
                exp,
                "fuzz i={i} a={a:#x} b={b:#x}"
            );
        }
    }

    /// `blake3` does not export **G**; this smoke test keeps the workspace `blake3` dependency wired for CI.
    #[test]
    fn blake3_crate_smoke_matches_known_empty_hash() {
        let h = blake3::hash(b"");
        let hex = h.to_hex();
        assert_eq!(
            hex.as_str(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn quarter_round_witness_wraps_g() {
        let a = 0x1111_1111u32;
        let b = 0x2222_2222;
        let c = 0x3333_3333;
        let d = 0x4444_4444;
        let mx = 0xAAAA_AAAA;
        let my = 0xBBBB_BBBB;
        let qr = QuarterRoundWitness::eval(a, b, c, d, mx, my);
        assert!(qr.validate());
        let full = g_function(a, b, c, d, mx, my);
        assert_eq!(qr.g, full.witness);
    }
}
