//! Phase 5 — BLAKE3 **`compress`** witness: **7** rounds × **8** **`G`** steps, message word permutation, Merkle parent via **`hash_domain`** preimage.
//!
//! Normative algorithm: [BLAKE3 reference implementation](https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs) § `compress` / `round` / `permute`.

use crate::blake3_native::{g_function, QuarterRoundWitness};

/// BLAKE3 **IV** (same as spec / `blake3` crate).
pub const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

pub const CHUNK_START: u32 = 1 << 0;
pub const CHUNK_END: u32 = 1 << 1;
pub const ROOT: u32 = 1 << 3;

/// Permute message words **between** rounds (reference `MSG_PERMUTATION`).
pub const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// One round’s **eight** `(mx_word, my_word)` pairs into the **current** 16-word message block (column then diagonal); **identical** for all **7** rounds before **`MSG_PERMUTATION`** reshuffles words between rounds.
pub const MSG_SCHEDULE_ROW: [(u8, u8); 8] = [
    (0, 1),
    (2, 3),
    (4, 5),
    (6, 7),
    (8, 9),
    (10, 11),
    (12, 13),
    (14, 15),
];

/// **`[round][step]`** — same row **7** times by spec (permutation applies to **words**, not this table).
pub const MSG_SCHEDULE: [[(u8, u8); 8]; 7] = [
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
    MSG_SCHEDULE_ROW,
];

/// Lane indices `(a,b,c,d)` into the **16-word state** plus `(mx_i, my_i)` into **`m[16]`** for each of the **8** `G` calls inside one `round`.
pub const ROUND_G_LANES: [(usize, usize, usize, usize, usize, usize); 8] = [
    (0, 4, 8, 12, 0, 1),
    (1, 5, 9, 13, 2, 3),
    (2, 6, 10, 14, 4, 5),
    (3, 7, 11, 15, 6, 7),
    (0, 5, 10, 15, 8, 9),
    (1, 6, 11, 12, 10, 11),
    (2, 7, 8, 13, 12, 13),
    (3, 4, 9, 14, 14, 15),
];

#[inline]
fn permute_block_words(m: &mut [u32; 16]) {
    let mut p = [0u32; 16];
    for i in 0..16 {
        p[i] = m[MSG_PERMUTATION[i]];
    }
    *m = p;
}

#[inline]
pub fn words_from_little_endian_bytes(bytes: &[u8], words: &mut [u32]) {
    debug_assert_eq!(bytes.len(), 4 * words.len());
    for (four, w) in bytes.chunks_exact(4).zip(words.iter_mut()) {
        *w = u32::from_le_bytes(four.try_into().expect("four"));
    }
}

/// Reference **`compress`** (native), for oracle checks.
#[must_use]
pub fn compress_native(
    chaining_value: &[u32; 8],
    block_words: &[u32; 16],
    counter_low: u32,
    counter_high: u32,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter_low,
        counter_high,
        block_len,
        flags,
    ];
    let mut block = *block_words;
    for round in 0..7 {
        for step in 0..8 {
            let (a, b, c, d, mi, mj) = ROUND_G_LANES[step];
            g_native(&mut state, a, b, c, d, block[mi], block[mj]);
        }
        if round < 6 {
            permute_block_words(&mut block);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= chaining_value[i];
    }
    state
}

#[inline]
fn g_native(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

/// One **`compress`** invocation: **56** chained **`QuarterRoundWitness`** (same semantics as [`compress_native`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionWitness {
    pub chaining_value: [u32; 8],
    pub block_words_initial: [u32; 16],
    pub counter_low: u32,
    pub counter_high: u32,
    pub block_len: u32,
    pub flags: u32,
    pub g_steps: [[QuarterRoundWitness; 8]; 7],
    pub output_words: [u32; 16],
}

impl CompressionWitness {
    #[must_use]
    pub fn build(
        chaining_value: [u32; 8],
        block_words_initial: [u32; 16],
        counter_low: u32,
        counter_high: u32,
        block_len: u32,
        flags: u32,
    ) -> Self {
        let mut state = [
            chaining_value[0],
            chaining_value[1],
            chaining_value[2],
            chaining_value[3],
            chaining_value[4],
            chaining_value[5],
            chaining_value[6],
            chaining_value[7],
            IV[0],
            IV[1],
            IV[2],
            IV[3],
            counter_low,
            counter_high,
            block_len,
            flags,
        ];
        let mut block = block_words_initial;
        let mut g_steps: [[QuarterRoundWitness; 8]; 7] = std::array::from_fn(|_| {
            std::array::from_fn(|_| {
                let z = g_function(0, 0, 0, 0, 0, 0);
                QuarterRoundWitness { g: z.witness }
            })
        });

        for round in 0..7 {
            for step in 0..8 {
                let (a, b, c, d, mi, mj) = ROUND_G_LANES[step];
                let r = g_function(state[a], state[b], state[c], state[d], block[mi], block[mj]);
                state[a] = r.a;
                state[b] = r.b;
                state[c] = r.c;
                state[d] = r.d;
                g_steps[round][step] = QuarterRoundWitness { g: r.witness };
            }
            if round < 6 {
                permute_block_words(&mut block);
            }
        }
        for i in 0..8 {
            state[i] ^= state[i + 8];
            state[i + 8] ^= chaining_value[i];
        }
        let output_words: [u32; 16] = state;
        Self {
            chaining_value,
            block_words_initial,
            counter_low,
            counter_high,
            block_len,
            flags,
            g_steps,
            output_words,
        }
    }

    pub fn validate(&self) -> bool {
        let expected = compress_native(
            &self.chaining_value,
            &self.block_words_initial,
            self.counter_low,
            self.counter_high,
            self.block_len,
            self.flags,
        );
        if expected != self.output_words {
            return false;
        }
        for round in 0..7 {
            for step in 0..8 {
                if !self.g_steps[round][step].validate() {
                    return false;
                }
            }
        }
        true
    }

    /// Phase 6: flat index-based JSON — **public** chaining / block / output words, **private** all **G** bit-wires.
    #[must_use]
    pub fn to_prover_json(&self) -> String {
        serde_json::to_string_pretty(&crate::prover_json::compression_witness_value(
            self,
            "CompressionWitness",
        ))
        .expect("compression witness JSON")
    }
}

#[inline]
pub fn first_8_words(compression_output: [u32; 16]) -> [u32; 8] {
    compression_output[0..8].try_into().expect("8 words")
}

/// First **32** bytes of **`compress`** output (little-endian words), BLAKE3 root style.
#[must_use]
pub fn output_words_to_hash32(words: &[u32; 16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..][..4].copy_from_slice(&words[i].to_le_bytes());
    }
    out
}

/// Full witness for **`hash_domain(DOMAIN_MERKLE_PARENT, &[left‖right])`** (same bytes as [`qssm_utils::merkle::merkle_parent`]).
///
/// Two **`compress`** calls: **(1)** first **64** bytes of preimage with **`CHUNK_START`**; **(2)** remaining bytes with **`CHUNK_END | ROOT`** (single-chunk **`finalize`** path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleParentHashWitness {
    pub compress_chunk_start: CompressionWitness,
    pub compress_root: CompressionWitness,
}

impl MerkleParentHashWitness {
    #[must_use]
    pub fn build(left: &[u8; 32], right: &[u8; 32]) -> Self {
        use qssm_utils::hashing::DOMAIN_MERKLE_PARENT;

        let mut preimage = Vec::new();
        preimage.extend_from_slice(DOMAIN_MERKLE_PARENT.as_bytes());
        preimage.extend_from_slice(left);
        preimage.extend_from_slice(right);

        debug_assert_eq!(
            preimage.len(),
            DOMAIN_MERKLE_PARENT.len() + 64,
            "merkle parent preimage is domain + 64 B"
        );

        let mut block0 = [0u32; 16];
        words_from_little_endian_bytes(&preimage[..64], &mut block0);
        let compress_chunk_start = CompressionWitness::build(IV, block0, 0, 0, 64, CHUNK_START);

        let cv1 = first_8_words(compress_chunk_start.output_words);
        let tail = &preimage[64..];
        let mut block1 = [0u8; 64];
        block1[..tail.len()].copy_from_slice(tail);
        let mut block1_words = [0u32; 16];
        words_from_little_endian_bytes(&block1, &mut block1_words);

        let block_len = tail.len() as u32;
        let compress_root =
            CompressionWitness::build(cv1, block1_words, 0, 0, block_len, CHUNK_END | ROOT);

        Self {
            compress_chunk_start,
            compress_root,
        }
    }

    pub fn validate(&self) -> bool {
        self.compress_chunk_start.validate() && self.compress_root.validate()
    }

    /// Phase 6: nested **`CompressionWitness`** JSON + **public** parent digest hex.
    #[must_use]
    pub fn to_prover_json(&self) -> String {
        serde_json::to_string_pretty(&crate::prover_json::merkle_parent_hash_witness_value(self))
            .expect("merkle parent hash witness JSON")
    }

    /// **32-byte** digest (bit-for-bit matches **`merkle_parent`**).
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        output_words_to_hash32(&self.compress_root.output_words)
    }
}

/// Build the Merkle-parent hash witness (for tests and provers).
#[must_use]
pub fn hash_merkle_parent_witness(left: &[u8; 32], right: &[u8; 32]) -> MerkleParentHashWitness {
    MerkleParentHashWitness::build(left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use qssm_utils::hashing::DOMAIN_MERKLE_PARENT;
    use qssm_utils::merkle::merkle_parent;

    #[test]
    fn msg_schedule_matches_round_g_lanes() {
        for round in 0..7 {
            for step in 0..8 {
                let (a, b, c, d, mi, mj) = ROUND_G_LANES[step];
                let _ = (a, b, c, d);
                assert_eq!(
                    (mi, mj),
                    (
                        MSG_SCHEDULE[round][step].0 as usize,
                        MSG_SCHEDULE[round][step].1 as usize
                    )
                );
            }
        }
    }

    #[test]
    fn compression_witness_matches_compress_native_smoke() {
        let block = std::array::from_fn(|i| i as u32);
        let w = CompressionWitness::build(IV, block, 0, 0, 64, 0);
        assert!(w.validate());
        assert_eq!(w.output_words, compress_native(&IV, &block, 0, 0, 64, 0));
    }

    #[test]
    fn merkle_parent_witness_matches_utils() {
        let left = std::array::from_fn(|i| (i * 3 + 1) as u8);
        let right = std::array::from_fn(|i| (i * 5 + 7) as u8);
        let w = hash_merkle_parent_witness(&left, &right);
        assert!(w.validate());
        let expected = merkle_parent(&left, &right);
        assert_eq!(w.digest(), expected);
        // Explicit bit parity
        for bi in 0..32 {
            for bit in 0..8 {
                assert_eq!(
                    (w.digest()[bi] >> bit) & 1,
                    (expected[bi] >> bit) & 1,
                    "byte {bi} bit {bit}"
                );
            }
        }
        let mut manual = blake3::Hasher::new();
        manual.update(DOMAIN_MERKLE_PARENT.as_bytes());
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left);
        buf[32..].copy_from_slice(&right);
        manual.update(&buf);
        assert_eq!(w.digest(), *manual.finalize().as_bytes());
    }
}
