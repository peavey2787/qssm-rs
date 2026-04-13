//! Phase 6 — flat **index-based** JSON for Engine A / external prover handoff.

use serde_json::{json, Value};

use crate::binding::SovereignWitness;
use crate::bits::{FullAdder, RippleCarryWitness, XorWitness};
use crate::blake3_compress::{CompressionWitness, MerkleParentHashWitness};
use crate::blake3_native::{Add32ChainedWitness, BitRotateWitness, GWitness};

#[inline]
fn bv(b: bool) -> u8 {
    u8::from(b)
}

fn push_bits32(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, bits: &[bool; 32]) {
    for i in 0..32 {
        if let Some(v) = out.as_mut() {
            v.push(json!({
                "idx": *idx,
                "path": path,
                "lane": i,
                "v": bv(bits[i]),
            }));
        }
        *idx += 1;
    }
}

fn push_bool_named(
    out: &mut Option<&mut Vec<Value>>,
    idx: &mut usize,
    path: &str,
    name: &str,
    b: bool,
) {
    if let Some(v) = out.as_mut() {
        v.push(json!({
            "idx": *idx,
            "path": path,
            "name": name,
            "v": bv(b),
        }));
    }
    *idx += 1;
}

fn full_adder_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, fa: &FullAdder) {
    push_bool_named(out, idx, path, "a", fa.a);
    push_bool_named(out, idx, path, "b", fa.b);
    push_bool_named(out, idx, path, "cin", fa.cin);
    push_bool_named(out, idx, path, "sum", fa.sum);
    push_bool_named(out, idx, path, "carry_out", fa.carry_out);
}

fn ripple_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, rw: &RippleCarryWitness) {
    push_bits32(out, idx, &format!("{path}.bits_a"), &rw.bits_a);
    push_bits32(out, idx, &format!("{path}.bits_b"), &rw.bits_b);
    push_bool_named(out, idx, path, "cin", rw.cin);
    for (si, st) in rw.stages.iter().enumerate() {
        let p = format!("{path}.stages[{si}]");
        full_adder_flat(out, idx, &p, st);
    }
    push_bits32(out, idx, &format!("{path}.sum_bits"), &rw.sum_bits);
    push_bool_named(out, idx, path, "cout", rw.cout);
}

fn xor_witness_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, xw: &XorWitness) {
    push_bits32(out, idx, &format!("{path}.bits_a"), &xw.bits_a);
    push_bits32(out, idx, &format!("{path}.bits_b"), &xw.bits_b);
    push_bits32(out, idx, &format!("{path}.and_bits"), &xw.and_bits);
    push_bits32(out, idx, &format!("{path}.output_bits"), &xw.output_bits);
}

fn bit_rotate_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, br: &BitRotateWitness) {
    push_bits32(out, idx, &format!("{path}.in_bits"), &br.in_bits);
    push_bits32(out, idx, &format!("{path}.out_bits"), &br.out_bits);
    if let Some(v) = out.as_mut() {
        v.push(json!({
            "idx": *idx,
            "path": path,
            "name": "rotr_offset_u8",
            "v": br.offset,
        }));
    }
    *idx += 1;
}

fn add32_chained_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, ac: &Add32ChainedWitness) {
    ripple_flat(out, idx, &format!("{path}.first"), &ac.first);
    ripple_flat(out, idx, &format!("{path}.second"), &ac.second);
}

fn g_witness_flat(out: &mut Option<&mut Vec<Value>>, idx: &mut usize, path: &str, gw: &GWitness) {
    add32_chained_flat(out, idx, &format!("{path}.add_ab_mx"), &gw.add_ab_mx);
    xor_witness_flat(out, idx, &format!("{path}.xor_d_a"), &gw.xor_d_a);
    bit_rotate_flat(out, idx, &format!("{path}.rot16"), &gw.rot16);
    ripple_flat(out, idx, &format!("{path}.add_c_d"), &gw.add_c_d);
    xor_witness_flat(out, idx, &format!("{path}.xor_b_c"), &gw.xor_b_c);
    bit_rotate_flat(out, idx, &format!("{path}.rot12"), &gw.rot12);
    add32_chained_flat(out, idx, &format!("{path}.add_ab_my"), &gw.add_ab_my);
    xor_witness_flat(out, idx, &format!("{path}.xor_d_a2"), &gw.xor_d_a2);
    bit_rotate_flat(out, idx, &format!("{path}.rot8"), &gw.rot8);
    ripple_flat(out, idx, &format!("{path}.add_c_d2"), &gw.add_c_d2);
    xor_witness_flat(out, idx, &format!("{path}.xor_b_c2"), &gw.xor_b_c2);
    bit_rotate_flat(out, idx, &format!("{path}.rot7"), &gw.rot7);
}

/// Count private bit-wire entries for a **`CompressionWitness`** (matches **`compression_witness_value`** indexing).
#[must_use]
pub fn compression_private_wire_count(w: &CompressionWitness) -> usize {
    let mut idx = 0usize;
    let mut no_sink: Option<&mut Vec<Value>> = None;
    for round in 0..7 {
        for step in 0..8 {
            let path = format!("count.g_steps[{round}][{step}]");
            g_witness_flat(&mut no_sink, &mut idx, &path, &w.g_steps[round][step].g);
        }
    }
    idx
}

/// Sum of both compress witnesses in a Merkle-parent package.
#[must_use]
pub fn merkle_parent_private_wire_count(w: &MerkleParentHashWitness) -> usize {
    compression_private_wire_count(&w.compress_chunk_start) + compression_private_wire_count(&w.compress_root)
}

/// **`SovereignWitness`** private limb bit count (**32** padded wires).
#[must_use]
pub fn sovereign_private_wire_count() -> usize {
    32
}

#[must_use]
pub fn sovereign_witness_value(w: &SovereignWitness) -> Value {
    let mut priv_wires = Vec::new();
    let mut idx = 0usize;
    let mut sink = Some(&mut priv_wires);
    push_bits32(&mut sink, &mut idx, "limb_bits", &w.limb_bits);
    json!({
        "kind": "SovereignWitnessV1",
        "public": {
            "root_hex": hex::encode(w.root),
            "digest_hex": hex::encode(w.digest),
            "message_limb_u30": w.message_limb,
            "domain_tag": w.domain_tag,
        },
        "private_aux_hex": {
            "rollup_context_digest": hex::encode(w.rollup_context_digest),
            "proof_metadata": hex::encode(&w.proof_metadata),
        },
        "private_bit_wires": priv_wires,
        "private_wire_count": idx,
    })
}

#[must_use]
pub fn compression_witness_value(w: &CompressionWitness, label: &str) -> Value {
    let mut priv_wires = Vec::new();
    let mut idx = 0usize;
    let mut sink = Some(&mut priv_wires);
    for round in 0..7 {
        for step in 0..8 {
            let path = format!("{label}.g_steps[{round}][{step}]");
            g_witness_flat(&mut sink, &mut idx, &path, &w.g_steps[round][step].g);
        }
    }
    json!({
        "kind": "CompressionWitnessV1",
        "label": label,
        "public": {
            "chaining_value_u32_hex": w.chaining_value.iter().map(|u| format!("{u:08x}")).collect::<Vec<_>>(),
            "output_words_u32_hex": w.output_words.iter().map(|u| format!("{u:08x}")).collect::<Vec<_>>(),
            "counter_low": w.counter_low,
            "counter_high": w.counter_high,
            "block_len": w.block_len,
            "flags": w.flags,
            "block_words_initial_u32_hex": w.block_words_initial.iter().map(|u| format!("{u:08x}")).collect::<Vec<_>>(),
        },
        "private_bit_wires": priv_wires,
        "private_wire_count": idx,
    })
}

#[must_use]
pub fn merkle_parent_hash_witness_value(w: &MerkleParentHashWitness) -> Value {
    json!({
        "kind": "MerkleParentHashWitnessV1",
        "public": {
            "parent_digest_hex": hex::encode(w.digest()),
        },
        "compress_chunk_start": compression_witness_value(&w.compress_chunk_start, "compress_chunk_start"),
        "compress_root": compression_witness_value(&w.compress_root, "compress_root"),
    })
}
