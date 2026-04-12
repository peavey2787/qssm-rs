//! CLI: Millionaire’s Duel demo (Public-Difference ZK + ML-DSA + SMT leaderboard).
#![forbid(unsafe_code)]

use std::env;
use std::time::Instant;

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, Seed};
use mssq_batcher::{
    apply_batch, elect_leader, mssq_seed_from_anchor, sort_lexicographical, LeaderAttestation,
    RollupState,
};
use qssm_common::{rollup_context_from_l1, Batch, L1Anchor, L2Transaction, MockKaspaAdapter};
use qssm_le::{prove_arithmetic, PublicInstance, VerifyingKey, Witness, verify_lattice};
use qssm_ref::millionaires_duel::{
    encode_millionaires_proof, format_leaf_data_hex, format_slot_hex, leaderboard_key,
    parse_leaderboard_leaf, prestige_payload, public_message_for_duel, MillionairesDuelVerifier,
};
use qssm_utils::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key};

fn parse_u64_args() -> (u64, u64) {
    let mut it = env::args().skip(1);
    let a = it.next().and_then(|s| s.parse().ok()).unwrap_or(1000u64);
    let b = it.next().and_then(|s| s.parse().ok()).unwrap_or(500u64);
    (a, b)
}

fn sign_attestation(
    sk: &ml_dsa::SigningKey<MlDsa65>,
    anchor: &MockKaspaAdapter,
    leader_id: [u8; 32],
    ctx_digest: [u8; 32],
) -> LeaderAttestation {
    let seed = mssq_seed_from_anchor(anchor);
    let msg = leader_attestation_signing_bytes(
        anchor.get_current_slot(),
        &anchor.parent_block_hash_prev(),
        &anchor.latest_qrng_value(),
        anchor.qrng_epoch(),
        &seed,
        &ctx_digest,
        None,
        &leader_id,
    );
    let sig = sk.sign(&msg);
    let pk = sk.verifying_key().encode();
    LeaderAttestation {
        slot: anchor.get_current_slot(),
        parent_block_hash: anchor.parent_block_hash_prev(),
        qrng_value: anchor.latest_qrng_value(),
        qrng_epoch: anchor.qrng_epoch(),
        claimed_leader_id: leader_id,
        signing_public_key: pk.as_slice().to_vec(),
        signature: sig.encode().as_slice().to_vec(),
        smt_root_pre: None,
    }
}

fn main() {
    let (v_a, v_b) = parse_u64_args();
    println!("Millionaire’s Duel — defaults: use args `<v_a> <v_b>` (demo uses Public-Difference ZK).");
    println!("Balances: Alice={v_a}, Bob={v_b}");

    let mut anchor = MockKaspaAdapter::new([0x42; 32]);
    anchor.set_slot(10);
    anchor.set_auto_finalize(false);
    anchor.tick_fast();
    anchor.finalize_volatile();

    let ctx = rollup_context_from_l1(&anchor);
    let ctx_digest = ctx.digest();

    let sk_alice = MlDsa65::from_seed(&Seed::from([0xA1u8; 32]));
    let sk_bob = MlDsa65::from_seed(&Seed::from([0xB2u8; 32]));
    let pk_alice = sk_alice.verifying_key().encode();
    let pk_bob = sk_bob.verifying_key().encode();
    let id_alice = leader_id_from_ml_dsa_public_key(pk_alice.as_slice());
    let id_bob = leader_id_from_ml_dsa_public_key(pk_bob.as_slice());
    let candidates = [id_alice, id_bob];

    let seed = mssq_seed_from_anchor(&anchor);
    let winner = elect_leader(&seed, &candidates).expect("candidates");
    let (winner_name, sk_winner) = if winner == id_alice {
        ("Alice", &sk_alice)
    } else {
        ("Bob", &sk_bob)
    };

    let public_m = match public_message_for_duel(v_a, v_b) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Invalid balances for demo encoding: {e:?}");
            std::process::exit(1);
        }
    };

    let vk = VerifyingKey::from_seed([0xDD; 32]);
    let public = PublicInstance {
        message: public_m,
    };
    let witness = Witness { r: [0i32; qssm_le::N] };
    let (commitment, proof) = match prove_arithmetic(&vk, &public, &witness, &ctx_digest) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Prover failed: {e:?}");
            std::process::exit(1);
        }
    };

    let att = sign_attestation(sk_winner, &anchor, winner, ctx_digest);
    let wire = encode_millionaires_proof(&att, vk.crs_seed, public_m, &commitment, &proof);

    let digest = ctx.digest();
    let t0 = Instant::now();
    let ok = verify_lattice(
        &vk,
        &public,
        &commitment,
        &proof,
        &digest,
    )
    .unwrap_or(false);
    let latency = t0.elapsed();
    if !ok {
        eprintln!("verify_lattice failed");
        std::process::exit(1);
    }

    if cfg!(debug_assertions) {
        println!(
            "DEBUG MODE: Verify took {:.3}ms. Switch to cargo run --release to see God-Mode speed.",
            latency.as_secs_f64() * 1000.0
        );
    } else {
        println!(
            "verify_lattice: {:.3}ms (release / God-Mode path)",
            latency.as_secs_f64() * 1000.0
        );
    }

    let lb_key = leaderboard_key();
    let tx = L2Transaction {
        id: lb_key,
        proof: wire,
        payload: prestige_payload(1),
    };
    let batch = Batch {
        txs: sort_lexicographical(vec![tx]),
    };
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: candidates.to_vec(),
    };
    let mut state = RollupState::new();
    apply_batch(&mut state, &batch, &ctx, &verifier).expect("apply_batch");

    let slot_hex = format_slot_hex(&lb_key);
    println!("[SMT State] Slot: 0x{slot_hex}");
    if let Some(leaf) = state.smt.get(&lb_key) {
        println!("[SMT State] Data: [{}]", format_leaf_data_hex(leaf));
        let (wins, has_tag) = parse_leaderboard_leaf(leaf);
        if has_tag {
            println!("Parsed: {wins} Win | Status: WealthiestKnight");
        } else {
            println!("Parsed: prestige tag missing in leaf tail (debug)");
        }
    }
    println!(
        "State transition: {winner_name} (ID: {}…) promoted to ‘Wealthiest Knight’ — rollup root {:02x}…",
        hex_prefix(&winner, 6),
        state.root()[0]
    );
    println!("Full SMT root: {}", hex_full(&state.root()));
}

fn hex_prefix(id: &[u8; 32], n: usize) -> String {
    id.iter()
        .take(n)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn hex_full(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect::<String>()
}
