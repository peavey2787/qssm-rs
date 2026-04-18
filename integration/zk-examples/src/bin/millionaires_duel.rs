//! CLI: Millionaire’s Duel demo (Public-Difference ZK + ML-DSA + SMT leaderboard).
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::time::{Duration, Instant};

use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{KeyGen, MlDsa65, Seed};
use mssq_batcher::{
    apply_batch, elect_leader, mssq_seed_from_anchor, sort_lexicographical, LeaderAttestation,
    RollupState,
};
use qssm_traits::{rollup_context_from_l1, Batch, L1Anchor, L2Transaction};
use qssm_examples::millionaires_duel::{
    duel_settlement_payload, encode_millionaires_proof, format_leaf_data_hex, format_slot_hex,
    leaderboard_key, parse_leaderboard_leaf, public_message_for_duel, MillionairesDuelVerifier,
};
use qssm_kaspa::MockKaspaAdapter;
use qssm_le::{prove_arithmetic, verify_lattice, PublicInstance, VerifyingKey, Witness};
use qssm_utils::{leader_attestation_signing_bytes, leader_id_from_ml_dsa_public_key};

fn read_u64_prompt(label: &str) -> u64 {
    loop {
        print!("Enter {label} balance (non-negative integer): ");
        let _ = io::stdout().flush();
        let mut line = String::new();
        if io::stdin().read_line(&mut line).is_err() {
            println!("(stdin unavailable; using 0)");
            return 0;
        }
        let t = line.trim();
        if t.is_empty() {
            println!("Empty input; try again.");
            continue;
        }
        match t.parse::<u64>() {
            Ok(v) => return v,
            Err(_) => println!("Invalid number; enter a non-negative integer (e.g. 1000)."),
        }
    }
}

fn pause_console() {
    let _ = io::stdout().flush();
    let _ = io::stderr().flush();
    let mut buf = String::new();
    println!("\nPress Enter to exit…");
    match io::stdin().read_line(&mut buf) {
        Ok(0) | Err(_) => {
            // No newline / EOF (e.g. double‑clicked exe with a broken stdin) — don’t vanish instantly.
            #[cfg(windows)]
            {
                println!(
                    "No console input (stdin closed). Closing in 8 seconds — or run from PowerShell / cmd for Enter-to-close."
                );
                std::thread::sleep(Duration::from_secs(8));
            }
        }
        Ok(_) => {}
    }
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
    let exit_code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    };
    pause_console();
    std::process::exit(exit_code);
}

fn run() -> Result<(), String> {
    println!("QSSM Protocol Family: Millionaires' Duel");
    println!("Privacy-Preserving Magnitude Comparison via Lattice-Based Predicates");
    println!("{}\n", "-".repeat(72));
    println!("Demo: Public-Difference ZK, ML-DSA attestations, SMT leaderboard.");
    println!("You will enter each player’s balance at the prompts below.\n");

    let v_a = read_u64_prompt("Alice’s");
    let v_b = read_u64_prompt("Bob’s");
    println!("\nUsing balances: Alice={v_a}, Bob={v_b}");
    let cmp = if v_a > v_b {
        "Alice > Bob (public duel scalar above shift)"
    } else if v_b > v_a {
        "Bob > Alice (public duel scalar below shift)"
    } else {
        "Tie (public duel scalar equals shift)"
    };
    println!("Magnitude: {cmp}\n");

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
    let winner = elect_leader(&seed, &candidates).map_err(|e| e.to_string())?;
    let (leader_name, sk_winner) = if winner == id_alice {
        ("Alice", &sk_alice)
    } else {
        ("Bob", &sk_bob)
    };
    let duel_winner = if v_a > v_b {
        "Alice"
    } else if v_b > v_a {
        "Bob"
    } else {
        "Tie"
    };

    let public_m = public_message_for_duel(v_a, v_b)
        .map_err(|e| format!("Invalid balances for demo encoding: {e:?}"))?;

    let vk = VerifyingKey::from_seed([0xDD; 32]);
    let public = PublicInstance::legacy_message(public_m);
    let witness = Witness {
        r: [0i32; qssm_le::N],
    };
    let (commitment, proof) = prove_arithmetic(&vk, &public, &witness, &ctx_digest, [0xBB; 32])
        .map_err(|e| format!("Prover failed: {e:?}"))?;

    let att = sign_attestation(sk_winner, &anchor, winner, ctx_digest);
    let wire = encode_millionaires_proof(&att, vk.crs_seed, public_m, &commitment, &proof);

    let digest = ctx.digest();
    let t0 = Instant::now();
    let ok = verify_lattice(&vk, &public, &commitment, &proof, &digest).unwrap_or(false);
    let latency = t0.elapsed();
    if !ok {
        return Err("verify_lattice failed".into());
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
    let pre_state = RollupState::new();
    let smt_proof = pre_state.smt.prove(&lb_key).encode();
    let tx = L2Transaction {
        id: lb_key,
        proof: smt_proof,
        payload: duel_settlement_payload(1, &wire),
    };
    let batch = Batch {
        txs: sort_lexicographical(vec![tx]),
    };
    let verifier = MillionairesDuelVerifier {
        expected_slot: anchor.get_current_slot(),
        candidates: candidates.to_vec(),
    };
    let mut state = RollupState::new();
    apply_batch(&mut state, &batch, &ctx, &verifier)
        .map_err(|e| format!("SMT batch failed: {e}"))?;

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
        "State transition: slot leader {leader_name} (ID: {}…) committed duel outcome winner={duel_winner} — rollup root {:02x}…",
        hex_prefix(&winner, 6),
        state.root()[0]
    );
    println!("Full SMT root: {}", hex_full(&state.root()));

    Ok(())
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
