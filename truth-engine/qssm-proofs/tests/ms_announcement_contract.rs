use qssm_proofs::shared::fiat_shamir::FiatShamirOracle;

const DOMAIN_MS: &str = "QSSM-MS-v1.0";

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn bitness_oracle_contract_is_table_driven() {
    let root = [3u8; 32];
    let binding_entropy = [5u8; 32];
    let binding_context = [7u8; 32];
    let context = b"announcement-contract-ms";
    let value = 42u64;
    let target = 21u64;
    let n = 11u8;
    let k = 17u8;

    let base = FiatShamirOracle::ms_bitness_challenge(
        DOMAIN_MS,
        &root,
        n,
        k,
        &binding_entropy,
        value,
        target,
        context,
        &binding_context,
    );

    struct Case {
        name: &'static str,
        digest: [u8; 32],
        must_change: bool,
    }

    // announcement-only contract: there are no response/challenge-share inputs,
    // so changing those hypothetical values must not affect the digest.
    let response_zero = [13u8; 32];
    let response_one = [19u8; 32];

    let cases = vec![
        Case {
            name: "mutate_root",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &[9u8; 32],
                n,
                k,
                &binding_entropy,
                value,
                target,
                context,
                &binding_context,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_n",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &root,
                n.wrapping_add(1),
                k,
                &binding_entropy,
                value,
                target,
                context,
                &binding_context,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_k",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &root,
                n,
                k.wrapping_add(1),
                &binding_entropy,
                value,
                target,
                context,
                &binding_context,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_binding_entropy",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &root,
                n,
                k,
                &[6u8; 32],
                value,
                target,
                context,
                &binding_context,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_context",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &root,
                n,
                k,
                &binding_entropy,
                value,
                target,
                b"announcement-contract-ms-mutated",
                &binding_context,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_binding_context",
            digest: FiatShamirOracle::ms_bitness_challenge(
                DOMAIN_MS,
                &root,
                n,
                k,
                &binding_entropy,
                value,
                target,
                context,
                &[8u8; 32],
            ),
            must_change: true,
        },
        Case {
            name: "mutate_hypothetical_response_zero",
            digest: {
                let _ = response_zero;
                let _ = response_one;
                FiatShamirOracle::ms_bitness_challenge(
                    DOMAIN_MS,
                    &root,
                    n,
                    k,
                    &binding_entropy,
                    value,
                    target,
                    context,
                    &binding_context,
                )
            },
            must_change: false,
        },
    ];

    for case in cases {
        if case.must_change {
            assert_ne!(case.digest, base, "case {} must change", case.name);
        } else {
            assert_eq!(case.digest, base, "case {} must not change", case.name);
        }
    }
}

#[test]
fn comparison_oracle_contract_is_table_driven() {
    let statement_digest = [23u8; 32];
    let clause_announcements = [31u8; 96];
    let base = FiatShamirOracle::ms_comparison_challenge(
        DOMAIN_MS,
        &statement_digest,
        &clause_announcements,
    );

    struct Case {
        name: &'static str,
        digest: [u8; 32],
        must_change: bool,
    }

    let response_share = [41u8; 32];
    let challenge_share = [43u8; 32];

    let cases = vec![
        Case {
            name: "mutate_statement_digest",
            digest: FiatShamirOracle::ms_comparison_challenge(
                DOMAIN_MS,
                &[29u8; 32],
                &clause_announcements,
            ),
            must_change: true,
        },
        Case {
            name: "mutate_clause_announcements",
            digest: FiatShamirOracle::ms_comparison_challenge(
                DOMAIN_MS,
                &statement_digest,
                &[37u8; 96],
            ),
            must_change: true,
        },
        Case {
            name: "mutate_hypothetical_response_or_challenge",
            digest: {
                let _ = response_share;
                let _ = challenge_share;
                FiatShamirOracle::ms_comparison_challenge(
                    DOMAIN_MS,
                    &statement_digest,
                    &clause_announcements,
                )
            },
            must_change: false,
        },
    ];

    for case in cases {
        if case.must_change {
            assert_ne!(case.digest, base, "case {} must change", case.name);
        } else {
            assert_eq!(case.digest, base, "case {} must not change", case.name);
        }
    }
}

#[test]
fn fixed_seed_programmed_query_sequence_matches_snapshot() {
    let binding_entropy = [7u8; 32];
    let binding_context = [9u8; 32];
    let context = b"announcement_contract_fixed_fixture";
    let (commitment, _witness) =
        qssm_ms::commit_value_v2(u64::MAX, [3u8; 32], binding_entropy).expect("commitment");
    let statement = qssm_ms::PredicateOnlyStatementV2::new(
        commitment,
        u64::MAX - 1,
        binding_entropy,
        binding_context,
        context.to_vec(),
    );
    let simulation =
        qssm_ms::simulate_predicate_only_v2(&statement, [5u8; 32]).expect("simulation");
    assert!(
        qssm_ms::verify_predicate_only_v2_with_programming(&statement, &simulation)
            .expect("programmed verifier")
    );

    let bitness = simulation
        .proof()
        .bitness_global_challenges()
        .expect("bitness global challenges");
    let comparison = simulation
        .proof()
        .comparison_global_challenge()
        .expect("comparison global challenge");

    let programmed = simulation.programmed_queries();
    assert_eq!(programmed.len(), 65, "expected 64 bitness + 1 comparison query");
    for idx in 0..64 {
        assert_eq!(
            programmed[idx].challenge(),
            &bitness[idx],
            "bitness challenge index {idx} mismatch"
        );
    }
    assert_eq!(programmed[64].challenge(), &comparison);

    let mut blob = Vec::new();
    for query in programmed {
        blob.extend_from_slice(query.query_digest());
        blob.extend_from_slice(query.challenge());
    }
    let sequence_hash = blake3::hash(&blob);
    let sequence_hash_hex = hex(sequence_hash.as_bytes());
    assert_eq!(
        sequence_hash_hex,
        "8c6f6e1c723aaa23ebe73fe45b317a72d6bf38799a7e3c0f3129d4c78ab45be3",
        "fixed-seed programmed-query sequence drifted"
    );
}
