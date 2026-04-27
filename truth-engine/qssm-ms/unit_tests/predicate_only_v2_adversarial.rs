//! MS v2 predicate-only adversarial cases (no GhostMirror coordinates).

use qssm_ms::{
    commit_value_v2, prove_predicate_only_v2, verify_predicate_only_v2, BitnessProofV2,
    ComparisonClauseProofV2, ComparisonProofV2, EqualitySubproofV2, MsError,
    PredicateOnlyProofV2, PredicateOnlyStatementV2, V2_BIT_COUNT,
};

const BE: [u8; 32] = [0x77; 32];
const BC: [u8; 32] = [0x88; 32];
const CTX: &[u8] = b"adversarial_ctx";

fn good_statement_proof() -> (PredicateOnlyStatementV2, PredicateOnlyProofV2) {
    let seed = [0x11u8; 32];
    let prover = [0x22u8; 32];
    let (c, w) = commit_value_v2(200, seed, BE).unwrap();
    let st = PredicateOnlyStatementV2::new(c, 50, BE, BC, CTX.to_vec());
    let proof = prove_predicate_only_v2(&st, &w, prover).unwrap();
    (st, proof)
}

fn clone_bitness(proof: &PredicateOnlyProofV2) -> Vec<BitnessProofV2> {
    proof
        .bitness_proofs()
        .iter()
        .map(|b| {
            BitnessProofV2::from_wire(
                *b.announce_zero_bytes(),
                *b.announce_one_bytes(),
                *b.challenge_zero_bytes(),
                *b.challenge_one_bytes(),
                *b.response_zero_bytes(),
                *b.response_one_bytes(),
            )
        })
        .collect()
}

fn clone_comparison(proof: &PredicateOnlyProofV2) -> ComparisonProofV2 {
    let clauses: Vec<ComparisonClauseProofV2> = proof
        .comparison_proof()
        .clauses_slice()
        .iter()
        .map(|cl| {
            let subs: Vec<EqualitySubproofV2> = cl
                .subproofs_slice()
                .iter()
                .map(|s| EqualitySubproofV2::from_wire(*s.announcement_bytes(), *s.response_bytes()))
                .collect();
            ComparisonClauseProofV2::from_wire(*cl.challenge_share_bytes(), subs)
        })
        .collect();
    ComparisonProofV2::from_clauses(clauses)
}

#[test]
fn prove_rejects_equal_value_and_target() {
    let (c, w) = commit_value_v2(42, [1u8; 32], BE).unwrap();
    let st = PredicateOnlyStatementV2::new(c, 42, BE, BC, CTX.to_vec());
    let err = prove_predicate_only_v2(&st, &w, [2u8; 32]).unwrap_err();
    assert!(matches!(err, MsError::UnsatisfiedPredicateRelation));
}

#[test]
fn verify_rejects_wrong_statement_digest_in_proof() {
    let (st, proof) = good_statement_proof();
    let mut bad_digest = *proof.statement_digest();
    bad_digest[0] ^= 1;
    let tampered = PredicateOnlyProofV2::from_wire_parts(
        proof.result(),
        bad_digest,
        clone_bitness(&proof),
        clone_comparison(&proof),
        st.target(),
    )
    .unwrap();
    let v = verify_predicate_only_v2(&st, &tampered);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_tampered_bitness_announcement() {
    let (st, proof) = good_statement_proof();
    let mut bitness = clone_bitness(&proof);
    let old = &bitness[0];
    let mut az = *old.announce_zero_bytes();
    az[0] ^= 0x01;
    bitness[0] = BitnessProofV2::from_wire(
        az,
        *old.announce_one_bytes(),
        *old.challenge_zero_bytes(),
        *old.challenge_one_bytes(),
        *old.response_zero_bytes(),
        *old.response_one_bytes(),
    );
    let tampered = PredicateOnlyProofV2::from_wire_parts(
        proof.result(),
        *proof.statement_digest(),
        bitness,
        clone_comparison(&proof),
        st.target(),
    )
    .unwrap();
    let v = verify_predicate_only_v2(&st, &tampered);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_tampered_bitness_challenge() {
    let (st, proof) = good_statement_proof();
    let mut bitness = clone_bitness(&proof);
    let i = 0;
    let old = &bitness[i];
    let mut cz = *old.challenge_zero_bytes();
    cz[0] ^= 0x01;
    bitness[i] = BitnessProofV2::from_wire(
        *old.announce_zero_bytes(),
        *old.announce_one_bytes(),
        cz,
        *old.challenge_one_bytes(),
        *old.response_zero_bytes(),
        *old.response_one_bytes(),
    );
    let tampered = PredicateOnlyProofV2::from_wire_parts(
        proof.result(),
        *proof.statement_digest(),
        bitness,
        clone_comparison(&proof),
        st.target(),
    )
    .unwrap();
    let v = verify_predicate_only_v2(&st, &tampered);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_tampered_comparison_subproof_response() {
    let (st, proof) = good_statement_proof();
    let mut comp = clone_comparison(&proof);
    let clauses = comp.clauses_slice().to_vec();
    if let Some(first) = clauses.first() {
        let subs: Vec<EqualitySubproofV2> = first
            .subproofs_slice()
            .iter()
            .enumerate()
            .map(|(j, s)| {
                let mut resp = *s.response_bytes();
                if j == 0 {
                    resp[0] ^= 0x01;
                }
                EqualitySubproofV2::from_wire(*s.announcement_bytes(), resp)
            })
            .collect();
        let new_first = ComparisonClauseProofV2::from_wire(*first.challenge_share_bytes(), subs);
        let mut new_clauses = vec![new_first];
        new_clauses.extend_from_slice(&clauses[1..]);
        comp = ComparisonProofV2::from_clauses(new_clauses);
    }
    let tampered = PredicateOnlyProofV2::from_wire_parts(
        proof.result(),
        *proof.statement_digest(),
        clone_bitness(&proof),
        comp,
        st.target(),
    )
    .unwrap();
    let v = verify_predicate_only_v2(&st, &tampered);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_wrong_target_on_statement() {
    let (st, proof) = good_statement_proof();
    let wrong = PredicateOnlyStatementV2::new(
        st.commitment().clone(),
        st.target().wrapping_add(1),
        *st.binding_entropy(),
        *st.binding_context(),
        st.context().to_vec(),
    );
    let v = verify_predicate_only_v2(&wrong, &proof);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_wrong_binding_context_on_statement() {
    let (st, proof) = good_statement_proof();
    let mut bad_bc = *st.binding_context();
    bad_bc[0] ^= 1;
    let wrong = PredicateOnlyStatementV2::new(
        st.commitment().clone(),
        st.target(),
        *st.binding_entropy(),
        bad_bc,
        st.context().to_vec(),
    );
    let v = verify_predicate_only_v2(&wrong, &proof);
    assert!(!matches!(v, Ok(true)), "{v:?}");
}

#[test]
fn verify_rejects_mismatched_bitness_proof_count() {
    let (st, proof) = good_statement_proof();
    let mut bitness = clone_bitness(&proof);
    bitness.truncate(V2_BIT_COUNT - 1);
    assert!(PredicateOnlyProofV2::from_wire_parts(
        proof.result(),
        *proof.statement_digest(),
        bitness,
        clone_comparison(&proof),
        st.target(),
    )
    .is_err());
}

#[test]
fn good_proof_still_verifies() {
    let (st, proof) = good_statement_proof();
    assert!(verify_predicate_only_v2(&st, &proof).unwrap());
}
