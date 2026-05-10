# Cross-Component Independence Audit (MS ↔ LE)

**Version:** QSSM-PROOF-FROZEN-v2.0
**Date:** 2026-04-25

## Question

Is there any hidden coupling channel between the MS and LE transcript distributions that would invalidate the additive composition argument?

## Why This Matters

The composed bound `Adv_QSSM(D) <= epsilon_ms + epsilon_le` relies on the MS and LE simulators being independent. If there is a hidden coupling, the additive composition breaks and the actual advantage could be as large as `epsilon_ms * epsilon_le` in the multiplicative case, or worse.

## Channel 1: Shared Randomness Leakage

### Mechanism Under Test
The global simulator splits one ambient `simulator_seed` into:
- `ms_seed = hash_domain("QSSM-ZK-SIM-v1.0", ["qssm_global_sim_ms_seed", seed, ms_statement_digest])`
- `le_seed = hash_domain("QSSM-ZK-SIM-v1.0", ["qssm_global_sim_le_seed", seed, le_binding_context, le_crs_seed])`

### Analysis
The two derived seeds share the same domain prefix `"QSSM-ZK-SIM-v1.0"` but differ in:
- The label: `"qssm_global_sim_ms_seed"` vs `"qssm_global_sim_le_seed"`
- The trailing material: MS statement digest vs LE binding context + CRS seed

Under the ROM, `hash_domain` is modeled as an independent random oracle for each distinct input. The label difference alone ensures distinct oracle queries, so the derived seeds are independently distributed.

### Risk Assessment
**LOW.** The domain separation is correct by construction. The labels are string-distinct. No path exists for one component seed to leak information about the other, assuming the ROM.

**Caveat:** In a non-ROM model (e.g., if Blake3 has structural weaknesses in related-key settings), the shared prefix could in principle create correlation. This is a standard ROM assumption dependency, not a design flaw.

### Verdict: NO LEAKAGE under ROM.

## Channel 2: Correlated Transcript Structure

### Mechanism Under Test
The MS transcript contains: `statement_digest, result, bitness_global_challenges, comparison_global_challenge, transcript_digest`.
The LE transcript contains: `commitment_coeffs, t_coeffs, z_coeffs, challenge_seed`.

### Analysis
- The MS transcript is derived entirely from `public_input.ms` + `ms_seed`.
- The LE transcript is derived entirely from `public_input.le` + `le_seed`.
- No MS field is computed from any LE field or vice versa.
- The real prover uses separate witnesses: MS uses (value, blinders), LE uses (witness r).
- The simulator uses separate seeds: ms_seed and le_seed share no state after derivation.

### Structural Check
Is there any field in one transcript that is a function of a field in the other?
- `statement_digest` is computed from MS public inputs only.
- `commitment_coeffs` is computed from LE public inputs + LE simulator coins only.
- `challenge_seed` in LE is derived from LE-only material.
- `bitness_global_challenges` in MS are derived from MS-only material.

### Verdict: NO STRUCTURAL CORRELATION.

## Channel 3: Challenge-Domain Overlap

### Mechanism Under Test
MS challenges are derived from query digests:
- `bitness_query_digest(statement_digest, bit_index, announcements)` → domain `QSSM-MS-v1.0`
- `comparison_query_digest(clause_announcements)` → domain `QSSM-MS-v1.0`

LE challenges are derived from:
- `fs_challenge_bytes(binding_context, vk, public, commitment, t)` → domain `QSSM-LE-FS-LYU-v1.0`

### Analysis
The domain prefixes are completely disjoint:
- MS: `"QSSM-MS-v1.0"`
- LE: `"QSSM-LE-FS-LYU-v1.0"`

Under the ROM, distinct domain prefixes produce independent random oracles. There is no overlap in the challenge derivation paths.

### Concrete Check
Could any MS query digest accidentally collide with an LE query digest?
- MS digests start with the MS domain string bytes.
- LE digests start with the LE domain string bytes.
- The first bytes are `Q,S,S,M,-,M,S` vs `Q,S,S,M,-,L,E` — they diverge at byte index 5.
- Even without the ROM, a collision requires a Blake3 preimage collision across distinct prefixes.

### Verdict: NO CHALLENGE-DOMAIN OVERLAP.

## Channel 4: Digest Namespace Collisions

### Mechanism Under Test
Additional domain separation tags used across the system:
- `DST_LE_COMMIT = "QSSM-LE-V1-COMMIT..............."`
- `DST_MS_VERIFY = "QSSM-MS-V1-VERIFY..............."`
- `DOMAIN_ZK_SIM = "QSSM-ZK-SIM-v1.0"`
- `DOMAIN_LE_FS = "QSSM-LE-FS-LYU-v1.0"`
- `DOMAIN_LE_CHALLENGE_POLY = "QSSM-LE-CHALLENGE-POLY-v1.0"`
- `CROSS_PROTOCOL_BINDING_LABEL = "cross_protocol_digest_v1"`

### Analysis
Every domain tag is string-distinct. The `qssm-utils` crate already has a test (`hash_domain` collision test) that verifies `DOMAIN_MS` and `DOMAIN_LE` produce distinct outputs for the same input.

The 32-byte DST constants (`DST_LE_COMMIT`, `DST_MS_VERIFY`) are padded to fixed width and are visually distinct in their first 8 bytes.

### Edge Case: Cross-Protocol Binding
The `CROSS_PROTOCOL_BINDING_LABEL` is used to bind MS and LE at the API level. This is intentional coupling at the protocol layer (the verifier checks that MS and LE commitments bind to the same statement). This is NOT a simulator independence issue — it is public input binding, present in both real and simulated worlds equally.

### Verdict: NO NAMESPACE COLLISIONS. Intentional binding is public-input-level only.

## Overall Conclusion

| Channel | Status | Risk |
|---------|--------|------|
| Shared randomness leakage | Clean | Low (ROM-dependent) |
| Correlated transcript structure | Clean | None |
| Challenge-domain overlap | Clean | None |
| Digest namespace collisions | Clean | None |

**The MS and LE components are independent under the ROM.**

The additive composition `Adv_QSSM(D) <= epsilon_ms + epsilon_le` is structurally justified. No hidden coupling channel was identified.

**One honest caveat:** The independence relies on the ROM. If the hash function (Blake3) exhibited related-key or structural weaknesses, the domain-separated seed derivation could leak correlation. This is a standard and accepted ROM dependency, shared with every Fiat-Shamir-based composed protocol in the literature.
