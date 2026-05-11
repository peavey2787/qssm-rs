# Spec/Formal Conformance Audit

Navigation: [EasyCrypt README](../README.md)

## 1. Executive Summary

This audit compares the protocol-spec tree under `docs/02-protocol-specs/` against the EasyCrypt model under `formal-verification/easycrypt/`.

Audit totals:

- Protocol-spec files audited: 14
- Key EasyCrypt files / theorem surfaces mapped: 43
- Blockers: 0
- High-severity items: 0
- Medium-severity items: 7
- Low-severity items: 2

Main conclusions:

- The exact-zero theorem story is aligned. The protocol theorem spec in `qssm-zk-theorem-spec.md` matches `theorem/MainTheorem.ec` for the exact-zero `G0 -> G1 -> G2` route and the exact MS-3a / MS-3b / MS-3c simulation lemmas.
- The EasyCrypt tree is broader than the current theorem spec. The formal model now has additional theorem surfaces for the demo semantic route, the LE-only parameterized route, the full canonical parameterized route, the abstract real-world upper-bound route, and the concrete 128 / all-reductions route.
- The initial theorem-surface drift blocker is now addressed in the protocol docs. `qssm-zk-theorem-spec.md` and `security/ASSUMPTION_ANALYSIS.md` now distinguish the exact-zero theorem skeleton from the charged parameterized, real-world, and concrete companion routes, preserve the explicit duplicated MS2 charge, and state that public AfterRom remains budget-close to canonical AfterRom rather than zero-equal.
- The initial concrete-128 blocker is now addressed in the protocol docs. `security/ASSUMPTION_ANALYSIS.md` and `security/SECURITY_MODEL_MAP.md` now state the `1 / 2^98` component epsilon, the `5 / 2^98` closed form, the explicit LE rejection / LE FS / MS1 / MS2 reduction-facing premises, the non-axiom status, the `3%r / 64%r` toy-mass caveat, and the lack of weighted/non-uniform sampler modeling.
- The previously high-severity documentation gaps are now addressed by explicit protocol-side scope notes. Soundness scope, byte/layout/domain boundaries, concrete LE constant/floor boundaries, announcement-only MS query-digest boundaries, and seam/version-lock boundaries are now documented as either current EasyCrypt coverage or explicit Rust-authoritative out-of-scope surfaces.
- Remaining gaps are now medium-severity refinement/model gaps rather than protocol-doc misstatements. Soundness, byte-level refinement, concrete constant embedding, announcement-only digest linkage, and seam/layout refinement all remain optional future EasyCrypt work rather than current protocol-spec inaccuracies.

Recommended next phase:

- The blocker-level protocol/spec mismatches are now addressed in docs.
- Remaining work starts with deciding whether the now-explicit medium-severity refinement gaps should remain documentation boundaries or move into future EasyCrypt work.

### Follow-Up Changelog

- Follow-up docs patch after the initial audit updated `docs/02-protocol-specs/qssm-zk-theorem-spec.md`, `docs/02-protocol-specs/security/ASSUMPTION_ANALYSIS.md`, and `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md`.
- The exact-zero theorem spec is now documented separately from the charged live routes.
- The concrete 128 route obligations, closed forms, and toy-mass caveats are now documented in the protocol-spec tree.
- Soundness scope is now explicitly documented as outside the current EasyCrypt theorem family.
- Byte, layout, domain, announcement-only, and seam/version-lock boundaries are now explicitly documented as Rust-authoritative conformance points rather than current EasyCrypt refinement claims.

## 2. Protocol Spec Inventory

### 2.1 Normative Core Specs

| File | Type | Component Covered | Relevant Objects / State | Algorithms / Procedures | Security Claims | Parameters / Constants | Failure Conditions | Transcript / Public Input | Adversary / Assumption Notes | Audit Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md` | Normative Level 1 execution spec | Composed MS v2 + LE execution and simulator plumbing | `SimulatedMsV2Transcript`, `SimulatedLeTranscript`, `SimulatedQssmTranscript`, simulator seeds | Exact seed derivation, exact FS/oracle construction, exact simulator ordering, exact transcript structs | No theorem claim; intended as byte-accurate formalization input | `DOMAIN_ZK_SIM`, `DOMAIN_LE_FS`, `DOMAIN_LE_CHALLENGE_POLY`, `DOMAIN_MS`, seam domains, simulator labels | Digest mismatch, algebra mismatch, failed recomputation | Exact MS / LE transcript field names and ordering | ROM dependence is implicit; Rust authoritative | Now explicitly marks byte/domain/layout rules and announcement-only query discipline as Rust-authoritative refinement boundaries rather than current EasyCrypt coverage |
| `docs/02-protocol-specs/qssm-zk-theorem-spec.md` | Normative Level 2 theorem spec | ZK theorem route | `G0`, `G1`, `G2`, `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, `epsilon_le` | Game hop decomposition | Additive ZK bound only | A1 / A2 / A4 mapping | None; theorem layer only | Refers to Level 1 for transcript details | Programmable ROM for ZK | Now distinguishes the exact-zero route from the charged parameterized / real-world / concrete companion routes |
| `docs/02-protocol-specs/qssm-le-engine-a.md` | Normative Level 3 engine spec | LE / Engine A | `PublicInstance`, `Witness`, `LatticeProof`, CRS seed, binding context | `prove_arithmetic`, `verify_lattice`, FS challenge bytes, challenge polynomial, rejection loop | LE hiding / HVZK discussion; parameter conditions; FS floor claims | `N`, `Q`, `BETA`, `ETA`, `GAMMA`, `C_POLY_SIZE`, `C_POLY_SPAN`, `MAX_PROVER_ATTEMPTS`, `PUBLIC_DIGEST_COEFFS` | Public validation failure, norm failure, FS mismatch, equation failure | Visible LE transcript fields and public binding inputs | Assumes Set B parameter soundness and FS conditions | Now explicitly marks constants, challenge expansion, attempt bounds, and byte-level FS surfaces as Rust-authoritative rather than current EasyCrypt-embedded constants |
| `docs/02-protocol-specs/qssm-ms-engine-b.md` | Normative Level 3 engine spec | MS / Engine B | `PredicateOnlyStatementV2`, `PredicateOnlyProofV2`, `BitnessProofV2`, `ComparisonProofV2`, `ProgrammedOracleQueryV2` | Commit, prove, verify, simulate, programmed verification, query digests | Announcement-only digest discipline; exact-simulation framing | `V2_BIT_COUNT = 64`, `DOMAIN_MS`, FS labels | Verification failure, simulator invalidity | Statement/proof/programmed-query fields | ROM/programmed-query assumptions | Now explicitly states that EasyCrypt models the announcement-only surface abstractly but does not prove the Rust digest functions byte-for-byte |
| `docs/02-protocol-specs/blake3-lattice-gadget-spec.md` | Normative Level 3 bridge spec | MS-to-LE bridge and seam | `MsPredicateOnlyV2BridgeOp`, `EngineABindingInput`, `EngineABindingOutput`, transcript layout sync points | Verify-then-bind bridge, seam commit / open / binding digests | Cross-engine binding / replay prevention | Seam domains, `BRIDGE_Q`, `MAX_LIMB_EXCLUSIVE`, transcript layout version sync | Hard reject on verification, digest, or version mismatch | Public seam inputs and outputs | Adversary includes replay, substitution, malleability | Now explicitly marks seam digests, serialization, and version-lock equality as Rust-authoritative bridge boundaries rather than current EasyCrypt coverage |
| `docs/02-protocol-specs/spec_layer_contract.md` | Normative meta-spec | Spec layering and authority boundaries | Level 1 / 2 / 3 ownership | Layer contract only | No direct crypto claim | None | None | None | Rust authoritative; layer discipline explicit | Strongly aligned with current EasyCrypt architecture split |

### 2.2 Security / Supporting Docs Under the Audited Tree

| File | Type | Component Covered | Relevant Objects / State | Algorithms / Procedures | Security Claims | Parameters / Constants | Failure Conditions | Transcript / Public Input | Adversary / Assumption Notes | Audit Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/02-protocol-specs/security/ASSUMPTION_ANALYSIS.md` | Security analysis | ZK theorem assumptions | A1 / A2 / A4, LE Set B numeric checks | Assumption mapping and dominance discussion | Additive theorem bound, 132.2-bit ZK floor, 121-bit soundness floor target references | LE floors and validation tolerances | None | Refers to theorem object, not transcript layout | ROM framing plus LE parameter conditions | Now also documents the charged live routes and concrete-route premises; some numeric floor claims remain external to EasyCrypt |
| `docs/02-protocol-specs/security/ROM_ANALYSIS.md` | Security analysis | ROM dependence | MS query digests, LE programmed digest, seed derivation helpers | Distinguishes essential vs non-essential ROM use | ROM is essential for simulation | FS/query surfaces explicitly named | Simulator chain fails without ROM | Refers to announcement-only and LE programmed surfaces | ROM model explicit | Now explicitly states that EasyCrypt models these surfaces abstractly and does not prove the Rust digest inputs byte-for-byte |
| `docs/02-protocol-specs/security/ZK_VS_SOUNDNESS_SPLIT.md` | Security analysis | ZK vs soundness split | ZK theorem, soundness theorem, soundness assumptions, implementation layer | Separates ZK, soundness, and implementation claims | States both ZK and soundness theorems, plus concrete soundness numbers | 121-bit, 132.2-bit, 196.2-bit figures | None | N/A | ROM for ZK; CR/SIS/FS for soundness | Now explicitly states that EasyCrypt currently proves the ZK/composition surfaces only and that soundness remains security-analysis scope on the current tree |
| `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md` | Security analysis | Security dependency map | ZK, soundness, implementation layers | Dependency decomposition only | Security floor summary and one-sentence security model | 121-bit and 132.2-bit floors | None | N/A | Assumption-to-mechanism mapping | Still not an EasyCrypt theorem surface, and now explicitly distinguishes ZK coverage from external soundness and Rust-authoritative refinement boundaries |
| `docs/02-protocol-specs/security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md` | Security analysis | MS / LE independence | Shared seed derivation, domain tags, transcript fields | Independence audit over simulator channels | Additive composition justified under ROM | Explicit domain and label strings | None | Uses concrete transcript and seed construction | ROM-dependent independence argument | Not re-proved in EasyCrypt from concrete strings; only abstractly assumed via separated surfaces |
| `docs/02-protocol-specs/security/WITNESS_ISOLATION_THREAT_MODEL.md` | Security analysis / implementation assurance | Witness isolation | Witness structs, zeroization, non-serialization, debug redaction, simulator signatures | Threat-model audit only | Claims witness does not leak by current API / type discipline | None | Future refactor risks, accidental leakage paths | N/A | Implementation-level assumptions | Outside current EasyCrypt scope |
| `docs/02-protocol-specs/engine-b-engine-a-binding-seam.md` | Supporting normative seam note | Commit-then-open seam | Seam inputs/outputs, rollup context, entropy link | Verify-then-bind sequence and hard rejects | Cross-engine replay and substitution resistance | Seam domains | Hard reject cases listed | Public seam fields and privacy boundary | Adversary model explicit | Now explicitly marks seam digests, serialization, and version-lock equality as Rust-authoritative rather than current EasyCrypt coverage |
| `docs/02-protocol-specs/implementation-plans/blake3-lattice-gadget-rust-plan.md` | Implementation plan | Rust gadget implementation plan | Witness APIs, bit decomposition, adders, limb extraction | Planned implementation phases | Normative for implementation plan, not theorem surface | Concrete plan-level constraints | Plan-level forbidden constructions | Public witness API references | No explicit EasyCrypt claim | Out of scope for spec/model conformance except as a non-normative support document |

## 3. Formal Model Inventory

This section inventories the key EasyCrypt owners and theorem surfaces that matter for protocol-spec conformance.

### 3.1 Budget Owners and Top-Level Route Owners

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `formal-verification/easycrypt/primitives/BudgetParameters.ec` | Exact-zero and demo semantic owner layer | `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, `epsilon_le`, `epsilon_ms_hash_binding_semantic`, `epsilon_ms_rom_programmability_semantic`, `epsilon_le_semantic` | Exact-zero + demo semantic |
| `formal-verification/easycrypt/primitives/ParameterizedBudgetParameters.ec` | Parameterized owner layer | `epsilon_ms_hash_binding_parameterized`, `epsilon_ms_rom_programmability_parameterized`, `epsilon_le_rej_parameterized`, `epsilon_le_fs_parameterized`, `epsilon_le_parameterized` | Parameterized |
| `formal-verification/easycrypt/primitives/RealWorldBudgetParameters.ec` | Abstract real-world budget record | `realworld_budget`, `epsilon_ms_hash_binding_realworld`, `epsilon_ms_rom_programmability_realworld`, `epsilon_le_rej_realworld`, `epsilon_le_fs_realworld`, `epsilon_le_realworld`, `epsilon_top_realworld` | Abstract real-world |
| `formal-verification/easycrypt/primitives/RealWorldBudgetObligations.ec` | Explicit budget-premise layer | `le_realworld_obligations`, `ms_realworld_obligations`, `qssm_realworld_obligations` | Abstract real-world |
| `formal-verification/easycrypt/RealWorldBudgetInstantiation.ec` | Concrete instantiation layer | `lambda_concrete_128`, `realworld_budget_concrete_128`, `qssm_main_theorem_realworld_concrete_128`, `qssm_main_theorem_realworld_concrete_128_with_all_reductions` | Concrete 128 / all-reductions |

### 3.2 LE Rejection, FS, and HVZK Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `formal-verification/easycrypt/le/LERejectionSamplerCore.ec` | Lower rejection sampler carrier | rejection sampler core objects | LE lower semantics |
| `formal-verification/easycrypt/le/LERejectionSamplerMass.ec` | Demo semantic rejection mass closure | rejection shadow failure probability equalities | Demo semantic |
| `formal-verification/easycrypt/le/LERejection.ec` | Theorem-facing rejection bridge | `le_rejection_distribution_defined`, `le_rejection_acceptance_probability_bounded`, `le_rejection_output_shape_preserved` | Exact-zero + demo semantic |
| `formal-verification/easycrypt/le/LERejectionParameterized.ec` | Parameterized rejection theorem wrapper | `A_LE_rejection_sampler_semantic_sdist_parameterized_bound` | Parameterized |
| `formal-verification/easycrypt/le/LERejectionConcreteReduction.ec` | External reduction obligation owner | `le_rejection_concrete_reduction_obligation` | Concrete 128 / reductions |
| `formal-verification/easycrypt/le/LEFsProgrammingSurface.ec` | Lower FS semantic shadow surface | semantic branch/state/image operators | LE lower semantics |
| `formal-verification/easycrypt/le/LEFsProgrammingFailureProbability.ec` | Demo semantic FS bad-branch owner | `le_fs_shadow_local_bad_branch_mass` | Demo semantic |
| `formal-verification/easycrypt/le/LEFsProgramming.ec` | Theorem-facing FS bridge | `le_fs_query_surface_defined`, `le_fs_programming_hiding_bound` | Exact-zero + demo semantic |
| `formal-verification/easycrypt/le/LEFsProgrammingParameterized.ec` | Parameterized FS theorem wrapper | parameterized FS programming bounds | Parameterized |
| `formal-verification/easycrypt/le/LEFsConcreteReduction.ec` | External reduction obligation owner | `le_fs_concrete_reduction_obligation` | Concrete 128 / reductions |
| `formal-verification/easycrypt/le/LEStatisticalDistance.ec` | LE additive composition | LE rejection + FS additive closure | Exact-zero + demo semantic |
| `formal-verification/easycrypt/le/LEStatisticalDistanceParameterized.ec` | LE parameterized additive composition | `A_LE_semantic_view_advantage_bound_from_parameterized_budget` | Parameterized |
| `formal-verification/easycrypt/le/LEStatisticalDistanceRealWorld.ec` | LE real-world additive wrapper | real-world LE transition bound | Abstract real-world |
| `formal-verification/easycrypt/le/LEHVZK.ec` | LE HVZK wrapper | theorem-facing HVZK consequences over LE distance layer | Exact-zero + demo semantic |
| `formal-verification/easycrypt/le/LEModel.ec` | Stable theorem-facing LE facade | LE-facing imports and packaged surface | Stable facade |

### 3.3 MS Hash Binding, ROM Programmability, and AfterRom Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `formal-verification/easycrypt/ms/SourceModel.ec` | Stable public-spine / source-model facade | `ms_v2_transcript_observable` and public transcript projections | All routes |
| `formal-verification/easycrypt/ms/source/SourceHashBindingSemanticBridge.ec` | MS1 semantic execution-owned bridge | `A_MS1_hash_binding_execution_owned_semantic_bound` | Demo semantic |
| `formal-verification/easycrypt/ms/source/SourceHashBindingSemanticBridgeParameterized.ec` | MS1 parameterized bridge | `A_MS1_hash_binding_execution_owned_parameterized_bound` | Parameterized |
| `formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticBridge.ec` | MS2 semantic execution-owned bridge | `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure`, `A_MS2_rom_programming_execution_owned_semantic_bound` | Demo semantic |
| `formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec` | MS2 parameterized bridge | `A_MS2_rom_programming_execution_owned_parameterized_bound` | Parameterized |
| `formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticLiveParameterizedMass.ec` | Live MS2 parameterized lower mass owner | `A_MS2_rom_programming_execution_owned_live_parameterized_bound` | Parameterized |
| `formal-verification/easycrypt/ms/MSProbabilitySurface.ec` | Canonical exact-zero and semantic MS probability surface | `A_MS1_hash_binding_bad_event_bound`, `A_MS2_rom_programming_transition_bound`, `A_MS2_rom_programming_semantic_transition_bound`, exact AfterRom stage law | Exact-zero + demo semantic |
| `formal-verification/easycrypt/ms/MSProbabilitySurfaceParameterized.ec` | Parameterized MS probability surface | `A_MS2_rom_programming_parameterized_public_endpoint_transition_bound`, `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound` | Parameterized |
| `formal-verification/easycrypt/ms/MSProbabilitySurfaceRealWorld.ec` | Real-world MS probability wrapper | real-world public-endpoint and landing bounds | Abstract real-world |
| `formal-verification/easycrypt/ms/TrueClause.ec` | Stable MS-3b facade | `MS_3b_true_clause_characterization` | Exact-zero / all routes |
| `formal-verification/easycrypt/ms/Comparison.ec` | Stable MS-3c facade | `MS_3c_exact_comparison_simulation` | Exact-zero / all routes |
| `formal-verification/easycrypt/ms/MS.ec` | Stable theorem-facing MS wrapper | game-hop predicates / packaged MS surface | Stable facade |

### 3.4 Game and Top Theorem Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `formal-verification/easycrypt/games/GameAdvantage.ec` | Core game probability layer | `game_pr`, `Adv`, exact-zero game arithmetic | Exact-zero + demo semantic |
| `formal-verification/easycrypt/games/GameAdvantageParameterized.ec` | Parameterized game arithmetic | parameterized game wrappers | Parameterized |
| `formal-verification/easycrypt/games/GameMSHopComposition.ec` | Exact-zero MS composition | `A_G0_to_G1_ms_transition_bound`, semantic sibling route | Exact-zero + demo semantic |
| `formal-verification/easycrypt/games/GameMSHopCompositionParameterized.ec` | Parameterized MS composition | `A_G0_to_G1_ms_parameterized_transition_bound` | Parameterized |
| `formal-verification/easycrypt/games/GameMSHopCompositionRealWorld.ec` | Real-world MS composition | `A_G0_to_G1_ms_realworld_transition_bound` | Abstract real-world |
| `formal-verification/easycrypt/games/GameLEBridge.ec` | Exact-zero / semantic LE bridge | `A_G1_to_G2_le_transition_bound`, semantic bridge variants | Exact-zero + demo semantic |
| `formal-verification/easycrypt/games/GameLEBridgeParameterized.ec` | Parameterized LE bridge | `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound` | Parameterized |
| `formal-verification/easycrypt/games/GameLEBridgeRealWorld.ec` | Real-world LE bridge | real-world LE transition bound | Abstract real-world |
| `formal-verification/easycrypt/theorem/MainTheorem.ec` | Canonical top theorem surface | `qssm_main_theorem_skeleton`, `qssm_main_theorem`, `qssm_main_theorem_semantic_budget` | Exact-zero + demo semantic |
| `formal-verification/easycrypt/theorem/MainTheoremParameterized.ec` | Parameterized top theorem surface | `qssm_main_theorem_le_parameterized_budget`, `qssm_main_theorem_parameterized_budget` | Parameterized |
| `formal-verification/easycrypt/theorem/MainTheoremRealWorld.ec` | Abstract real-world top theorem surface | `qssm_main_theorem_realworld_budget` | Abstract real-world |

### 3.5 Stable Facades and Route Summary

Stable facades that downstream proof users should treat as entrypoints:

- `formal-verification/easycrypt/ms/TrueClause.ec`
- `formal-verification/easycrypt/ms/Comparison.ec`
- `formal-verification/easycrypt/ms/SourceModel.ec`
- `formal-verification/easycrypt/ms/MS.ec`
- `formal-verification/easycrypt/le/LEModel.ec`
- `formal-verification/easycrypt/games/Games.ec`
- `formal-verification/easycrypt/theorem/MainTheorem.ec`
- `formal-verification/easycrypt/theorem/MainTheoremParameterized.ec`
- `formal-verification/easycrypt/theorem/MainTheoremRealWorld.ec`
- `formal-verification/easycrypt/RealWorldBudgetInstantiation.ec`

Route summary:

- Exact-zero public route: `qssm_main_theorem`
- Demo semantic route: `qssm_main_theorem_semantic_budget`
- LE-only parameterized route: `qssm_main_theorem_le_parameterized_budget`
- Full canonical parameterized route: `qssm_main_theorem_parameterized_budget`
- Abstract real-world upper-bound route: `qssm_main_theorem_realworld_budget`
- Concrete 128 component-bound route: `qssm_main_theorem_realworld_concrete_128`
- Concrete 128 all-reductions route: `qssm_main_theorem_realworld_concrete_128_with_all_reductions`

## 4. Spec-to-Formal Mapping Table

| Spec File / Section | Spec Object or Claim | Formal File / Theorem / Operator | Match Status | Notes |
|---|---|---|---|---|
| `spec_layer_contract.md` whole file | Level 1 execution, Level 2 theorem, Level 3 interface split; Rust authoritative | `docs/ARCHITECTURE.md`, `theorem/MainTheorem.ec`, `ms/MS.ec`, `le/LEModel.ec` | Exact match | The formal tree follows the same layer separation and explicitly treats Rust as authoritative for concrete execution details |
| `qssm-zk-theorem-spec.md` `G0 -> G1 -> G2` | Exact game chain | `games/GameMSHopComposition.ec`, `games/GameLEBridge.ec`, `theorem/MainTheorem.ec` | Exact match | The canonical exact-zero theorem route matches the stated game chain |
| `qssm-zk-theorem-spec.md` additive bound | `Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le` | `theorem/MainTheorem.ec : qssm_main_theorem_skeleton`, `qssm_main_theorem` | Exact match | Correct for the exact-zero route |
| `qssm-zk-theorem-spec.md` A1 / A2 / A4 map | A1 to MS1, A2 to MS2, A4 to LE | `primitives/BudgetParameters.ec`, `theorem/MainTheorem.ec` | Exact match | Correct for the exact-zero theorem surface |
| `qssm-zk-theorem-spec.md` MS-3a exactness | Exact bitness simulation | `ms/source/SourceTheorem.ec : MS_3a_exact_bitness_simulation` via `use_MS_3a` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` MS-3b exactness | True-clause characterization | `ms/TrueClause.ec : MS_3b_true_clause_characterization` via `use_MS_3b` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` MS-3c exactness | Exact comparison simulation | `ms/Comparison.ec : MS_3c_exact_comparison_simulation` via `use_MS_3c` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` whole document | Route status for exact-zero versus charged live theorem surfaces | `theorem/MainTheoremParameterized.ec`, `theorem/MainTheoremRealWorld.ec`, `RealWorldBudgetInstantiation.ec` | Addressed by follow-up docs patch | The protocol theorem spec now separates the exact-zero theorem skeleton from the charged parameterized, real-world, and concrete routes |
| `qssm-zk-concrete-execution-spec.md` transcript structs | Exact MS and LE observable field sets and order | `ms/SourceModel.ec`, `le/LESurface.ec`, `games/GameTypes.ec` | Modeled abstraction | Observable shapes align, and the protocol doc now explicitly marks byte-level refinement as Rust-authoritative rather than current EasyCrypt coverage |
| `qssm-zk-concrete-execution-spec.md` FS domain strings and labels | Exact `DOMAIN_*`, `DST_*`, seam strings, label bytes | No direct EasyCrypt owner; abstract domain separation only | Addressed by docs clarification | The protocol doc now explicitly states that string literals and concrete domain/tag equality are Rust-authoritative conformance points |
| `qssm-zk-concrete-execution-spec.md` simulator seed derivation order | Exact `ms_seed` / `le_seed` derivation schedule | No direct EasyCrypt theorem; abstract `seed` carrier only | Addressed by docs clarification | The protocol doc now explicitly states that the formal model does not verify seed schedule or label ordering byte-for-byte |
| `qssm-zk-concrete-execution-spec.md` LE programmed query digest order | Exact digest preimage order | `le/LEFsProgrammingSurface.ec` and game-layer LE observables | Modeled abstraction | Existence of programmed query surface is modeled; concrete hash-input order is not |
| `qssm-ms-engine-b.md` statement / proof public structure | Public MS objects and transcript fields | `ms/SourceModel.ec`, `ms/MS.ec` | Partially modeled | Formal model captures public observable content, not the full concrete Rust structs |
| `qssm-ms-engine-b.md` announcement-only query discipline | Query digests depend only on announcements | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `ms/comparison/ComparisonPayloadSemanticBridge.ec` | Addressed by docs clarification | The protocol docs now explicitly state that EasyCrypt models this surface abstractly and does not verify the Rust query functions byte-for-byte |
| `qssm-ms-engine-b.md` programmed verification path | Simulator + programmed query validation | `ms/Comparison.ec`, `games/GameMSHopComposition.ec` | Modeled abstraction | The formal model captures the programmed challenge story abstractly |
| `qssm-le-engine-a.md` visible proof transcript | `C`, `t`, `z`, `challenge_seed` are public | `le/LESurface.ec`, `games/GameLEBridge.ec` | Exact match | The public LE observable surface matches the proof-facing transcript abstraction |
| `qssm-le-engine-a.md` concrete Set B constants | `N`, `Q`, `BETA`, `ETA`, `GAMMA`, `C_POLY_SIZE`, `C_POLY_SPAN`, `MAX_PROVER_ATTEMPTS` | No concrete embedding in EasyCrypt theorem files | Addressed by docs clarification | The protocol docs now explicitly state that EasyCrypt proves over symbolic owners and predicates rather than the Rust constants |
| `qssm-le-engine-a.md` rejection sampler semantics | reject if `||z||_inf > GAMMA`; bounded attempt count | `le/LERejection.ec`, `le/LEStatisticalDistance.ec` | Modeled abstraction | Rejection is modeled as a theorem-facing sampler / distance surface, not with concrete norm arithmetic or attempt bounds |
| `qssm-le-engine-a.md` LE FS pipeline | Exact 11-item FS preimage and challenge polynomial expansion | `le/LEFsProgrammingSurface.ec`, `le/LEFsProgramming.ec` | Addressed by docs clarification | The protocol docs now explicitly state that EasyCrypt models theorem-level FS consequences rather than the BLAKE3/XOF algorithm or byte ordering |
| `qssm-le-engine-a.md` HVZK / A4 | LE HVZK replacement loss | `le/LEHVZK.ec`, `games/GameLEBridge.ec` | Partially modeled | The theorem surface exists, but the cryptographic hardness behind LE HVZK is not internally discharged in EasyCrypt |
| `blake3-lattice-gadget-spec.md` verify-then-bind rule | MS verification must succeed before seam binding | No dedicated EasyCrypt seam theorem; composition assumes verified public input | Partially modeled | This is enforced by Rust bridge code, not re-proved in EasyCrypt |
| `blake3-lattice-gadget-spec.md` seam commitment/open/binding digests | Exact domains and preimage order | No direct EasyCrypt owner | Addressed by docs clarification | The protocol docs now explicitly state that concrete seam hashing remains Rust-authoritative rather than current EasyCrypt coverage |
| `blake3-lattice-gadget-spec.md` transcript-map layout sync | `TRANSCRIPT_MAP_LAYOUT_VERSION` and `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION` must match | No direct EasyCrypt owner | Addressed by docs clarification | The protocol docs now explicitly state that version-lock equality is a Rust compile-time/test-time conformance point rather than a current EasyCrypt theorem |
| `security/ASSUMPTION_ANALYSIS.md` additive ZK theorem summary | A1/A2/A4 additive theorem summary | `theorem/MainTheorem.ec`, `primitives/BudgetParameters.ec` | Exact match | Accurate for the exact-zero theorem surface |
| `security/ASSUMPTION_ANALYSIS.md` theorem surface and concrete-route status | Charged live routes, duplicate MS2 charge, explicit concrete 128 premises, and toy-mass caveat | `theorem/MainTheoremParameterized.ec`, `theorem/MainTheoremRealWorld.ec`, `RealWorldBudgetInstantiation.ec`, `docs/FORMAL_THEOREM_MAP.md` | Addressed by follow-up docs patch | The protocol security docs now state the public-AfterRom caveat, the duplicate MS2 charge, the concrete `1 / 2^98` / `5 / 2^98` route, and the explicit premise status |
| `security/ASSUMPTION_ANALYSIS.md` 132.2-bit floor and concrete LE validation references | Numeric floor and external validation story | `docs/FORMAL_THEOREM_MAP.md`, no direct theorem in EasyCrypt | Formal model weaker than spec | EasyCrypt does not derive those concrete numeric floors internally |
| `security/ROM_ANALYSIS.md` ROM-critical MS and LE query surfaces | Announcement-only MS and programmed LE surfaces are ROM-critical | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `le/LEFsProgramming.ec` | Modeled abstraction | Correct at the abstraction level, not at the concrete hash-function level |
| `security/ZK_VS_SOUNDNESS_SPLIT.md` ZK theorem | ZK bound in ROM | `theorem/MainTheorem.ec` and companion routes | Exact match | ZK half is aligned |
| `security/ZK_VS_SOUNDNESS_SPLIT.md` soundness theorem and concrete soundness numbers | `Adv^snd_QSSM(A) <= epsilon_ms_soundness + epsilon_le_soundness`, 121 / 132.2 / 196.2 figures | No matching EasyCrypt soundness theorem surface in `formal-verification/easycrypt/` | Addressed by docs clarification | The protocol docs now explicitly state that soundness lives outside the current EasyCrypt theorem tree |
| `security/SECURITY_MODEL_MAP.md` one-sentence security model and floors | Combined ZK / soundness / implementation summary with concrete floors | `docs/FORMAL_THEOREM_MAP.md`, `docs/SPEC_FORMAL_CONFORMANCE_AUDIT.md` | Addressed by docs clarification | The protocol docs now explicitly state that ZK route coverage is distinct from external soundness floors and implementation guarantees |
| `security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md` additive composition justified by concrete domain-separated seed schedule | Independence from concrete labels/domains | `games/GameMSHopComposition.ec`, `games/GameLEBridge.ec` | Modeled abstraction | Formal model assumes separated MS/LE public surfaces and additive composition; it does not prove independence from exact concrete string schedules |
| `security/WITNESS_ISOLATION_THREAT_MODEL.md` witness isolation by API/type discipline | non-serialization, redacted debug, no witness in simulator APIs | No matching theorem surface | Not modeled | Pure implementation assurance, outside EasyCrypt |
| `engine-b-engine-a-binding-seam.md` seam hard rejects and privacy boundary | verify-then-bind, seam digest mismatch reject, privacy of entropy link | No dedicated EasyCrypt theorem surface | Addressed by docs clarification | The protocol docs now explicitly state that this is a Rust/bridge contract, not current EasyCrypt theorem content |
| `implementation-plans/blake3-lattice-gadget-rust-plan.md` planned witness API / limb extraction rules | implementation plan constraints | No matching theorem surface | Not modeled | Out of scope for this audit except as a supporting/non-normative document |

## 5. Discrepancy Table

| Severity | Discrepancy | Spec Reference | Formal Reference | Notes | Recommended Fix Bucket |
|---|---|---|---|---|---|
| Resolved | The protocol theorem spec previously presented a single three-term theorem story, even though the live parameterized / real-world / concrete theorem routes require an explicit public-AfterRom to canonical-AfterRom landing and therefore a duplicated MS2 charge | `qssm-zk-theorem-spec.md`, `security/ASSUMPTION_ANALYSIS.md` | `docs/FORMAL_THEOREM_MAP.md`, `theorem/MainTheoremParameterized.ec`, `theorem/MainTheoremRealWorld.ec`, `primitives/RealWorldBudgetParameters.ec` | Addressed in the follow-up docs patch: the protocol docs now distinguish the exact-zero theorem from the charged live routes and preserve the duplicate MS2/public-AfterRom caveat | Addressed |
| Resolved | The concrete 128 / all-reductions EasyCrypt route previously lacked protocol-spec documentation for its explicit external obligations and the live-mass caveat | `security/ASSUMPTION_ANALYSIS.md`, `security/SECURITY_MODEL_MAP.md` | `RealWorldBudgetInstantiation.ec`, `docs/FORMAL_THEOREM_MAP.md` | Addressed in the follow-up docs patch: the protocol docs now state the explicit LE rejection / LE FS / MS1 / MS2 premises, the `1 / 2^98` / `5 / 2^98` arithmetic, and the `3%r / 64%r` caveat | Addressed |
| Medium | Soundness remains outside the current EasyCrypt theorem scope by design on the audited tree | `security/ZK_VS_SOUNDNESS_SPLIT.md`, `security/SECURITY_MODEL_MAP.md` | No soundness theorem files under `formal-verification/easycrypt/`; only ZK/composition surfaces are present | The docs now make this boundary explicit; residual theorem work remains only if a separate EasyCrypt soundness family is desired | Docs clarification + optional future theorem work |
| Medium | Exact FS domain strings, seed schedules, digest preimage order, and byte-level execution details remain Rust-authoritative and are not currently covered by a byte-for-byte EasyCrypt refinement layer | `qssm-zk-concrete-execution-spec.md`, `qssm-le-engine-a.md`, `blake3-lattice-gadget-spec.md` | EasyCrypt abstracts these surfaces; no concrete byte-refinement theorem exists | The docs now make this boundary explicit; residual model work remains only if implementation-level refinement is desired | Docs clarification + optional refinement work |
| Medium | Concrete LE Set B constants, challenge-expansion details, attempt bounds, and numeric security floors are not embedded as current EasyCrypt constants or numeric theorem outputs | `qssm-le-engine-a.md`, `security/ASSUMPTION_ANALYSIS.md`, `security/SECURITY_MODEL_MAP.md` | `le/*.ec` surfaces are symbolic / predicate-based; `docs/FORMAL_THEOREM_MAP.md` is explanatory rather than a concrete-constant proof | The docs now make this boundary explicit; residual work remains only if constant-level machine-checked refinement is desired | Docs clarification + optional refinement work |
| Medium | The announcement-only MS query-digest discipline is modeled abstractly but is not currently linked byte-for-byte to the Rust query-digest functions | `qssm-ms-engine-b.md`, `qssm-zk-concrete-execution-spec.md`, `security/ROM_ANALYSIS.md` | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `ms/comparison/ComparisonPayloadSemanticBridge.ec` | The docs now make this boundary explicit; residual work remains only if formal implementation-level coverage is desired | Docs clarification + optional refinement work |
| Medium | Bridge/seam layout, public-binding serialization, version-lock equality, and digest preimage order remain Rust-authoritative rather than current EasyCrypt theorem coverage | `blake3-lattice-gadget-spec.md`, `engine-b-engine-a-binding-seam.md` | No direct theorem surface; Rust sync checks only | The docs now make this boundary explicit; residual work remains only if bridge/refinement theorems are desired | Docs clarification + optional refinement work |
| Resolved | The abstract real-world theorem route previously lacked a protocol-spec note explaining that it is an upper-bound theorem over explicit obligations and does not model weighted or non-uniform samplers internally | `security/ASSUMPTION_ANALYSIS.md`, `security/SECURITY_MODEL_MAP.md` | `primitives/RealWorldBudgetObligations.ec`, `theorem/MainTheoremRealWorld.ec`, `docs/FORMAL_THEOREM_MAP.md` | Addressed in the follow-up docs patch: the protocol security docs now state the explicit-obligation and no-weighted-sampler caveats | Addressed |
| Medium | Cross-component independence, witness isolation, CT/zeroization, and API misuse claims live in security/implementation documents, not in EasyCrypt theorem surfaces | `security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md`, `security/WITNESS_ISOLATION_THREAT_MODEL.md`, `security/ZK_VS_SOUNDNESS_SPLIT.md` | No matching theorem surfaces | These should not be read as “proved by EasyCrypt” | Docs-only |
| Medium | Proof size, performance, mobile / sub-ms verification, product API behavior, and architecture claims are outside EasyCrypt scope | No in-scope protocol theorem file states them as EasyCrypt claims; some appear elsewhere in repo | No matching theorem surfaces | Not a contradiction, but should be called out explicitly in the audit | Docs-only |
| Low | The audited tree mixes normative specs, security analyses, seam notes, and an implementation plan under one directory | `docs/02-protocol-specs/` overall | N/A | This is a documentation categorization issue, not a theorem mismatch | Docs-only |
| Low | Several apparent “mismatches” are intentional layer separation rather than proof bugs | `spec_layer_contract.md` | `docs/ARCHITECTURE.md`, `docs/FORMAL_THEOREM_MAP.md` | The spec/formal split is largely honest; the missing piece is clearer documentation of what EasyCrypt intentionally abstracts away | Docs-only |

## 6. Resolved / Medium-Severity Items

### Resolved / Addressed By Follow-Up Docs Patch

1. `qssm-zk-theorem-spec.md` and `security/ASSUMPTION_ANALYSIS.md` now distinguish `qssm_main_theorem` from the charged parameterized / real-world / concrete theorem routes, preserve the explicit duplicate MS2 charge, and state that public AfterRom remains budget-close to canonical AfterRom rather than zero-equal.
2. `security/ASSUMPTION_ANALYSIS.md` and `security/SECURITY_MODEL_MAP.md` now state the concrete-128 theorem surfaces, the `1 / 2^98` component epsilon, the `5 / 2^98` closed form, the `95.67807190511263` bit equivalent, the explicit external LE rejection / LE FS / MS1 / MS2 premises, the non-axiom status, and the `3%r / 64%r` toy-mass caveat.
3. The protocol security docs now state that the abstract real-world theorem route packages externally supplied obligations only and does not model weighted or non-uniform sampler internals.
4. `security/ZK_VS_SOUNDNESS_SPLIT.md` and `security/SECURITY_MODEL_MAP.md` now explicitly state that EasyCrypt currently proves the ZK/composition theorem surfaces only, and that soundness claims and soundness numbers remain security-analysis scope on the current tree.
5. `qssm-zk-concrete-execution-spec.md`, `qssm-le-engine-a.md`, and `blake3-lattice-gadget-spec.md` now explicitly mark byte-level domains, seed schedules, serialization order, and layout/version-lock surfaces as Rust-authoritative conformance points rather than current EasyCrypt refinement claims.
6. `qssm-ms-engine-b.md` and `security/ROM_ANALYSIS.md` now explicitly state that the announcement-only MS query-digest surface is modeled abstractly in EasyCrypt and is not yet linked byte-for-byte to the Rust digest functions.
7. `blake3-lattice-gadget-spec.md` and `engine-b-engine-a-binding-seam.md` now explicitly state that seam digests, public-binding serialization, and version-lock equality are Rust-authoritative bridge contracts rather than current EasyCrypt theorem coverage.

### Medium-Severity Items

1. The current EasyCrypt tree still does not contain a separate soundness theorem family. That is now documented honestly as out of scope for the present theorem surface.
2. The current EasyCrypt tree still does not contain a byte-for-byte refinement layer from the Rust execution, digest, and layout surfaces to the abstract observables.
3. The current EasyCrypt tree still does not embed the deployed LE constants or prove the numeric security floors for those exact Rust constants.
4. The current EasyCrypt tree still does not link the abstract announcement-only MS query discipline to the Rust query-digest functions byte-for-byte.
5. The current EasyCrypt tree still does not contain a bridge/refinement theorem for seam serialization, digest preimage order, or version-lock equality.

## 7. Medium / Low-Severity Items

### Medium-Severity Items

6. Cross-component independence, witness isolation, CT/zeroization, and API misuse claims are important, but they are implementation/security-audit claims rather than EasyCrypt theorem claims.
7. Proof size, performance, mobile / sub-ms verification, statelessness, no-prover-network, and product API behavior are not current EasyCrypt model claims. Some of these are not asserted anywhere in the in-scope protocol specs; others live elsewhere in the repo.

### Low-Severity Items

1. `docs/02-protocol-specs/` currently mixes normative specs with analyses and plans, which makes it easier to confuse “authoritative protocol claim” with “supporting discussion”.
2. The spec/formal layer split is mostly healthy. Several gaps found in this audit are documentation gaps about intentional abstraction boundaries, not evidence of a broken theorem.

## 8. Claims Not Covered By EasyCrypt

The following claims or claim families are not currently covered by the EasyCrypt model under `formal-verification/easycrypt/`:

- Exact BLAKE3 / XOF domain strings, labels, and preimage ordering for MS, LE, seam digests, and simulator seed derivation.
- Concrete serialization and layout invariants such as `TRANSCRIPT_MAP_LAYOUT_VERSION`, `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION`, limb packing, and public-binding byte layout.
- A machine-checked refinement from the Rust implementation to the EasyCrypt abstract observables.
- A separate EasyCrypt soundness theorem family matching `security/ZK_VS_SOUNDNESS_SPLIT.md` and `security/SECURITY_MODEL_MAP.md`.
- Concrete numeric soundness floors and proof-size / performance claims.
- Weighted or non-uniform sampler semantics.
- Witness isolation, constant-time behavior, zeroization guarantees, and API misuse prevention.
- Product/API architecture claims such as statelessness, no prover network, or UI / mobile verification performance.

Notes on specific claims mentioned during this audit:

- `NIZK` is partially covered only in the sense that the EasyCrypt tree proves a ROM-based ZK composition route. It does not prove product/API non-interactivity or architecture claims beyond that theorem surface.
- `no trusted setup` is not materially asserted in the in-scope protocol-spec files. The EasyCrypt tree does model CRS- and seed-dependent public inputs, but it does not separately prove a “no trusted setup” architecture claim.
- `proof size` is not asserted in the in-scope protocol-spec files and is not modeled by EasyCrypt.
- `stateless` and `no prover network` do not appear as in-scope protocol-spec theorem claims in `docs/02-protocol-specs/`; EasyCrypt does not address them.

## 9. Recommended Fix Plan

### 9.1 Completed In This Follow-Up Docs Patch

- Added an explicit note to `docs/02-protocol-specs/qssm-zk-theorem-spec.md` that the three-term bound describes the exact-zero theorem skeleton only, and documented the charged parameterized / real-world / concrete theorem routes together with the duplicate MS2/public-AfterRom caveat.
- Added explicit notes to `docs/02-protocol-specs/security/ASSUMPTION_ANALYSIS.md` and `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md` covering the concrete-128 route, the `1 / 2^98` component epsilon, the `5 / 2^98` closed form, the explicit external obligations, the non-axiom status, the toy `3%r / 64%r` caveat, and the weighted/non-uniform sampler limitation.
- Added explicit notes to `docs/02-protocol-specs/security/ZK_VS_SOUNDNESS_SPLIT.md` and `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md` that EasyCrypt currently proves the ZK/composition theorem surfaces only, and that soundness claims and soundness numbers remain security-analysis scope on the current tree.
- Added explicit Rust-authoritative refinement-boundary notes to `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`, `docs/02-protocol-specs/qssm-le-engine-a.md`, `docs/02-protocol-specs/qssm-ms-engine-b.md`, `docs/02-protocol-specs/security/ROM_ANALYSIS.md`, `docs/02-protocol-specs/blake3-lattice-gadget-spec.md`, and `docs/02-protocol-specs/engine-b-engine-a-binding-seam.md` for byte layouts, domains, announcement-only digest discipline, seam digests, and version-lock equality.

### 9.2 Remaining Docs-Only Fixes

- Clearly mark `docs/02-protocol-specs/implementation-plans/blake3-lattice-gadget-rust-plan.md` as implementation-plan material outside formal conformance scope.

### 9.3 EasyCrypt Model Changes

- If stronger protocol-spec conformance is desired, add a refinement layer from the concrete Rust transcript / digest / layout surfaces to the existing EasyCrypt abstract observables instead of weakening the abstraction boundary informally.
- Consider adding a small formal surface for the announcement-only query-digest contract so that the MS simulator assumptions are linked more directly to the concrete digest interfaces.
- Consider adding a bridge/model layer for public-binding and seam-layout conformance if Engine B -> Engine A serialization is intended to be within formal-scope claims.
- Keep any future weighted/non-uniform sampler modeling below `RealWorldBudgetObligations.ec` and `qssm_main_theorem_realworld_budget`, rather than replacing those theorem surfaces.

### 9.4 Theorem Changes

- Do not hide or rename away the duplicated MS2 charge unless a stronger lower theorem actually proves a tighter public-AfterRom to canonical-AfterRom relationship.
- Do not restate the concrete-128 route as unconditional unless the four explicit reduction obligations are actually discharged in-scope.
- If soundness is meant to become part of the EasyCrypt theorem surface, add a separate soundness theorem family rather than blending soundness prose into the current ZK theorem claims.

### 9.5 Implementation / Performance Claims Outside EasyCrypt Scope

- Track proof size, performance, mobile/sub-ms verification, API behavior, and deployment architecture in implementation assurance docs and tests, not in EasyCrypt conformance claims.
- Track witness isolation, CT behavior, zeroization, and misuse resistance as implementation and audit claims tied to Rust tests, type boundaries, and crate visibility.

## 10. Recommended Next Phase

Recommended next phase: decide whether the remaining medium-severity conformance gaps require EasyCrypt refinement work or should remain explicit documentation boundaries.

Order:

1. Decide whether a separate EasyCrypt soundness theorem family is desired, or whether soundness should remain an explicit external/security-analysis boundary.
2. Decide whether byte-level execution, digest, and layout surfaces need a dedicated implementation-to-model refinement layer, or whether Rust-authoritative documentation plus tests is sufficient.
3. Decide whether announcement-only query-digest discipline and seam/version-lock surfaces need dedicated EasyCrypt refinement/model layers, or whether they should remain explicit Rust conformance boundaries.
4. Only after those refinement-scope decisions are made, decide whether any stronger lower public-AfterRom landing theorem is worth pursuing.

## 11. Audit Constraints

This audit phase and the blocker-resolution follow-up remained intentionally read-only with respect to the EasyCrypt proof sources.

- No `.ec` files were edited.
- `check_easycrypt.sh` was not edited.
- No `.eco` files were generated.
- No EasyCrypt checker rerun was required for this report.