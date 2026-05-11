# Spec/Formal Conformance Audit

Navigation: [EasyCrypt README](../README.md)

## 1. Executive Summary

This audit compares the protocol-spec tree under `docs/02-protocol-specs/` against the EasyCrypt model under `docs/03-formal-verification/easycrypt/`.

Audit totals:

- Protocol-spec files audited: 14
- Key EasyCrypt files / theorem surfaces mapped: 43
- Blockers: 2
- High-severity items: 5
- Medium-severity items: 3
- Low-severity items: 2

Main conclusions:

- The exact-zero theorem story is aligned. The protocol theorem spec in `qssm-zk-theorem-spec.md` matches `theorem/MainTheorem.ec` for the exact-zero `G0 -> G1 -> G2` route and the exact MS-3a / MS-3b / MS-3c simulation lemmas.
- The EasyCrypt tree is broader than the current theorem spec. The formal model now has additional theorem surfaces for the demo semantic route, the LE-only parameterized route, the full canonical parameterized route, the abstract real-world upper-bound route, and the concrete 128 / all-reductions route.
- The main blocker is theorem-surface drift on the MS side. The formal model explicitly distinguishes public AfterRom from canonical AfterRom and therefore carries an explicit duplicated MS2 charge on the parameterized, real-world, and concrete reduction-facing routes. The current protocol theorem spec does not state that caveat.
- The second blocker is the concrete-128 story. `RealWorldBudgetInstantiation.ec` proves a concrete external-bound route only under explicit external component or reduction obligations. The current protocol-spec tree does not state those premises or the fact that the live `3%r / 64%r` lower masses do not instantiate the `1 / 2^98` component budget.
- The Level 1 execution specs intentionally go beyond what EasyCrypt checks. Exact domain strings, seed-derivation order, byte ordering, serialization/layout locks, and seam hash preimage order are Rust-authoritative and are currently abstracted, not re-proved, in EasyCrypt.
- Several security and implementation assurance notes under `docs/02-protocol-specs/security/` are not EasyCrypt theorem claims at all. Soundness, witness isolation, CT/zeroization, proof size, and performance are either outside the current EasyCrypt scope or live only in Rust / auxiliary analysis.

Recommended next phase:

- Fix blockers in docs first.
- Only consider EasyCrypt theorem or model changes after the spec documents accurately describe the current charged/public-endpoint and concrete-obligation caveats.

## 2. Protocol Spec Inventory

### 2.1 Normative Core Specs

| File | Type | Component Covered | Relevant Objects / State | Algorithms / Procedures | Security Claims | Parameters / Constants | Failure Conditions | Transcript / Public Input | Adversary / Assumption Notes | Audit Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md` | Normative Level 1 execution spec | Composed MS v2 + LE execution and simulator plumbing | `SimulatedMsV2Transcript`, `SimulatedLeTranscript`, `SimulatedQssmTranscript`, simulator seeds | Exact seed derivation, exact FS/oracle construction, exact simulator ordering, exact transcript structs | No theorem claim; intended as byte-accurate formalization input | `DOMAIN_ZK_SIM`, `DOMAIN_LE_FS`, `DOMAIN_LE_CHALLENGE_POLY`, `DOMAIN_MS`, seam domains, simulator labels | Digest mismatch, algebra mismatch, failed recomputation | Exact MS / LE transcript field names and ordering | ROM dependence is implicit; Rust authoritative | Central conformance input for execution details; EasyCrypt only abstracts most of it |
| `docs/02-protocol-specs/qssm-zk-theorem-spec.md` | Normative Level 2 theorem spec | ZK theorem route | `G0`, `G1`, `G2`, `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, `epsilon_le` | Game hop decomposition | Additive ZK bound only | A1 / A2 / A4 mapping | None; theorem layer only | Refers to Level 1 for transcript details | Programmable ROM for ZK | Aligns with exact-zero route, but omits newer charged parameterized / real-world caveats |
| `docs/02-protocol-specs/qssm-le-engine-a.md` | Normative Level 3 engine spec | LE / Engine A | `PublicInstance`, `Witness`, `LatticeProof`, CRS seed, binding context | `prove_arithmetic`, `verify_lattice`, FS challenge bytes, challenge polynomial, rejection loop | LE hiding / HVZK discussion; parameter conditions; FS floor claims | `N`, `Q`, `BETA`, `ETA`, `GAMMA`, `C_POLY_SIZE`, `C_POLY_SPAN`, `MAX_PROVER_ATTEMPTS`, `PUBLIC_DIGEST_COEFFS` | Public validation failure, norm failure, FS mismatch, equation failure | Visible LE transcript fields and public binding inputs | Assumes Set B parameter soundness and FS conditions | Concrete execution details are more specific than EasyCrypt |
| `docs/02-protocol-specs/qssm-ms-engine-b.md` | Normative Level 3 engine spec | MS / Engine B | `PredicateOnlyStatementV2`, `PredicateOnlyProofV2`, `BitnessProofV2`, `ComparisonProofV2`, `ProgrammedOracleQueryV2` | Commit, prove, verify, simulate, programmed verification, query digests | Announcement-only digest discipline; exact-simulation framing | `V2_BIT_COUNT = 64`, `DOMAIN_MS`, FS labels | Verification failure, simulator invalidity | Statement/proof/programmed-query fields | ROM/programmed-query assumptions | Formal model matches theorem structure but not concrete query function implementation |
| `docs/02-protocol-specs/blake3-lattice-gadget-spec.md` | Normative Level 3 bridge spec | MS-to-LE bridge and seam | `MsPredicateOnlyV2BridgeOp`, `EngineABindingInput`, `EngineABindingOutput`, transcript layout sync points | Verify-then-bind bridge, seam commit / open / binding digests | Cross-engine binding / replay prevention | Seam domains, `BRIDGE_Q`, `MAX_LIMB_EXCLUSIVE`, transcript layout version sync | Hard reject on verification, digest, or version mismatch | Public seam inputs and outputs | Adversary includes replay, substitution, malleability | Most concrete seam / layout details are Rust-only, not EasyCrypt-checked |
| `docs/02-protocol-specs/spec_layer_contract.md` | Normative meta-spec | Spec layering and authority boundaries | Level 1 / 2 / 3 ownership | Layer contract only | No direct crypto claim | None | None | None | Rust authoritative; layer discipline explicit | Strongly aligned with current EasyCrypt architecture split |

### 2.2 Security / Supporting Docs Under the Audited Tree

| File | Type | Component Covered | Relevant Objects / State | Algorithms / Procedures | Security Claims | Parameters / Constants | Failure Conditions | Transcript / Public Input | Adversary / Assumption Notes | Audit Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| `docs/02-protocol-specs/security/ASSUMPTION_ANALYSIS.md` | Security analysis | ZK theorem assumptions | A1 / A2 / A4, LE Set B numeric checks | Assumption mapping and dominance discussion | Additive theorem bound, 132.2-bit ZK floor, 121-bit soundness floor target references | LE floors and validation tolerances | None | Refers to theorem object, not transcript layout | ROM framing plus LE parameter conditions | Some numeric floor claims are external to EasyCrypt |
| `docs/02-protocol-specs/security/ROM_ANALYSIS.md` | Security analysis | ROM dependence | MS query digests, LE programmed digest, seed derivation helpers | Distinguishes essential vs non-essential ROM use | ROM is essential for simulation | FS/query surfaces explicitly named | Simulator chain fails without ROM | Refers to announcement-only and LE programmed surfaces | ROM model explicit | Partially aligned; concrete hash plumbing is outside EasyCrypt |
| `docs/02-protocol-specs/security/ZK_VS_SOUNDNESS_SPLIT.md` | Security analysis | ZK vs soundness split | ZK theorem, soundness theorem, soundness assumptions, implementation layer | Separates ZK, soundness, and implementation claims | States both ZK and soundness theorems, plus concrete soundness numbers | 121-bit, 132.2-bit, 196.2-bit figures | None | N/A | ROM for ZK; CR/SIS/FS for soundness | High-risk file: EasyCrypt tree covers ZK route, not the stated soundness theorem surface |
| `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md` | Security analysis | Security dependency map | ZK, soundness, implementation layers | Dependency decomposition only | Security floor summary and one-sentence security model | 121-bit and 132.2-bit floors | None | N/A | Assumption-to-mechanism mapping | Not an EasyCrypt theorem surface; mixes theorem and non-theorem claims |
| `docs/02-protocol-specs/security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md` | Security analysis | MS / LE independence | Shared seed derivation, domain tags, transcript fields | Independence audit over simulator channels | Additive composition justified under ROM | Explicit domain and label strings | None | Uses concrete transcript and seed construction | ROM-dependent independence argument | Not re-proved in EasyCrypt from concrete strings; only abstractly assumed via separated surfaces |
| `docs/02-protocol-specs/security/WITNESS_ISOLATION_THREAT_MODEL.md` | Security analysis / implementation assurance | Witness isolation | Witness structs, zeroization, non-serialization, debug redaction, simulator signatures | Threat-model audit only | Claims witness does not leak by current API / type discipline | None | Future refactor risks, accidental leakage paths | N/A | Implementation-level assumptions | Outside current EasyCrypt scope |
| `docs/02-protocol-specs/idk/engine-b-engine-a-binding-seam.md` | Supporting normative seam note | Commit-then-open seam | Seam inputs/outputs, rollup context, entropy link | Verify-then-bind sequence and hard rejects | Cross-engine replay and substitution resistance | Seam domains | Hard reject cases listed | Public seam fields and privacy boundary | Adversary model explicit | Overlaps the gadget bridge spec; still mostly outside EasyCrypt |
| `docs/02-protocol-specs/implementation-plans/blake3-lattice-gadget-rust-plan.md` | Implementation plan | Rust gadget implementation plan | Witness APIs, bit decomposition, adders, limb extraction | Planned implementation phases | Normative for implementation plan, not theorem surface | Concrete plan-level constraints | Plan-level forbidden constructions | Public witness API references | No explicit EasyCrypt claim | Out of scope for spec/model conformance except as a non-normative support document |

## 3. Formal Model Inventory

This section inventories the key EasyCrypt owners and theorem surfaces that matter for protocol-spec conformance.

### 3.1 Budget Owners and Top-Level Route Owners

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `docs/03-formal-verification/easycrypt/primitives/BudgetParameters.ec` | Exact-zero and demo semantic owner layer | `epsilon_ms_hash_binding`, `epsilon_ms_rom_programmability`, `epsilon_le`, `epsilon_ms_hash_binding_semantic`, `epsilon_ms_rom_programmability_semantic`, `epsilon_le_semantic` | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/primitives/ParameterizedBudgetParameters.ec` | Parameterized owner layer | `epsilon_ms_hash_binding_parameterized`, `epsilon_ms_rom_programmability_parameterized`, `epsilon_le_rej_parameterized`, `epsilon_le_fs_parameterized`, `epsilon_le_parameterized` | Parameterized |
| `docs/03-formal-verification/easycrypt/primitives/RealWorldBudgetParameters.ec` | Abstract real-world budget record | `realworld_budget`, `epsilon_ms_hash_binding_realworld`, `epsilon_ms_rom_programmability_realworld`, `epsilon_le_rej_realworld`, `epsilon_le_fs_realworld`, `epsilon_le_realworld`, `epsilon_top_realworld` | Abstract real-world |
| `docs/03-formal-verification/easycrypt/primitives/RealWorldBudgetObligations.ec` | Explicit budget-premise layer | `le_realworld_obligations`, `ms_realworld_obligations`, `qssm_realworld_obligations` | Abstract real-world |
| `docs/03-formal-verification/easycrypt/RealWorldBudgetInstantiation.ec` | Concrete instantiation layer | `lambda_concrete_128`, `realworld_budget_concrete_128`, `qssm_main_theorem_realworld_concrete_128`, `qssm_main_theorem_realworld_concrete_128_with_all_reductions` | Concrete 128 / all-reductions |

### 3.2 LE Rejection, FS, and HVZK Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `docs/03-formal-verification/easycrypt/le/LERejectionSamplerCore.ec` | Lower rejection sampler carrier | rejection sampler core objects | LE lower semantics |
| `docs/03-formal-verification/easycrypt/le/LERejectionSamplerMass.ec` | Demo semantic rejection mass closure | rejection shadow failure probability equalities | Demo semantic |
| `docs/03-formal-verification/easycrypt/le/LERejection.ec` | Theorem-facing rejection bridge | `le_rejection_distribution_defined`, `le_rejection_acceptance_probability_bounded`, `le_rejection_output_shape_preserved` | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/le/LERejectionParameterized.ec` | Parameterized rejection theorem wrapper | `A_LE_rejection_sampler_semantic_sdist_parameterized_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/le/LERejectionConcreteReduction.ec` | External reduction obligation owner | `le_rejection_concrete_reduction_obligation` | Concrete 128 / reductions |
| `docs/03-formal-verification/easycrypt/le/LEFsProgrammingSurface.ec` | Lower FS semantic shadow surface | semantic branch/state/image operators | LE lower semantics |
| `docs/03-formal-verification/easycrypt/le/LEFsProgrammingFailureProbability.ec` | Demo semantic FS bad-branch owner | `le_fs_shadow_local_bad_branch_mass` | Demo semantic |
| `docs/03-formal-verification/easycrypt/le/LEFsProgramming.ec` | Theorem-facing FS bridge | `le_fs_query_surface_defined`, `le_fs_programming_hiding_bound` | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/le/LEFsProgrammingParameterized.ec` | Parameterized FS theorem wrapper | parameterized FS programming bounds | Parameterized |
| `docs/03-formal-verification/easycrypt/le/LEFsConcreteReduction.ec` | External reduction obligation owner | `le_fs_concrete_reduction_obligation` | Concrete 128 / reductions |
| `docs/03-formal-verification/easycrypt/le/LEStatisticalDistance.ec` | LE additive composition | LE rejection + FS additive closure | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/le/LEStatisticalDistanceParameterized.ec` | LE parameterized additive composition | `A_LE_semantic_view_advantage_bound_from_parameterized_budget` | Parameterized |
| `docs/03-formal-verification/easycrypt/le/LEStatisticalDistanceRealWorld.ec` | LE real-world additive wrapper | real-world LE transition bound | Abstract real-world |
| `docs/03-formal-verification/easycrypt/le/LEHVZK.ec` | LE HVZK wrapper | theorem-facing HVZK consequences over LE distance layer | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/le/LEModel.ec` | Stable theorem-facing LE facade | LE-facing imports and packaged surface | Stable facade |

### 3.3 MS Hash Binding, ROM Programmability, and AfterRom Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `docs/03-formal-verification/easycrypt/ms/SourceModel.ec` | Stable public-spine / source-model facade | `ms_v2_transcript_observable` and public transcript projections | All routes |
| `docs/03-formal-verification/easycrypt/ms/source/SourceHashBindingSemanticBridge.ec` | MS1 semantic execution-owned bridge | `A_MS1_hash_binding_execution_owned_semantic_bound` | Demo semantic |
| `docs/03-formal-verification/easycrypt/ms/source/SourceHashBindingSemanticBridgeParameterized.ec` | MS1 parameterized bridge | `A_MS1_hash_binding_execution_owned_parameterized_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticBridge.ec` | MS2 semantic execution-owned bridge | `ms_rom_public_observable_divergence_mass_le_execution_owned_semantic_failure`, `A_MS2_rom_programming_execution_owned_semantic_bound` | Demo semantic |
| `docs/03-formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticBridgeParameterized.ec` | MS2 parameterized bridge | `A_MS2_rom_programming_execution_owned_parameterized_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/ms/comparison/ComparisonPayloadSemanticLiveParameterizedMass.ec` | Live MS2 parameterized lower mass owner | `A_MS2_rom_programming_execution_owned_live_parameterized_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/ms/MSProbabilitySurface.ec` | Canonical exact-zero and semantic MS probability surface | `A_MS1_hash_binding_bad_event_bound`, `A_MS2_rom_programming_transition_bound`, `A_MS2_rom_programming_semantic_transition_bound`, exact AfterRom stage law | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/ms/MSProbabilitySurfaceParameterized.ec` | Parameterized MS probability surface | `A_MS2_rom_programming_parameterized_public_endpoint_transition_bound`, `A_MS_public_after_rom_to_canonical_after_rom_parameterized_transition_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/ms/MSProbabilitySurfaceRealWorld.ec` | Real-world MS probability wrapper | real-world public-endpoint and landing bounds | Abstract real-world |
| `docs/03-formal-verification/easycrypt/ms/TrueClause.ec` | Stable MS-3b facade | `MS_3b_true_clause_characterization` | Exact-zero / all routes |
| `docs/03-formal-verification/easycrypt/ms/Comparison.ec` | Stable MS-3c facade | `MS_3c_exact_comparison_simulation` | Exact-zero / all routes |
| `docs/03-formal-verification/easycrypt/ms/MS.ec` | Stable theorem-facing MS wrapper | game-hop predicates / packaged MS surface | Stable facade |

### 3.4 Game and Top Theorem Surfaces

| File / Surface | Role | Key Operators / Theorems | Route / Scope |
|---|---|---|---|
| `docs/03-formal-verification/easycrypt/games/GameAdvantage.ec` | Core game probability layer | `game_pr`, `Adv`, exact-zero game arithmetic | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/games/GameAdvantageParameterized.ec` | Parameterized game arithmetic | parameterized game wrappers | Parameterized |
| `docs/03-formal-verification/easycrypt/games/GameMSHopComposition.ec` | Exact-zero MS composition | `A_G0_to_G1_ms_transition_bound`, semantic sibling route | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/games/GameMSHopCompositionParameterized.ec` | Parameterized MS composition | `A_G0_to_G1_ms_parameterized_transition_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/games/GameMSHopCompositionRealWorld.ec` | Real-world MS composition | `A_G0_to_G1_ms_realworld_transition_bound` | Abstract real-world |
| `docs/03-formal-verification/easycrypt/games/GameLEBridge.ec` | Exact-zero / semantic LE bridge | `A_G1_to_G2_le_transition_bound`, semantic bridge variants | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/games/GameLEBridgeParameterized.ec` | Parameterized LE bridge | `A_G1_to_G2_le_semantic_parameterized_budget_transition_bound` | Parameterized |
| `docs/03-formal-verification/easycrypt/games/GameLEBridgeRealWorld.ec` | Real-world LE bridge | real-world LE transition bound | Abstract real-world |
| `docs/03-formal-verification/easycrypt/theorem/MainTheorem.ec` | Canonical top theorem surface | `qssm_main_theorem_skeleton`, `qssm_main_theorem`, `qssm_main_theorem_semantic_budget` | Exact-zero + demo semantic |
| `docs/03-formal-verification/easycrypt/theorem/MainTheoremParameterized.ec` | Parameterized top theorem surface | `qssm_main_theorem_le_parameterized_budget`, `qssm_main_theorem_parameterized_budget` | Parameterized |
| `docs/03-formal-verification/easycrypt/theorem/MainTheoremRealWorld.ec` | Abstract real-world top theorem surface | `qssm_main_theorem_realworld_budget` | Abstract real-world |

### 3.5 Stable Facades and Route Summary

Stable facades that downstream proof users should treat as entrypoints:

- `docs/03-formal-verification/easycrypt/ms/TrueClause.ec`
- `docs/03-formal-verification/easycrypt/ms/Comparison.ec`
- `docs/03-formal-verification/easycrypt/ms/SourceModel.ec`
- `docs/03-formal-verification/easycrypt/ms/MS.ec`
- `docs/03-formal-verification/easycrypt/le/LEModel.ec`
- `docs/03-formal-verification/easycrypt/games/Games.ec`
- `docs/03-formal-verification/easycrypt/theorem/MainTheorem.ec`
- `docs/03-formal-verification/easycrypt/theorem/MainTheoremParameterized.ec`
- `docs/03-formal-verification/easycrypt/theorem/MainTheoremRealWorld.ec`
- `docs/03-formal-verification/easycrypt/RealWorldBudgetInstantiation.ec`

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
| `spec_layer_contract.md` whole file | Level 1 execution, Level 2 theorem, Level 3 interface split; Rust authoritative | `formal/ARCHITECTURE.md`, `theorem/MainTheorem.ec`, `ms/MS.ec`, `le/LEModel.ec` | Exact match | The formal tree follows the same layer separation and explicitly treats Rust as authoritative for concrete execution details |
| `qssm-zk-theorem-spec.md` `G0 -> G1 -> G2` | Exact game chain | `games/GameMSHopComposition.ec`, `games/GameLEBridge.ec`, `theorem/MainTheorem.ec` | Exact match | The canonical exact-zero theorem route matches the stated game chain |
| `qssm-zk-theorem-spec.md` additive bound | `Adv_QSSM(D) <= epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le` | `theorem/MainTheorem.ec : qssm_main_theorem_skeleton`, `qssm_main_theorem` | Exact match | Correct for the exact-zero route |
| `qssm-zk-theorem-spec.md` A1 / A2 / A4 map | A1 to MS1, A2 to MS2, A4 to LE | `primitives/BudgetParameters.ec`, `theorem/MainTheorem.ec` | Exact match | Correct for the exact-zero theorem surface |
| `qssm-zk-theorem-spec.md` MS-3a exactness | Exact bitness simulation | `ms/source/SourceTheorem.ec : MS_3a_exact_bitness_simulation` via `use_MS_3a` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` MS-3b exactness | True-clause characterization | `ms/TrueClause.ec : MS_3b_true_clause_characterization` via `use_MS_3b` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` MS-3c exactness | Exact comparison simulation | `ms/Comparison.ec : MS_3c_exact_comparison_simulation` via `use_MS_3c` | Exact match | Zero-residual exact lemma is present |
| `qssm-zk-theorem-spec.md` whole document | Current theorem story is a single three-term additive route | `theorem/MainTheoremParameterized.ec`, `theorem/MainTheoremRealWorld.ec`, `RealWorldBudgetInstantiation.ec` | Mismatch | EasyCrypt now has additional live routes with explicit duplicated MS2 and explicit real-world / concrete premises |
| `qssm-zk-concrete-execution-spec.md` transcript structs | Exact MS and LE observable field sets and order | `ms/SourceModel.ec`, `le/LESurface.ec`, `games/GameTypes.ec` | Modeled abstraction | Observable shapes align, but EasyCrypt works at abstract record level rather than byte serialization |
| `qssm-zk-concrete-execution-spec.md` FS domain strings and labels | Exact `DOMAIN_*`, `DST_*`, seam strings, label bytes | No direct EasyCrypt owner; abstract domain separation only | Not modeled | String literals and concrete domain/tag equality are Rust-level conformance points |
| `qssm-zk-concrete-execution-spec.md` simulator seed derivation order | Exact `ms_seed` / `le_seed` derivation schedule | No direct EasyCrypt theorem; abstract `seed` carrier only | Not modeled | Formal model does not verify seed schedule or label ordering |
| `qssm-zk-concrete-execution-spec.md` LE programmed query digest order | Exact digest preimage order | `le/LEFsProgrammingSurface.ec` and game-layer LE observables | Modeled abstraction | Existence of programmed query surface is modeled; concrete hash-input order is not |
| `qssm-ms-engine-b.md` statement / proof public structure | Public MS objects and transcript fields | `ms/SourceModel.ec`, `ms/MS.ec` | Partially modeled | Formal model captures public observable content, not the full concrete Rust structs |
| `qssm-ms-engine-b.md` announcement-only query discipline | Query digests depend only on announcements | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `ms/comparison/ComparisonPayloadSemanticBridge.ec` | Partially modeled | Exact-simulation theorems rely on announcement-only behavior, but EasyCrypt does not verify the Rust query functions directly |
| `qssm-ms-engine-b.md` programmed verification path | Simulator + programmed query validation | `ms/Comparison.ec`, `games/GameMSHopComposition.ec` | Modeled abstraction | The formal model captures the programmed challenge story abstractly |
| `qssm-le-engine-a.md` visible proof transcript | `C`, `t`, `z`, `challenge_seed` are public | `le/LESurface.ec`, `games/GameLEBridge.ec` | Exact match | The public LE observable surface matches the proof-facing transcript abstraction |
| `qssm-le-engine-a.md` concrete Set B constants | `N`, `Q`, `BETA`, `ETA`, `GAMMA`, `C_POLY_SIZE`, `C_POLY_SPAN`, `MAX_PROVER_ATTEMPTS` | No concrete embedding in EasyCrypt theorem files | Not modeled | EasyCrypt proves over symbolic owners and predicates, not the Rust constants |
| `qssm-le-engine-a.md` rejection sampler semantics | reject if `||z||_inf > GAMMA`; bounded attempt count | `le/LERejection.ec`, `le/LEStatisticalDistance.ec` | Modeled abstraction | Rejection is modeled as a theorem-facing sampler / distance surface, not with concrete norm arithmetic or attempt bounds |
| `qssm-le-engine-a.md` LE FS pipeline | Exact 11-item FS preimage and challenge polynomial expansion | `le/LEFsProgrammingSurface.ec`, `le/LEFsProgramming.ec` | Modeled abstraction | EasyCrypt models the FS-programming consequence, not the BLAKE3/XOF algorithm or byte ordering |
| `qssm-le-engine-a.md` HVZK / A4 | LE HVZK replacement loss | `le/LEHVZK.ec`, `games/GameLEBridge.ec` | Partially modeled | The theorem surface exists, but the cryptographic hardness behind LE HVZK is not internally discharged in EasyCrypt |
| `blake3-lattice-gadget-spec.md` verify-then-bind rule | MS verification must succeed before seam binding | No dedicated EasyCrypt seam theorem; composition assumes verified public input | Partially modeled | This is enforced by Rust bridge code, not re-proved in EasyCrypt |
| `blake3-lattice-gadget-spec.md` seam commitment/open/binding digests | Exact domains and preimage order | No direct EasyCrypt owner | Not modeled | Concrete seam hashing remains outside EasyCrypt |
| `blake3-lattice-gadget-spec.md` transcript-map layout sync | `TRANSCRIPT_MAP_LAYOUT_VERSION` and `LE_FS_PUBLIC_BINDING_LAYOUT_VERSION` must match | No direct EasyCrypt owner | Not modeled | Rust compile-time / test-time conformance point |
| `security/ASSUMPTION_ANALYSIS.md` additive ZK theorem summary | A1/A2/A4 additive theorem summary | `theorem/MainTheorem.ec`, `primitives/BudgetParameters.ec` | Exact match | Accurate for the exact-zero theorem surface |
| `security/ASSUMPTION_ANALYSIS.md` 132.2-bit floor and concrete LE validation references | Numeric floor and external validation story | `formal/SECURITY_INSTANTIATION.md`, no direct theorem in EasyCrypt | Formal model weaker than spec | EasyCrypt does not derive those concrete numeric floors internally |
| `security/ROM_ANALYSIS.md` ROM-critical MS and LE query surfaces | Announcement-only MS and programmed LE surfaces are ROM-critical | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `le/LEFsProgramming.ec` | Modeled abstraction | Correct at the abstraction level, not at the concrete hash-function level |
| `security/ZK_VS_SOUNDNESS_SPLIT.md` ZK theorem | ZK bound in ROM | `theorem/MainTheorem.ec` and companion routes | Exact match | ZK half is aligned |
| `security/ZK_VS_SOUNDNESS_SPLIT.md` soundness theorem and concrete soundness numbers | `Adv^snd_QSSM(A) <= epsilon_ms_soundness + epsilon_le_soundness`, 121 / 132.2 / 196.2 figures | No matching EasyCrypt theorem surface in `docs/03-formal-verification/easycrypt/` | Not modeled | Soundness lives outside the current EasyCrypt theorem tree |
| `security/SECURITY_MODEL_MAP.md` one-sentence security model and floors | Combined ZK / soundness / implementation summary with concrete floors | `formal/FORMAL_THEOREM_MAP.md`, `formal/SECURITY_INSTANTIATION.md` | Partially modeled | ZK route is modeled; soundness floors and implementation guarantees are not EasyCrypt theorems |
| `security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md` additive composition justified by concrete domain-separated seed schedule | Independence from concrete labels/domains | `games/GameMSHopComposition.ec`, `games/GameLEBridge.ec` | Modeled abstraction | Formal model assumes separated MS/LE public surfaces and additive composition; it does not prove independence from exact concrete string schedules |
| `security/WITNESS_ISOLATION_THREAT_MODEL.md` witness isolation by API/type discipline | non-serialization, redacted debug, no witness in simulator APIs | No matching theorem surface | Not modeled | Pure implementation assurance, outside EasyCrypt |
| `idk/engine-b-engine-a-binding-seam.md` seam hard rejects and privacy boundary | verify-then-bind, seam digest mismatch reject, privacy of entropy link | No dedicated EasyCrypt theorem surface | Not modeled | Rust/bridge contract, not EasyCrypt theorem content |
| `implementation-plans/blake3-lattice-gadget-rust-plan.md` planned witness API / limb extraction rules | implementation plan constraints | No matching theorem surface | Not modeled | Out of scope for this audit except as a supporting/non-normative document |

## 5. Discrepancy Table

| Severity | Discrepancy | Spec Reference | Formal Reference | Notes | Recommended Fix Bucket |
|---|---|---|---|---|---|
| Blocker | The protocol theorem spec presents a single three-term theorem story, but the live parameterized / real-world / concrete theorem routes require an explicit public-AfterRom to canonical-AfterRom landing and therefore a duplicated MS2 charge | `qssm-zk-theorem-spec.md`, `security/ASSUMPTION_ANALYSIS.md` | `formal/SEMANTIC_GAP_ANALYSIS.md`, `theorem/MainTheoremParameterized.ec`, `theorem/MainTheoremRealWorld.ec`, `primitives/RealWorldBudgetParameters.ec` | Exact-zero route is aligned; newer theorem routes are not described honestly in the spec tree | Spec clarification |
| Blocker | The concrete 128 / all-reductions EasyCrypt route is conditional on explicit external obligations, and the current live `3%r / 64%r` lower masses do not instantiate the `1 / 2^98` component budget | No in-scope spec file states the explicit component/reduction premises or the live-mass caveat | `RealWorldBudgetInstantiation.ec`, `formal/SECURITY_INSTANTIATION.md` | The formal theorem is honest and conditional; the spec tree currently lacks those premises | Spec clarification |
| High | `security/ZK_VS_SOUNDNESS_SPLIT.md` states a separate soundness theorem and concrete soundness numbers, but there is no matching EasyCrypt soundness theorem surface in the audited formal tree | `security/ZK_VS_SOUNDNESS_SPLIT.md`, `security/SECURITY_MODEL_MAP.md` | No soundness theorem files under `docs/03-formal-verification/easycrypt/`; only ZK/composition surfaces are present | This is a real coverage gap between in-scope security docs and EasyCrypt | Docs-only + possible future theorem work |
| High | Exact FS domain strings, seed schedules, seam digest preimage order, and byte-level execution details are Rust-authoritative but not EasyCrypt-checked | `qssm-zk-concrete-execution-spec.md`, `qssm-le-engine-a.md`, `blake3-lattice-gadget-spec.md` | EasyCrypt abstracts these surfaces; no concrete string or byte-order theorem | Intentional abstraction boundary, but currently under-documented as such in the conformance story | Docs-only |
| High | Concrete LE Set B constants, challenge-polynomial expansion details, attempt bounds, and numeric security floors are not embedded in the EasyCrypt theorem surfaces | `qssm-le-engine-a.md`, `security/ASSUMPTION_ANALYSIS.md`, `security/SECURITY_MODEL_MAP.md` | `le/*.ec` surfaces are symbolic / predicate-based; `formal/SECURITY_INSTANTIATION.md` is explanatory, not a concrete-constant proof | The formal model proves abstract consequences, not concrete Rust constant conformance | Docs-only + possible model refinement |
| High | The announcement-only MS query-digest discipline is relied on by the theorem story but not formally linked to the concrete Rust query functions | `qssm-ms-engine-b.md`, `qssm-zk-concrete-execution-spec.md`, `security/ROM_ANALYSIS.md` | `ms/Comparison.ec`, `ms/MSProbabilitySurface.ec`, `ms/comparison/ComparisonPayloadSemanticBridge.ec` | EasyCrypt assumes/programs the public digest surface; it does not verify the Rust hash-input functions | EasyCrypt model change |
| High | Bridge/seam layout and public-binding serialization/version-lock claims are not formalized in EasyCrypt | `blake3-lattice-gadget-spec.md`, `idk/engine-b-engine-a-binding-seam.md` | No direct theorem surface; Rust sync checks only | Important conformance point for Engine B -> Engine A handoff | Docs-only + possible model refinement |
| Medium | The abstract real-world theorem route is an upper-bound theorem over explicit obligations; it does not model weighted or non-uniform samplers internally | No in-scope spec file currently explains this limitation | `primitives/RealWorldBudgetObligations.ec`, `theorem/MainTheoremRealWorld.ec`, `formal/SEMANTIC_GAP_ANALYSIS.md` | Honest in formal docs, absent in protocol-spec tree | Spec clarification |
| Medium | Cross-component independence, witness isolation, CT/zeroization, and API misuse claims live in security/implementation documents, not in EasyCrypt theorem surfaces | `security/CROSS_COMPONENT_INDEPENDENCE_AUDIT.md`, `security/WITNESS_ISOLATION_THREAT_MODEL.md`, `security/ZK_VS_SOUNDNESS_SPLIT.md` | No matching theorem surfaces | These should not be read as “proved by EasyCrypt” | Docs-only |
| Medium | Proof size, performance, mobile / sub-ms verification, product API behavior, and architecture claims are outside EasyCrypt scope | No in-scope protocol theorem file states them as EasyCrypt claims; some appear elsewhere in repo | No matching theorem surfaces | Not a contradiction, but should be called out explicitly in the audit | Docs-only |
| Low | The audited tree mixes normative specs, security analyses, seam notes, and an implementation plan under one directory | `docs/02-protocol-specs/` overall | N/A | This is a documentation categorization issue, not a theorem mismatch | Docs-only |
| Low | Several apparent “mismatches” are intentional layer separation rather than proof bugs | `spec_layer_contract.md` | `formal/ARCHITECTURE.md`, `formal/FORMAL_THEOREM_MAP.md` | The spec/formal split is largely honest; the missing piece is clearer documentation of what EasyCrypt intentionally abstracts away | Docs-only |

## 6. Blockers / High-Severity Items

### Blockers

1. `qssm-zk-theorem-spec.md` does not describe the live public-AfterRom versus canonical-AfterRom distinction or the explicit duplicated MS2 charge that now appears in `qssm_main_theorem_parameterized_budget`, `qssm_main_theorem_realworld_budget`, and the concrete reduction-facing route. The exact-zero route still aligns; the broader theorem story does not.
2. The protocol-spec tree does not describe the premises of the concrete-128 EasyCrypt route. `RealWorldBudgetInstantiation.ec` proves `5 / 2^98` only under explicit component or reduction obligations, and the formal docs explicitly say the current live `3%r / 64%r` lower actuals do not satisfy those `1 / 2^98` component bounds.

### High-Severity Items

1. `security/ZK_VS_SOUNDNESS_SPLIT.md` states a separate soundness theorem and concrete soundness numbers, but the EasyCrypt tree under the audited scope does not carry a matching soundness theorem family.
2. The exact execution specs state concrete domain strings, seed schedules, seam digest orders, and FS pipelines that EasyCrypt does not verify. This is an intentional abstraction boundary, but it is currently easy to over-read as theorem coverage.
3. LE Set B constants, challenge-expansion details, attempt bounds, and concrete numeric floors remain Rust / analysis facts, not EasyCrypt theorems.
4. The theorem route relies on announcement-only MS query discipline, but EasyCrypt does not prove the concrete Rust query functions satisfy that discipline.
5. The bridge/seam serialization and version-lock contract is enforced in Rust, not EasyCrypt.

## 7. Medium / Low-Severity Items

### Medium-Severity Items

1. The abstract real-world theorem route is explicit and honest, but the protocol-spec tree does not currently say that it is only an upper-bound route over externally supplied obligations and that weighted/non-uniform sampler semantics remain outside the current model.
2. Cross-component independence, witness isolation, CT/zeroization, and API misuse claims are important, but they are implementation/security-audit claims rather than EasyCrypt theorem claims.
3. Proof size, performance, mobile / sub-ms verification, statelessness, no-prover-network, and product API behavior are not current EasyCrypt model claims. Some of these are not asserted anywhere in the in-scope protocol specs; others live elsewhere in the repo.

### Low-Severity Items

1. `docs/02-protocol-specs/` currently mixes normative specs with analyses and plans, which makes it easier to confuse “authoritative protocol claim” with “supporting discussion”.
2. The spec/formal layer split is mostly healthy. Several gaps found in this audit are documentation gaps about intentional abstraction boundaries, not evidence of a broken theorem.

## 8. Claims Not Covered By EasyCrypt

The following claims or claim families are not currently covered by the EasyCrypt model under `docs/03-formal-verification/easycrypt/`:

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

### 9.1 Docs-Only Fixes

- Add an explicit note to `docs/02-protocol-specs/qssm-zk-theorem-spec.md` that the file describes the exact-zero theorem skeleton only, and does not by itself describe the live parameterized, abstract real-world, or concrete reduction-facing theorem surfaces.
- Add an explicit note to `docs/02-protocol-specs/security/ZK_VS_SOUNDNESS_SPLIT.md` and `docs/02-protocol-specs/security/SECURITY_MODEL_MAP.md` that the soundness theorem and concrete soundness numbers are not EasyCrypt theorem claims in the current audited tree.
- Add an explicit note to `docs/02-protocol-specs/qssm-zk-concrete-execution-spec.md`, `docs/02-protocol-specs/qssm-le-engine-a.md`, and `docs/02-protocol-specs/blake3-lattice-gadget-spec.md` that their exact string / byte-order / layout claims are Rust-authoritative conformance points and are currently abstracted, not re-proved, in EasyCrypt.
- Clearly mark `docs/02-protocol-specs/implementation-plans/blake3-lattice-gadget-rust-plan.md` as implementation-plan material outside formal conformance scope.

### 9.2 Spec Clarifications

- Add a protocol-spec note covering the public AfterRom versus canonical AfterRom distinction and the resulting duplicated MS2 charge on the parameterized, real-world, and concrete reduction-facing theorem routes.
- Add a protocol-spec note covering the concrete-128 route: `1 / 2^98` component epsilon, `5 / 2^98` top epsilon, and the fact that the theorem remains conditional on explicit external component or reduction obligations.
- Add a protocol-spec note that the abstract real-world upper-bound route does not internally model weighted or non-uniform samplers.
- Distinguish clearly between normative protocol specs, security analysis notes, and implementation assurance notes inside `docs/02-protocol-specs/`.

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

Recommended next phase: fix blockers first, starting with protocol/spec documentation updates.

Order:

1. Update the theorem/spec documents so they describe the live parameterized / real-world / concrete theorem surfaces honestly, including the public-AfterRom caveat and duplicated MS2 charge.
2. Update the concrete-128 documentation so it states the explicit external obligations and the current live-mass caveat.
3. Decide whether soundness should remain outside EasyCrypt or whether a separate EasyCrypt soundness surface is now required.
4. Only after the docs are honest, decide whether concrete execution conformance layers or stronger lower MS landing theorems are worth modeling.

## 11. Audit Constraints

This audit phase was intentionally read-only with respect to the EasyCrypt proof sources.

- No `.ec` files were edited.
- `check_easycrypt.sh` was not edited.
- No `.eco` files were generated.
- No EasyCrypt checker rerun was required for this report.