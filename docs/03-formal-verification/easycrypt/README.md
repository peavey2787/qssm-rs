# EasyCrypt Skeleton (Phase 1)

This directory contains the **initial EasyCrypt scaffold only**.

> **Warning:** This is **not** a completed machine-checked security proof. All high-level statements are either abstract operators or explicit axioms until lemmas are proved and axioms removed.

## Scope

- Phase 1 target: checker-ready syntax, explicit interfaces, and admitted placeholders.
- No completed end-to-end proof chain yet.
- No Rust logic changes are implied by these files.

## Installing EasyCrypt (for this repo)

EasyCrypt may not be in `PATH` on all hosts. Install it locally before running the check script.

**Recommended (official):** use [OPAM](https://opam.ocaml.org/) as documented upstream:

1. Install and initialize OPAM (see [OPAM install guide](https://opam.ocaml.org/doc/Install.html)).
2. Create/activate a dedicated switch (optional but recommended).
3. Pin and install EasyCrypt:

   ```bash
   opam pin -yn add easycrypt https://github.com/EasyCrypt/easycrypt.git
   opam install --deps-only easycrypt
   opam install alt-ergo.2.6.0
   opam install easycrypt
   ```

4. Configure Why3 for SMT solvers:

   ```bash
   easycrypt why3config
   ```

Full detail and alternatives (Nix, from source): [EasyCrypt `INSTALL.md`](https://github.com/EasyCrypt/easycrypt/blob/main/INSTALL.md) and [Setting up EasyCrypt](https://easycrypt.gitlab.io/easycrypt-web/docs/guides/setting-up-easycrypt/).

**Repo allowlist:** see `../easycrypt-import-allowlist.md` for which Rust/spec artifacts are in scope for formalization.

## How to run the checker

From a Unix-like shell (Git Bash, WSL, Linux, macOS), in **this directory**:

```bash
chmod +x check_easycrypt.sh   # once, if needed
./check_easycrypt.sh
```

Or with an explicit binary path:

```bash
EASYCRYPT=/path/to/easycrypt ./check_easycrypt.sh
```

The script type-checks theories in dependency order. Each file is checked with `easycrypt compile -R . <path>` so that theories in subfolders are resolved by **basename** (theory name equals the filename without `.ec`). Imports use those basenames (for example `require import QssmTypes FS.`).

**Order (see `check_easycrypt.sh`):**

1. `primitives/Domains.ec`
2. `primitives/QssmTypes.ec` (named `QssmTypes` to avoid clashing with the EasyCrypt prelude theory `Types`)
3. `primitives/Algebra.ec`
4. `primitives/FS.ec`
5. `ms/SchnorrBranch.ec`
6. `ms/BitnessOne.ec`
7. `ms/BitnessVector.ec`
8. `ms/TranscriptObservable.ec`
9. `ms/TrueClause.ec`
10. `ms/Comparison.ec`
11. `ms/SourceModel.ec` (MS-3a observable frame: abstract transcript ops, pack, digest helpers)
12. `ms/source/SourceTypes.ec`
13. `ms/source/SourceConstructors.ec`
14. `ms/source/SourceDistributions.ec`
15. `ms/source/SourceObligations.ec`
16. `ms/source/SourceTheorem.ec`
17. `ms/MS.ec`
18. `le/LEModel.ec`
19. `sim/Simulator.ec`
20. `games/Games.ec`
21. `theorem/MainTheorem.ec`

If your EasyCrypt build exposes the binary as `ec` instead of `easycrypt`, the script falls back automatically when `easycrypt` is missing.

**Single-file check (top of the stack):**

```bash
cd docs/03-formal-verification/easycrypt
easycrypt compile -R . theorem/MainTheorem.ec
```

## Layout (directories)

```
docs/03-formal-verification/easycrypt/
├── README.md
├── check_easycrypt.sh
├── primitives/
│   ├── Domains.ec
│   ├── QssmTypes.ec
│   ├── Algebra.ec
│   └── FS.ec
├── ms/
│   ├── SchnorrBranch.ec
│   ├── BitnessOne.ec
│   ├── BitnessVector.ec
│   ├── TranscriptObservable.ec
│   ├── TrueClause.ec
│   ├── Comparison.ec
│   ├── SourceModel.ec
│   ├── source/
│   │   ├── SourceTypes.ec
│   │   ├── SourceConstructors.ec
│   │   ├── SourceDistributions.ec
│   │   ├── SourceObligations.ec
│   │   └── SourceTheorem.ec
│   └── MS.ec
├── le/
│   └── LEModel.ec
├── sim/
│   └── Simulator.ec
├── games/
│   └── Games.ec
├── theorem/
│   └── MainTheorem.ec
└── plans/
    ├── MS_3a_proof_plan.md
    ├── MS_3b_proof_plan.md
    ├── MS_3c_proof_plan.md
    └── G0_G1_G2_game_plan.md
```

## File map (legacy Qssm* names → current paths)

| Former root file | Current location |
|------------------|-------------------|
| `QssmDomains.ec` | `primitives/Domains.ec` |
| `QssmTypes.ec` | `primitives/QssmTypes.ec` (theory `QssmTypes`; see note above) |
| `QssmFS.ec` | `primitives/FS.ec` |
| `QssmSchnorrSingleBit.ec` | `primitives/Algebra.ec` + `ms/SchnorrBranch.ec` |
| `QssmMSBitnessSingle.ec` | `ms/BitnessOne.ec` |
| `QssmMSBitnessVector.ec` | `ms/BitnessVector.ec` |
| `QssmMSTranscriptObservable.ec` | `ms/TranscriptObservable.ec` |
| `QssmMSTrueClause.ec` | `ms/TrueClause.ec` |
| `QssmMSComparison.ec` | `ms/Comparison.ec` |
| `QssmMS.ec` (bulk) | `ms/SourceModel.ec` + `ms/source/*.ec` (split MS-3a material) |
| `QssmMS.ec` (façade: hash binding + MS-3c wrapper) | `ms/MS.ec` |
| `QssmLE.ec` | `le/LEModel.ec` |
| `QssmSim.ec` | `sim/Simulator.ec` |
| `QssmGames.ec` | `games/Games.ec` |
| `QssmTheorem.ec` | `theorem/MainTheorem.ec` |

## Admitted / axiomatized placeholders (Phase 1)

- **ROM / programmability (A2 surface):** `primitives/FS.ec` — `A2_ms_rom_programmability_nonneg`, `A2_programmable_oracle_exists`
- **MS:** `ms/SourceModel.ec` — abstract observable frame (pack / digest / alignment); **`ms/source/`** — structured source types, constructors, `d_ms3a_*` laws, payload axioms, and **`MS_3a_exact_bitness_simulation`**; `ms/MS.ec` — `epsilon_ms_hash_binding`, **`ms1_hash_binding_step`**, **`ms2_rom_programming_step`**, **`ms3a_bitness_exact_step`**, **`ms3b_true_clause_exact_step`** (MS3b: same MS-3b forall bundle as the old game axiom + frozen `GV_ms`, `AfterBitness`→`AfterComparison`; **`Algebra`**, **`List`**, **`TrueClause`** in scope), `A1_ms_hash_binding_nonneg`, **`MS_3c_exact_comparison_simulation`** (wrapper over `ms/Comparison.ec`). ROM budget **`epsilon_ms_rom_programmability`** lives in **`primitives/FS.ec`** with **`A2_ms_rom_programmability_nonneg`** and **`A2_programmable_oracle_exists`**. **MS-3b** in **`ms/TrueClause.ec`**. **MS-3c** in **`ms/Comparison.ec`** — comparison payloads (`d_ms3c_{real,sim}_comparison_payload`), `dmap` schedules, **proved** **`A_ms3c_payload_schedule_equiv`** from a narrower coupling/scheduling layer (`ms3c_real_sim_payload_coupled`, explicit coupling projections `d_ms3c_coupling_{real,sim}_projection`, `ms3c_ax_payload_support_coupling`, and coupling/marginal axioms) plus component payload obligations (see `plans/MS_3c_proof_plan.md`), proved schedule bridge, surface clause laws; **ordered announcement digest list** is **`ms3c_clause_ann_digests_from_surface`** (true then false branch digests via **`ms_single_bit_branch_digest`**), with **`A_ms3c_digest_announcement_only`** stating programmed **`mscc_query_digest`** against that projection only, and true-clause bridge **`A_ms3c_true_clause_from_ms3b_and_schnorr`** now proved from explicit MS-3b hook (`ms3c_true_clause_uses_ms3b_blinder_point`) plus Schnorr reparam readiness (`ms3c_true_clause_reparam_ready` / `MS_3a_single_branch_schnorr_reparam`).
- **LE:** `le/LEModel.ec` — non-vacuous `set_b_parameter_well_formed` predicate, `A4_le_hvzk_bound_nonneg`, LE hop carrier `le_game_hop_adv`, transcript predicate `le_real_sim_transcript_equiv`, and narrow LE transition placeholder `A_LE_HVZK_transition_bound`
- **Simulator:** `sim/Simulator.ec` — `simulate_qssm_transcript_public_only`
- **Types / games:** `primitives/QssmTypes.ec` defines `ms_game_stage`, `ms_game_view_record` (QSSM public input, seed, MS public input, MS transcript observable, stage tag, optional LE observable placeholder), and `game_view` as either `GV_ms` of that record or `GV_g2_full_sim` of a small `qssm_g2_shell_record` (pub + seed). **`games/Games.ec`** — `mk_ms_game_view` builds all MS-stage views; `G0_real_qssm` / `G1_ms_sim_le_real` / every `G_MS_*` are concrete `GV_ms` constructors differing only in `msgv_stage`; `G2_full_sim` is the G2 shell variant. **MS1** uses axiom **`A_MS1_hash_binding_replacement_bound`** (`ms1_hash_binding_step` ⇒ `Adv <= epsilon_ms_hash_binding`); lemma **`A_MS1_hash_binding_transition`** packages `G_MS_real`→`G_MS_after_binding`. **MS2** uses axiom **`A_MS2_rom_programming_replacement_bound`** (`ms2_rom_programming_step` ⇒ `Adv <= epsilon_ms_rom_programmability`); lemma **`A_MS2_rom_programming_transition`** packages `G_MS_after_binding`→`G_MS_after_rom`. **MS3a** uses axiom **`A_MS3a_bitness_exact_step_bound`** (`ms3a_bitness_exact_step` ⇒ `Adv <= 0%r`); lemma **`A_MS3a_bitness_transition`** packages `G_MS_after_rom`→`G_MS_after_bitness`. **MS3b** uses axiom **`A_MS3b_true_clause_exact_step_bound`** (`ms3b_true_clause_exact_step` ⇒ `Adv <= 0%r`); lemma **`A_MS3b_true_clause_transition`** packages `G_MS_after_bitness`→`G_MS_after_comparison`. **`A_MS3c_comparison_transition`** remains the prior staged axiom shape for this pass. Advantages `Adv_G0_G1_MS` / `Adv_G1_G2_LE` / `Adv_G0_G2_QSSM` thread a shared `xms` on the G0/G1 side; proved `A_adv_gamehop_triangle`, `A_adv_ms_hop_telescope`, composed MS hop `A_G0_to_G1_ms_transition_bound`, and LE hop `A_G1_to_G2_le_transition_bound`
- **Theorem:** `theorem/MainTheorem.ec` — non-negativity placeholders `A1_ms_hash_binding`, `A2_ms_rom_programmability`, `A4_le_hvzk`, bridge lemmas `use_MS_3a` / `use_MS_3b` / `use_MS_3c`, and proved additive game-hop lemma `qssm_main_theorem_skeleton` over `Adv_G0_G2_QSSM`

- **Single-branch MS-3a (`ms/SchnorrBranch.ec` + `primitives/Algebra.ec`):** `MS_3a_single_branch_schnorr_reparam` is fully proved (no `admit`). Root Schnorr-layer assumption is **`duni_scalar_shift_reparam`** on `duni_scalar`.

- **Checker note:** there is **no** `admit` remaining in any `*.ec` file under this directory; open items are **named axioms** only (see each theory).

## Next proof target

1. **MS-3a (residual)** — shrink the four payload axioms in `ms/source/SourceObligations.ec`; see `plans/MS_3a_proof_plan.md`.
2. **MS-3b** — replace hook preds and narrow axioms in `ms/TrueClause.ec`; see `plans/MS_3b_proof_plan.md`.

Then: shrink MS-3c axioms in **`ms/Comparison.ec`** (`plans/MS_3c_proof_plan.md`). On the game layer, discharge **`A_MS1_hash_binding_replacement_bound`** / **`A_MS2_rom_programming_replacement_bound`** from concrete games tied to **`epsilon_ms_hash_binding`** / **`epsilon_ms_rom_programmability`** (FS ROM surface); discharge **`A_MS3a_bitness_exact_step_bound`** / **`A_MS3b_true_clause_exact_step_bound`** from exact simulation / true-clause games given the step predicates; **`A_MS3c_comparison_transition`** proof debt unchanged (`plans/G0_G1_G2_game_plan.md`).

## Syntax / checker notes

- Theories are loaded by **basename** under this tree with `easycrypt compile -R . <file>`.
- Trivial placeholder axioms often use the proposition `true` (not `True`). MS-3a’s global lemma targets **`ms3a_bitness_real_sim_equiv`** (distribution equality on `ms_transcript_observable`).
- `DOMAIN_MS` is fixed to match `truth-engine/qssm-utils/src/hashing.rs` (not invented).
