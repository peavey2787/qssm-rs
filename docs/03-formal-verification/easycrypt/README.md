# EasyCrypt Skeleton (Phase 1)

This directory contains the **initial EasyCrypt scaffold only**.

> **Warning:** This is **not** a completed machine-checked security proof. All high-level statements are either abstract operators or explicit axioms until lemmas are proved and axioms removed.

## Scope

- Phase 1 target: checker-ready syntax, explicit interfaces, and admitted placeholders.
- No completed end-to-end proof chain yet.
- No Rust logic changes are implied by these files.

## Installing EasyCrypt (for this repo)

EasyCrypt was **not** detected in `PATH` on the CI-style Windows host used for development here. Install it locally before running the check script.

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

The script type-checks theories in dependency order:

1. `QssmDomains.ec`
2. `QssmTypes.ec`
3. `QssmSchnorrSingleBit.ec`
4. `QssmFS.ec`
5. `QssmMSBitnessSingle.ec`
6. `QssmMSBitnessVector.ec`
7. `QssmMSTranscriptObservable.ec`
8. `QssmMS.ec`
9. `QssmLE.ec`
10. `QssmSim.ec`
11. `QssmGames.ec`
12. `QssmTheorem.ec`

If your EasyCrypt build exposes the binary as `ec` instead of `easycrypt`, the script falls back automatically when `easycrypt` is missing.

**Single-file check (equivalent idea):**

```bash
cd docs/03-formal-verification/easycrypt
easycrypt QssmTheorem.ec
```

(Adjust the command name if your install uses `ec`.)

## Files

- `QssmDomains.ec` — domain and label constants
- `QssmTypes.ec` — abstract types for digests, transcripts, games
- `QssmSchnorrSingleBit.ec` — single-branch Schnorr observable distributions; `MS_3a_single_branch_schnorr_reparam` proved (axiom `duni_scalar_shift_reparam` only)
- `QssmFS.ec` — abstract FS / ROM hooks
- `QssmMSBitnessSingle.ec` / `QssmMSBitnessVector.ec` — per-bit and 64-bit OR bitness layer
- `QssmMSTranscriptObservable.ec` — canonical v2 transcript observable record
- `QssmMS.ec` — MS v2 observable surface + MS-3 placeholders
- `QssmLE.ec` — LE observable surface + Set B placeholders
- `QssmSim.ec` — composed simulator interface
- `QssmGames.ec` — G0/G1/G2 skeleton
- `QssmTheorem.ec` — additive bound skeleton
- `check_easycrypt.sh` — batch validation (dependency order)
- `MS_3a_proof_plan.md` — first lemma proof plan

## Admitted / axiomatized placeholders (Phase 1)

- **ROM / programmability (A2 surface):** `QssmFS.ec` — `A2_ms_rom_programmability_nonneg`, `A2_programmable_oracle_exists`
- **MS:** `QssmMS.ec` — `A1_ms_hash_binding_nonneg`, `MS_3a_exact_bitness_simulation` (proves **`ms3a_bitness_real_sim_equiv`** via `MS_3a_exact_bitness_simulation_from_layers`; bitness **source** laws are **`dmap`** pushforwards of abstract `ms3a_{real,sim}_source_payload` distributions through `ms3a_make_*_source`; **`dmap` membership** in preimage lemmas uses **`supp_dmap`** from `Distr` (proved helper `distr_mem_eq`); skeleton discharged through `ms3a_source_observable_equiv_from_layer`; **MS-3a:** folded source equality **`ms3a_source_eq_from_bitness_layer`** is proved from **`ms3a_payload_schedule_equivalence`** (payload `dmap` equality under the `ms3a_ax_*` premises; no axiom states real/sim **folded** source laws are equal without those premises). **Constructor-style obligations** (`ms3a_real_source_constructor_wf`, `ms3a_sim_source_constructor_wf`, `ms3a_source_constructors_same_public_fields`, `ms3a_source_constructors_programmed_bitness`, `ms3a_source_constructors_bitness_exact`) are **proved lemmas** from the payload support axioms **`ms3a_payload_{real,sim}_support_programmed`**, **`ms3a_payload_pair_public_fields_on_support`**, and **`MS_3a_bitness_layer_exact_simulation`** (`QssmMSBitnessVector.ec`). Remaining MS-3a payload axioms are the four above plus packaging; generic digest constructor still uses **`ms3a_pack_observable_with_digest_field_correct`**; `MS_3b_true_clause_characterization`, `MS_3c_exact_comparison_simulation`
- **LE:** `QssmLE.ec` — `set_b_parameter_well_formed` (placeholder until `Int` order is wired), `A4_le_hvzk_bound_nonneg`
- **Simulator:** `QssmSim.ec` — `simulate_qssm_transcript_public_only`
- **Games:** `QssmGames.ec` — `G0_to_G1_skeleton`, `G1_to_G2_skeleton`, `Adv_def`
- **Theorem:** `QssmTheorem.ec` — `A1_ms_hash_binding`, `A2_ms_rom_programmability`, `A4_le_hvzk`, `use_MS_3a` (lemma, **`ms3a_bitness_real_sim_equiv`**) / `use_MS_3b` / `use_MS_3c` (axioms), `qssm_main_theorem_skeleton`

- **Single-branch MS-3a (`QssmSchnorrSingleBit.ec`):** `MS_3a_single_branch_schnorr_reparam` is fully proved (no `admit`). The only Schnorr-layer root assumption is the axiom **`duni_scalar_shift_reparam`** (uniform shift on `duni_scalar` for the joint pair `(alpha*H, alpha+t)` vs `((z-t)*H, z)`), a standard finite-field-style fact, not a new hardness assumption. Structural helpers: `ms3a_schnorr_reparam_obs_eq`, `qssm_pair_eq`, `qssm_dunit_eq`.
- **Checker note:** there is **no** `admit` remaining in any `*.ec` file under this directory; open items are **named axioms** only (see each theory).

## Next proof target

1. **MS-3a (residual)** — shrink the four payload axioms in `QssmMS.ec` (support programmed, pair public fields on support, schedule equivalence); see `MS_3a_proof_plan.md`.
2. **MS-3b** — `MS_3b_true_clause_characterization` is the natural next milestone after that surface is acceptable.

Then: MS-3c, `G0→G1`, `G1→G2`, final additive theorem.

## Syntax / checker notes

- Theories follow the standard EasyCrypt layout: **one theory per `.ec` file**, named after the file (no nested `theory ... end` wrapper).
- Trivial placeholder axioms often use the proposition `true` (not `True`). MS-3a’s global lemma instead targets **`ms3a_bitness_real_sim_equiv`** (distribution equality on `ms_transcript_observable`).
- `DOMAIN_MS` is fixed to `"QSSM-MS-v1.0"` to match `truth-engine/qssm-utils/src/hashing.rs` (not invented).
