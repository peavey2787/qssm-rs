# Assumptions and Model Boundary

Navigation: [EasyCrypt README](../README.md)

## Current In-Tree Assumption State

At the current May 2026 checkpoint, the EasyCrypt `*.ec` files under this directory contain no named `axiom` declarations.

That does not mean the formalization is final. It means the current proof tree closes on explicit checked budget models rather than on open in-tree axioms.

The public theorem API now has two checked modes: `qssm_main_theorem` is the exact-zero abstraction theorem, while `qssm_main_theorem_semantic_budget` is the preferred semantic-budget theorem for nonzero LE FS modeling. `qssm_main_theorem_nonzero_budget` is a façade alias to that same semantic theorem, and the local-mass / owned / umbrella variants are retained for proof history and bisectability.

## Budget Models Today

The budget surface currently lives in `primitives/BudgetParameters.ec` and is concrete:

| Budget | Current value | Meaning on the active model |
|---|---:|---|
| `epsilon_ms_hash_binding` | `0%r` | MS1 hash-binding gap on the current stage law |
| `epsilon_ms_rom_programmability` | `0%r` | MS2 ROM-programming gap on the current stage law |
| `epsilon_le_rej` | `0%r` | LE rejection component gap on the current shadow lane |
| `epsilon_le_rej_semantic` | `le_rejection_semantic_ticket_failure_probability = mu1 d_le_rejection_semantic_ticket_repair_choice true = (soft_repair_slot_count + hard_repair_slot_count + invalid_slot_count)%r / ticket_total_slot_count%r = 3%r / 6%r = 1%r / 2%r` | Primitive-owned multi-category semantic ticket-failure budget matched by the execution-owned semantic rejection ticket sampler |
| `epsilon_le_fs` | `0%r` | LE FS component gap on the current shadow lane |
| `epsilon_le` | `epsilon_le_rej + epsilon_le_fs` | Umbrella LE budget consumed by theorem-facing arithmetic |
| `epsilon_le_fs_semantic` | `mu1 d_le_fs_semantic_branch_choice true = bad_slot_count%r / total_slot_count%r = 3%r / 6%r = 1%r / 2%r` | Primitive-owned structured semantic FS bad-branch weight on the branch-sensitive shadow lane |
| `epsilon_le_semantic` | `epsilon_le_rej_semantic + epsilon_le_fs_semantic` | Preferred semantic umbrella LE budget consumed by `qssm_main_theorem_semantic_budget` |

These are exact values in the current model, not placeholders. The caution is that the exact-zero theorem path is still structurally simplified enough that its active MS and LE component values are all zero, while the semantic-budget theorem path now uses an execution-owned lower semantic rejection lane with a primitive multi-category ticket law: `soft_repair`, `hard_repair`, and `invalid` are failure categories with one slot each, `accept` has three slots, and the resulting primitive ticket-failure law is `epsilon_le_rej_semantic = 3%r / 6%r = 1%r / 2%r`. Together with the primitive-owned structured FS category law, where `query_collision`, `programming_collision`, and `transcript_mismatch` are failure categories with one slot each and `clean` has three slots, giving `epsilon_le_fs_semantic = 3%r / 6%r = 1%r / 2%r`, the present semantic umbrella evaluates to `1%r`. That umbrella is intentionally loose today because both LE semantic subterms are still concrete demo/surrogate laws rather than final cryptographic tightness claims. `BudgetParameters.ec` still owns those concrete branch weights, `LERealExecution.ec` now proves that the concrete execution-owned rejection ticket failure probability matches that primitive ticket-failure law, `LERejectionSampler.ec` proves that the semantic rejection failure probability equals that concrete ticket-failure quantity, and `LEFsProgrammingSurface.ec` now interprets the primitive FS categories on category-coupled shadow states whose lower meanings are checker-validated independently of the still-provisional slot masses.

Those slot counts should currently be read as concrete demo/proof parameters for the semantic FS lane. They are not yet sourced from a protocol-parameter bundle, and any move to a dedicated `primitives/ProtocolParameters.ec` leaf is deferred until there is a real shared protocol parameter surface to centralize.

## What the Zero Budgets Depend On

The exact-zero path depends on the present semantics of the lower surfaces.

- The MS1 and MS2 paths close because the current lower stage laws collapse by exact equality on the active probability surface.
- The theorem-facing LE rejection endpoint routes through a semantic shadow lane whose failure quantity is currently zero on the active carrier.
- The theorem-facing LE FS endpoint also routes through a semantic shadow lane whose failure quantity is currently zero on the active carrier.
- The umbrella LE theorem path is therefore the additive composition of two exact-zero component endpoints.

The semantic-budget path depends on an execution-owned semantic rejection lane feeding a semantic FS lane.

- `LERejectionSampler.ec` proves both the exact-zero shadow rejection failure quantity `le_rejection_shadow_failure_probability` and the parallel semantic experiment quantity `le_rejection_shadow_semantic_failure_probability`; the exact-zero quantity still closes to `0%r`, while the semantic experiment closes to `epsilon_le_rej_semantic = 1%r / 2%r` through the primitive multi-category ticket law.
- `LEFsProgrammingSurface.ec` proves the local bad-branch mass and semantic failure probability in closed form on that shadow lane.
- `BudgetParameters.ec` owns the semantic FS branch/programming law via the primitive category support `clean`, `query_collision`, `programming_collision`, `transcript_mismatch`, failure predicate “non-clean”, provisional slot masses `3,1,1,1`, the derived compatibility sampler `d_le_fs_semantic_branch_choice`, and the owned bad-branch mass `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true = 3%r / 6%r = 1%r / 2%r`. `LEFsProgrammingSurface.ec` now interprets those primitive categories on a category-coupled shadow state: `clean` is the no-failure/programmed-view branch, `query_collision` is bad-branch query-row alignment, `programming_collision` is bad-branch programmed-response digest/log alignment, and `transcript_mismatch` is bad-branch visible-shell agreement with a cleared semantic bad flag.
- `epsilon_le_semantic` is the preferred nonzero umbrella LE budget consumed by the top-level semantic theorem.

## ROM, Rejection, and FS Semantics

### ROM / MS

The MS theorem path is currently modeled with a concrete exact-zero budget surface. The relevant question is no longer whether a repo-local ROM axiom remains in-tree; it does not. The real open issue is whether a future refinement should replace the exact-zero stage equalities with a nontrivial ROM-programming model and a derived nonzero budget.

### LE Rejection

The theorem-facing rejection endpoint is already routed through a lower shadow lane. On the active exact-zero carrier, that route still collapses to zero failure probability, so the exact-zero rejection component budget stays at `0%r`. In parallel, the semantic theorem path now exposes `epsilon_le_rej_semantic` as the owned budget for an execution-owned semantic rejection lane. `LERealExecution.ec` owns the semantic rejection branch support and branch-dependent material, `LERejectionSampler.ec` exports `d_le_semantic_post_rejection_view`, and the semantic local-mass theorem path now uses `le_rejection_shadow_semantic_failure_probability` beside the unchanged exact-zero route; its current closed form is `1%r / 2%r` via the primitive category support `soft_repair`, `hard_repair`, `invalid`, `accept` with failure predicate “non-accept” and provisional masses `1,1,1,3`.

### LE FS Programming

The exact-zero theorem-facing FS endpoint is already routed through a lower semantic shadow lane and still collapses to `0%r` on the active carrier. In parallel, the proof tree now exports a separate semantic-budget theorem path whose FS lane starts from `d_le_pre_fs_semantic_programming_view = LERejectionSampler.d_le_semantic_post_rejection_view`, then packages the primitive-owned structured FS category law through a category-coupled shadow state and the derived bad-branch budget `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true`. `LEFsProgrammingSurface.ec` proves the local equality `le_fs_shadow_local_bad_branch_mass = epsilon_le_fs_semantic`, together with concrete clean/query-collision/programming-collision/transcript-mismatch interpretation lemmas, while `LEFsProgramming.ec` and the higher theorem-facing wrappers use the corresponding `<=` bridge together with the semantic rejection budget through the umbrella budget `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic`. That semantic path is the intended citation target when a nonzero LE theorem is needed today.

## What Is Still Assumed Outside the Formal Tree

Even with `0` named in-tree axioms, the overall result still relies on external boundaries:

- trust in the EasyCrypt checker and standard library foundations
- trust in the human mapping from the Rust implementation and protocol specs into the EasyCrypt model
- trust that the current exact-zero abstraction is an intentional staging model rather than the final desired semantic boundary

## How Future Assumptions Should Reappear

If nontrivial budgets or external assumptions are reintroduced later, they should be added in the narrowest honest place.

- Keep theorem-facing names stable where possible.
- Keep `qssm_main_theorem` and `qssm_main_theorem_semantic_budget` as the primary public theorem names unless there is a compelling proof-surface reason to change them.
- Prefer lower semantic surfaces and proved bridge theorems over top-level wrappers.
- Centralize budget ownership in `primitives/BudgetParameters.ec` or another explicit owner rather than scattering assumptions through theorem-facing files.
- If a protocol-parameter owner is introduced later, prefer a leaf `primitives/ProtocolParameters.ec` imported by `primitives/BudgetParameters.ec`; do not move the current semantic FS demo counts until there is a real shared parameter source.
- Prefer derived formulas or lower failure bounds over opaque budget parameters.

## Related Documents

- [PROOF_STATUS.md](PROOF_STATUS.md) for the current theorem-facing state
- [ARCHITECTURE.md](ARCHITECTURE.md) for where each proof surface lives
- [PROOF_HISTORY.md](PROOF_HISTORY.md) for the detailed closure log that led to the current zero-budget model