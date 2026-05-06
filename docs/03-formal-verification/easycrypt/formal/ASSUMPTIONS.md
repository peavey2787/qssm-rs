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
| `epsilon_le_rej_semantic` | `0%r` | Owned semantic rejection budget on the rejection shadow lane |
| `epsilon_le_fs` | `0%r` | LE FS component gap on the current shadow lane |
| `epsilon_le` | `epsilon_le_rej + epsilon_le_fs` | Umbrella LE budget consumed by theorem-facing arithmetic |
| `epsilon_le_fs_semantic` | `mu1 d_le_fs_semantic_branch_choice true = bad_slot_count%r / total_slot_count%r = 1%r / 2%r` | Primitive-owned semantic FS bad-branch weight on the branch-sensitive shadow lane |
| `epsilon_le_semantic` | `epsilon_le_rej_semantic + epsilon_le_fs_semantic` | Preferred semantic umbrella LE budget consumed by `qssm_main_theorem_semantic_budget` |

These are exact values in the current model, not placeholders. The caution is that the exact-zero theorem path is still structurally simplified enough that its active MS and LE component values are all zero, while the semantic-budget theorem path now uses a semantic rejection component `epsilon_le_rej_semantic = 0%r` together with a primitive-owned count-parameterized FS bad-branch weight with `total_slot_count = 4` and `bad_slot_count = 2`, so the present semantic umbrella still evaluates to `1%r / 2%r`.

Those slot counts should currently be read as concrete demo/proof parameters for the semantic FS lane. They are not yet sourced from a protocol-parameter bundle, and any move to a dedicated `primitives/ProtocolParameters.ec` leaf is deferred until there is a real shared protocol parameter surface to centralize.

## What the Zero Budgets Depend On

The exact-zero path depends on the present semantics of the lower surfaces.

- The MS1 and MS2 paths close because the current lower stage laws collapse by exact equality on the active probability surface.
- The theorem-facing LE rejection endpoint routes through a semantic shadow lane whose failure quantity is currently zero on the active carrier.
- The theorem-facing LE FS endpoint also routes through a semantic shadow lane whose failure quantity is currently zero on the active carrier.
- The umbrella LE theorem path is therefore the additive composition of two exact-zero component endpoints.

The semantic-budget path depends on parallel semantic rejection and FS lanes.

- `LERejectionSampler.ec` proves the local shadow rejection failure quantity `le_rejection_shadow_failure_probability` and the bridge `le_rejection_shadow_failure_probability <= epsilon_le_rej_semantic`; on the current carrier that local failure quantity still closes to `0%r`.
- `LEFsProgrammingSurface.ec` proves the local bad-branch mass and semantic failure probability in closed form on that shadow lane.
- `BudgetParameters.ec` owns the semantic branch sampler via the concrete counts `total_slot_count = 4` and `bad_slot_count = 2`, the support `le_fs_semantic_branch_slot_support = range 0 total_slot_count`, the predicate `le_fs_semantic_bad_branch_slot slot = slot < bad_slot_count`, and the sampler `d_le_fs_semantic_branch_slot_choice = duniform le_fs_semantic_branch_slot_support`, then defines `d_le_fs_semantic_branch_choice = dmap d_le_fs_semantic_branch_slot_choice le_fs_semantic_bad_branch_slot` and the owned bad-branch mass `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true`.
- `epsilon_le_semantic` is the preferred nonzero umbrella LE budget consumed by the top-level semantic theorem.

## ROM, Rejection, and FS Semantics

### ROM / MS

The MS theorem path is currently modeled with a concrete exact-zero budget surface. The relevant question is no longer whether a repo-local ROM axiom remains in-tree; it does not. The real open issue is whether a future refinement should replace the exact-zero stage equalities with a nontrivial ROM-programming model and a derived nonzero budget.

### LE Rejection

The theorem-facing rejection endpoint is already routed through a lower semantic shadow lane. On the current carrier, that lane still collapses to zero failure probability, so the exact-zero rejection component budget stays at `0%r`. In parallel, the semantic theorem path now exposes `epsilon_le_rej_semantic` as the owned rejection budget for that same shadow lane; its current closed form is still `0%r`, but the semantic rejection owner and theorem-facing endpoint now exist separately from the exact-zero route.

### LE FS Programming

The exact-zero theorem-facing FS endpoint is already routed through a lower semantic shadow lane and still collapses to `0%r` on the active carrier. In parallel, the proof tree now exports a separate semantic-budget theorem path that uses the primitive-owned branch-weight budget `epsilon_le_fs_semantic = mu1 d_le_fs_semantic_branch_choice true` together with the semantic rejection budget `epsilon_le_rej_semantic`, and packages them through the umbrella budget `epsilon_le_semantic = epsilon_le_rej_semantic + epsilon_le_fs_semantic`. That semantic path is the intended citation target when a nonzero LE theorem is needed today.

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