# Simulation-Based Zero-Knowledge for Canonical QSSM

## Introduction

This paper draft studies the canonical composed QSSM construction obtained from:

- MS v2 Option B for the mirror-shift predicate layer
- LE Set B for the lattice-based arithmetic layer

The goal is a standard game-based zero-knowledge theorem for the full verifier view. The intended theorem compares the real joint transcript game `G0` against a public-input-only global simulator game `G2` through a single intermediate hybrid `G1`.

The MS simulation layer is discharged by exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c`, which contribute zero residual advantage by construction. The theorem depends only on hash binding (`A1`), ROM programmability (`A2`), and the LE HVZK bound (`A4`).

## Construction

### MS v2 Option B

The MS component commits independently to each value bit using Pedersen-style commitments and proves the predicate `value > target` through:

- bitness subproofs for each committed bit
- a comparison proof over candidate positions determined by zero bits of the public target
- a Fiat-Shamir transcript built from announcement-only query digests

The verifier-visible MS transcript contains only the statement digest, the bitness transcripts, the comparison proof, and derived transcript digests. The hidden value and blinders are not part of the observable interface.

### LE Set B

The LE component is the committed Set B lattice layer. Its simulator uses a parameterized rejection-sampling and Fiat-Shamir argument under the currently encoded Set B constraints. The LE theorem contribution is represented by `epsilon_le`.

### Global Composition

The composed simulator is:

```text
simulate_qssm_transcript(public_input, simulator_seed)
```

It derives domain-separated MS and LE seeds from one ambient simulator seed and invokes:

- `simulate_ms_v2_transcript(public_input.ms, ms_seed)`
- `simulate_le_transcript(public_input.le, le_seed)`

This interface is public-input-only.

## Formal Theorem

Let:

- `G0` be the real joint QSSM transcript game
- `G1` be the game with MS replaced by its simulator and LE left real
- `G2` be the game output by the global simulator

Then the target theorem is:

```text
For every PPT distinguisher D,
|Pr[D(G0)=1] - Pr[D(G2)=1]|
  <= epsilon_ms_hash_binding
   + epsilon_ms_rom_programmability
   + epsilon_le.
```

The MS simulation layer contributes zero residual advantage. The exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c` discharge the programmed MS transcript gap exactly by Schnorr reparameterization on the frozen observable boundary.

## Assumption Table

| ID | Symbol | Role | Classification |
| --- | --- | --- | --- |
| `A1` | `epsilon_ms_hash_binding` | binding of the concrete MS commitment and statement digest | standard-style, scheme-instantiated |
| `A2` | `epsilon_ms_rom_programmability` | programmable Fiat-Shamir interface for MS | standard ROM assumption |
| `A4` | `epsilon_le` | LE Set B simulator bound under the encoded rejection-sampling and Fiat-Shamir template | standard-style but parameterized and scheme-specific |

The MS simulation layer (formerly carried as a separate assumption) is now discharged by exact-simulation lemmas `MS-3a`, `MS-3b`, and `MS-3c` with zero advantage by construction.

## Reduction Sketch

The reduction proceeds in two large steps.

### Step 1: `G0 -> G1`

This step replaces the MS prover by the MS simulator.

The theorem loss for this step is:

```text
epsilon_ms_hash_binding
+ epsilon_ms_rom_programmability
```

The two terms have conventional interpretations:

- `epsilon_ms_hash_binding` covers the commitment and digest binding layer (`MS-1`)
- `epsilon_ms_rom_programmability` covers Fiat-Shamir programming on the frozen observable boundary (`MS-2`)

The MS simulation layer (formerly carried as a separate assumption) is now discharged exactly by the following lemmas:

- `MS-3a`: exact bitness transcript simulation under programmed challenges (zero advantage by construction)
- `MS-3b`: true-clause public-point characterization `P = r * H` at the highest differing bit (zero advantage by construction)
- `MS-3c`: exact comparison-clause simulation under programmed challenges (zero advantage by construction)

### Exact Simulation Argument

For both the bitness proofs and the true comparison clause, the witness-using real branch is an ordinary Schnorr transcript against a public point of the form `w * H`. Under programmed challenges, the real transcript distribution is exactly the same as the simulated transcript distribution:

```text
real: alpha <- U; a = alpha H; z = alpha + c w
sim:  z <- U;     a = z H - c (w H)
```

Because the query digests hash announcements only, challenge programming is transcript-consistent. False clauses are already simulated in the real prover. The three exact-simulation lemmas formalize this argument and eliminate any residual MS assumption.

### Step 2: `G1 -> G2`

This step replaces the real LE prover with the LE simulator and packages the MS and LE simulators into one global simulator. Its loss is the current `epsilon_le` term under the Set B parameterized HVZK argument.

## Discussion

### What Is Novel

- the canonical QSSM composition of MS v2 Option B with LE Set B
- the frozen observable boundary discipline across the composed proof system
- the single global simulator surface for the joint transcript
- the attempt to turn a framework-style theorem object into a standard `G0 -> G2` simulation statement

### What Is Standard

- programmable random oracle reasoning for Fiat-Shamir-style simulation
- Schnorr-style exact transcript simulation for witness relations of the form `P = wH`
- additive game-hopping bounds
- parameterized HVZK accounting on the LE side

### What Remains Assumption-Bound

- `A4` is still a concrete Set B parameterized proof obligation, not a theorem imported from an external formal development

The safe public claim is:

```text
Under explicit assumptions A1 (hash binding), A2 (ROM programmability), and A4 (LE HVZK bound) in the programmable Random Oracle Model, the real joint QSSM transcript and the global simulator output are computationally indistinguishable with advantage at most epsilon_ms_hash_binding + epsilon_ms_rom_programmability + epsilon_le. The MS simulation layer contributes zero residual advantage by exact-simulation lemmas MS-3a, MS-3b, and MS-3c.
```