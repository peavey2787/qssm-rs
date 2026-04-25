# LE parameter analysis

This note derives the exact HVZK-style constraints currently encoded in the formal crate and checks the committed LE Set B configuration.

## Encoded proof constraints

The current formal route in [truth-engine/qssm-proofs/src/reduction_rejection.rs](../../truth-engine/qssm-proofs/src/reduction_rejection.rs) uses:

$$
\|cr\|_\infty \le c_\text{size} \cdot c_\text{span} \cdot \beta
$$

and the standard HVZK template bound:

$$
\eta \ge 11 \cdot \|cr\|_\infty \cdot \sqrt{\frac{\ln(2N/\varepsilon)}{\pi}}
$$

For the committed proof target:

- $N = 256$
- $\varepsilon = 2^{-128}$
- $\beta = 8$
- $c_\text{size} = 48$
- $c_\text{span} = 8$

the crate’s formula gives:

$$
\|cr\|_\infty = 48 \cdot 8 \cdot 8 = 3072
$$

$$
\eta_\text{required} \approx 185{,}785.57
$$

The formal crate also uses a hard-cap verifier bound on $z$, so a simple support-containment rule is:

$$
\gamma \ge \eta + \|cr\|_\infty
$$

This is a strong proof-safe condition for the exact truncated model implemented in the repository.

## Committed Set B

Current parameters:

- $\eta = 196{,}608$
- $\gamma = 199{,}680$
- $\beta = 8$
- $c_\text{size} = 48$
- $c_\text{span} = 8$

Derived properties:

- HVZK masking margin: $196{,}608 - 185{,}785.57 \approx 10{,}822.43$
- Support-containment margin: $199{,}680 - (196{,}608 + 3072) = 0$
- FS challenge space: $48 \cdot \log_2(17) \approx 196.20$ bits
- FS security margin with $Q_H = 2^{64}$: $196.20 - 64 \approx 132.20$ bits

This is the proof-safe configuration now committed in the codebase. It satisfies the exact eta/gamma/challenge-shape conditions encoded in the formal crate while still clearing the 128-bit Fiat-Shamir target.

The corresponding formal objects are now aligned with this set in [truth-engine/qssm-proofs/src/reduction_rejection.rs](../../truth-engine/qssm-proofs/src/reduction_rejection.rs), [truth-engine/qssm-proofs/src/reduction_lattice.rs](../../truth-engine/qssm-proofs/src/reduction_lattice.rs), and [truth-engine/qssm-proofs/src/reduction_zk.rs](../../truth-engine/qssm-proofs/src/reduction_zk.rs).