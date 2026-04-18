# Prove & Verify Pipeline

## Prove Flow

```mermaid
sequenceDiagram
    participant Caller
    participant Prover as qssm-local-prover
    participant Templates as qssm-templates
    participant Entropy as qssm-entropy
    participant MS as qssm-ms
    participant LE as qssm-le
    participant Gadget as qssm-gadget

    Caller->>Prover: prove(template_id, claim, witness, binding_ctx, entropy_seed)

    Prover->>Templates: resolve(template_id)
    Templates-->>Prover: Template

    Prover->>Templates: eval_predicates(claim)
    Templates-->>Prover: Ok

    Prover->>Entropy: derive_keys(entropy_seed, binding_ctx)
    Entropy-->>Prover: mask_seed, salt

    Prover->>MS: ms_commit(witness, salt)
    MS-->>Prover: MsCommitment

    Prover->>LE: le_prove(witness, mask_seed)
    LE-->>Prover: LeProof

    Prover->>Gadget: bind(LeProof, MsCommitment, binding_ctx)
    Gadget-->>Prover: GadgetBinding

    Prover-->>Caller: ProofBundle
```

## Verify Flow

```mermaid
sequenceDiagram
    participant Caller
    participant API as qssm-api
    participant Templates as qssm-templates
    participant MS as qssm-ms
    participant LE as qssm-le
    participant Gadget as qssm-gadget

    Caller->>API: verify(template_id, claim, proof, binding_ctx)

    API->>Templates: resolve(template_id)
    Templates-->>API: Template

    API->>Templates: eval_predicates(claim)
    Templates-->>API: Ok

    API->>LE: le_verify(proof.le)
    LE-->>API: Ok

    API->>MS: ms_verify(proof.ms, binding_ctx)
    MS-->>API: Ok

    API->>Gadget: verify_binding(proof.gadget, proof.le, proof.ms)
    Gadget-->>API: Ok

    API-->>Caller: Ok(true)
```

## Offline Verify Flow (qssm-local-verifier)

```mermaid
sequenceDiagram
    participant Caller
    participant LV as qssm-local-verifier
    participant API as qssm-api
    participant Templates as qssm-templates

    Caller->>LV: verify_proof_offline(proof_bytes)

    LV->>API: decode(proof_bytes)
    API-->>LV: ProofBundle

    LV->>Templates: resolve(template_id)
    Templates-->>LV: Template

    LV->>API: verify(template, claim, proof, binding_ctx)
    API-->>LV: Ok(true)

    LV-->>Caller: Ok(true)
```

## Key Properties

| Property | Guarantee |
|---|---|
| **Determinism** | Same inputs → same `ProofBundle` bytes |
| **No internal randomness** | All entropy from caller-provided `entropy_seed` |
| **Domain separation** | Every hash call uses a unique domain tag |
| **Binding** | Proofs bound to `binding_ctx` — no cross-context replay |
| **Constant-time** | Secret operations via `subtle` crate |
| **Zeroization** | All intermediates zeroized on drop |
