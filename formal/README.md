# ASTRA-PQ Formal Verification

This directory contains the Tamarin models used to verify selected
protocol-level security properties of ASTRA-PQ.

## Verification environment

- Tamarin-Prover: 1.10.0
- Maude: 3.2

Tamarin-Prover 1.10.0 reports Maude 3.2 as an unsupported version,
although the installation check succeeds. The final verification
artifact should preferably be rerun using a Tamarin-supported Maude
release such as 3.2.1 or later for reproducibility.

## Models

### `astra-pq-r3.spthy`

Models the evaluated ASTRA-PQ R3 session-establishment profile.

The model abstracts:

- ML-DSA using Tamarin's symbolic signing theory.
- ML-KEM using asymmetric protection of a fresh KEM contribution.
- transcript-bound key derivation using domain-separated hash terms.
- authorization evidence as network-visible data.
- single-use replay state using a linear symbolic fact.
- initiating-gateway and responder compromise using explicit corruption rules.

The R3 authorization profile requires six authenticated evidence
contributions:

- `a1`: source and risk-floor evidence.
- `a2`: destination and risk-floor evidence.
- `a3`: safety and risk-floor evidence.

Verified session lemmas:

- `protocol_exec`
- `authorization_before_acceptance`
- `responder_injective_agreement`
- `session_key_secrecy`
- `responder_no_double_accept`

Phase-executability lemmas used during model validation:

- `exec_authority`
- `exec_initiator_request`
- `exec_responder_derived`
- `exec_initiator_confirmed`

Example command:

    tamarin-prover formal/astra-pq-r3.spthy \
      --prove=authorization_before_acceptance

Run the principal session properties individually:

    for lemma in \
      protocol_exec \
      authorization_before_acceptance \
      responder_injective_agreement \
      session_key_secrecy \
      responder_no_double_accept
    do
      echo "===== $lemma ====="
      tamarin-prover formal/astra-pq-r3.spthy --prove="$lemma"
    done

## Governance model

### `astra-pq-governance.spthy`

Models the local validated governance high-water state maintained by
each verifier instance.

Each verifier has a fresh symbolic identifier and maintains a linear
state containing:

- governance epoch,
- checkpoint digest,
- object version.

Verified governance lemmas:

- `governance_exec`
- `governance_no_rollback`
- `governance_no_same_epoch_conflict`

Example command:

    tamarin-prover formal/astra-pq-governance.spthy \
      --prove=governance_no_rollback

Run all governance properties:

    for lemma in \
      governance_exec \
      governance_no_rollback \
      governance_no_same_epoch_conflict
    do
      echo "===== $lemma ====="
      tamarin-prover formal/astra-pq-governance.spthy --prove="$lemma"
    done

## Scope and abstraction boundaries

The Tamarin models establish symbolic protocol properties under the
modeled assumptions.

They do not constitute computational proofs of:

- ML-KEM,
- ML-DSA,
- HKDF,
- the LWR-based distributed PRF.

The governance model does not model:

- IOTA consensus,
- ledger availability,
- physical or filesystem rollback of durable storage.

Instead, it verifies the local governance-state invariant after a
checkpoint has been validated and accepted by a verifier.

The session model does not claim forward secrecy. Compromise of the
responder's long-term ML-KEM decapsulation secret is explicitly treated
as a condition under which historical session-key secrecy is not
guaranteed.
