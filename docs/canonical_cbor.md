# Canonical CBOR in qsh

## Why enforce canonical encodings?

CBOR (Concise Binary Object Representation) is a flexible format: the same logical value can be encoded in multiple byte sequences. For example, the integer `0` can be encoded in short or long forms, and map keys can appear in arbitrary orders. All of these decode to the same semantic structure.

That flexibility is fine for general-purpose data exchange, but in a cryptographic protocol like qsh it introduces risk:

- **Transcript uniqueness:** Confirm tags and key derivation in the handshake are bound to the raw bytes of control-plane messages. If two different byte encodings can represent the same structure, implementations may compute different transcript hashes for the same logical handshake. Canonical form ensures one value = one transcript = one tag.

- **Golden vectors and interop:** Test vectors are only reproducible if every implementation encodes the same values into the same bytes. Canonical CBOR guarantees all conforming encoders produce identical outputs, avoiding “works on A, fails on B” problems.

- **Tamper detection:** An attacker or middlebox could re-encode fields into “weird but valid” CBOR forms. The semantics wouldn’t change, but the transcript bytes would, causing confirm/tag failures or denial of service. By rejecting non-canonical encodings we remove that ambiguity.

- **Minimal encoding hygiene:** Canonical CBOR requires integers and lengths to be minimally encoded. This reduces parser surface area and edge cases, which hardens the implementation.

- **Fingerprinting resistance:** Allowing multiple encodings lets observers infer which library/version produced them (based on map order or integer form). Canonical form reduces that metadata leakage.

- **Audit simplicity:** Reviewers can reason at the semantic level: *given this Hello, the bytes are exactly …*. Without canonical enforcement, they must consider many byte-level encodings for the same message.

## What happens if we did not enforce canonical CBOR?

If qsh accepted any well-formed CBOR:
- Some handshakes would fail because peers’ transcript hashes diverged when they re-encoded internally.
- Golden vectors could not be reproduced across implementations.
- Attackers could exploit re-encoding differences for denial-of-service.
- Different encoders could leak which implementation/version is in use (fingerprinting).
- Audits and formal reasoning about the protocol would become more complex.

## Summary

Canonical CBOR is not about whether we can *parse* a message — it is about ensuring every participant in the protocol computes the same cryptographic transcript, every implementation produces the same bytes for the same values, and the audit story stays simple. For this reason, qsh **always enforces canonical CBOR** and rejects any input that does not match its deterministic form.