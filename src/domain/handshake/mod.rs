/*
`Handshake` message type definitions for `qsh` v1 (spec §5.1).

This module is the single source of truth for the wire schema of the
four‑message handshake.
It intentionally keeps **all secret material out** (only public keys,
signatures, ciphertexts, nonces, and advisory metadata) so zeroization is
not required for the types themselves.

This module defines the CBOR-serializable structures exchanged during the
four‑message handshake:
`HELLO -> ACCEPT -> FINISH_CLIENT -> FINISH_SERVER`.

Goals:
* Enforce wire‑format length invariants at the type level where practical (fixed-size newtypes for nonces, public keys, ciphertexts, signatures).
* Provide explicit, typed validation errors via [`HandshakeError`] for semantic checks not encoded in the Rust type system (capability ordering, certificate list bounds, etc.).
* Keep defensive size limits private constants while documenting their intent.

Notes:
* Padding fields ([`pad`]) are excluded from any future transcript hash (per spec rationale).
* Baseline capabilities [`EXEC`] and [`TTY`] are mandatory and validated.
* AEAD confirmation tags ([`client_confirm`], [`server_confirm`]) are fixed to [`AEAD_TAG_LEN`] (=16) bytes.
* No private / secret key material is represented here; zeroization is not required.
* [`UserAuth`] uses a custom deserializer to reject ambiguous inputs containing both [`raw_keys`] and [`user_cert_chain`] (emits [`HandshakeError::UserAuthAmbiguous`]).

*/

pub mod accept;
pub mod capability;
pub mod errors;
pub mod finish;
pub mod hello;
mod helpers;
pub mod kem;
pub mod keys;
pub mod nonce;
mod params;
pub mod user_auth;
#[macro_use]
mod large_array_serde;

pub use accept::*;
pub use capability::*;
pub use errors::HandshakeError;
pub use finish::*;
pub use hello::*;
pub use kem::*;
pub use keys::*;
pub use nonce::*;
pub use user_auth::*;
