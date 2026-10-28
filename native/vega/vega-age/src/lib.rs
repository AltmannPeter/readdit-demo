//! Age verification for credentials such as the PID, proved with Vega.
//!
//! The holder of a credential proves to a verifier that its birth date lies in an age range,
//! without showing the credential. The verifier names the credential's type and the attribute that
//! holds the birth date ([`request`]).
//!
//! Two credential formats are supported: an ISO/IEC 18013-5 mdoc ([`mdoc`]) and an SD-JWT VC
//! ([`sdjwt`]).
//!
//! The crate follows the structure that the Vega specification gives a computation.
//!
//! | Module | Role | Specification |
//! | --- | --- | --- |
//! | [`table`] | The shared table of signed blocks and hash states | 5.3, 5.4 |
//! | [`step`] | The step circuit, one SHA-256 compression at a public position | 4.2, 5.3 |
//! | [`mdoc`], [`sdjwt`] | The core circuits, with the checks that happen once | 4.2, 5.3 |
//! | [`bsc`] | The core circuit of the nym_auth rulebook v0.5 attestation (`bsc`, `psc`) | 4.2, 5.3 |
//! | [`presentation`] | The presentation-specific rules and the public values of both cores | 4.4, 5.4, 5.6 |
//! | [`request`] | The patterns of the credential type and the attribute name the verifier asks for | 4.4, 5.4 |
//! | [`app`] | Setup, the witness, proving and acceptance by the application | 4.3, 4.4, 5.6 |
//! | [`challenge`] | The challenge the device key signs, from the verifier's values | |
//! | [`gadgets`] | Rules for bits, selection, byte windows, base64url and P-256, and the native values of the costly ones | 5.2, 5.3 |
//! | [`fixtures`] | Test credentials signed with test keys, and a CBOR reader for real ones | |
//!
//! The prover's engine is `vega_prover::provider::T256HyraxEngine`: the curve T-256 with Hyrax
//! commitments. The rules compute in its scalar field, `t256::Scalar` of
//! `vega_prover::provider::pt256`, which is the field of P-256 coordinates, so the rules compute
//! on P-256 points natively. The code names both types as the prover does, with no alias.

// Doctests forbid unsafe code too: `[lints]` does not reach them.
#![doc(test(attr(forbid(unsafe_code))))]

pub mod app;
pub mod bsc;
pub mod challenge;
pub mod fixtures;
pub mod gadgets;
pub mod mdoc;
pub mod presentation;
pub mod pseudonym;
pub mod request;
pub mod sdjwt;
pub mod step;
pub mod table;
