//! Plugin framework on ETSI BBS committed disclosures (`bbs_cd`, draft v0.7).
//!
//! * [`schema`]: typed credential layout (`Octets` and plugin-typed `Scalars`);
//! * [`issuer`]: issuer, issuer parameters, credentials, attribute handlers;
//! * [`request`]: the verifier's request, `ctx` and the presentation header;
//! * [`envelope`]: commitment preparation, presentation and verification;
//! * [`plugin`]: the plugin traits and what a plugin is bound to;
//! * [`session`]: single-use, expiring nonces;
//! * shared utilities for plugins: [`codec`], [`transcript`], [`par`], [`error`].
//!
//! See `docs/DESIGN.md` and `docs/ENVELOPE.md`.  **Not constant-time. Not audited. Not for production.**
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

pub mod codec;
pub mod envelope;
pub mod error;
pub mod issuer;
pub mod par;
pub mod params;
pub mod plugin;
pub mod request;
pub mod schema;
pub mod session;
pub mod transcript;

pub use error::{Error, Result};
