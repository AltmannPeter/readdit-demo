//! Toolkit for plugins that prove statements in the P-256 fields about values
//! committed in an ETSI BBS committed-disclosure presentation.
//!
//! * `tom`, `comb`: Tom-256 (a curve whose group order is the P-256 base
//!   field) with fixed-base tables;
//! * `transfer`, `config`: moving a BLS12-381 Pedersen commitment to an
//!   integer into a Tom-256 commitment (Chase–Orrù–Perrin–Zaverucha, with the
//!   HPI parameters as one configuration);
//! * `sm`, `pa`, `oncurve`: scalar multiplication, point addition and
//!   on-curve proofs over committed P-256 coordinates;
//! * `batch`: random-linear-combination verification of the linear equations;
//! * `p256x`: strict P-256 encodings and the limb layout of a P-256 point.
//!
//! **Not constant-time. Not audited. Not for production.**
#![forbid(unsafe_code)]
#![allow(non_snake_case)]

pub mod batch;
pub mod comb;
pub mod config;
pub mod oncurve;
pub mod p256x;
pub mod pa;
pub mod params;
pub mod sm;
pub mod tom;
pub mod transfer;

pub use bbs_cd_plugin::{par, Error, Result};
