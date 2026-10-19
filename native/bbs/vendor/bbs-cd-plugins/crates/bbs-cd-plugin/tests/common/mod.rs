//! A minimal example plugin and attribute handler, used by the framework
//! tests and as a template for plugin authors.
//!
//! `example-eq/0.1` proves that a committed one-message `uint` attribute
//! equals a public value v given in the request parameters:
//!   D − v·Y0 = s·Y1, a Schnorr proof of knowledge of s w.r.t. Y1,
//! with the challenge bound to the plugin id, the envelope statement, the
//! plugin's position, its parameters, D, the announcement and the nonce.
#![allow(dead_code)]
use bbs_cd::primitives::{decode_G1, point_to_octets_E1, scalar_from_octets, scalar_from_wide, scalar_to_octets};
use bbs_cd::types::ScalarInput;
use bbs_cd::utils::commitment_generators;
use bbs_cd_plugin::codec::Reader;
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::issuer::{scalar_from_u128, AttrHandler, SUITE};
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::schema::{AttributeSpec, ScalarsSpec};
use bbs_cd_plugin::transcript::Transcript;
use bls12_381::{G1Projective, Scalar};
use sha2::{Digest, Sha512};

pub const EQ_ID: &[u8] = b"example-eq/0.1";
pub const TYPE_UINT: &str = "uint";

/// Issuance handler for `uint`: input is a 16-byte big-endian integer.
pub struct UintHandler;

impl AttrHandler for UintHandler {
    fn type_id(&self) -> &str {
        TYPE_UINT
    }
    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>> {
        let v: [u8; 16] = input.try_into().map_err(|_| Error::Prover("uint: 16 bytes".into()))?;
        let v = u128::from_be_bytes(v);
        if spec.count != 1 || spec.bits > 128 || (spec.bits < 128 && v >> spec.bits != 0) {
            return Err(Error::Prover("uint: out of range".into()));
        }
        Ok(vec![scalar_from_u128(v)])
    }
}

fn challenge(env: &EnvContext, params: &[u8], d: &G1Projective, t: &G1Projective) -> Scalar {
    let tr = Transcript::new(b"EXAMPLE-EQ/0.1/challenge")
        .add(b"plugin", EQ_ID)
        .add(b"env", &env.env_digest())
        .add(b"plugin_index", &env.plugin_index.to_be_bytes())
        .add(b"params", params)
        .add(b"nv", &env.nonce)
        .add(b"D", &point_to_octets_E1(d))
        .add(b"T", &point_to_octets_E1(t))
        .into_bytes();
    let w: [u8; 64] = Sha512::digest(&tr).into();
    scalar_from_wide(&w[..48].try_into().unwrap())
}

fn value(params: &[u8]) -> Result<Scalar> {
    let v: [u8; 16] = params.try_into().map_err(|_| Error::Reject("example-eq: params".into()))?;
    Ok(Scalar::from_raw([
        u64::from_be_bytes(v[8..].try_into().unwrap()),
        u64::from_be_bytes(v[..8].try_into().unwrap()),
        0,
        0,
    ]))
}

fn rand_scalar(rng: &mut dyn CryptoRngCore) -> Scalar {
    let mut w = [0u8; 48];
    rng.fill_bytes(&mut w);
    scalar_from_wide(&w)
}

pub struct EqProver;

impl PluginProver for EqProver {
    fn plugin_id(&self) -> &[u8] {
        EQ_ID
    }
    fn prove(
        self: Box<Self>,
        env: &EnvContext,
        input: &CommittedInput,
        params: &[u8],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let (_, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
        let m = &input.messages[0];
        let s = m.opening.to_scalar()?;
        let t_s = rand_scalar(rng);
        let t = y1 * t_s;
        let c = challenge(env, params, &m.commitment, &t);
        let z = t_s + c * s;
        Ok([&point_to_octets_E1(&t)[..], &scalar_to_octets(&z)[..]].concat())
    }
}

pub struct EqVerifier;

impl PluginVerifier for EqVerifier {
    fn plugin_id(&self) -> &[u8] {
        EQ_ID
    }
    fn check_request(&self, attr: &AttributeSpec, params: &[u8]) -> Result<()> {
        match attr.scalars_spec() {
            Some(s) if s.type_id == TYPE_UINT && s.count == 1 => {}
            _ => return Err(Error::Reject("example-eq: wrong attribute type".into())),
        }
        value(params).map(|_| ())
    }
    fn verify(
        &self,
        env: &EnvContext,
        view: &CommittedView,
        params: &[u8],
        proof: &[u8],
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        let (y0, y1) = commitment_generators(SUITE, &SUITE.api_id())?;
        let mut r = Reader::new(proof, 80)?;
        let t = decode_G1(r.take(48)?, true).map_err(|_| Error::Decode("example-eq: T".into()))?;
        let z = scalar_from_octets(r.take(32)?).map_err(|_| Error::Decode("example-eq: z".into()))?;
        r.end()?;
        let d = view.commitments[0];
        let c = challenge(env, params, &d, &t);
        if y1 * z != t + (d - y0 * value(params)?) * c {
            return Err(Error::Reject("example-eq: proof".into()));
        }
        Ok(b"equal".to_vec())
    }
}

pub fn uint_input(v: u128) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}
