//! Issuer, issuer parameters and credentials.
//!
//! The BBS header is a framework transcript of the schema, so the signature
//! fixes the attribute layout and types.  `Scalars` attributes are produced
//! by the attribute handler registered for their `type_id`, which also runs
//! the type's issuance checks (for example, a device-key attestation).
use bbs_cd::interface::{KeyGen, Sign, SkToPk, Verify};
use bbs_cd::params::Ciphersuite;
use bbs_cd::types::{Message, MessageType, ScalarInput};
use rand_core::{OsRng, RngCore};

use crate::codec::{Reader, Writer};
use crate::error::{decode, Error, Result};
use crate::params::{DST_HDR, FRAMEWORK_ID, MAX_ATTR_LEN};
use crate::schema::{AttrKind, ScalarsSpec, Schema};
use crate::transcript::Transcript;

/// The ETSI ciphersuite used throughout (BLS12-381-SHA-256).
pub const SUITE: Ciphersuite = Ciphersuite::Sha256;

/// Public issuer parameters known to holders and verifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerParams {
    pub pk: Vec<u8>,
    pub schema: Schema,
}

impl IssuerParams {
    /// Total message count L.
    pub fn l(&self) -> usize {
        self.schema.message_count()
    }

    /// BBS header: the framework id, the api_id and the schema.
    pub fn header(&self) -> Vec<u8> {
        Transcript::new(DST_HDR)
            .add(b"protocol", FRAMEWORK_ID)
            .add(b"api_id", &SUITE.api_id())
            .add(b"L", &(self.l() as u16).to_be_bytes())
            .add(b"schema", &self.schema.encode())
            .into_bytes()
    }

    pub fn message_types(&self) -> Vec<MessageType> {
        self.schema.message_types()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.var_u8(&self.pk).var_u16(&self.schema.encode());
        w.into_bytes()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, 1 << 15)?;
        let pk = r.var_u8(96)?.to_vec();
        let schema = Schema::decode(r.var_u16(1 << 14)?)?;
        r.end()?;
        if pk.len() != 96 {
            return decode("issuer pk length");
        }
        bbs_cd::primitives::octets_to_pubkey(&pk).map_err(|_| Error::Decode("issuer pk".into()))?;
        Ok(IssuerParams { pk, schema })
    }
}

/// Encodes issuance input for one attribute type and runs its checks.
pub trait AttrHandler: Send + Sync {
    /// The `type_id` this handler serves.
    fn type_id(&self) -> &str;
    /// Check `input` (handler-defined bytes) and return exactly `spec.count`
    /// scalars, each < 2^`spec.bits`.  Errors are issuance refusals.
    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>>;
}

/// The value given to the issuer for one attribute, in schema order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttrValue {
    /// For an `Octets` attribute.
    Octets(Vec<u8>),
    /// For a `Scalars` attribute: input for its type's handler.
    Input(Vec<u8>),
}

/// ETSI scalar message from an unsigned integer (< 2^128 < r).
pub fn scalar_from_u128(m: u128) -> ScalarInput {
    let mut b = [0u8; 32];
    b[16..].copy_from_slice(&m.to_be_bytes());
    ScalarInput(b)
}

/// The integer value of a scalar message if it is < 2^128.
pub fn scalar_to_u128(s: &ScalarInput) -> Option<u128> {
    if s.0[..16].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(s.0[16..].try_into().unwrap()))
}

/// Whether the big-endian scalar is < 2^bits.
pub fn scalar_fits(s: &ScalarInput, bits: u16) -> bool {
    let bits = bits as usize;
    if bits >= 256 {
        return true;
    }
    let full = (256 - bits) / 8; // leading bytes that must be zero
    let rem = (256 - bits) % 8; // leading bits of the next byte that must be zero
    if s.0[..full].iter().any(|&b| b != 0) {
        return false;
    }
    rem == 0 || (s.0[full] >> (8 - rem)) == 0
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub issuer: IssuerParams,
    pub signature: Vec<u8>,
    pub messages: Vec<Message>,
}

impl Credential {
    /// Holder-side check: layout matches the schema and the signature verifies.
    pub fn verify(&self) -> Result<()> {
        let types = self.issuer.message_types();
        if self.messages.len() != types.len() {
            return Err(Error::Reject("credential: message count".into()));
        }
        for (a, r) in self.issuer.schema.attributes().iter().zip(ranges(&self.issuer.schema)) {
            match &a.kind {
                AttrKind::Octets => match &self.messages[r.start] {
                    Message::Octets(v) if v.len() <= MAX_ATTR_LEN => {}
                    _ => return Err(Error::Reject(format!("credential: attribute {}", a.name))),
                },
                AttrKind::Scalars(s) => {
                    for m in &self.messages[r] {
                        match m {
                            Message::Scalar(x) if scalar_fits(x, s.bits) => {}
                            _ => return Err(Error::Reject(format!("credential: attribute {}", a.name))),
                        }
                    }
                }
            }
        }
        Verify(SUITE, &self.issuer.pk, &self.signature, &self.issuer.header(), &self.messages, &types)
            .map_err(|e| Error::Reject(format!("credential signature: {e}")))
    }

    /// Value of an `Octets` attribute.
    pub fn octets(&self, name: &str) -> Option<&[u8]> {
        let (_, a, r) = self.issuer.schema.find(name)?;
        match (&a.kind, &self.messages[r.start]) {
            (AttrKind::Octets, Message::Octets(v)) => Some(v),
            _ => None,
        }
    }

    /// Scalars of a `Scalars` attribute.
    pub fn scalars(&self, name: &str) -> Option<Vec<ScalarInput>> {
        let (_, a, r) = self.issuer.schema.find(name)?;
        a.scalars_spec()?;
        self.messages[r]
            .iter()
            .map(|m| match m {
                Message::Scalar(x) => Some(*x),
                Message::Octets(_) => None,
            })
            .collect()
    }
}

/// Message ranges of all attributes, in schema order.
pub fn ranges(schema: &Schema) -> Vec<std::ops::Range<usize>> {
    let mut o = 0;
    schema
        .attributes()
        .iter()
        .map(|a| {
            let n = a.message_count();
            o += n;
            o - n..o
        })
        .collect()
}

pub struct Issuer {
    sk: ScalarInput,
    pub params: IssuerParams,
    handlers: Vec<Box<dyn AttrHandler>>,
}

impl Issuer {
    /// Issuer with a fresh random key.
    pub fn new(schema: Schema, handlers: Vec<Box<dyn AttrHandler>>) -> Result<Self> {
        let mut km = [0u8; 32];
        OsRng.fill_bytes(&mut km);
        let sk = KeyGen(SUITE, &km, b"bbs-cd-plugins-issuer", None)?;
        Self::with_key(schema, handlers, sk)
    }

    /// Deterministic issuer key from seed material (>= 32 bytes).
    pub fn from_seed(schema: Schema, handlers: Vec<Box<dyn AttrHandler>>, seed: &[u8]) -> Result<Self> {
        let sk = KeyGen(SUITE, seed, b"bbs-cd-plugins-issuer", None)?;
        Self::with_key(schema, handlers, sk)
    }

    /// Issuer with a caller-chosen key.  Every `Scalars` type in the schema
    /// needs a handler.
    pub fn with_key(schema: Schema, handlers: Vec<Box<dyn AttrHandler>>, sk: ScalarInput) -> Result<Self> {
        for a in schema.attributes() {
            if let AttrKind::Scalars(s) = &a.kind {
                if !handlers.iter().any(|h| h.type_id() == s.type_id) {
                    return Err(Error::Prover(format!("no handler for attribute type {}", s.type_id)));
                }
            }
        }
        let pk = SkToPk(sk)?;
        Ok(Issuer { sk, params: IssuerParams { pk, schema }, handlers })
    }

    /// Check every value with the schema (and the type handlers) and sign.
    pub fn issue(&self, values: &[AttrValue]) -> Result<Credential> {
        let schema = &self.params.schema;
        if values.len() != schema.attributes().len() {
            return Err(Error::Prover("issue: one value per attribute, in schema order".into()));
        }
        let mut messages = Vec::with_capacity(schema.message_count());
        for (a, v) in schema.attributes().iter().zip(values) {
            match (&a.kind, v) {
                (AttrKind::Octets, AttrValue::Octets(x)) => {
                    if x.len() > MAX_ATTR_LEN {
                        return Err(Error::Prover(format!("{}: exceeds MAX_ATTR_LEN", a.name)));
                    }
                    messages.push(Message::Octets(x.clone()));
                }
                (AttrKind::Scalars(s), AttrValue::Input(x)) => {
                    let h = self.handlers.iter().find(|h| h.type_id() == s.type_id).expect("checked in with_key");
                    let sc = h.encode(s, x)?;
                    if sc.len() != s.count as usize
                        || sc.iter().any(|m| !scalar_fits(m, s.bits) || m.to_scalar().is_err())
                    {
                        return Err(Error::Prover(format!("{}: handler output out of range", a.name)));
                    }
                    messages.extend(sc.into_iter().map(Message::Scalar));
                }
                _ => return Err(Error::Prover(format!("{}: value kind does not match the schema", a.name))),
            }
        }
        let signature =
            Sign(SUITE, self.sk, &self.params.pk, &self.params.header(), &messages, &self.params.message_types())?;
        Ok(Credential { issuer: self.params.clone(), signature, messages })
    }
}
