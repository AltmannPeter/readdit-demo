//! The verifier's request, its context `ctx` and the ETSI presentation header
//! `ph = Tr(nonce, ctx)` shared by every BBS proof of a presentation.
use bbs_cd::types::{DisclosureState, COMMIT, DISCLOSE, HIDE};
use rand_core::{CryptoRng, RngCore};

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result};
use crate::issuer::{ranges, IssuerParams};
use crate::params::*;
use crate::schema::{AttrKind, Schema};
use crate::transcript::Transcript;

/// One credential the verifier asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRequest {
    pub issuer_pk: Vec<u8>,
    /// `Schema::digest()` of the expected schema.
    pub schema_digest: [u8; 32],
    /// `Octets` attributes to disclose, in schema order.
    pub disclose: Vec<String>,
}

/// One plugin proof the verifier asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginRequest {
    pub plugin_id: Vec<u8>,
    /// Index into `Request::credentials`.
    pub credential: u8,
    /// The `Scalars` attribute the plugin works on (it is committed).
    pub attribute: String,
    /// Plugin-specific parameters, validated by the plugin's verifier.
    pub params: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub audience: Vec<u8>,
    pub nonce: Vec<u8>,
    pub credentials: Vec<CredentialRequest>,
    pub plugins: Vec<PluginRequest>,
}

fn rej<T>(s: impl Into<String>) -> Result<T> {
    Err(Error::Reject(format!("request: {}", s.into())))
}

impl CredentialRequest {
    pub fn new(issuer: &IssuerParams, disclose: &[&str]) -> Self {
        CredentialRequest {
            issuer_pk: issuer.pk.clone(),
            schema_digest: issuer.schema.digest(),
            disclose: disclose.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Request {
    /// Request with a fresh 32-byte nonce.
    pub fn new<R: RngCore + CryptoRng + ?Sized>(
        audience: &[u8],
        credentials: Vec<CredentialRequest>,
        plugins: Vec<PluginRequest>,
        rng: &mut R,
    ) -> Self {
        let mut nonce = vec![0u8; 32];
        rng.fill_bytes(&mut nonce);
        Request { audience: audience.to_vec(), nonce, credentials, plugins }
    }

    /// Structural checks against the issuers' parameters (one per requested
    /// credential, in order).  Plugin parameters are checked by the plugins.
    pub fn validate(&self, issuers: &[IssuerParams]) -> Result<()> {
        if self.nonce.len() < MIN_NONCE_LEN || self.nonce.len() > MAX_NONCE_LEN {
            return rej("nonce length");
        }
        if self.audience.len() > MAX_AUDIENCE_LEN {
            return rej("audience too long");
        }
        if self.credentials.is_empty() || self.credentials.len() > MAX_CREDENTIALS {
            return rej("credential count");
        }
        if self.plugins.len() > MAX_PLUGINS {
            return rej("plugin count");
        }
        if issuers.len() != self.credentials.len() {
            return rej("one issuer per requested credential");
        }
        for (c, iss) in self.credentials.iter().zip(issuers) {
            if c.issuer_pk != iss.pk {
                return rej("issuer mismatch");
            }
            if c.schema_digest != iss.schema.digest() {
                return rej("schema mismatch");
            }
            let mut last = None;
            for name in &c.disclose {
                let Some((pos, a, _)) = iss.schema.find(name) else { return rej(format!("unknown attribute {name}")) };
                if a.kind != AttrKind::Octets {
                    return rej(format!("{name} cannot be disclosed"));
                }
                if last.is_some_and(|l| l >= pos) {
                    return rej("disclosed attributes must be unique and in schema order");
                }
                last = Some(pos);
            }
        }
        for (i, p) in self.plugins.iter().enumerate() {
            if p.plugin_id.is_empty() || p.plugin_id.len() > MAX_PLUGIN_ID_LEN {
                return rej("plugin id");
            }
            if p.params.len() > MAX_PLUGIN_PARAMS {
                return rej("plugin params too long");
            }
            let Some(iss) = issuers.get(p.credential as usize) else { return rej("plugin credential index") };
            let Some((_, a, _)) = iss.schema.find(&p.attribute) else {
                return rej(format!("unknown attribute {}", p.attribute));
            };
            if a.scalars_spec().is_none() {
                return rej(format!("{} is not a committable attribute", p.attribute));
            }
            if self.plugins[..i]
                .iter()
                .any(|q| q.plugin_id == p.plugin_id && q.credential == p.credential && q.attribute == p.attribute)
            {
                return rej("duplicate plugin request");
            }
        }
        Ok(())
    }

    /// Attributes of credential `cred` that some plugin commits, in schema order.
    pub fn committed_attributes(&self, cred: usize, schema: &Schema) -> Vec<String> {
        schema
            .attributes()
            .iter()
            .filter(|a| self.plugins.iter().any(|p| p.credential as usize == cred && p.attribute == a.name))
            .map(|a| a.name.clone())
            .collect()
    }

    /// Message indexes of credential `cred`: (committed, disclosed), ascending.
    pub fn message_indexes(&self, cred: usize, schema: &Schema) -> (Vec<u16>, Vec<u16>) {
        let committed = self.committed_attributes(cred, schema);
        let mut c = Vec::new();
        let mut d = Vec::new();
        for (a, r) in schema.attributes().iter().zip(ranges(schema)) {
            if committed.contains(&a.name) {
                c.extend(r.map(|i| i as u16));
            } else if self.credentials[cred].disclose.contains(&a.name) {
                d.extend(r.map(|i| i as u16));
            }
        }
        (c, d)
    }

    /// ETSI disclosure states of credential `cred`.
    pub fn disclosure_states(&self, cred: usize, schema: &Schema) -> Vec<DisclosureState> {
        let (c, d) = self.message_indexes(cred, schema);
        (0..schema.message_count() as u16)
            .map(|i| {
                if c.contains(&i) {
                    COMMIT
                } else if d.contains(&i) {
                    DISCLOSE
                } else {
                    HIDE
                }
            })
            .collect()
    }

    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(self.credentials.len() as u8);
        for c in &self.credentials {
            w.var_u8(&c.issuer_pk).raw(&c.schema_digest).u8(c.disclose.len() as u8);
            for n in &c.disclose {
                w.var_u8(n.as_bytes());
            }
        }
        w.u8(self.plugins.len() as u8);
        for p in &self.plugins {
            w.var_u8(&p.plugin_id).u8(p.credential).var_u8(p.attribute.as_bytes()).var_u16(&p.params);
        }
        w.into_bytes()
    }

    /// Request context: everything except the nonce.
    pub fn context(&self) -> Vec<u8> {
        Transcript::new(DST_CTX)
            .add(b"protocol", FRAMEWORK_ID)
            .add(b"audience", &self.audience)
            .add(b"body", &self.body())
            .into_bytes()
    }

    /// ETSI presentation header of every BBS proof in the presentation.
    pub fn presentation_header(&self) -> Vec<u8> {
        Transcript::new(DST_PH).add(b"nv", &self.nonce).add(b"ctx", &self.context()).into_bytes()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.var_u16(&self.audience).var_u8(&self.nonce).raw(&self.body());
        w.into_bytes()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, 1 << 16)?;
        let utf8 = |x: &[u8]| String::from_utf8(x.to_vec()).map_err(|_| Error::Decode("request: utf-8".into()));
        let audience = r.var_u16(MAX_AUDIENCE_LEN)?.to_vec();
        let nonce = r.var_u8(MAX_NONCE_LEN)?.to_vec();
        let nc = r.u8()? as usize;
        let mut credentials = Vec::with_capacity(nc);
        for _ in 0..nc {
            let issuer_pk = r.var_u8(96)?.to_vec();
            let schema_digest: [u8; 32] = r.arr()?;
            let nd = r.u8()? as usize;
            let disclose = (0..nd).map(|_| r.var_u8(MAX_NAME_LEN).and_then(utf8)).collect::<Result<Vec<_>>>()?;
            credentials.push(CredentialRequest { issuer_pk, schema_digest, disclose });
        }
        let np = r.u8()? as usize;
        let mut plugins = Vec::with_capacity(np);
        for _ in 0..np {
            let plugin_id = r.var_u8(MAX_PLUGIN_ID_LEN)?.to_vec();
            let credential = r.u8()?;
            let attribute = utf8(r.var_u8(MAX_NAME_LEN)?)?;
            let params = r.var_u16(MAX_PLUGIN_PARAMS)?.to_vec();
            plugins.push(PluginRequest { plugin_id, credential, attribute, params });
        }
        r.end()?;
        Ok(Request { audience, nonce, credentials, plugins })
    }
}
