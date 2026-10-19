//! Presentation envelope: offline commitment preparation, online
//! presentation with plugins, strict parsing and verification.
//!
//! Encoding (docs/ENVELOPE.md §6):
//! ```text
//! "BCDP" 0x01
//! u8 n_credentials ( u16 n_disclosed (u32-len value)*  u32-len BBS proof )*
//! u8 n_plugins     ( u8-len plugin_id  u32-len proof )*
//! ```
//! Every count is compared with the request and the schema.
use std::time::{Duration, Instant};

use bbs_cd::interface::{PrecomputeCommitment, ProofGen, ProofVerify};
use bbs_cd::primitives::point_to_octets_E1;
use bbs_cd::types::{Index, Message, MessageType, Proof, ScalarInput, ScalarSource};
use bbs_cd::utils::{messages_to_scalars, octets_to_proof};
use bbs_cd::BbsResult;
use bls12_381::G1Projective;
use rand_core::{CryptoRng, RngCore, SeedableRng};

use crate::codec::{Reader, Writer};
use crate::error::{decode, Error, Result};
use crate::issuer::{ranges, Credential, IssuerParams, SUITE};
use crate::params::*;
use crate::plugin::{
    CommittedInput, CommittedMessage, CommittedView, CryptoRngCore, EnvContext, PluginProver, PluginVerifier,
};
use crate::request::Request;
use crate::transcript::Transcript;

// ------------------------------------------------------------- randomness
/// Adapter: an RNG as the ETSI crate's scalar source (48-byte samples
/// reduced mod r).
pub struct RngScalars<'a, R: RngCore + CryptoRng + ?Sized>(pub &'a mut R);

impl<R: RngCore + CryptoRng + ?Sized> ScalarSource for RngScalars<'_, R> {
    fn calculate_random_scalars(&mut self, count: usize) -> BbsResult<Vec<ScalarInput>> {
        Ok((0..count)
            .map(|_| {
                let mut w = [0u8; 48];
                self.0.fill_bytes(&mut w);
                ScalarInput::from(bbs_cd::primitives::scalar_from_wide(&w))
            })
            .collect())
    }
}

// ------------------------------------------------------------- statements
/// Credential statement cstmt_i (docs/ENVELOPE.md §5).
pub fn credential_statement(
    issuer: &IssuerParams,
    disclosed: &[(u16, ScalarInput)],
    committed: &[u16],
    d_bytes: &[[u8; 48]],
) -> Vec<u8> {
    let mut disc = Vec::with_capacity(disclosed.len() * 34);
    for (i, m) in disclosed {
        disc.extend_from_slice(&i.to_be_bytes());
        disc.extend_from_slice(&m.0);
    }
    let comm: Vec<u8> = committed.iter().flat_map(|i| i.to_be_bytes()).collect();
    Transcript::new(DST_CSTMT)
        .add(b"issuer_pk", &issuer.pk)
        .add(b"header", &issuer.header())
        .add(b"L", &(issuer.l() as u16).to_be_bytes())
        .add(b"disclosed", &disc)
        .add(b"committed", &comm)
        .add(b"D", &d_bytes.concat())
        .into_bytes()
}

/// Envelope statement `env` (docs/ENVELOPE.md §5).
pub fn envelope_statement(ctx: &[u8], cstmts: &[Vec<u8>]) -> Vec<u8> {
    let mut t = Transcript::new(DST_ENV)
        .add(b"protocol", FRAMEWORK_ID)
        .add(b"ctx", ctx)
        .add(b"n_credentials", &[cstmts.len() as u8]);
    for c in cstmts {
        t = t.add(b"credential", c);
    }
    t.into_bytes()
}

fn disclosed_scalars(issuer: &IssuerParams, idx: &[u16], msgs: &[Message]) -> Result<Vec<(u16, ScalarInput)>> {
    let types = issuer.message_types();
    let dtypes: Vec<MessageType> = idx.iter().map(|&i| types[i as usize].clone()).collect();
    let s = messages_to_scalars(SUITE, msgs, &dtypes, &SUITE.api_id())?;
    Ok(idx.iter().copied().zip(s).collect())
}

// ------------------------------------------------------------------ holder
/// Offline, request-independent commitment state of one credential
/// (ETSI `PrecomputeCommitment`).  Single use; not `Clone`.
pub struct CredentialSlot {
    pub issuer: IssuerParams,
    /// Committed attributes, in schema order.
    pub committed: Vec<String>,
    /// Their message indexes, ascending.
    pub indexes: Vec<u16>,
    pub d: Vec<G1Projective>,
    pub d_bytes: Vec<[u8; 48]>,
    /// ETSI openings s_j, in index order.
    pub rands: Vec<ScalarInput>,
}

/// Precompute the commitments of `committed` attributes of `cred`.
pub fn prepare_credential<R: RngCore + CryptoRng + ?Sized>(
    cred: &Credential,
    committed: &[&str],
    rng: &mut R,
) -> Result<CredentialSlot> {
    let schema = &cred.issuer.schema;
    let mut names: Vec<String> = Vec::new();
    let mut indexes: Vec<u16> = Vec::new();
    for (a, r) in schema.attributes().iter().zip(ranges(schema)) {
        if committed.contains(&a.name.as_str()) {
            if a.scalars_spec().is_none() {
                return Err(Error::Prover(format!("{} is not a committable attribute", a.name)));
            }
            names.push(a.name.clone());
            indexes.extend(r.map(|i| i as u16));
        }
    }
    if names.len() != committed.len() {
        return Err(Error::Prover("unknown or duplicate committed attribute".into()));
    }
    let (d, rands) = if indexes.is_empty() {
        (vec![], vec![])
    } else {
        let msgs: Vec<Message> = indexes.iter().map(|&i| cred.messages[i as usize].clone()).collect();
        let idx: Vec<Index> = indexes.iter().map(|&i| Index::Integer(i as u64)).collect();
        PrecomputeCommitment(SUITE, &msgs, &idx, &cred.issuer.message_types(), Some(&mut RngScalars(rng)))?
    };
    if d.len() != indexes.len() || rands.len() != indexes.len() {
        return Err(Error::Prover("commitment count".into()));
    }
    let d_bytes = d.iter().map(point_to_octets_E1).collect();
    Ok(CredentialSlot { issuer: cred.issuer.clone(), committed: names, indexes, d, d_bytes, rands })
}

impl CredentialSlot {
    /// Prover input of one committed attribute (for plugin preparation and
    /// proving).  `credential` is the position in the request.
    pub fn committed_input(&self, cred: &Credential, credential: usize, attribute: &str) -> Result<CommittedInput> {
        let (_, spec, r) = self
            .issuer
            .schema
            .find(attribute)
            .ok_or_else(|| Error::Prover(format!("unknown attribute {attribute}")))?;
        if !self.committed.iter().any(|c| c == attribute) {
            return Err(Error::Prover(format!("{attribute} is not committed in this slot")));
        }
        let mut messages = Vec::with_capacity(r.len());
        for i in r {
            let k = self.indexes.iter().position(|&x| x as usize == i).expect("committed index");
            let value = match &cred.messages[i] {
                Message::Scalar(v) => *v,
                Message::Octets(_) => return Err(Error::Prover("committed message is not a scalar".into())),
            };
            messages.push(CommittedMessage { index: i as u16, value, opening: self.rands[k], commitment: self.d[k] });
        }
        Ok(CommittedInput { credential, attribute: spec.clone(), messages })
    }
}

/// (ctx, env, disclosed messages per credential).
pub type HolderStatements = (Vec<u8>, Vec<u8>, Vec<Vec<Message>>);

/// Holder side of docs/ENVELOPE.md §5: ctx, env and the disclosed messages, from
/// the request, the credentials and their slots (before any BBS proof).
/// `present` uses it; a plugin that needs `env` ahead of time can too.
pub fn holder_statements(
    request: &Request,
    creds: &[&Credential],
    slots: &[CredentialSlot],
) -> Result<HolderStatements> {
    if slots.len() != creds.len() {
        return Err(Error::Prover("one slot per credential".into()));
    }
    let mut disclosed_vals = Vec::with_capacity(creds.len());
    let mut cstmts = Vec::with_capacity(creds.len());
    for (k, (cred, slot)) in creds.iter().zip(slots).enumerate() {
        let (c_idx, d_idx) = request.message_indexes(k, &cred.issuer.schema);
        if slot.issuer != cred.issuer || slot.indexes != c_idx {
            return Err(Error::Prover(format!("credential {k}: slot does not match the request")));
        }
        let msgs: Vec<Message> = d_idx.iter().map(|&i| cred.messages[i as usize].clone()).collect();
        if msgs.iter().any(|m| matches!(m, Message::Octets(v) if v.len() > MAX_ATTR_LEN)) {
            return Err(Error::Prover("disclosed attribute exceeds MAX_ATTR_LEN".into()));
        }
        let ds = disclosed_scalars(&cred.issuer, &d_idx, &msgs)?;
        cstmts.push(credential_statement(&cred.issuer, &ds, &c_idx, &slot.d_bytes));
        disclosed_vals.push(msgs);
    }
    let ctx = request.context();
    let env = envelope_statement(&ctx, &cstmts);
    Ok((ctx, env, disclosed_vals))
}

#[derive(Clone, Debug, Default)]
pub struct PresentStats {
    /// ETSI `ProofGen` for all credentials.
    pub bbs: Duration,
    /// Each plugin's `prove`.
    pub plugins: Vec<Duration>,
    pub total: Duration,
    pub bytes: usize,
}

fn bbs_proof(
    cred: &Credential,
    ph: &[u8],
    req: &Request,
    k: usize,
    slot: &CredentialSlot,
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>> {
    let states = req.disclosure_states(k, &cred.issuer.schema);
    // A zero response scalar (negligible) makes ProofGen return INVALID;
    // retry with fresh masks, openings unchanged (ETSI §3.3.4.2).
    let mut last = None;
    for _ in 0..4 {
        match ProofGen(
            SUITE,
            &cred.issuer.pk,
            &cred.signature,
            &cred.issuer.header(),
            ph,
            &cred.messages,
            &cred.issuer.message_types(),
            &states,
            Some(&slot.rands),
            Some(&mut RngScalars(&mut *rng)),
        ) {
            Ok((proof, _)) => return Ok(proof),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap().into())
}

/// Online presentation.  `creds` and `slots` follow `request.credentials`;
/// `provers` follow `request.plugins`.  Consumes the slots and provers.
pub fn present<'a>(
    request: &Request,
    creds: &[&Credential],
    slots: Vec<CredentialSlot>,
    provers: Vec<Box<dyn PluginProver + 'a>>,
    rng: &mut dyn CryptoRngCore,
    stats: Option<&mut PresentStats>,
) -> Result<Vec<u8>> {
    let t0 = Instant::now();
    let issuers: Vec<IssuerParams> = creds.iter().map(|c| c.issuer.clone()).collect();
    request.validate(&issuers).map_err(|e| Error::Prover(e.to_string()))?;
    if slots.len() != creds.len() || provers.len() != request.plugins.len() {
        return Err(Error::Prover("one slot per credential and one prover per plugin request".into()));
    }
    for (p, pr) in request.plugins.iter().zip(&provers) {
        if pr.plugin_id() != p.plugin_id.as_slice() {
            return Err(Error::Prover("prover order does not match the request".into()));
        }
    }
    let (ctx, env, disclosed_vals) = holder_statements(request, creds, &slots)?;
    let ph = request.presentation_header();
    // BBS proofs: independent of every plugin.
    let tb = Instant::now();
    let mut proofs = Vec::with_capacity(creds.len());
    for (k, (cred, slot)) in creds.iter().zip(&slots).enumerate() {
        let p = bbs_proof(cred, &ph, request, k, slot, rng)?;
        if octets_to_proof(&p)?.commitments != slot.d {
            return Err(Error::Prover("BBS commitments differ from the precomputed D".into()));
        }
        proofs.push(p);
    }
    let bbs_time = tb.elapsed();
    let mut plugin_proofs = Vec::with_capacity(provers.len());
    let mut plugin_times = Vec::with_capacity(provers.len());
    for (i, (p, prover)) in request.plugins.iter().zip(provers).enumerate() {
        let k = p.credential as usize;
        let input = slots[k].committed_input(creds[k], k, &p.attribute)?;
        let ectx =
            EnvContext { nonce: request.nonce.clone(), ctx: ctx.clone(), env: env.clone(), plugin_index: i as u16 };
        let tp = Instant::now();
        let proof = prover.prove(&ectx, &input, &p.params, rng)?;
        plugin_times.push(tp.elapsed());
        if proof.len() > MAX_PLUGIN_PROOF {
            return Err(Error::Prover("plugin proof exceeds MAX_PLUGIN_PROOF".into()));
        }
        plugin_proofs.push(proof);
    }
    let mut w = Writer::new();
    w.raw(MAGIC).u8(creds.len() as u8);
    for (msgs, proof) in disclosed_vals.iter().zip(&proofs) {
        w.u16(msgs.len() as u16);
        for m in msgs {
            match m {
                Message::Octets(v) => w.var_u32(v),
                Message::Scalar(_) => unreachable!("only octets attributes are disclosed"),
            };
        }
        w.var_u32(proof);
    }
    w.u8(plugin_proofs.len() as u8);
    for (p, proof) in request.plugins.iter().zip(&plugin_proofs) {
        w.var_u8(&p.plugin_id).var_u32(proof);
    }
    let out = w.into_bytes();
    if out.len() > MAX_PRESENTATION {
        return Err(Error::Prover("presentation exceeds MAX_PRESENTATION".into()));
    }
    if let Some(st) = stats {
        *st = PresentStats { bbs: bbs_time, plugins: plugin_times, total: t0.elapsed(), bytes: out.len() };
    }
    Ok(out)
}

// ---------------------------------------------------------------- verifier
/// One credential section of a parsed presentation.
pub struct ParsedCredential {
    pub disclosed: Vec<Vec<u8>>,
    pub bbs_proof: Vec<u8>,
    pub bbs: Proof,
    /// Byte range of the BBS proof in the presentation.
    pub bbs_range: (usize, usize),
}

/// Parsed presentation (public data only).
pub struct ParsedEnvelope {
    pub credentials: Vec<ParsedCredential>,
    pub plugin_proofs: Vec<Vec<u8>>,
    /// Byte range of each plugin proof in the presentation.
    pub plugin_ranges: Vec<(usize, usize)>,
}

/// Strict parser: every count comes from `request` and the issuers' schemas.
pub fn parse(b: &[u8], issuers: &[IssuerParams], request: &Request) -> Result<ParsedEnvelope> {
    let mut rd = Reader::new(b, MAX_PRESENTATION)?;
    if rd.take(MAGIC.len())? != MAGIC {
        return decode("magic");
    }
    let nc = rd.u8()? as usize;
    if nc != request.credentials.len() || nc != issuers.len() {
        return decode("credential count");
    }
    let mut credentials = Vec::with_capacity(nc);
    for (k, iss) in issuers.iter().enumerate() {
        let (c_idx, d_idx) = request.message_indexes(k, &iss.schema);
        let nd = rd.u16()? as usize;
        if nd != d_idx.len() {
            return decode("disclosed count");
        }
        let disclosed = (0..nd).map(|_| rd.var_u32(MAX_ATTR_LEN).map(|v| v.to_vec())).collect::<Result<Vec<_>>>()?;
        let start = b.len() - rd.remaining() + 4;
        let bbs_proof = rd.var_u32(MAX_BBS_PROOF)?.to_vec();
        let bbs = octets_to_proof(&bbs_proof).map_err(|e| Error::Decode(format!("bbs proof: {e}")))?;
        if bbs.N != c_idx.len() as u128 || bbs.commitments.len() != c_idx.len() {
            return decode("commitment count");
        }
        credentials.push(ParsedCredential { disclosed, bbs_range: (start, start + bbs_proof.len()), bbs_proof, bbs });
    }
    let np = rd.u8()? as usize;
    if np != request.plugins.len() {
        return decode("plugin count");
    }
    let mut plugin_proofs = Vec::with_capacity(np);
    let mut plugin_ranges = Vec::with_capacity(np);
    for p in &request.plugins {
        if rd.var_u8(MAX_PLUGIN_ID_LEN)? != p.plugin_id.as_slice() {
            return decode("plugin id");
        }
        let start = b.len() - rd.remaining() + 4;
        let proof = rd.var_u32(MAX_PLUGIN_PROOF)?.to_vec();
        plugin_ranges.push((start, start + proof.len()));
        plugin_proofs.push(proof);
    }
    rd.end()?;
    Ok(ParsedEnvelope { credentials, plugin_proofs, plugin_ranges })
}

/// Verifier side of docs/ENVELOPE.md §5 for a parsed presentation: ctx, env and the
/// view of each plugin request (in request order).  Does not verify the BBS
/// proofs; `Verifier::verify` does that first.
pub fn verifier_statements(
    issuers: &[IssuerParams],
    request: &Request,
    pe: &ParsedEnvelope,
) -> Result<(Vec<u8>, Vec<u8>, Vec<CommittedView>)> {
    let mut cstmts = Vec::with_capacity(issuers.len());
    let mut committed: Vec<(Vec<u16>, Vec<G1Projective>)> = Vec::with_capacity(issuers.len());
    for (k, (iss, pc)) in issuers.iter().zip(&pe.credentials).enumerate() {
        let (c_idx, d_idx) = request.message_indexes(k, &iss.schema);
        let msgs: Vec<Message> = pc.disclosed.iter().map(|v| Message::Octets(v.clone())).collect();
        let ds = disclosed_scalars(iss, &d_idx, &msgs).map_err(|_| Error::Reject("disclosed messages".into()))?;
        let d_bytes: Vec<[u8; 48]> = pc.bbs.commitments.iter().map(point_to_octets_E1).collect();
        cstmts.push(credential_statement(iss, &ds, &c_idx, &d_bytes));
        committed.push((c_idx, pc.bbs.commitments.clone()));
    }
    let ctx = request.context();
    let env = envelope_statement(&ctx, &cstmts);
    let mut views = Vec::with_capacity(request.plugins.len());
    for p in &request.plugins {
        let k = p.credential as usize;
        let (_, spec, range) = issuers[k]
            .schema
            .find(&p.attribute)
            .ok_or_else(|| Error::Reject(format!("unknown attribute {}", p.attribute)))?;
        let (c_idx, d) = &committed[k];
        let mut view = CommittedView { credential: k, attribute: spec.clone(), indexes: vec![], commitments: vec![] };
        for m in range {
            let pos = c_idx
                .iter()
                .position(|&x| x as usize == m)
                .ok_or_else(|| Error::Reject("plugin attribute is not committed".into()))?;
            view.indexes.push(m as u16);
            view.commitments.push(d[pos]);
        }
        views.push(view);
    }
    Ok((ctx, env, views))
}

/// Result of a successful verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Per credential: (attribute name, value) of each disclosed attribute.
    pub disclosed: Vec<Vec<(String, Vec<u8>)>>,
    /// Per plugin request: the plugin's public output.
    pub outputs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub struct VerifyStats {
    pub parse: Duration,
    pub bbs: Duration,
    pub plugins: Vec<Duration>,
    pub total: Duration,
}

/// Envelope verifier with a registry of plugin verifiers.
#[derive(Default)]
pub struct Verifier {
    plugins: Vec<Box<dyn PluginVerifier>>,
}

impl Verifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(mut self, p: Box<dyn PluginVerifier>) -> Self {
        assert!(self.find(p.plugin_id()).is_none(), "plugin id registered twice");
        self.plugins.push(p);
        self
    }

    pub fn find(&self, id: &[u8]) -> Option<&dyn PluginVerifier> {
        self.plugins.iter().find(|p| p.plugin_id() == id).map(|p| p.as_ref())
    }

    /// Verifier-side request check: structure, issuers and plugin policies.
    pub fn check_request(&self, issuers: &[IssuerParams], request: &Request) -> Result<()> {
        request.validate(issuers)?;
        for p in &request.plugins {
            let v = self.find(&p.plugin_id).ok_or_else(|| {
                Error::Reject(format!("request: unsupported plugin {}", String::from_utf8_lossy(&p.plugin_id)))
            })?;
            let (_, a, _) = issuers[p.credential as usize].schema.find(&p.attribute).expect("validated");
            v.check_request(a, &p.params)?;
        }
        Ok(())
    }

    /// Stateless acceptance predicate.  `issuers` follow `request.credentials`.
    /// Without `rng`, verifier randomness is a ChaCha20 stream seeded from the
    /// operating system.
    pub fn verify(
        &self,
        issuers: &[IssuerParams],
        request: &Request,
        presentation: &[u8],
        rng: Option<&mut dyn CryptoRngCore>,
        stats: Option<&mut VerifyStats>,
    ) -> Result<Verified> {
        let t0 = Instant::now();
        self.check_request(issuers, request)?;
        let pe = parse(presentation, issuers, request)?;
        let t_parse = Instant::now();
        let ph = request.presentation_header();
        let mut disclosed = Vec::with_capacity(issuers.len());
        for (k, (iss, pc)) in issuers.iter().zip(&pe.credentials).enumerate() {
            let msgs: Vec<Message> = pc.disclosed.iter().map(|v| Message::Octets(v.clone())).collect();
            ProofVerify(
                SUITE,
                &iss.pk,
                &pc.bbs_proof,
                &iss.header(),
                &ph,
                &msgs,
                &pc.bbs.commitments,
                &iss.message_types(),
                &request.disclosure_states(k, &iss.schema),
            )
            .map_err(|e| Error::Reject(format!("credential {k}: bbs: {e}")))?;
            let names = request.credentials[k].disclose.iter().cloned();
            disclosed.push(names.zip(pc.disclosed.iter().cloned()).collect());
        }
        let t_bbs = Instant::now();
        let (ctx, env, views) = verifier_statements(issuers, request, &pe)?;
        let mut own;
        let rng: &mut dyn CryptoRngCore = match rng {
            Some(r) => r,
            None => {
                own = rand_chacha::ChaCha20Rng::from_rng(rand_core::OsRng)
                    .map_err(|e| Error::Reject(format!("verifier randomness unavailable: {e}")))?;
                &mut own
            }
        };
        let mut outputs = Vec::with_capacity(request.plugins.len());
        let mut times = Vec::with_capacity(request.plugins.len());
        for (i, (p, proof)) in request.plugins.iter().zip(&pe.plugin_proofs).enumerate() {
            let view = &views[i];
            let ectx =
                EnvContext { nonce: request.nonce.clone(), ctx: ctx.clone(), env: env.clone(), plugin_index: i as u16 };
            let tp = Instant::now();
            let out = self.find(&p.plugin_id).expect("checked").verify(&ectx, view, &p.params, proof, rng)?;
            times.push(tp.elapsed());
            outputs.push(out);
        }
        if let Some(st) = stats {
            *st = VerifyStats { parse: t_parse - t0, bbs: t_bbs - t_parse, plugins: times, total: t0.elapsed() };
        }
        Ok(Verified { disclosed, outputs })
    }
}
