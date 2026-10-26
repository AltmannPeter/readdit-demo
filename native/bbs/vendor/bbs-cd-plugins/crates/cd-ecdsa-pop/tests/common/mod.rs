#![allow(dead_code)]
use std::cell::RefCell;
use std::sync::Mutex;

use bbs_cd_plugin::envelope::{parse, prepare_credential, present, verifier_statements, ParsedEnvelope, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Credential, Issuer, IssuerParams};
use bbs_cd_plugin::plugin::{CommittedInput, CommittedView, CryptoRngCore, EnvContext, PluginProver};
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use bbs_cd_plugin::Result;
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::common::{segments, Segments};
use cd_ecdsa_pop::device::{HashSigner, RawSigner, SoftwareDevice};
use cd_ecdsa_pop::{
    prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, Mode, ProveStats, Signer, VerifyMode, PLUGIN_ID,
};
use cd_tom256::config::n_limbs;
use p256::Scalar;
use rand_core::OsRng;

pub const KEY: &str = "device_key";
pub const DISCLOSE: &str = "nationality";

/// Test schema whose device key is attested for `mode` only.
pub fn schema(mode: Mode, limb_bits: u8) -> Schema {
    Schema::new(
        "pid-test",
        vec![
            AttributeSpec::scalars(KEY, mode.key_type(), n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::octets("name"),
            AttributeSpec::octets("birth_date"),
            AttributeSpec::octets(DISCLOSE),
            AttributeSpec::octets("country"),
        ],
    )
    .unwrap()
}

pub fn values(device_pub: &[u8; 33], att: &[u8], name: &str) -> Vec<AttrValue> {
    vec![
        AttrValue::Input(key_input(device_pub, att)),
        AttrValue::Octets(name.as_bytes().to_vec()),
        AttrValue::Octets(b"1990-01-01".to_vec()),
        AttrValue::Octets(b"SE".to_vec()),
        AttrValue::Octets(b"DK".to_vec()),
    ]
}

pub struct World {
    pub man: Manufacturer,
    pub iss: Issuer,
    pub dev: SoftwareDevice,
    pub cred: Credential,
    pub limb_bits: u8,
    /// The only mode the device key is attested (and the device usable) for.
    pub mode: Mode,
}

/// Issuer, device and credential for `mode` (a device key serves one mode).
pub fn world_for(mode: Mode) -> World {
    world_with(mode, 96, false)
}

pub fn world_with(mode: Mode, limb_bits: u8, deterministic: bool) -> World {
    let man = Manufacturer::new();
    let iss = Issuer::new(schema(mode, limb_bits), vec![Box::new(P256KeyHandler::new(vec![man.public_key()], mode))])
        .unwrap();
    let (dev, att) = man.provision(mode, deterministic);
    let cred = iss.issue(&values(&dev.hash_public_key().unwrap(), &att, "Alice")).unwrap();
    World { man, iss, dev, cred, limb_bits, mode }
}

pub fn verifier() -> Verifier {
    Verifier::new().register(Box::new(EcdsaPopVerifier::new()))
}

pub fn verifier_mode(mode: VerifyMode) -> Verifier {
    Verifier::new().register(Box::new(EcdsaPopVerifier { verify_mode: mode, ..EcdsaPopVerifier::new() }))
}

impl World {
    pub fn params(&self, mode: Mode) -> EcdsaParams {
        match mode {
            Mode::Hashed => EcdsaParams::hashed(self.limb_bits),
            Mode::Raw => EcdsaParams::raw(self.limb_bits),
        }
    }

    pub fn request_with(&self, p: &EcdsaParams) -> Request {
        Request::new(
            b"rp.example",
            vec![CredentialRequest::new(&self.iss.params, &[DISCLOSE])],
            vec![PluginRequest {
                plugin_id: PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: KEY.into(),
                params: p.encode(),
            }],
            &mut OsRng,
        )
    }

    pub fn request(&self, mode: Mode) -> Request {
        self.request_with(&self.params(mode))
    }

    pub fn issuers(&self) -> Vec<IssuerParams> {
        vec![self.iss.params.clone()]
    }

    pub fn other_credential(&self, name: &str) -> (SoftwareDevice, Credential) {
        let (dev, att) = self.man.provision(self.mode, false);
        let cred = self.iss.issue(&values(&dev.hash_public_key().unwrap(), &att, name)).unwrap();
        (dev, cred)
    }

    pub fn honest(&self, mode: Mode) -> (Request, Vec<u8>) {
        let req = self.request(mode);
        let out = present_with(&req, &self.cred, &self.dev, mode, None).unwrap();
        (req, out)
    }

    pub fn ok(&self, req: &Request, b: &[u8]) -> bool {
        verifier().verify(&self.issuers(), req, b, None, None).is_ok()
    }

    pub fn reject(&self, req: &Request, b: &[u8]) -> bbs_cd_plugin::Error {
        verifier().verify(&self.issuers(), req, b, None, None).expect_err("must reject")
    }
}

/// Committed input of the key attribute for a fresh credential slot.
pub fn slot_and_input(cred: &Credential) -> (bbs_cd_plugin::envelope::CredentialSlot, CommittedInput) {
    let slot = prepare_credential(cred, &[KEY], &mut OsRng).unwrap();
    let input = slot.committed_input(cred, 0, KEY).unwrap();
    (slot, input)
}

/// Honest holder with `dev` for the (single) plugin request of `req`.
pub fn present_with(
    req: &Request,
    cred: &Credential,
    dev: &SoftwareDevice,
    mode: Mode,
    stats: Option<&RefCell<ProveStats>>,
) -> Result<Vec<u8>> {
    let params = EcdsaParams::decode(&req.plugins[0].params)?;
    let (cslot, input) = slot_and_input(cred);
    let pslot = prepare(&input, &params, 4, bbs_cd_plugin::par::Parallelism::Off, &mut OsRng)?;
    let signer = match mode {
        Mode::Hashed => Signer::Hash(dev),
        Mode::Raw => Signer::Raw(dev),
    };
    let mut prover = EcdsaPopProver::new(pslot, signer);
    prover.stats = stats;
    present(req, &[cred], vec![cslot], vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)
}

/// Absolute byte ranges of the plugin proof sections in a presentation.
pub fn plugin_segments(w: &World, req: &Request, b: &[u8]) -> Segments {
    let pe = parse(b, &w.issuers(), req).unwrap();
    let off = pe.plugin_ranges[0].0;
    let params = EcdsaParams::decode(&req.plugins[0].params).unwrap();
    let (_, spec, _) = w.iss.params.schema.find(KEY).unwrap();
    let mut s = segments(spec, &params).unwrap();
    assert_eq!(s.len, pe.plugin_ranges[0].1 - off, "exact proof size");
    let sh = |r: &mut (usize, usize)| {
        if r.1 > r.0 {
            *r = (r.0 + off, r.1 + off);
        }
    };
    for r in [&mut s.magic, &mut s.nh, &mut s.point, &mut s.r, &mut s.s, &mut s.oc, &mut s.link, &mut s.sm] {
        sh(r);
    }
    for r in s.t.iter_mut().chain(s.tr.iter_mut()).chain(s.tr_z.iter_mut()) {
        sh(r);
    }
    s
}

/// The plugin's EnvContext and view, recomputed from a presentation.
pub fn env_and_view(w: &World, req: &Request, b: &[u8]) -> (ParsedEnvelope, EnvContext, CommittedView) {
    let pe = parse(b, &w.issuers(), req).unwrap();
    let (ctx, env, views) = verifier_statements(&w.issuers(), req, &pe).unwrap();
    let e = EnvContext { nonce: req.nonce.clone(), ctx, env, plugin_index: 0 };
    (pe, e, views.into_iter().next().unwrap())
}

/// Attacker "signer" after device loss: returns a retained / forged signature.
pub struct ReplaySigner {
    pub sig: (Scalar, Scalar),
    pub pubkey: [u8; 33],
    pub seen: Mutex<Vec<[u8; 32]>>,
}

impl RawSigner for ReplaySigner {
    fn public_key(&self) -> Result<[u8; 33]> {
        Ok(self.pubkey)
    }
    fn sign_representative(&self, rep: &[u8; 32]) -> Result<(Scalar, Scalar)> {
        self.seen.lock().unwrap().push(*rep);
        Ok(self.sig)
    }
}

pub fn put(b: &[u8], range: (usize, usize), v: &[u8]) -> Vec<u8> {
    assert_eq!(range.1 - range.0, v.len(), "replacement length");
    let mut o = b.to_vec();
    o[range.0..range.1].copy_from_slice(v);
    o
}

pub const MODES: [Mode; 2] = [Mode::Hashed, Mode::Raw];

/// A plugin prover that runs a closure: lets a test act as a malicious
/// holder that builds the `ecdsa-pop` proof by hand.
pub struct FnProver<F>(pub F);

impl<F> PluginProver for FnProver<F>
where
    F: FnOnce(&EnvContext, &CommittedInput, &[u8], &mut dyn CryptoRngCore) -> Result<Vec<u8>>,
{
    fn plugin_id(&self) -> &[u8] {
        PLUGIN_ID
    }
    fn prove(
        self: Box<Self>,
        env: &EnvContext,
        input: &CommittedInput,
        params: &[u8],
        rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>> {
        (self.0)(env, input, params, rng)
    }
}
