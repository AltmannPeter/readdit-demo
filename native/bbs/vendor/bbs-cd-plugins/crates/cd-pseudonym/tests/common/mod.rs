#![allow(dead_code)]
use bbs_cd_plugin::envelope::{prepare_credential, present, Verified, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Credential, Issuer, IssuerParams};
use bbs_cd_plugin::plugin::{CommittedInput, CryptoRngCore, EnvContext, PluginProver};
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use bbs_cd_plugin::Result;
use cd_pseudonym::{
    new_seed, NymSeedHandler, PseudonymParams, PseudonymProver, PseudonymVerifier, PLUGIN_ID,
    TYPE_NYM_SEED_ISSUER_KNOWN,
};
use rand_core::{OsRng, RngCore};

pub const ATTR: &str = "nym_seed";
pub const RP_A: &[u8] = b"https://rp-a.example";
pub const RP_B: &[u8] = b"https://rp-b.example";

pub struct World {
    pub iss: Issuer,
    pub seed: [u8; 32],
    pub cred: Credential,
}

pub fn schema() -> Schema {
    Schema::new(
        "pid-nym-test",
        vec![
            AttributeSpec::octets("name"),
            AttributeSpec::scalars(ATTR, TYPE_NYM_SEED_ISSUER_KNOWN, 1, 255),
            AttributeSpec::octets("nationality"),
        ],
    )
    .unwrap()
}

pub fn issuer() -> Issuer {
    Issuer::new(schema(), vec![Box::new(NymSeedHandler)]).unwrap()
}

/// Issuer and a credential with a fresh seed.
pub fn world() -> World {
    let iss = issuer();
    let seed = new_seed(&mut OsRng);
    let cred = issue(&iss, &seed);
    World { iss, seed, cred }
}

pub fn issue(iss: &Issuer, seed: &[u8; 32]) -> Credential {
    iss.issue(&[
        AttrValue::Octets(b"Alice".to_vec()),
        AttrValue::Input(seed.to_vec()),
        AttrValue::Octets(b"SE".to_vec()),
    ])
    .unwrap()
}

pub fn request_raw(iss: &Issuer, params: Vec<u8>) -> Request {
    Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&iss.params, &["nationality"])],
        vec![PluginRequest { plugin_id: PLUGIN_ID.to_vec(), credential: 0, attribute: ATTR.into(), params }],
        &mut OsRng,
    )
}

impl World {
    pub fn issuers(&self) -> Vec<IssuerParams> {
        vec![self.iss.params.clone()]
    }

    pub fn request(&self, rp: &[u8]) -> Request {
        request_raw(&self.iss, PseudonymParams::known_offender_matching(rp).encode())
    }

    pub fn present_with<'a>(&self, req: &Request, prover: Box<dyn PluginProver + 'a>) -> Result<Vec<u8>> {
        present_cred(&self.cred, req, prover)
    }

    /// Honest holder whose wallet read `rp` from the access certificate.
    pub fn present(&self, req: &Request, rp: &[u8]) -> Result<Vec<u8>> {
        self.present_with(req, Box::new(PseudonymProver::new(rp)))
    }

    pub fn verify(&self, req: &Request, b: &[u8]) -> Result<Verified> {
        verifier().verify(&self.issuers(), req, b, None, None)
    }

    /// Plugin-level context (random env and nonce) and committed input.
    pub fn plugin_input(&self) -> (EnvContext, CommittedInput) {
        let slot = prepare_credential(&self.cred, &[ATTR], &mut OsRng).unwrap();
        let input = slot.committed_input(&self.cred, 0, ATTR).unwrap();
        let mut env = vec![0u8; 200];
        OsRng.fill_bytes(&mut env);
        (EnvContext { nonce: env[..32].to_vec(), ctx: env[32..64].to_vec(), env, plugin_index: 0 }, input)
    }
}

pub fn present_cred<'a>(cred: &Credential, req: &Request, prover: Box<dyn PluginProver + 'a>) -> Result<Vec<u8>> {
    let slot = prepare_credential(cred, &[ATTR], &mut OsRng)?;
    present(req, &[cred], vec![slot], vec![prover], &mut OsRng, None)
}

pub fn verifier() -> Verifier {
    Verifier::new().register(Box::new(PseudonymVerifier::any()))
}

/// A plugin prover that runs a closure: a malicious holder.
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
