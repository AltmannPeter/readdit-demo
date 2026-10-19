#![allow(dead_code)]
use bbs_cd_plugin::envelope::{prepare_credential, present, Verified, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Credential, Issuer, IssuerParams};
use bbs_cd_plugin::plugin::{CommittedInput, CryptoRngCore, EnvContext, PluginProver};
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use bbs_cd_plugin::Result;
use cd_date_range::{
    date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, PLUGIN_ID, TYPE_DATE,
};
use rand_core::{OsRng, RngCore};

pub const ATTR: &str = "birth_date";

pub struct World {
    pub iss: Issuer,
    pub cred: Credential,
}

pub fn schema(bits: u16) -> Schema {
    Schema::new(
        "pid-date-test",
        vec![
            AttributeSpec::octets("name"),
            AttributeSpec::scalars(ATTR, TYPE_DATE, 1, bits),
            AttributeSpec::octets("nationality"),
        ],
    )
    .unwrap()
}

/// Issuer (17-bit dates) and a credential with birth date `iso`.
pub fn world(iso: &str) -> World {
    world_bits(iso, 17)
}

pub fn world_bits(iso: &str, bits: u16) -> World {
    let iss = Issuer::new(schema(bits), vec![Box::new(DateHandler)]).unwrap();
    let cred = iss
        .issue(&[
            AttrValue::Octets(b"Alice".to_vec()),
            AttrValue::Input(date_input(iso)),
            AttrValue::Octets(b"SE".to_vec()),
        ])
        .unwrap();
    World { iss, cred }
}

impl World {
    pub fn issuers(&self) -> Vec<IssuerParams> {
        vec![self.iss.params.clone()]
    }

    pub fn request(&self, params: &DateRangeParams) -> Request {
        self.request_raw(params.encode())
    }

    pub fn request_raw(&self, params: Vec<u8>) -> Request {
        Request::new(
            b"rp.example",
            vec![CredentialRequest::new(&self.iss.params, &["nationality"])],
            vec![PluginRequest { plugin_id: PLUGIN_ID.to_vec(), credential: 0, attribute: ATTR.into(), params }],
            &mut OsRng,
        )
    }

    /// Present with any plugin prover.
    pub fn present_with<'a>(&self, req: &Request, prover: Box<dyn PluginProver + 'a>) -> Result<Vec<u8>> {
        let slot = prepare_credential(&self.cred, &[ATTR], &mut OsRng)?;
        present(req, &[&self.cred], vec![slot], vec![prover], &mut OsRng, None)
    }

    pub fn present(&self, req: &Request) -> Result<Vec<u8>> {
        self.present_with(req, Box::new(DateRangeProver::new()))
    }

    pub fn verify(&self, req: &Request, b: &[u8]) -> Result<Verified> {
        verifier().verify(&self.issuers(), req, b, None, None)
    }

    /// A plugin-level context (random env and nonce) and the committed input.
    pub fn plugin_input(&self) -> (EnvContext, CommittedInput) {
        let slot = prepare_credential(&self.cred, &[ATTR], &mut OsRng).unwrap();
        let input = slot.committed_input(&self.cred, 0, ATTR).unwrap();
        let mut env = vec![0u8; 200];
        OsRng.fill_bytes(&mut env);
        (EnvContext { nonce: env[..32].to_vec(), ctx: env[32..64].to_vec(), env, plugin_index: 0 }, input)
    }
}

pub fn verifier() -> Verifier {
    Verifier::new().register(Box::new(DateRangeVerifier))
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
