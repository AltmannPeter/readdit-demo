//! Stateful verifier front end: fresh nonces, at most one presentation per
//! outstanding nonce (replay protection is verifier state; `Verifier::verify`
//! is stateless).  Outstanding requests expire after `ttl` and are bounded by
//! `max_outstanding`; when full, the oldest request is dropped.
use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand_core::{CryptoRng, RngCore};

use crate::envelope::{Verified, Verifier};
use crate::error::{Error, Result};
use crate::issuer::IssuerParams;
use crate::request::{CredentialRequest, PluginRequest, Request};

/// Default bound on outstanding requests.
pub const SESSION_MAX_OUTSTANDING: usize = 10_000;
/// Default lifetime of an outstanding request.
pub const SESSION_TTL: Duration = Duration::from_secs(300);

pub struct VerifierSession {
    pub verifier: Verifier,
    pub audience: Vec<u8>,
    max_outstanding: usize,
    ttl: Duration,
    open: HashMap<Vec<u8>, (Request, Vec<IssuerParams>, Instant)>,
}

impl VerifierSession {
    pub fn new(verifier: Verifier, audience: &[u8]) -> Self {
        Self::with_limits(verifier, audience, SESSION_MAX_OUTSTANDING, SESSION_TTL)
    }

    pub fn with_limits(verifier: Verifier, audience: &[u8], max_outstanding: usize, ttl: Duration) -> Self {
        VerifierSession {
            verifier,
            audience: audience.to_vec(),
            max_outstanding: max_outstanding.max(1),
            ttl,
            open: HashMap::new(),
        }
    }

    /// Number of outstanding (issued, unanswered, possibly expired) requests.
    pub fn outstanding(&self) -> usize {
        self.open.len()
    }

    /// Issue a request.  It is checked against the issuers and the registered
    /// plugins before it is recorded.
    pub fn request<R: RngCore + CryptoRng + ?Sized>(
        &mut self,
        issuers: &[IssuerParams],
        credentials: Vec<CredentialRequest>,
        plugins: Vec<PluginRequest>,
        rng: &mut R,
    ) -> Result<Request> {
        let req = Request::new(&self.audience, credentials, plugins, rng);
        self.verifier.check_request(issuers, &req)?;
        let now = Instant::now();
        let ttl = self.ttl;
        self.open.retain(|_, (_, _, t)| now.duration_since(*t) < ttl);
        while self.open.len() >= self.max_outstanding {
            let oldest = self.open.iter().min_by_key(|(_, (_, _, t))| *t).map(|(k, _)| k.clone());
            match oldest {
                Some(k) => {
                    self.open.remove(&k);
                }
                None => break,
            }
        }
        self.open.insert(req.nonce.clone(), (req.clone(), issuers.to_vec(), now));
        Ok(req)
    }

    /// Consumes the nonce before verifying.  Expired nonces are rejected.
    pub fn accept(&mut self, nonce: &[u8], presentation: &[u8]) -> Result<Verified> {
        let (req, issuers, issued) =
            self.open.remove(nonce).ok_or_else(|| Error::Reject("unknown or already used nonce".into()))?;
        if issued.elapsed() >= self.ttl {
            return Err(Error::Reject("expired nonce".into()));
        }
        self.verifier.verify(&issuers, &req, presentation, None, None)
    }
}
