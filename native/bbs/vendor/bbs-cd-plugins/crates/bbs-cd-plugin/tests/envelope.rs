//! Framework tests with the example plugin (`tests/common`): schema, issuer,
//! request, envelope binding, multi-credential presentations, parsing and
//! the verifier session.
mod common;

use std::time::Duration;

use bbs_cd_plugin::codec::{Reader, Writer};
use bbs_cd_plugin::envelope::{parse, prepare_credential, present, Verifier};
use bbs_cd_plugin::error::Error;
use bbs_cd_plugin::issuer::{AttrValue, Credential, Issuer, IssuerParams};
use bbs_cd_plugin::params::*;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use bbs_cd_plugin::session::VerifierSession;
use bbs_cd_plugin::transcript::Transcript;
use common::*;
use rand_core::OsRng;

fn schema(id: &str) -> Schema {
    Schema::new(
        id,
        vec![
            AttributeSpec::octets("name"),
            AttributeSpec::scalars("age", TYPE_UINT, 1, 16),
            AttributeSpec::octets("country"),
            AttributeSpec::scalars("score", TYPE_UINT, 1, 64),
        ],
    )
    .unwrap()
}

fn issuer(id: &str) -> Issuer {
    Issuer::new(schema(id), vec![Box::new(UintHandler)]).unwrap()
}

fn cred(iss: &Issuer, name: &str, age: u128, score: u128) -> Credential {
    iss.issue(&[
        AttrValue::Octets(name.as_bytes().to_vec()),
        AttrValue::Input(uint_input(age)),
        AttrValue::Octets(b"DK".to_vec()),
        AttrValue::Input(uint_input(score)),
    ])
    .unwrap()
}

fn eq(cred: u8, attr: &str, v: u128) -> PluginRequest {
    PluginRequest {
        plugin_id: EQ_ID.to_vec(),
        credential: cred,
        attribute: attr.into(),
        params: v.to_be_bytes().to_vec(),
    }
}

fn verifier() -> Verifier {
    Verifier::new().register(Box::new(EqVerifier))
}

/// Holder: prepare the commitments the request needs and present.
fn holder(req: &Request, creds: &[&Credential]) -> bbs_cd_plugin::Result<Vec<u8>> {
    let mut slots = vec![];
    for (k, c) in creds.iter().enumerate() {
        let names = req.committed_attributes(k, &c.issuer.schema);
        let names: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        slots.push(prepare_credential(c, &names, &mut OsRng)?);
    }
    let provers: Vec<Box<dyn PluginProver>> =
        req.plugins.iter().map(|_| Box::new(EqProver) as Box<dyn PluginProver>).collect();
    present(req, creds, slots, provers, &mut OsRng, None)
}

#[test]
fn schema_roundtrip_and_rejections() {
    let s = schema("pid");
    assert_eq!(Schema::decode(&s.encode()).unwrap(), s);
    assert_eq!(s.message_count(), 4);
    assert_eq!(s.range("score"), Some(3..4));
    let mut b = s.encode();
    b.push(0);
    assert!(Schema::decode(&b).is_err(), "trailing byte");
    assert!(Schema::new("pid", vec![AttributeSpec::octets("a"), AttributeSpec::octets("a")]).is_err(), "duplicate");
    assert!(Schema::new("pid", vec![AttributeSpec::octets("A")]).is_err(), "name charset");
    assert!(Schema::new("pid", vec![AttributeSpec::scalars("k", "t", 0, 8)]).is_err(), "count 0");
    assert!(Schema::new("pid", vec![AttributeSpec::scalars("k", "t", 1, 256)]).is_err(), "bits");
    let mut blind = AttributeSpec::scalars("k", "t", 1, 8);
    if let bbs_cd_plugin::schema::AttrKind::Scalars(sp) = &mut blind.kind {
        sp.blind = true;
    }
    assert!(Schema::new("pid", vec![blind]).is_err(), "blind issuance is reserved");
    assert!(Schema::new("pid", vec![AttributeSpec::scalars("k", "t", 129, 8)]).is_err(), "too many messages");
    assert_ne!(schema("pid").digest(), schema("pid2").digest());
}

#[test]
fn issuer_checks_and_params_roundtrip() {
    let iss = issuer("pid");
    assert_eq!(IssuerParams::decode(&iss.params.encode()).unwrap(), iss.params);
    let c = cred(&iss, "Alice", 42, 7);
    c.verify().unwrap();
    assert_eq!(c.octets("name"), Some(&b"Alice"[..]));
    assert!(c.octets("age").is_none());
    // a value out of the attribute's range is refused by the handler
    let bad = iss.issue(&[
        AttrValue::Octets(b"A".to_vec()),
        AttrValue::Input(uint_input(1 << 16)),
        AttrValue::Octets(b"DK".to_vec()),
        AttrValue::Input(uint_input(1)),
    ]);
    assert!(bad.is_err());
    // wrong value kind, wrong count, oversize attribute
    assert!(iss.issue(&[AttrValue::Octets(b"A".to_vec())]).is_err());
    let big = vec![0u8; MAX_ATTR_LEN + 1];
    assert!(iss
        .issue(&[
            AttrValue::Octets(big),
            AttrValue::Input(uint_input(1)),
            AttrValue::Octets(vec![]),
            AttrValue::Input(uint_input(1))
        ])
        .is_err());
    // no handler for a scalar type
    assert!(Issuer::new(schema("pid"), vec![]).is_err());
    // tampered message fails holder validation
    let mut t = c.clone();
    t.messages[0] = bbs_cd::types::Message::Octets(b"Mallory".to_vec());
    assert!(t.verify().is_err());
}

#[test]
fn request_roundtrip_and_validation() {
    let iss = issuer("pid");
    let p = &iss.params;
    let req = Request::new(b"rp", vec![CredentialRequest::new(p, &["name"])], vec![eq(0, "age", 42)], &mut OsRng);
    assert_eq!(Request::decode(&req.encode()).unwrap(), req);
    req.validate(std::slice::from_ref(p)).unwrap();
    let mut r = req.clone();
    r.credentials[0].disclose = vec!["age".into()];
    assert!(r.validate(std::slice::from_ref(p)).is_err(), "scalars cannot be disclosed");
    let mut r = req.clone();
    r.credentials[0].disclose = vec!["country".into(), "name".into()];
    assert!(r.validate(std::slice::from_ref(p)).is_err(), "schema order");
    let mut r = req.clone();
    r.plugins[0].attribute = "name".into();
    assert!(r.validate(std::slice::from_ref(p)).is_err(), "octets cannot be committed");
    let mut r = req.clone();
    r.plugins.push(r.plugins[0].clone());
    assert!(r.validate(std::slice::from_ref(p)).is_err(), "duplicate plugin request");
    let mut r = req.clone();
    r.nonce.truncate(8);
    assert!(r.validate(std::slice::from_ref(p)).is_err(), "short nonce");
    let other = issuer("pid");
    assert!(req.validate(std::slice::from_ref(&other.params)).is_err(), "issuer mismatch");
    let (c, d) = req.message_indexes(0, &p.schema);
    assert_eq!((c, d), (vec![1], vec![0]));
    // every request field changes the context
    let mut r = req.clone();
    r.audience = b"rp2".to_vec();
    assert_ne!(r.context(), req.context());
    let mut r = req.clone();
    r.plugins[0].params = 43u128.to_be_bytes().to_vec();
    assert_ne!(r.context(), req.context());
    let mut r = req.clone();
    r.nonce[0] ^= 1;
    assert_eq!(r.context(), req.context());
    assert_ne!(r.presentation_header(), req.presentation_header());
}

#[test]
fn honest_presentation_two_credentials() {
    let (pid, mdl) = (issuer("pid"), issuer("mdl"));
    let (c1, c2) = (cred(&pid, "Alice", 42, 7), cred(&mdl, "Alice", 42, 99));
    let issuers = [pid.params.clone(), mdl.params.clone()];
    let req = Request::new(
        b"rp",
        vec![CredentialRequest::new(&pid.params, &["name", "country"]), CredentialRequest::new(&mdl.params, &[])],
        vec![eq(0, "age", 42), eq(1, "score", 99), eq(0, "score", 7)],
        &mut OsRng,
    );
    let p = holder(&req, &[&c1, &c2]).unwrap();
    let v = verifier().verify(&issuers, &req, &p, None, None).unwrap();
    assert_eq!(v.disclosed[0], vec![("name".to_string(), b"Alice".to_vec()), ("country".to_string(), b"DK".to_vec())]);
    assert!(v.disclosed[1].is_empty());
    assert_eq!(v.outputs, vec![b"equal".to_vec(); 3]);
    // a false statement cannot be proven
    let req2 = Request::new(b"rp", vec![CredentialRequest::new(&pid.params, &[])], vec![eq(0, "age", 41)], &mut OsRng);
    let p2 = holder(&req2, &[&c1]).unwrap();
    assert!(verifier().verify(std::slice::from_ref(&pid.params), &req2, &p2, None, None).is_err());
}

#[test]
fn bound_to_request_and_commitments() {
    let iss = issuer("pid");
    let c = cred(&iss, "Alice", 42, 7);
    let issuers = [iss.params.clone()];
    let req =
        Request::new(b"rp", vec![CredentialRequest::new(&iss.params, &["name"])], vec![eq(0, "age", 42)], &mut OsRng);
    let p = holder(&req, &[&c]).unwrap();
    let vf = verifier();
    vf.verify(&issuers, &req, &p, None, None).unwrap();
    for change in 0..4 {
        let mut r = req.clone();
        match change {
            0 => r.nonce[0] ^= 1,
            1 => r.audience = b"other".to_vec(),
            2 => r.credentials[0].disclose = vec![],
            _ => r.plugins[0].attribute = "score".into(),
        }
        if r == req {
            continue;
        }
        assert!(vf.verify(&issuers, &r, &p, None, None).is_err(), "change {change} accepted");
    }
    // A second presentation for the same request: swapping its plugin proof in fails.
    let p2 = holder(&req, &[&c]).unwrap();
    let pe1 = parse(&p, &issuers, &req).unwrap();
    let pe2 = parse(&p2, &issuers, &req).unwrap();
    let (a, b) = pe1.plugin_ranges[0];
    let (a2, b2) = pe2.plugin_ranges[0];
    let mut spliced = p.clone();
    spliced.splice(a..b, p2[a2..b2].iter().copied());
    assert!(vf.verify(&issuers, &req, &spliced, None, None).is_err(), "plugin proof from another presentation");
    // Flip a byte in every section.
    for pos in [6, pe1.credentials[0].bbs_range.0 + 10, a + 3, b - 1, p.len() - 1] {
        let mut t = p.clone();
        t[pos] ^= 1;
        assert!(vf.verify(&issuers, &req, &t, None, None).is_err(), "flip at {pos} accepted");
    }
    let mut t = p.clone();
    t.push(0);
    assert!(matches!(vf.verify(&issuers, &req, &t, None, None), Err(Error::Decode(_))));
}

#[test]
fn unknown_plugin_and_slot_mismatch() {
    let iss = issuer("pid");
    let c = cred(&iss, "Alice", 42, 7);
    let req = Request::new(b"rp", vec![CredentialRequest::new(&iss.params, &[])], vec![eq(0, "age", 42)], &mut OsRng);
    let p = holder(&req, &[&c]).unwrap();
    assert!(
        Verifier::new().verify(std::slice::from_ref(&iss.params), &req, &p, None, None).is_err(),
        "unregistered plugin"
    );
    // a slot prepared for other committed attributes is refused
    let slot = prepare_credential(&c, &["score"], &mut OsRng).unwrap();
    let r = present(&req, &[&c], vec![slot], vec![Box::new(EqProver)], &mut OsRng, None);
    assert!(r.is_err());
}

#[test]
fn verifier_session_single_use_and_expiry() {
    let iss = issuer("pid");
    let c = cred(&iss, "Alice", 42, 7);
    let issuers = [iss.params.clone()];
    let mut s = VerifierSession::new(verifier(), b"rp");
    let req = s
        .request(&issuers, vec![CredentialRequest::new(&iss.params, &[])], vec![eq(0, "age", 42)], &mut OsRng)
        .unwrap();
    let p = holder(&req, &[&c]).unwrap();
    s.accept(&req.nonce, &p).unwrap();
    assert!(s.accept(&req.nonce, &p).is_err(), "replay");
    // unsupported plugin requests are refused when issued
    let bad = PluginRequest { plugin_id: b"nope".to_vec(), credential: 0, attribute: "age".into(), params: vec![] };
    assert!(s.request(&issuers, vec![CredentialRequest::new(&iss.params, &[])], vec![bad], &mut OsRng).is_err());
    let mut s = VerifierSession::with_limits(verifier(), b"rp", 2, Duration::from_millis(1));
    let req = s.request(&issuers, vec![CredentialRequest::new(&iss.params, &[])], vec![], &mut OsRng).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    let p = holder(&req, &[&c]).unwrap();
    assert!(s.accept(&req.nonce, &p).is_err(), "expired");
    for _ in 0..5 {
        s.request(&issuers, vec![CredentialRequest::new(&iss.params, &[])], vec![], &mut OsRng).unwrap();
    }
    assert!(s.outstanding() <= 2);
}

#[test]
fn transcript_injective_and_dsts_distinct() {
    let a = Transcript::new(b"D").add(b"ab", b"c").into_bytes();
    let b = Transcript::new(b"D").add(b"a", b"bc").into_bytes();
    let c = Transcript::new(b"D").add(b"a", b"b").add(b"", b"c").into_bytes();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(Transcript::new(b"D1").digest(), Transcript::new(b"D2").digest());
    let dsts = [DST_SCHEMA, DST_HDR, DST_CTX, DST_PH, DST_CSTMT, DST_ENV];
    for i in 0..dsts.len() {
        for j in i + 1..dsts.len() {
            assert_ne!(dsts[i], dsts[j]);
        }
    }
}

#[test]
fn reader_limits() {
    assert!(Reader::new(&[0u8; 10], 9).is_err());
    let mut w = Writer::new();
    w.var_u8(b"abc").u16(7);
    let b = w.into_bytes();
    let mut r = Reader::new(&b, 100).unwrap();
    assert!(r.var_u8(2).is_err(), "length above max");
    let mut r = Reader::new(&b, 100).unwrap();
    assert_eq!(r.var_u8(3).unwrap(), b"abc");
    assert_eq!(r.u16().unwrap(), 7);
    r.end().unwrap();
    let mut r = Reader::new(&b[..4], 100).unwrap();
    r.var_u8(3).unwrap();
    assert!(r.u16().is_err(), "truncated");
    let mut r = Reader::new(&b, 100).unwrap();
    r.var_u8(3).unwrap();
    assert!(r.end().is_err(), "trailing");
}
