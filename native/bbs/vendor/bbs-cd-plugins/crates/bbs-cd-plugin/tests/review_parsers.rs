use bbs_cd_plugin::envelope::{parse, prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer, IssuerParams};
use bbs_cd_plugin::request::{CredentialRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use rand_core::OsRng;

fn bytes(seed: &mut u64, len: usize) -> Vec<u8> {
    (0..len)
        .map(|_| {
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            *seed as u8
        })
        .collect()
}

#[test]
fn single_byte_mutations_of_valid_envelope_are_rejected() {
    let schema = Schema::new("review", vec![AttributeSpec::octets("name")]).unwrap();
    let issuer = Issuer::from_seed(schema, vec![], &[43; 32]).unwrap();
    let credential = issuer.issue(&[AttrValue::Octets(b"Alice".to_vec())]).unwrap();
    let request = Request {
        audience: b"review-verifier".to_vec(),
        nonce: vec![9; 32],
        credentials: vec![CredentialRequest::new(&issuer.params, &["name"])],
        plugins: vec![],
    };
    let slot = prepare_credential(&credential, &[], &mut OsRng).unwrap();
    let presentation = present(&request, &[&credential], vec![slot], vec![], &mut OsRng, None).unwrap();
    let verifier = Verifier::new();
    assert!(verifier.verify(std::slice::from_ref(&issuer.params), &request, &presentation, None, None).is_ok());
    for i in 0..presentation.len() {
        let mut changed = presentation.clone();
        changed[i] ^= 1;
        assert!(
            verifier.verify(std::slice::from_ref(&issuer.params), &request, &changed, None, None).is_err(),
            "mutated byte {i} was accepted"
        );
    }
}

#[test]
fn arbitrary_wire_bytes_do_not_panic_framework_decoders() {
    let schema = Schema::new("review", vec![AttributeSpec::octets("name")]).unwrap();
    let issuer = Issuer::from_seed(schema, vec![], &[42; 32]).unwrap();
    let params: IssuerParams = issuer.params;
    let request = Request {
        audience: b"review-verifier".to_vec(),
        nonce: vec![7; 32],
        credentials: vec![CredentialRequest::new(&params, &["name"])],
        plugins: vec![],
    };
    let mut seed = 0x5eed_1234_5678_9abcu64;
    for len in 0..2048 {
        let data = bytes(&mut seed, len);
        let result = std::panic::catch_unwind(|| {
            let _ = Request::decode(&data);
            let _ = Schema::decode(&data);
            let _ = IssuerParams::decode(&data);
            let _ = parse(&data, std::slice::from_ref(&params), &request);
        });
        assert!(result.is_ok(), "decoder panicked at length {len}");
    }
}
