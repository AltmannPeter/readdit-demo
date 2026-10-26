//! Length-prefixed, domain-separated transcript (same encoding as the Python
//! prototype):  I2OSP(len(dst),1) || dst || ( I2OSP(len(label),1) || label ||
//! I2OSP(len(value),4) || value )*.
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    pub fn new(dst: &[u8]) -> Self {
        assert!(!dst.is_empty() && dst.len() < 256, "bad DST");
        let mut buf = vec![dst.len() as u8];
        buf.extend_from_slice(dst);
        Transcript { buf }
    }
    pub fn add(mut self, label: &[u8], value: &[u8]) -> Self {
        assert!(label.len() < 256 && (value.len() as u64) < (1u64 << 32));
        self.buf.push(label.len() as u8);
        self.buf.extend_from_slice(label);
        self.buf.extend_from_slice(&(value.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(value);
        self
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.buf).into()
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
