//! Strict canonical reader/writer.  Every failure is `Error::Decode`.
use crate::error::{decode, Result};
use num_bigint::BigUint;

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn u8(&mut self, x: u8) -> &mut Self {
        self.buf.push(x);
        self
    }
    pub fn u16(&mut self, x: u16) -> &mut Self {
        self.raw(&x.to_be_bytes())
    }
    pub fn u32(&mut self, x: u32) -> &mut Self {
        self.raw(&x.to_be_bytes())
    }
    pub fn var_u8(&mut self, b: &[u8]) -> &mut Self {
        assert!(b.len() < 256);
        self.u8(b.len() as u8).raw(b)
    }
    pub fn var_u16(&mut self, b: &[u8]) -> &mut Self {
        assert!(b.len() < 1 << 16);
        self.u16(b.len() as u16).raw(b)
    }
    pub fn var_u32(&mut self, b: &[u8]) -> &mut Self {
        self.u32(b.len() as u32).raw(b)
    }
    /// Fixed-width big-endian integer; panics if it does not fit (prover bug).
    pub fn big(&mut self, x: &BigUint, n: usize) -> &mut Self {
        let b = x.to_bytes_be();
        assert!(b.len() <= n, "integer does not fit");
        self.buf.extend(std::iter::repeat_n(0u8, n - b.len()));
        self.raw(&b)
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    b: &'a [u8],
    o: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8], max_len: usize) -> Result<Self> {
        if b.len() > max_len {
            return decode("input exceeds size limit");
        }
        Ok(Reader { b, o: 0 })
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.o.checked_add(n).is_none_or(|e| e > self.b.len()) {
            return decode("truncated input");
        }
        let out = &self.b[self.o..self.o + n];
        self.o += n;
        Ok(out)
    }
    pub fn arr<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.arr()?))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.arr()?))
    }
    pub fn var_u8(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        if n > max {
            return decode("length field exceeds limit");
        }
        self.take(n)
    }
    pub fn var_u16(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        if n > max {
            return decode("length field exceeds limit");
        }
        self.take(n)
    }
    pub fn var_u32(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.u32()? as usize;
        if n > max {
            return decode("length field exceeds limit");
        }
        self.take(n)
    }
    /// Fixed-width big-endian integer in [lo, hi).
    pub fn big(&mut self, n: usize, lo: &BigUint, hi: &BigUint) -> Result<BigUint> {
        let x = BigUint::from_bytes_be(self.take(n)?);
        if &x < lo || &x >= hi {
            return decode("integer out of range");
        }
        Ok(x)
    }
    /// Bytes not yet read.
    pub fn remaining(&self) -> usize {
        self.b.len() - self.o
    }
    pub fn end(&self) -> Result<()> {
        if self.o != self.b.len() {
            return decode("trailing bytes");
        }
        Ok(())
    }
}
