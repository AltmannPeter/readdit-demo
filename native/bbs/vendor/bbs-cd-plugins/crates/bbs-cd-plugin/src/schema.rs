//! Credential schema: an ordered list of named attributes.  Each attribute
//! occupies consecutive BBS messages:
//!
//! * `Octets`: one OCTETS message; may be disclosed or hidden;
//! * `Scalars`: `count` SCALAR messages, each < 2^`bits`, of a plugin-defined
//!   type (`type_id`); may be committed for a plugin or hidden.
//!
//! The canonical encoding of the schema is part of the BBS header, so the
//! issuer's signature fixes the layout.
use std::ops::Range;

use bbs_cd::types::{MessageType, OCTETS, SCALAR};

use crate::codec::{Reader, Writer};
use crate::error::{decode, Error, Result};
use crate::params::{DST_SCHEMA, MAX_MESSAGES, MAX_NAME_LEN, MAX_SCHEMA_ATTRIBUTES};
use crate::transcript::Transcript;

/// A plugin-defined attribute made of scalars.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScalarsSpec {
    /// Attribute type, e.g. `p256-point-xy.ecdsa-sha256`.  Its handler encodes issuance
    /// input and runs the type's issuance checks.
    pub type_id: String,
    /// Number of SCALAR messages (1..=128).
    pub count: u16,
    /// Every scalar is < 2^bits (1..=255).
    pub bits: u16,
    /// Reserved for blind issuance (holder secrets).  Must be `false` in 0.1.
    pub blind: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AttrKind {
    Octets,
    Scalars(ScalarsSpec),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttributeSpec {
    pub name: String,
    pub kind: AttrKind,
}

impl AttributeSpec {
    pub fn octets(name: &str) -> Self {
        AttributeSpec { name: name.into(), kind: AttrKind::Octets }
    }
    pub fn scalars(name: &str, type_id: &str, count: u16, bits: u16) -> Self {
        AttributeSpec {
            name: name.into(),
            kind: AttrKind::Scalars(ScalarsSpec { type_id: type_id.into(), count, bits, blind: false }),
        }
    }
    /// Number of BBS messages.
    pub fn message_count(&self) -> usize {
        match &self.kind {
            AttrKind::Octets => 1,
            AttrKind::Scalars(s) => s.count as usize,
        }
    }
    pub fn scalars_spec(&self) -> Option<&ScalarsSpec> {
        match &self.kind {
            AttrKind::Scalars(s) => Some(s),
            AttrKind::Octets => None,
        }
    }
}

fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
}

/// A validated schema.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Schema {
    id: String,
    attrs: Vec<AttributeSpec>,
}

impl Schema {
    pub fn new(id: &str, attrs: Vec<AttributeSpec>) -> Result<Self> {
        let bad = |s: String| Err(Error::Decode(format!("schema: {s}")));
        if !valid_name(id) {
            return bad("schema id".into());
        }
        if attrs.is_empty() || attrs.len() > MAX_SCHEMA_ATTRIBUTES {
            return bad("attribute count".into());
        }
        let mut total = 0usize;
        for (i, a) in attrs.iter().enumerate() {
            if !valid_name(&a.name) {
                return bad(format!("attribute name {:?}", a.name));
            }
            if attrs[..i].iter().any(|b| b.name == a.name) {
                return bad(format!("duplicate attribute {:?}", a.name));
            }
            if let AttrKind::Scalars(s) = &a.kind {
                if !valid_name(&s.type_id) {
                    return bad(format!("type id {:?}", s.type_id));
                }
                if s.count == 0 || s.count as usize > MAX_MESSAGES {
                    return bad(format!("{}: scalar count", a.name));
                }
                if s.bits == 0 || s.bits > 255 {
                    return bad(format!("{}: scalar bits", a.name));
                }
                if s.blind {
                    return bad(format!("{}: blind issuance is not supported in this version", a.name));
                }
            }
            total += a.message_count();
        }
        if total > MAX_MESSAGES {
            return bad("too many messages".into());
        }
        Ok(Schema { id: id.into(), attrs })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn attributes(&self) -> &[AttributeSpec] {
        &self.attrs
    }
    /// Total number of BBS messages L.
    pub fn message_count(&self) -> usize {
        self.attrs.iter().map(|a| a.message_count()).sum()
    }
    /// Position, spec and message range of an attribute.
    pub fn find(&self, name: &str) -> Option<(usize, &AttributeSpec, Range<usize>)> {
        let mut o = 0;
        for (i, a) in self.attrs.iter().enumerate() {
            let n = a.message_count();
            if a.name == name {
                return Some((i, a, o..o + n));
            }
            o += n;
        }
        None
    }
    /// Message range of an attribute.
    pub fn range(&self, name: &str) -> Option<Range<usize>> {
        self.find(name).map(|x| x.2)
    }
    pub fn message_types(&self) -> Vec<MessageType> {
        let mut t = Vec::with_capacity(self.message_count());
        for a in &self.attrs {
            match &a.kind {
                AttrKind::Octets => t.push(OCTETS),
                AttrKind::Scalars(s) => t.extend(std::iter::repeat_n(SCALAR, s.count as usize)),
            }
        }
        t
    }

    /// Canonical encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.var_u8(self.id.as_bytes()).u8(self.attrs.len() as u8);
        for a in &self.attrs {
            w.var_u8(a.name.as_bytes());
            match &a.kind {
                AttrKind::Octets => {
                    w.u8(0);
                }
                AttrKind::Scalars(s) => {
                    w.u8(1).var_u8(s.type_id.as_bytes()).u16(s.count).u16(s.bits).u8(s.blind as u8);
                }
            }
        }
        w.into_bytes()
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Reader::new(b, 1 << 14)?;
        let utf8 = |x: &[u8]| String::from_utf8(x.to_vec()).map_err(|_| Error::Decode("schema: utf-8".into()));
        let id = utf8(r.var_u8(MAX_NAME_LEN)?)?;
        let n = r.u8()? as usize;
        let mut attrs = Vec::with_capacity(n);
        for _ in 0..n {
            let name = utf8(r.var_u8(MAX_NAME_LEN)?)?;
            let kind = match r.u8()? {
                0 => AttrKind::Octets,
                1 => {
                    let type_id = utf8(r.var_u8(MAX_NAME_LEN)?)?;
                    let count = r.u16()?;
                    let bits = r.u16()?;
                    let blind = match r.u8()? {
                        0 => false,
                        1 => true,
                        _ => return decode("schema: blind flag"),
                    };
                    AttrKind::Scalars(ScalarsSpec { type_id, count, bits, blind })
                }
                _ => return decode("schema: attribute kind"),
            };
            attrs.push(AttributeSpec { name, kind });
        }
        r.end()?;
        let s = Schema::new(&id, attrs)?;
        if s.encode() != b {
            return decode("schema: non-canonical encoding");
        }
        Ok(s)
    }

    /// SHA-256 digest of the canonical encoding (what a request names).
    pub fn digest(&self) -> [u8; 32] {
        Transcript::new(DST_SCHEMA).add(b"schema", &self.encode()).digest()
    }
}
