//! The Ligero tableau with its subfield rows packed (P1). A row whose entries all lie in the
//! 2-byte subfield (the witness rows below `subfield_boundary`: their randomness is drawn from the
//! subfield and the Reed–Solomon encoding over the subfield's points keeps them there) is stored
//! as each entry's subfield coordinates, 2 bytes, instead of the full 16-byte element. Every other
//! row is stored as full elements. A packed entry is expanded back to the full element wherever it
//! is used: the Merkle leaves (which hash the full element's bytes), the low-degree, dot and
//! quadratic responses, and the opened columns. The output is the same, byte for byte.
//!
//! Packing is checked: an entry packs only when its expansion gives back exactly its bytes, and a
//! row with an entry that does not is an internal error, never a silently different value.

use core_algebra::SerializableField;
use runtime_algebra::Subfield;

use crate::Error;

const DEFECT: Error = Error::Internal("inconsistent");
const NOT_IN_SUBFIELD: Error = Error::Internal("a packed row left the subfield");

/// Subfield coordinates (16 bits) from and to a field element's serialized bytes. Both maps are
/// GF(2)-linear in the bytes, so each is a table per byte: one table of 256 coordinates for each
/// byte that holds a pivot bit (GF(2^128)'s subfield: bytes 0 to 2) one way, two tables of 256
/// serialized elements the other (under 20 kB in all).
pub(crate) struct Packer {
    /// The field element's serialized size, in bytes.
    n: usize,
    /// For each byte position t that holds a pivot, and byte value b: the coordinates its bits
    /// contribute.
    q: Vec<(usize, [u16; 256])>,
    /// The serialized elements of the low byte's 256 values, then the high byte's (2 · 256 · n).
    s: Vec<u8>,
    /// The same as `s` as little-endian u128, for 16-byte elements (GF(2^128)).
    wide: Option<Box<[u128; 512]>>,
}

impl Packer {
    /// The packer for `sf` in `f`, when `sf` is a 2-byte subfield of a larger field; `None`
    /// otherwise (P-256's "subfield" is the whole field), or when the basis does not have full
    /// rank in `f`'s bytes.
    pub(crate) fn new<F, SF>(f: &F, sf: &SF) -> Option<Packer>
    where
        F: SerializableField,
        SF: Subfield<E = F::E>,
    {
        let n = f.serialized_size_bytes();
        if sf.serialized_size_bytes() != 2 || n <= 2 || n > 128 {
            return None;
        }
        // The basis elements' bytes, and the coordinates each stands for.
        let mut rows: Vec<(Vec<u8>, u16)> = Vec::with_capacity(16);
        for i in 0..16 {
            let e = sf.bytes_to_element(&(1u16 << i).to_le_bytes()).ok()?;
            let mut v = vec![0u8; n];
            f.to_bytes_into(&e, &mut v);
            rows.push((v, 1u16 << i));
        }
        let mut s = vec![0u8; 2 * 256 * n];
        for half in 0..2 {
            for b in 0..256usize {
                let out = &mut s[(half * 256 + b) * n..(half * 256 + b + 1) * n];
                for (i, (v, _)) in rows.iter().enumerate().skip(8 * half).take(8) {
                    if b >> (i - 8 * half) & 1 == 1 {
                        for (o, x) in out.iter_mut().zip(v) {
                            *o ^= x;
                        }
                    }
                }
            }
        }
        // Reduced row echelon form over GF(2): pivot bit p_k, and the coordinates c_k of the row
        // that has a one at p_k and zeros at every other pivot. An element of the subfield is
        // the sum of the rows whose pivot bit it has set, so its coordinates are the sum of c_k.
        let bit = |v: &[u8], j: usize| v[j / 8] >> (j % 8) & 1 == 1;
        let mut pivots = Vec::with_capacity(16);
        let mut rank = 0;
        for j in 0..8 * n {
            let Some(k) = (rank..16).find(|&k| bit(&rows[k].0, j)) else { continue };
            rows.swap(rank, k);
            let (pv, pc) = rows[rank].clone();
            for (k, (v, c)) in rows.iter_mut().enumerate() {
                if k != rank && bit(v, j) {
                    for (x, y) in v.iter_mut().zip(&pv) {
                        *x ^= y;
                    }
                    *c ^= pc;
                }
            }
            pivots.push(j);
            rank += 1;
            if rank == 16 {
                break;
            }
        }
        if rank != 16 {
            return None;
        }
        let mut q: Vec<(usize, [u16; 256])> = Vec::new();
        for (k, &p) in pivots.iter().enumerate() {
            let c = rows[k].1;
            let t = match q.iter().position(|(t, _)| *t == p / 8) {
                Some(t) => t,
                None => {
                    q.push((p / 8, [0u16; 256]));
                    q.len() - 1
                }
            };
            for b in 0..256usize {
                if b >> (p % 8) & 1 == 1 {
                    q[t].1[b] ^= c;
                }
            }
        }
        let wide = (n == 16).then(|| {
            let mut w = Box::new([0u128; 512]);
            for (k, x) in w.iter_mut().enumerate() {
                *x = u128::from_le_bytes(s[16 * k..16 * k + 16].try_into().unwrap_or([0; 16]));
            }
            w
        });
        Some(Packer { n, q, s, wide })
    }

    /// The coordinates of the element serialized as `bytes`, when it lies in the subfield.
    fn pack(&self, bytes: &[u8], check: &mut [u8]) -> Option<u16> {
        let mut u = 0u16;
        for (t, table) in &self.q {
            u ^= table[usize::from(*bytes.get(*t)?)];
        }
        if let Some(w) = &self.wide {
            let x = u128::from_le_bytes(bytes.try_into().ok()?);
            return (w[usize::from(u & 0xff)] ^ w[256 + usize::from(u >> 8)] == x).then_some(u);
        }
        self.expand_bytes(u, check);
        (check == bytes).then_some(u)
    }

    /// The serialized element of coordinates `u`.
    fn expand_bytes(&self, u: u16, out: &mut [u8]) {
        if let Some(w) = &self.wide {
            out.copy_from_slice(&(w[usize::from(u & 0xff)] ^ w[256 + usize::from(u >> 8)]).to_le_bytes());
            return;
        }
        let n = self.n;
        let lo = usize::from(u & 0xff) * n;
        let hi = (256 + usize::from(u >> 8)) * n;
        for ((o, a), b) in out.iter_mut().zip(&self.s[lo..lo + n]).zip(&self.s[hi..hi + n]) {
            *o = a ^ b;
        }
    }
}

/// Where a row lives: its offset in the full or in the packed store.
#[derive(Clone, Copy, Debug)]
enum Slot {
    Full(usize),
    Packed(usize),
}

/// The encoded tableau: `nrow` rows of `width` entries.
pub(crate) struct Table<E> {
    width: usize,
    slots: Vec<Slot>,
    full: Vec<E>,
    packed: Vec<u16>,
    packer: Option<Packer>,
}

/// The rows of a run being filled (`Table::runs`): each row's index and its place in the run's
/// parts of the two stores.
pub(crate) struct Run<'a, E> {
    pub(crate) rows: std::ops::Range<usize>,
    slots: &'a [Slot],
    full: &'a mut [E],
    full_at: usize,
    packed: &'a mut [u16],
    packed_at: usize,
}

impl<E: Clone> Table<E> {
    /// An empty table, `packed[r]` saying which rows to pack (ignored without a packer).
    pub(crate) fn new(width: usize, packed: &[bool], packer: Option<Packer>, zero: E) -> Table<E> {
        let (mut nf, mut np) = (0, 0);
        let slots = packed
            .iter()
            .map(|&p| {
                if p && packer.is_some() {
                    np += width;
                    Slot::Packed(np - width)
                } else {
                    nf += width;
                    Slot::Full(nf - width)
                }
            })
            .collect();
        Table { width, slots, full: vec![zero; nf], packed: vec![0; np], packer }
    }

    pub(crate) fn nrow(&self) -> usize {
        self.slots.len()
    }

    /// Splits the stores for runs of consecutive rows (the runs cover the rows in order).
    pub(crate) fn runs(&mut self, runs: &[std::ops::Range<usize>]) -> Result<(Vec<Run<'_, E>>, Option<&Packer>), Error> {
        let width = self.width;
        let mut full: &mut [E] = &mut self.full;
        let mut packed: &mut [u16] = &mut self.packed;
        let (mut fa, mut pa) = (0, 0);
        let mut out = Vec::with_capacity(runs.len());
        for run in runs {
            let slots = self.slots.get(run.clone()).ok_or(DEFECT)?;
            let nf = slots.iter().filter(|s| matches!(s, Slot::Full(_))).count() * width;
            let np = slots.len() * width - nf;
            let (f, rest) = std::mem::take(&mut full).split_at_mut(nf);
            full = rest;
            let (p, rest) = std::mem::take(&mut packed).split_at_mut(np);
            packed = rest;
            out.push(Run { rows: run.clone(), slots, full: f, full_at: fa, packed: p, packed_at: pa });
            fa += nf;
            pa += np;
        }
        Ok((out, self.packer.as_ref()))
    }

    /// Row `r`'s entries in `cols`: the stored slice for a full row, or the entries expanded into
    /// `scratch` for a packed one.
    pub(crate) fn row<'a, F>(
        &'a self,
        r: usize,
        cols: std::ops::Range<usize>,
        scratch: &'a mut Vec<E>,
        f: &F,
    ) -> Result<&'a [E], Error>
    where
        F: SerializableField<E = E>,
    {
        if cols.end > self.width {
            return Err(DEFECT);
        }
        match *self.slots.get(r).ok_or(DEFECT)? {
            Slot::Full(at) => self.full.get(at + cols.start..at + cols.end).ok_or(DEFECT),
            Slot::Packed(at) => {
                let pk = self.packer.as_ref().ok_or(DEFECT)?;
                let src = self.packed.get(at + cols.start..at + cols.end).ok_or(DEFECT)?;
                scratch.clear();
                let mut buf = [0u8; 128];
                let buf = buf.get_mut(..pk.n).ok_or(DEFECT)?;
                for &u in src {
                    pk.expand_bytes(u, buf);
                    scratch.push(f.bytes_to_element(buf).map_err(|_| DEFECT)?);
                }
                Ok(scratch)
            }
        }
    }

    /// Entry (r, c).
    pub(crate) fn get<F>(&self, r: usize, c: usize, f: &F) -> Result<E, Error>
    where
        F: SerializableField<E = E>,
    {
        let mut one = Vec::with_capacity(1);
        Ok(self.row(r, c..c + 1, &mut one, f)?.first().ok_or(DEFECT)?.clone())
    }

    /// Writes the serialized bytes of entry (r, c) of every row, for c in `cols`, through `sink`
    /// (row by row, then column by column): the Merkle leaves' input.
    pub(crate) fn for_each_bytes<F>(
        &self,
        cols: std::ops::Range<usize>,
        f: &F,
        mut sink: impl FnMut(usize, &[u8]),
    ) -> Result<(), Error>
    where
        F: SerializableField<E = E>,
    {
        let n = f.serialized_size_bytes();
        let mut buf = [0u8; 128];
        let buf = buf.get_mut(..n).ok_or(DEFECT)?;
        if cols.end > self.width {
            return Err(DEFECT);
        }
        for slot in &self.slots {
            match *slot {
                Slot::Full(at) => {
                    for (k, e) in self.full.get(at + cols.start..at + cols.end).ok_or(DEFECT)?.iter().enumerate() {
                        f.to_bytes_into(e, buf);
                        sink(k, buf);
                    }
                }
                Slot::Packed(at) => {
                    let pk = self.packer.as_ref().ok_or(DEFECT)?;
                    for (k, &u) in self.packed.get(at + cols.start..at + cols.end).ok_or(DEFECT)?.iter().enumerate() {
                        pk.expand_bytes(u, buf);
                        sink(k, buf);
                    }
                }
            }
        }
        Ok(())
    }

}

impl<E> Table<E> {
    /// The bytes the table holds: full rows at `elt` bytes an entry, packed rows at 2.
    pub(crate) fn held_bytes(&self, elt: usize) -> usize {
        self.full.len() * elt + self.packed.len() * 2
    }
}

impl<E> Run<'_, E> {
    /// Stores the encoded row `r` (a row of this run, `width` entries): copied for a full row,
    /// packed, entry by entry, for a packed row.
    pub(crate) fn store<F>(&mut self, r: usize, row: &[E], packer: Option<&Packer>, f: &F) -> Result<(), Error>
    where
        E: Clone,
        F: SerializableField<E = E>,
    {
        let k = r.checked_sub(self.rows.start).ok_or(DEFECT)?;
        match *self.slots.get(k).ok_or(DEFECT)? {
            Slot::Full(at) => {
                let at = at.checked_sub(self.full_at).ok_or(DEFECT)?;
                self.full.get_mut(at..at + row.len()).ok_or(DEFECT)?.clone_from_slice(row);
            }
            Slot::Packed(at) => {
                let pk = packer.ok_or(DEFECT)?;
                let at = at.checked_sub(self.packed_at).ok_or(DEFECT)?;
                let dst = self.packed.get_mut(at..at + row.len()).ok_or(DEFECT)?;
                let mut buf = [0u8; 128];
                let mut check = [0u8; 128];
                let (buf, check) = (buf.get_mut(..pk.n).ok_or(DEFECT)?, check.get_mut(..pk.n).ok_or(DEFECT)?);
                for (d, e) in dst.iter_mut().zip(row) {
                    f.to_bytes_into(e, buf);
                    *d = pk.pack(buf, check).ok_or(NOT_IN_SUBFIELD)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runtime_algebra::{gf2_128::Gf2_128Field, subfield::BinarySubfield};

    #[test]
    fn packs_the_subfield_and_refuses_the_rest() {
        let f = Gf2_128Field::new();
        let sf = BinarySubfield::new(&core_algebra::proto::GF2_16_BASIS_V1);
        let pk = Packer::new(&f, &sf).expect("a 2-byte subfield of GF(2^128)");
        let (mut buf, mut check, mut back) = ([0u8; 16], [0u8; 16], [0u8; 16]);
        for u in (0..=u16::MAX).step_by(7).chain([0, 1, u16::MAX]) {
            let e = sf.bytes_to_element(&u.to_le_bytes()).unwrap();
            f.to_bytes_into(&e, &mut buf);
            assert_eq!(pk.pack(&buf, &mut check), Some(u), "{u}");
            pk.expand_bytes(u, &mut back);
            assert_eq!(back, buf);
        }
        // Elements outside the subfield do not pack.
        for x in [2u128, 1 << 64, 0x0123_4567_89ab_cdef_0011_2233_4455_6677, u128::MAX] {
            let e = f.bytes_to_element(&x.to_le_bytes()).unwrap();
            f.to_bytes_into(&e, &mut buf);
            assert!(!sf.contains(&e) || pk.pack(&buf, &mut check).is_some());
            assert_eq!(pk.pack(&buf, &mut check).is_some(), sf.contains(&e), "{x:x}");
        }
    }

    #[test]
    fn no_packer_for_a_whole_field() {
        let p = runtime_algebra::p256::P256Field::new();
        let sf = runtime_algebra::p256::P256Subfield::new(&p);
        assert!(Packer::new(&p, &sf).is_none());
    }
}
