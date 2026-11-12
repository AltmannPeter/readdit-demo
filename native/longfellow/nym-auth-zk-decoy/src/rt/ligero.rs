// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Modified: independent work runs in parallel; every output is identical to the original.
//! Google's Ligero commitment, proof and verification (`runtime_ligero`), with the tableau's rows,
//! the Merkle leaves and the dot products computed in parallel. Byte for byte Google's output.

use std::ops::Range;

use core_algebra::SerializableField;
use core_algebra::SupportsU64Conversions;
use super::par::{self, Cost, FieldCost};
use crate::Error;
use runtime_algebra::{
    Interpolator, InterpolatorFactory, RuntimeField, Subfield, SupportsSampling,
};
use runtime_ligero::{
    inner_product_vector, LigeroCommitment, LigeroLinearConstraint, LigeroParam, LigeroProof,
    LigeroQuadraticConstraint, TranscriptLigero,
};
use runtime_merkle::{Digest, MerkleCommitment, MerkleHeap, MerkleNonce};
use runtime_random::{RandomEngine, Transcript};
use sha2::{Digest as _, Sha256};

const DEFECT: Error = Error::Internal("inconsistent");
const REFUSED: Error = Error::Proof("does not verify");

const ROW: FieldCost = FieldCost::new(12, 436);
const LEAF_BYTE: Cost = Cost::ir(8);
const DOT_ROW: FieldCost = FieldCost::new(28, 527);
const CHECK_ROW: FieldCost = FieldCost::new(7_423, 47_049);

fn n_log_n(n: usize) -> usize {
    let log = usize::BITS - n.saturating_sub(1).leading_zeros();
    n.saturating_mul(usize::try_from(log.max(1)).unwrap_or(1))
}

pub(crate) fn spans(n: usize, parts: usize) -> Vec<Range<usize>> {
    let parts = parts.clamp(1, n.max(1));
    let (q, r) = (n / parts, n % parts);
    let mut out = Vec::with_capacity(parts);
    let mut at = 0;
    for k in 0..parts {
        let len = q + usize::from(k < r);
        out.push(at..at + len);
        at += len;
    }
    out
}

fn row<E>(tableau: &[E], width: usize, r: usize) -> Result<&[E], Error> {
    let at = r.checked_mul(width).ok_or(DEFECT)?;
    tableau
        .get(at..at.checked_add(width).ok_or(DEFECT)?)
        .ok_or(DEFECT)
}

fn vaxpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &[F::E], x: &[F::E], f: &F) {
    for (yi, (ai, xi)) in y.iter_mut().zip(a.iter().zip(x)) {
        f.fma(yi, ai, xi);
    }
}

fn axpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &F::E, x: &[F::E], f: &F) {
    for (yi, xi) in y.iter_mut().zip(x) {
        f.fma(yi, a, xi);
    }
}

fn add<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], x: &[F::E], f: &F) {
    for (yi, xi) in y.iter_mut().zip(x) {
        f.add(yi, xi);
    }
}

fn layout_aext<const W: usize, F: RuntimeField<W>>(
    param: &LigeroParam,
    i: usize,
    a: &[F::E],
    a_ext: &mut [F::E],
    f: &F,
) -> Result<(), Error> {
    a_ext.fill(f.zero());
    let at = i.checked_mul(param.w).ok_or(DEFECT)?;
    let src = a.get(at..at + param.w).ok_or(DEFECT)?;
    a_ext
        .get_mut(param.r..param.r + param.w)
        .ok_or(DEFECT)?
        .clone_from_slice(src);
    Ok(())
}

pub(crate) struct Committed<E> {
    param: LigeroParam,
    tableau: Vec<E>,
    mc: MerkleCommitment,
}

fn random_row<const W: usize, F: SupportsSampling<W>, R: RandomEngine>(
    out: &mut [F::E],
    rng: &mut R,
    f: &F,
) {
    for e in out {
        *e = rng.elt_field(f);
    }
}

fn random_subfield_row<SF: Subfield, R: RandomEngine>(out: &mut [SF::E], rng: &mut R, sf: &SF) {
    for e in out {
        *e = rng.elt_subfield(sf);
    }
}

#[allow(clippy::too_many_arguments)]
fn layout<const W: usize, F, IF, R, SF>(
    subfield_boundary: usize,
    witness: &[F::E],
    param: &LigeroParam,
    lqc: &[LigeroQuadraticConstraint],
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
    sf: &SF,
) -> Result<Vec<F::E>, Error>
where
    F: SupportsSampling<W> + Sync,
    F::E: Send + Sync,
    IF: InterpolatorFactory<W, F>,
    IF::Interpolator: Sync,
    R: RandomEngine,
    SF: Subfield<E = F::E>,
{
    let width = param.block_enc;
    let len = param.nrow.checked_mul(width).ok_or(DEFECT)?;
    let mut tableau = vec![f.zero(); len];
    let (r, w) = (param.r, param.w);
    {
        let mut rows: Vec<&mut [F::E]> = tableau.chunks_exact_mut(width).collect();
        let ildt = rows.get_mut(param.ildt).ok_or(DEFECT)?;
        random_row(ildt.get_mut(..param.block).ok_or(DEFECT)?, rng, f);
        let idot = rows.get_mut(param.idot).ok_or(DEFECT)?;
        random_row(idot.get_mut(..param.dblock).ok_or(DEFECT)?, rng, f);
        let mut sum = f.zero();
        for x in idot.get(r..r + w).ok_or(DEFECT)? {
            f.add(&mut sum, x);
        }
        f.sub(idot.get_mut(r).ok_or(DEFECT)?, &sum);
        let iquad = rows.get_mut(param.iquad).ok_or(DEFECT)?;
        random_row(iquad.get_mut(..param.dblock).ok_or(DEFECT)?, rng, f);
        iquad.get_mut(r..r + w).ok_or(DEFECT)?.fill(f.zero());
        for i in 0..param.nwrow {
            let row = rows.get_mut(param.iw + i).ok_or(DEFECT)?;
            let random = row.get_mut(..r).ok_or(DEFECT)?;
            if (i + 1) * w <= subfield_boundary {
                random_subfield_row(random, rng, sf);
            } else {
                random_row(random, rng, f);
            }
            let first = i * w;
            let max_col = w.min(param.nw.checked_sub(first).ok_or(DEFECT)?);
            let src = witness.get(first..first + max_col).ok_or(DEFECT)?;
            let dst = row.get_mut(r..r + w).ok_or(DEFECT)?;
            let (laid, rest) = dst.split_at_mut(max_col);
            laid.clone_from_slice(src);
            rest.fill(f.zero());
        }
        let (iqx, iqy, iqz) = (
            param.iq,
            param.iq + param.nqtriples,
            param.iq + 2 * param.nqtriples,
        );
        for i in 0..param.nqtriples {
            for k in [iqx + i, iqy + i, iqz + i] {
                let row = rows.get_mut(k).ok_or(DEFECT)?;
                random_row(row.get_mut(..r).ok_or(DEFECT)?, rng, f);
            }
            let first = i * w;
            let max_j = w.min(param.nq.saturating_sub(first));
            for j in 0..max_j {
                let l = lqc.get(first + j).ok_or(DEFECT)?;
                for (k, at) in [(iqx + i, l.x), (iqy + i, l.y), (iqz + i, l.z)] {
                    let v = witness.get(at).ok_or(DEFECT)?.clone();
                    *rows
                        .get_mut(k)
                        .and_then(|row| row.get_mut(j + r))
                        .ok_or(DEFECT)? = v;
                }
            }
            for k in [iqx + i, iqy + i, iqz + i] {
                let row = rows.get_mut(k).ok_or(DEFECT)?;
                row.get_mut(r + max_j..r + w).ok_or(DEFECT)?.fill(f.zero());
            }
        }
    }
    let interp_block = make_interpolator.make(param.block, width);
    let interp_dblock = make_interpolator.make(param.dblock, width);
    let nrow = tableau.len() / width.max(1);
    let work = ROW.at::<W>().of(nrow.saturating_mul(n_log_n(width)));
    let mut rows = tableau.chunks_exact_mut(width).enumerate();
    let runs: Vec<Vec<_>> = spans(nrow, par::pieces(work))
        .into_iter()
        .map(|run| rows.by_ref().take(run.len()).collect())
        .collect();
    par::map(runs, |run| {
        for (k, row) in run {
            if k == param.idot || k == param.iquad {
                interp_dblock.interpolate(row);
            } else {
                interp_block.interpolate(row);
            }
        }
    });
    Ok(tableau)
}

fn leaves<const W: usize, F>(
    tableau: &[F::E],
    param: &LigeroParam,
    nonces: &[MerkleNonce],
    f: &F,
) -> Result<Vec<Digest>, Error>
where
    F: RuntimeField<W> + SerializableField + Sync,
    F::E: Sync,
{
    let width = param.block_enc;
    let len = f.serialized_size_bytes();
    let rows = tableau.len() / width.max(1);
    let bytes = nonces.len().saturating_mul(rows).saturating_mul(len);
    let runs = spans(nonces.len(), par::pieces(LEAF_BYTE.of(bytes)));
    let hashed = par::map(runs, |run| -> Result<Vec<Digest>, Error> {
        let mut hashers: Vec<Sha256> = nonces
            .get(run.clone())
            .ok_or(DEFECT)?
            .iter()
            .map(|n| {
                let mut sha = Sha256::new();
                sha.update(n.bytes);
                sha
            })
            .collect();
        let mut buf = [0u8; 128];
        let buf = buf.get_mut(..len).ok_or(DEFECT)?;
        let cols = param.dblock + run.start..param.dblock + run.end;
        for row in tableau.chunks_exact(width) {
            for (sha, e) in hashers.iter_mut().zip(row.get(cols.clone()).ok_or(DEFECT)?) {
                f.to_bytes_into(e, buf);
                sha.update(&*buf);
            }
        }
        Ok(hashers
            .into_iter()
            .map(|sha| Digest {
                data: sha.finalize().into(),
            })
            .collect())
    });
    let mut out = Vec::with_capacity(nonces.len());
    for run in hashed {
        out.extend(run?);
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn commit<const W: usize, F, IF, R, SF>(
    subfield_boundary: usize,
    witness: &[F::E],
    param: LigeroParam,
    ts: &mut Transcript,
    lqc: &[LigeroQuadraticConstraint],
    make_interpolator: &IF,
    rng: &mut R,
    f: &F,
    sf: &SF,
) -> Result<(Committed<F::E>, LigeroCommitment), Error>
where
    F: SupportsSampling<W> + SerializableField + Sync,
    F::E: Send + Sync,
    IF: InterpolatorFactory<W, F>,
    IF::Interpolator: Sync,
    R: RandomEngine,
    SF: Subfield<E = F::E>,
{
    let tableau = layout(
        subfield_boundary,
        witness,
        &param,
        lqc,
        make_interpolator,
        rng,
        f,
        sf,
    )?;
    let num_leaves = param.block_enc.checked_sub(param.dblock).ok_or(DEFECT)?;
    let mut nonce = Vec::with_capacity(num_leaves);
    for _ in 0..num_leaves {
        let bytes: [u8; 32] = rng.bytes(32).try_into().map_err(|_| DEFECT)?;
        nonce.push(MerkleNonce { bytes });
    }
    let digests = leaves(&tableau, &param, &nonce, f)?;
    if digests.is_empty() {
        return Err(DEFECT);
    }
    let mh = MerkleHeap::new(&digests);
    let commitment = LigeroCommitment { root: mh.root() };
    ts.write_commitment(&commitment);
    let mc = MerkleCommitment {
        num_leaves,
        mh,
        nonce,
    };
    Ok((Committed { param, tableau, mc }, commitment))
}

impl<E: Clone + Send + Sync> Committed<E> {
    fn row(&self, r: usize) -> Result<&[E], Error> {
        row(&self.tableau, self.param.block_enc, r)
    }

    fn low_degree_proof<const W: usize, F>(
        &self,
        u_ldt: &[E],
        f: &F,
    ) -> Result<Vec<E>, Error>
    where
        F: RuntimeField<W, E = E>,
    {
        let p = &self.param;
        let mut y = self.row(p.ildt)?.get(..p.block).ok_or(DEFECT)?.to_vec();
        for (i, u) in u_ldt.iter().enumerate().take(p.nwqrow) {
            axpy(
                &mut y,
                u,
                self.row(i + p.iw)?.get(..p.block).ok_or(DEFECT)?,
                f,
            );
        }
        Ok(y)
    }

    fn dot_proof<const W: usize, F, IF>(
        &self,
        a: &[E],
        make_interpolator: &IF,
        f: &F,
    ) -> Result<Vec<E>, Error>
    where
        F: RuntimeField<W, E = E> + Sync,
        IF: InterpolatorFactory<W, F>,
        IF::Interpolator: Sync,
    {
        let p = &self.param;
        let interp_a = make_interpolator.make(p.block, p.dblock);
        let blinding = self.row(p.idot)?.get(..p.dblock).ok_or(DEFECT)?;
        let work = DOT_ROW
            .at::<W>()
            .of(p.nwqrow.saturating_mul(n_log_n(p.dblock)));
        let runs = spans(p.nwqrow, par::tasks(work));
        let sums = par::map(runs, |run| -> Result<Vec<E>, Error> {
            let mut y = if run.start == 0 {
                blinding.to_vec()
            } else {
                vec![f.zero(); p.dblock]
            };
            let mut a_ext = vec![f.zero(); p.dblock];
            for i in run {
                layout_aext(p, i, a, &mut a_ext, f)?;
                interp_a.interpolate(&mut a_ext);
                let x = self.row(i + p.iw)?.get(..p.dblock).ok_or(DEFECT)?;
                vaxpy(&mut y, &a_ext, x, f);
            }
            Ok(y)
        });
        let mut sums = sums.into_iter();
        let mut y = sums.next().ok_or(DEFECT)??;
        for s in sums {
            add(&mut y, &s?, f);
        }
        Ok(y)
    }

    fn quadratic_proof<const W: usize, F>(
        &self,
        u_quad: &[E],
        f: &F,
    ) -> Result<(Vec<E>, Vec<E>), Error>
    where
        F: RuntimeField<W, E = E>,
    {
        let p = &self.param;
        let mut y = self.row(p.iquad)?.get(..p.dblock).ok_or(DEFECT)?.to_vec();
        let (iqx, iqy, iqz) = (p.iq, p.iq + p.nqtriples, p.iq + 2 * p.nqtriples);
        for (i, u) in u_quad.iter().enumerate().take(p.nqtriples) {
            let mut tmp = self.row(iqz + i)?.get(..p.dblock).ok_or(DEFECT)?.to_vec();
            let x = self.row(iqx + i)?.get(..p.dblock).ok_or(DEFECT)?;
            let yy = self.row(iqy + i)?.get(..p.dblock).ok_or(DEFECT)?;
            for (t, (xi, yi)) in tmp.iter_mut().zip(x.iter().zip(yy)) {
                f.fnms(t, xi, yi);
            }
            axpy(&mut y, u, &tmp, f);
        }
        let w_part = y.get(p.r..p.r + p.w).ok_or(DEFECT)?;
        if w_part.iter().any(|e| !f.is_zero(e)) {
            return Err(Error::Unsatisfied);
        }
        let y0 = y.get(..p.r).ok_or(DEFECT)?.to_vec();
        let y2 = y.get(p.block..).ok_or(DEFECT)?.to_vec();
        Ok((y0, y2))
    }

    fn opened_columns(&self, idx: &[usize]) -> Result<Vec<E>, Error> {
        let p = &self.param;
        let mut req = Vec::with_capacity(p.nrow.saturating_mul(p.nreq));
        for r in self.tableau.chunks_exact(p.block_enc) {
            let cols = r.get(p.dblock..).ok_or(DEFECT)?;
            for &i in idx {
                req.push(cols.get(i).ok_or(DEFECT)?.clone());
            }
        }
        Ok(req)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prove<const W: usize, F, IF>(
        &self,
        linear_evals: &[E],
        ts: &mut Transcript,
        linear_constraints: &[LigeroLinearConstraint<W, F>],
        hash_of_ligero_statement: &Digest,
        lqc: &[LigeroQuadraticConstraint],
        make_interpolator: &IF,
        f: &F,
    ) -> Result<LigeroProof<W, F>, Error>
    where
        F: SupportsSampling<W, E = E> + SerializableField + Sync,
        IF: InterpolatorFactory<W, F>,
        IF::Interpolator: Sync,
    {
        let p = &self.param;
        ts.write_ligero_statement(hash_of_ligero_statement);
        let y_ldt = self.low_degree_proof(&ts.gen_uldt(p, f), f)?;
        let alphal = ts.gen_alphal(linear_evals.len(), f);
        let alphaq = ts.gen_alphaq(p, f);
        let a = inner_product_vector(p, linear_constraints, &alphal, lqc, &alphaq, f);
        let y_dot = self.dot_proof(&a, make_interpolator, f)?;
        let (y_quad_0, y_quad_2) = self.quadratic_proof(&ts.gen_uquad(p, f), f)?;
        ts.write_elt_field_slice(&y_ldt, f);
        ts.write_elt_field_slice(&y_dot, f);
        ts.write_elt_field_slice(&y_quad_0, f);
        ts.write_elt_field_slice(&y_quad_2, f);
        let idx = ts.gen_idx(p);
        let req = self.opened_columns(&idx)?;
        if idx.iter().any(|&i| i >= self.mc.num_leaves) {
            return Err(DEFECT);
        }
        let merkle = runtime_merkle::open(&self.mc, &idx);
        Ok(LigeroProof {
            y_ldt,
            y_dot,
            y_quad_0,
            y_quad_2,
            req,
            merkle,
        })
    }
}

fn req_row<E>(proof_req: &[E], nreq: usize, r: usize) -> Result<&[E], Error> {
    row(proof_req, nreq, r).map_err(|_| REFUSED)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    Block,
    Dblock,
}

pub(crate) trait Columns<const W: usize, F: RuntimeField<W>>: Sync {
    type Reader: ReadColumns<W, F> + Sync;
    fn reader(
        &self,
        param: &LigeroParam,
        idx: &[usize],
        f: &F,
    ) -> Result<Self::Reader, Error>;
}

pub(crate) trait ReadColumns<const W: usize, F: RuntimeField<W>> {
    fn read(&self, width: Width, lo: usize, y: &[F::E], f: &F) -> Result<Vec<F::E>, Error>;
}

pub(crate) struct Interpolated<'f, IF>(pub(crate) &'f IF);

pub(crate) struct InterpolatedReader<I> {
    block: I,
    dblock: I,
    n: [usize; 2],
    block_enc: usize,
    cols: Vec<usize>,
}

impl<const W: usize, F, IF> Columns<W, F> for Interpolated<'_, IF>
where
    F: RuntimeField<W>,
    IF: InterpolatorFactory<W, F> + Sync,
    IF::Interpolator: Sync,
{
    type Reader = InterpolatedReader<IF::Interpolator>;

    fn reader(
        &self,
        param: &LigeroParam,
        idx: &[usize],
        _: &F,
    ) -> Result<Self::Reader, Error> {
        let cols = idx
            .iter()
            .map(|&i| param.dblock.checked_add(i).filter(|&c| c < param.block_enc))
            .collect::<Option<Vec<usize>>>()
            .ok_or(REFUSED)?;
        Ok(InterpolatedReader {
            block: self.0.make(param.block, param.block_enc),
            dblock: self.0.make(param.dblock, param.block_enc),
            n: [param.block, param.dblock],
            block_enc: param.block_enc,
            cols,
        })
    }
}

impl<const W: usize, F, I> ReadColumns<W, F> for InterpolatedReader<I>
where
    F: RuntimeField<W>,
    I: Interpolator<W, F>,
{
    fn read(&self, width: Width, lo: usize, y: &[F::E], f: &F) -> Result<Vec<F::E>, Error> {
        let (interp, n) = match width {
            Width::Block => (&self.block, self.n[0]),
            Width::Dblock => (&self.dblock, self.n[1]),
        };
        let end = lo.checked_add(y.len()).filter(|&e| e <= n).ok_or(DEFECT)?;
        let mut ext = vec![f.zero(); self.block_enc];
        ext.get_mut(lo..end).ok_or(DEFECT)?.clone_from_slice(y);
        interp.interpolate(&mut ext);
        self.cols
            .iter()
            .map(|&c| ext.get(c).cloned().ok_or(DEFECT))
            .collect()
    }
}

pub(crate) struct Barycentric;

pub(crate) struct BarycentricReader<E> {
    inv: Vec<E>,
    xs: Vec<usize>,
    lead: [Vec<E>; 2],
    binom: [Vec<E>; 2],
}

impl<const W: usize, F> Columns<W, F> for Barycentric
where
    F: RuntimeField<W> + SupportsU64Conversions + Sync,
    F::E: Send + Sync,
{
    type Reader = BarycentricReader<F::E>;

    fn reader(
        &self,
        param: &LigeroParam,
        idx: &[usize],
        f: &F,
    ) -> Result<Self::Reader, Error> {
        let m = param.block_enc;
        let xs = idx
            .iter()
            .map(|&i| param.dblock.checked_add(i).filter(|&x| x < m))
            .collect::<Option<Vec<usize>>>()
            .ok_or(REFUSED)?;
        let mut fact = Vec::with_capacity(m);
        let (mut acc, mut i_e) = (f.one(), f.zero());
        for i in 0..m {
            if i > 0 {
                f.add(&mut i_e, &f.one());
                f.mul(&mut acc, &i_e);
            }
            fact.push(acc.clone());
        }
        let mut inv = vec![f.zero(); m];
        let mut inv_fact = f.invert(fact.last().ok_or(DEFECT)?);
        for i in (1..m).rev() {
            let before = fact.get(i - 1).ok_or(DEFECT)?;
            *inv.get_mut(i).ok_or(DEFECT)? = f.mulf(&inv_fact, before);
            f.mul(&mut inv_fact, &f.u64_to_element(i as u64));
        }
        let lead = [
            leading(param.block, m, &xs, &inv, f)?,
            leading(param.dblock, m, &xs, &inv, f)?,
        ];
        let binom = [
            binomials(param.block, &inv, f)?,
            binomials(param.dblock, &inv, f)?,
        ];
        Ok(BarycentricReader {
            inv,
            xs,
            lead,
            binom,
        })
    }
}

fn leading<const W: usize, F>(
    n: usize,
    m: usize,
    xs: &[usize],
    inv: &[F::E],
    f: &F,
) -> Result<Vec<F::E>, Error>
where
    F: RuntimeField<W> + SupportsU64Conversions,
{
    let d = n.checked_sub(1).ok_or(DEFECT)?;
    let count = m.checked_sub(n).ok_or(DEFECT)?;
    let mut binom = Vec::with_capacity(count + 1);
    binom.push(f.one());
    let mut acc = f.one();
    for t in 1..=count {
        f.mul(&mut acc, &f.u64_to_element((d + t) as u64));
        f.mul(&mut acc, inv.get(t).ok_or(DEFECT)?);
        binom.push(acc.clone());
    }
    xs.iter()
        .map(|&x| {
            let t = x.checked_sub(d).ok_or(DEFECT)?;
            let mut v = f.mulf(binom.get(t).ok_or(DEFECT)?, &f.u64_to_element(t as u64));
            if d % 2 == 1 {
                v = f.neg(&v);
            }
            Ok(v)
        })
        .collect()
}

fn binomials<const W: usize, F>(n: usize, inv: &[F::E], f: &F) -> Result<Vec<F::E>, Error>
where
    F: RuntimeField<W> + SupportsU64Conversions,
{
    let mut out = Vec::with_capacity(n);
    let mut acc = f.one();
    for j in 0..n {
        if j > 0 {
            f.mul(&mut acc, &f.u64_to_element((n - j) as u64));
            f.mul(&mut acc, inv.get(j).ok_or(DEFECT)?);
        }
        out.push(if j % 2 == 1 { f.neg(&acc) } else { acc.clone() });
    }
    Ok(out)
}

impl<const W: usize, F> ReadColumns<W, F> for BarycentricReader<F::E>
where
    F: RuntimeField<W>,
{
    fn read(&self, width: Width, lo: usize, y: &[F::E], f: &F) -> Result<Vec<F::E>, Error> {
        let k = match width {
            Width::Block => 0,
            Width::Dblock => 1,
        };
        let (lead, binom) = (
            self.lead.get(k).ok_or(DEFECT)?,
            self.binom.get(k).ok_or(DEFECT)?,
        );
        let end = lo
            .checked_add(y.len())
            .filter(|&e| e <= binom.len())
            .ok_or(DEFECT)?;
        if y.is_empty() {
            return Ok(vec![f.zero(); self.xs.len()]);
        }
        let scaled: Vec<F::E> = binom
            .get(lo..end)
            .ok_or(DEFECT)?
            .iter()
            .zip(y)
            .map(|(b, v)| f.mulf(b, v))
            .collect();
        self.xs
            .iter()
            .zip(lead)
            .map(|(&x, l)| {
                let from = x.checked_sub(end - 1).filter(|&a| a > 0).ok_or(DEFECT)?;
                let to = x.checked_sub(lo).ok_or(DEFECT)?;
                let window = self.inv.get(from..=to).ok_or(DEFECT)?;
                let mut acc = f.zero_accum();
                for (i, v) in window.iter().rev().zip(&scaled) {
                    f.mac(&mut acc, i, v);
                }
                Ok(f.mulf(l, &f.accum_reduce(&acc)))
            })
            .collect()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify<const W: usize, F, C>(
    param: &LigeroParam,
    ts: &mut Transcript,
    linear_evals: &[F::E],
    commitment: &LigeroCommitment,
    proof: &LigeroProof<W, F>,
    linear_constraints: &[LigeroLinearConstraint<W, F>],
    hash_of_ligero_statement: &Digest,
    lqc: &[LigeroQuadraticConstraint],
    columns: &C,
    f: &F,
) -> Result<(), Error>
where
    F: SupportsSampling<W> + SerializableField + Sync,
    F::E: Send + Sync,
    C: Columns<W, F>,
{
    let p = param;
    let lengths_hold = proof.y_ldt.len() == p.block
        && proof.y_dot.len() == p.dblock
        && proof.y_quad_0.len() == p.r
        && Some(proof.y_quad_2.len()) == p.dblock.checked_sub(p.block)
        && Some(proof.req.len()) == p.nrow.checked_mul(p.nreq);
    if !lengths_hold {
        return Err(REFUSED);
    }
    if linear_constraints
        .iter()
        .any(|t| t.w >= p.nw || t.c >= linear_evals.len())
    {
        return Err(REFUSED);
    }
    let quadratic = lqc.get(..p.nq).ok_or(REFUSED)?;
    if quadratic
        .iter()
        .any(|l| l.x >= p.nw || l.y >= p.nw || l.z >= p.nw)
    {
        return Err(REFUSED);
    }
    ts.write_ligero_statement(hash_of_ligero_statement);
    let u_ldt = ts.gen_uldt(p, f);
    let alphal = ts.gen_alphal(linear_evals.len(), f);
    let alphaq = ts.gen_alphaq(p, f);
    let u_quad = ts.gen_uquad(p, f);
    ts.write_elt_field_slice(&proof.y_ldt, f);
    ts.write_elt_field_slice(&proof.y_dot, f);
    ts.write_elt_field_slice(&proof.y_quad_0, f);
    ts.write_elt_field_slice(&proof.y_quad_2, f);
    let idx = ts.gen_idx(p);

    let len = f.serialized_size_bytes();
    let mut buf = [0u8; 128];
    let buf = buf.get_mut(..len).ok_or(DEFECT)?;
    let mut missing = false;
    let leaf = |r: usize, _col: usize, sha: &mut Sha256| {
        for i in 0..p.nrow {
            match proof.req.get(i * p.nreq + r) {
                Some(val) => {
                    f.to_bytes_into(val, buf);
                    sha.update(&*buf);
                }
                None => missing = true,
            }
        }
    };
    let leaves = p.block_enc.checked_sub(p.dblock).ok_or(DEFECT)?;
    let merkle = runtime_merkle::verify(leaves, &commitment.root, &idx, &proof.merkle, leaf);
    if merkle.is_err() || missing {
        return Err(REFUSED);
    }

    let mut yc = req_row(&proof.req, p.nreq, p.ildt)?.to_vec();
    for (i, u) in u_ldt.iter().enumerate().take(p.nwqrow) {
        axpy(&mut yc, u, req_row(&proof.req, p.nreq, i + p.iw)?, f);
    }
    let reader = columns.reader(p, &idx, f)?;
    let yp = reader.read(Width::Block, 0, &proof.y_ldt, f)?;
    if yp != yc {
        return Err(REFUSED);
    }

    let a = inner_product_vector(p, linear_constraints, &alphal, lqc, &alphaq, f);
    let blinding = req_row(&proof.req, p.nreq, p.idot)?;
    let work = CHECK_ROW.at::<W>().of(p.nwqrow.saturating_mul(p.nreq));
    let runs = spans(p.nwqrow, par::tasks(work));
    let sums = par::map(runs, |run| -> Result<Vec<F::E>, Error> {
        let mut yc = if run.start == 0 {
            blinding.to_vec()
        } else {
            vec![f.zero(); p.nreq]
        };
        for i in run {
            let at = i.checked_mul(p.w).ok_or(DEFECT)?;
            let row = a.get(at..at + p.w).ok_or(DEFECT)?;
            let a_req = reader.read(Width::Block, p.r, row, f)?;
            vaxpy(&mut yc, &a_req, req_row(&proof.req, p.nreq, i + p.iw)?, f);
        }
        Ok(yc)
    });
    let mut sums = sums.into_iter();
    let mut yc = sums.next().ok_or(DEFECT)??;
    for s in sums {
        add(&mut yc, &s?, f);
    }
    let yp = reader.read(Width::Dblock, 0, &proof.y_dot, f)?;
    if yp != yc {
        return Err(REFUSED);
    }

    let mut want_dot = f.zero();
    for (x, y) in linear_evals.iter().zip(&alphal) {
        f.fma(&mut want_dot, x, y);
    }
    let mut sum = f.zero();
    for x in proof.y_dot.get(p.r..p.r + p.w).ok_or(REFUSED)? {
        f.add(&mut sum, x);
    }
    f.add(&mut sum, &want_dot);
    if !f.is_zero(&sum) {
        return Err(REFUSED);
    }

    let mut yc = req_row(&proof.req, p.nreq, p.iquad)?.to_vec();
    let (iqx, iqy, iqz) = (p.iq, p.iq + p.nqtriples, p.iq + 2 * p.nqtriples);
    for (i, u) in u_quad.iter().enumerate().take(p.nqtriples) {
        let mut tmp = req_row(&proof.req, p.nreq, iqz + i)?.to_vec();
        let x = req_row(&proof.req, p.nreq, iqx + i)?;
        let y = req_row(&proof.req, p.nreq, iqy + i)?;
        for (t, (xi, yi)) in tmp.iter_mut().zip(x.iter().zip(y)) {
            f.fnms(t, xi, yi);
        }
        axpy(&mut yc, u, &tmp, f);
    }
    let mut yquad = proof.y_quad_0.clone();
    yquad.resize(p.block, f.zero());
    yquad.extend_from_slice(&proof.y_quad_2);
    let yp = reader.read(Width::Dblock, 0, &yquad, f)?;
    if yp != yc {
        return Err(REFUSED);
    }
    Ok(())
}
