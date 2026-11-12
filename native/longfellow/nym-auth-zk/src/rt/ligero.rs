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

//! Google's Ligero commitment, proof and verification (`runtime_ligero` at 61a8a73:
//! `LigeroProver::commit`, `LigeroProver::prove`, `LigeroVerifier::verify`), on the runtime's
//! public types, with their independent work at once ([`super::par`]):
//! - **the tableau's rows**, each interpolated on its own (a row's code word is a function of
//!   that row alone), after every random element of every row is drawn in Google's order, so
//!   that the same random engine gives the same tableau;
//! - **the Merkle leaves**, each column hashed on its own, after every nonce is drawn in Google's
//!   order; the heap above them is Google's;
//! - **the dot-product proof and check**, the rows' interpolated combinations split into runs,
//!   each summed apart, the runs' sums added in order (the field's addition is exact, so the
//!   split changes no bit).
//!
//! The verifier reads each row it checks only at the opened columns ([`Columns`]): Google's
//! verifier interpolates the whole row to `block_enc` points and keeps those columns
//! ([`Interpolated`], GF(2^128)'s, whose additive FFT is cheaper than any other evaluation, each
//! interpolator made once per verification), where P-256's rows, whose points are 0, 1, 2, …, are
//! evaluated at those columns alone by the barycentric form of Google's own interpolation
//! formula ([`Barycentric`]; Berrut and Trefethen, "Barycentric Lagrange interpolation", 2004):
//! the same values, a sum of `nreq` × the row's nonzero values in place of FFTs of
//! `next_pow2(block_enc)` points.
//!
//! Every output is Google's, byte for byte, at any thread count: the tableau, the root, the
//! proof, and the verdict. Copied from Google's `ligero/src/prover.rs` and `verifier.rs`, with:
//! - the tableau a row-major vector of its own (Google's `Tableau` lends no row but one at a
//!   time), and the prover's state ([`Committed`]) this module's (Google's `LigeroProver` keeps
//!   its fields private);
//! - every index through `get` and every length mismatch an error where Google asserts: a
//!   witness whose quadratic rows do not hold is [`crate::Error::Unsatisfied`] (Google's "W part
//!   is nonzero" assertion), a proof that does not verify [`crate::Error::Proof`], any other
//!   count [`crate::Error::Internal`].

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

/// A build defect: a length or an index Google's runtime asserts on.
const DEFECT: Error = Error::Internal("a count the runtime asserts on");
/// A proof the verifier refuses.
const REFUSED: Error = Error::Proof("does not verify");

/// The instructions a tableau row's code word takes per element of the row times the row's
/// log2 length (an interpolation is n log n). Instructions per unit, measured offline, as every
/// cost here.
const ROW: FieldCost = FieldCost::new(12, 436);
/// The instructions a byte of a Merkle leaf takes to hash.
const LEAF_BYTE: Cost = Cost::ir(8);
/// The instructions a witness row of the prover's dot product takes per element of `dblock`
/// times its log2 (the row of `a` interpolated, then multiplied in).
const DOT_ROW: FieldCost = FieldCost::new(28, 527);
/// The instructions a witness row of the verifier's dot check takes per opened column (the row
/// of `a` read at the columns, then multiplied in).
const CHECK_ROW: FieldCost = FieldCost::new(7_423, 47_049);

/// `n` times its log2, rounded up (at least `n`): an interpolation's size factor.
fn n_log_n(n: usize) -> usize {
    let log = usize::BITS - n.saturating_sub(1).leading_zeros();
    n.saturating_mul(usize::try_from(log.max(1)).unwrap_or(1))
}

/// `0..n` cut into at most `parts` runs of near-equal length, in order: one run for one part.
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

/// Row `r` of a row-major `tableau` of `width` columns.
fn row<E>(tableau: &[E], width: usize, r: usize) -> Result<&[E], Error> {
    let at = r.checked_mul(width).ok_or(DEFECT)?;
    tableau
        .get(at..at.checked_add(width).ok_or(DEFECT)?)
        .ok_or(DEFECT)
}

/// `y[i] += a[i] · x[i]` over the three slices' common length.
fn vaxpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &[F::E], x: &[F::E], f: &F) {
    for (yi, (ai, xi)) in y.iter_mut().zip(a.iter().zip(x)) {
        f.fma(yi, ai, xi);
    }
}

/// `y[i] += a · x[i]` over the two slices' common length.
fn axpy<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], a: &F::E, x: &[F::E], f: &F) {
    for (yi, xi) in y.iter_mut().zip(x) {
        f.fma(yi, a, xi);
    }
}

/// `y[i] += x[i]` over the two slices' common length.
fn add<const W: usize, F: RuntimeField<W>>(y: &mut [F::E], x: &[F::E], f: &F) {
    for (yi, xi) in y.iter_mut().zip(x) {
        f.add(yi, xi);
    }
}

/// `a_ext` zero but `a`'s row `i` of `w` elements at `r..r + w`: Google's `layout_aext_into`.
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

/// What a commitment keeps for its proof: the parameters, the tableau (`nrow` rows of
/// `block_enc` elements, row-major) and the Merkle tree with its nonces. It holds the witness
/// and the blinding rows: it is the prover's secret, never printed.
pub(crate) struct Committed<E> {
    param: LigeroParam,
    tableau: Vec<E>,
    mc: MerkleCommitment,
}

/// Fills `out` with field elements from `rng`, one after another (Google's `random_row`).
fn random_row<const W: usize, F: SupportsSampling<W>, R: RandomEngine>(
    out: &mut [F::E],
    rng: &mut R,
    f: &F,
) {
    for e in out {
        *e = rng.elt_field(f);
    }
}

/// Fills `out` with subfield elements from `rng` (Google's `random_subfield_row`).
fn random_subfield_row<SF: Subfield, R: RandomEngine>(out: &mut [SF::E], rng: &mut R, sf: &SF) {
    for e in out {
        *e = rng.elt_subfield(sf);
    }
}

/// Google's `layout`: the tableau's every random element drawn and every witness and
/// quadratic-constraint value laid, in Google's order (the low-degree, dot-product and quadratic
/// blinding rows, then each witness row, then each quadratic triple); then every row
/// interpolated at once, the blinding rows of the dot product and the quadratic check from
/// `dblock` elements, every other row from `block`.
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
        // The low-degree blinding row: `block` random elements.
        let ildt = rows.get_mut(param.ildt).ok_or(DEFECT)?;
        random_row(ildt.get_mut(..param.block).ok_or(DEFECT)?, rng, f);
        // The dot-product blinding row: `dblock` random elements, constrained to SUM(W) = 0.
        let idot = rows.get_mut(param.idot).ok_or(DEFECT)?;
        random_row(idot.get_mut(..param.dblock).ok_or(DEFECT)?, rng, f);
        let mut sum = f.zero();
        for x in idot.get(r..r + w).ok_or(DEFECT)? {
            f.add(&mut sum, x);
        }
        f.sub(idot.get_mut(r).ok_or(DEFECT)?, &sum);
        // The quadratic-check blinding row: `dblock` random elements, constrained to W = 0.
        let iquad = rows.get_mut(param.iquad).ok_or(DEFECT)?;
        random_row(iquad.get_mut(..param.dblock).ok_or(DEFECT)?, rng, f);
        iquad.get_mut(r..r + w).ok_or(DEFECT)?.fill(f.zero());
        // The witness rows: EXTEND([RANDOM[R], WITNESS[W]], BLOCK).
        for i in 0..param.nwrow {
            let row = rows.get_mut(param.iw + i).ok_or(DEFECT)?;
            let random = row.get_mut(..r).ok_or(DEFECT)?;
            // The whole row in the subfield: its blinding drawn from the subfield.
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
        // The quadratic triples: each row's blinding, then the constraints' x, y and z values.
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
    // Every row's code word, in as many runs of rows at once as their work pays for, the pool
    // balancing them (`par::pieces`): each a function of its own row.
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

/// The leaves of the Merkle tree over `tableau`'s columns `dblock..block_enc`: leaf `j` is
/// SHA-256 of nonce `j` then column `dblock + j`'s elements, row after row, each in the field's
/// encoding (Google's `update_leaf_hash`). The columns are hashed in runs at once (as many as the
/// hashing's work pays for, the pool balancing them: `par::pieces`), each run's rows read in
/// order.
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

/// Google's `LigeroProver::commit`: the tableau of `witness` (its first `subfield_boundary`
/// elements in the subfield, so blinded from it), the Merkle tree over its columns with a nonce
/// per leaf, and the root written to `ts`. The random engine is drawn from in Google's order:
/// the tableau's elements, then the nonces.
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

    /// Google's `low_degree_proof`: the low-degree blinding row plus `u_ldt[i]` times witness or
    /// quadratic row `i`, over `block` columns.
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

    /// Google's `dot_proof`: the dot-product blinding row plus, for each witness or quadratic
    /// row, `a`'s row interpolated to `dblock` elements times it. The rows are summed in runs at
    /// once, the first run from the blinding row, the others from zero, and the runs' sums added
    /// in order.
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

    /// Google's `quadratic_proof`: the quadratic blinding row plus `u_quad[i] · (z − x · y)` of
    /// each triple; its W part must be zero (a witness whose triples hold), and its first `r`
    /// and last `dblock − block` elements are the proof's.
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

    /// Google's `gather_opened_columns`: each row's elements at the opened columns, row after
    /// row.
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

    /// Google's `LigeroProver::prove`: the statement's hash written, the low-degree, dot-product
    /// and quadratic proofs on the challenges `ts` draws, then the opened columns and their
    /// Merkle proof.
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

/// The opened columns' row `r` of a proof's `req`: `nreq` elements.
fn req_row<E>(proof_req: &[E], nreq: usize, r: usize) -> Result<&[E], Error> {
    row(proof_req, nreq, r).map_err(|_| REFUSED)
}

/// A row's width of evaluations, as the verifier reads it: `block` (the low-degree proof, the
/// dot product's rows of `a`) or `dblock` (the dot and quadratic proofs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Width {
    Block,
    Dblock,
}

/// How the verifier reads a row at the opened columns (module documentation): a reader per
/// verification, from the proof's opened columns.
pub(crate) trait Columns<const W: usize, F: RuntimeField<W>>: Sync {
    type Reader: ReadColumns<W, F> + Sync;
    /// The reader of rows at the opened columns `idx` (each past `dblock`) of `param`'s code.
    fn reader(
        &self,
        param: &LigeroParam,
        idx: &[usize],
        f: &F,
    ) -> Result<Self::Reader, Error>;
}

/// A reader of rows at a verification's opened columns ([`Columns::reader`]).
pub(crate) trait ReadColumns<const W: usize, F: RuntimeField<W>> {
    /// At each opened column `dblock + idx[k]`, the value of the polynomial of degree below `n`
    /// (`width`'s) whose evaluation at `lo + j` is `y[j]` and at every other point below `n` is
    /// zero: the row's code word there. `lo + y.len()` must not pass `n`.
    fn read(&self, width: Width, lo: usize, y: &[F::E], f: &F) -> Result<Vec<F::E>, Error>;
}

/// Google's reading: the row interpolated to `block_enc` points by the interpolators of `IF`,
/// one per width made once per verification (Google's verifier makes one per row it reads),
/// then the opened columns kept.
pub(crate) struct Interpolated<'f, IF>(pub(crate) &'f IF);

/// [`Interpolated`]'s reader: the two interpolators, the code's geometry and the opened columns.
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

/// Barycentric reading for a code whose points are 0, 1, 2, … (Google's P-256 interpolator,
/// `runtime_algebra::reed_solomon`): a polynomial of degree d = n − 1 given by its values p(j)
/// at 0 … d is, at a point x past d,
/// p(x) = (−1)^d (x − d) C(x, d) · Σ_j (−1)^j C(d, j) p(j) / (x − j)
/// (Google's own formula, which its interpolator computes for every x by a middle product), so
/// that a row's value at the opened columns is a sum over its nonzero values alone, from the
/// inverses of 1 … block_enc − 1, each column's leading factor and each width's signed binomials.
pub(crate) struct Barycentric;

/// [`Barycentric`]'s reader: 1/i for i below `block_enc` (0 at 0), each opened column's point and
/// its leading factor for each width, and each width's signed binomials.
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
        // i! for i below m, then 1/i = (i − 1)! / i! from 1/(m − 1)!, one inversion.
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

/// Each point x of `xs` (each in n … m − 1)'s leading factor (−1)^d (x − d) C(x, d), d = n − 1,
/// from C(d + t, d) = C(d + t − 1, d) · (d + t) / t (Google's `leading_constant`).
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

/// (−1)^j C(n − 1, j) for j below `n`, from C(d, j) = C(d, j − 1) · (d − j + 1) / j (Google's
/// `binom_i`).
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
        // (−1)^j C(d, j) p(j) for the row's nonzero values, j in lo..end.
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
                // 1/(x − j) for j = lo … end − 1: inv[x − end + 1 ..= x − lo], read backwards.
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

/// Google's `LigeroVerifier::verify` on `param`, `ts` past the commitment: the proof's lengths
/// and the constraints' indices checked, the protocol replayed for its challenges, then the
/// Merkle, low-degree, dot-product, linear and quadratic checks, in Google's order. Every row
/// the checks read at the opened columns is read by `columns`' reader (Google interpolates each
/// to `block_enc` points); the dot-product check's rows (each `a`'s row read at the opened
/// columns) are summed in runs at once.
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

    // The Merkle check: each opened column's leaf from its nonce and the proof's elements.
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

    // The low-degree check: the blinding row's columns plus u_ldt[i] times row i's.
    let mut yc = req_row(&proof.req, p.nreq, p.ildt)?.to_vec();
    for (i, u) in u_ldt.iter().enumerate().take(p.nwqrow) {
        axpy(&mut yc, u, req_row(&proof.req, p.nreq, i + p.iw)?, f);
    }
    let reader = columns.reader(p, &idx, f)?;
    let yp = reader.read(Width::Block, 0, &proof.y_ldt, f)?;
    if yp != yc {
        return Err(REFUSED);
    }

    // The dot-product check, its rows summed in runs at once.
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
            // `a`'s row i, at r … r + w of `block` evaluations (Google's `layout_aext_into`).
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

    // The linear check: alpha_L · (A w) + alpha_L · b = 0.
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

    // The quadratic check: the blinding row's columns plus u_quad[i] · (z − x · y).
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
