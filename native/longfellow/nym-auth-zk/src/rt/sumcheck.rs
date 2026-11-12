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

//! Google's circuit evaluation and sumcheck prover (`runtime_sumcheck` at 61a8a73:
//! `eval_circuit`, `eval_quad`, `prove_core` and its `layer`, `HQuad::bind_g`, `HQuad::bind_h`,
//! `eq::eq2`, `dense::bind`), on the runtime's public types, with their independent work at once
//! ([`super::par`]). A layer's terms are deltas from the term before, in the order of its tokens'
//! segments, so a run of terms cut anywhere is decoded from the term before it, which the runs'
//! summed deltas, taken at once, give without decoding the terms before it:
//! - **the evaluation**: each run of a layer's terms accumulates its outputs into a buffer of
//!   its own over the outputs it reaches, and the buffers are added block by block of the
//!   outputs (a scatter-add privatized per run, then reduced); the runs are cut once a layer,
//!   and the proof binds the same runs;
//! - **the eq tables**: each built by halves, a large one cut at the top of its halving into
//!   pieces filled at once, the verifier's every layer's pieces in one region;
//! - **the bound quad** (Google's `HQuad`): each run of terms bound on its own, and each run of
//!   its corners bound to every challenge on its own: Google's bindings are linear in the
//!   corners' values, so the quad is the sum of its runs (a corner split by a cut is one corner
//!   in two runs, and its two values add), and so are a round's sums and the bound quad's value;
//! - **each round** of the prover is one region: each run compacts itself to the challenge of
//!   the round before, then takes its share of the round's sums (a scatter into a buffer of its
//!   own over the pairs its range of the hand's wires touches, or corner by corner where that
//!   range is wider than its corners); the first round's region binds the terms too; the wires
//!   are halved in place, in order, as Google halves them;
//! - **the verifier's bound quads**: every run of every layer bound to its eq table and to all
//!   its rounds' challenges in one region.
//!
//! The rounds are sequential (each challenge hashes the round before's polynomial), so a round
//! is the least a region can carry. Each step's work is estimated from its sizes (units times a
//! cost per unit, instructions measured offline, [`super::par`]); work too small for a region
//! runs on the calling thread, and on one thread every step is Google's own loop. Every value is
//! Google's, at any thread count: the field's additions are exact, so the order of a sum's terms
//! changes no bit, and every challenge is the one Google's code makes. Copied from Google's
//! `sumcheck/src/{eval.rs, prover.rs, hquad.rs, eq.rs, dense.rs}`, with every assertion an error:
//! a witness the circuit does not hold (an assertion's product not zero, a nonzero output, a
//! round's sum that is not the claimed one) [`crate::Error::Unsatisfied`], an index or a count
//! past the circuit's [`crate::Error::Internal`].

use std::ops::Range;

use core_algebra::SerializableField;
use core_proto::circuit::{Circuit, Layer, TermDelta};
use super::par::{self, Cost, FieldCost};
use crate::Error;
use runtime_algebra::{InterpolationField, RuntimeField, SupportsSampling};
use runtime_random::Transcript;
use runtime_sumcheck::dense::{
    affine_interpolation, affine_interpolation_nz_z, affine_interpolation_z_nz,
};
use runtime_sumcheck::{
    sane_logw, LayerProof, Poly, QuadRoundPoly, QuadWirePoly, SumcheckProof, SumcheckProofAux,
    TranscriptSumcheck, MAX_LOGW,
};

use super::ligero::spans;

/// A defect of the circuit or of this code: an index or a count Google's runtime asserts on.
const DEFECT: Error = Error::Internal("a count the runtime asserts on");
/// A witness the circuit does not hold.
const UNSATISFIED: Error = Error::Unsatisfied;

/// The instructions a layer's term takes in the evaluation ([`eval_quad`]): the unit of a
/// layer's cut into runs of terms, which the proof binds as cut. Instructions per unit, measured
/// offline, as every cost here.
const TERM: FieldCost = FieldCost::new(166, 500);
/// The instructions a term's delta takes to sum ([`term_runs`]).
const DELTA: Cost = Cost::ir(12);
/// The instructions an element of a part takes to add into its vector ([`assemble`]).
const ADD: FieldCost = FieldCost::new(17, 32);
/// The instructions an eq table's element takes ([`eq_tables`]).
const EQ: FieldCost = FieldCost::new(147, 618);
/// The instructions a corner takes in a prover's round: its compaction, then its share of the
/// round's sums ([`Corners::round`]).
const ROUND: FieldCost = FieldCost::new(103, 418);
/// The instructions a layer's term takes in the prover's first round: bound to the eq table,
/// then its corner's share of round 0's sums ([`bind_first`]).
const FIRST: FieldCost = FieldCost::new(104, 483);
/// The instructions a corner takes to compact ([`Corners::bind_h`]).
const COMPACT: FieldCost = FieldCost::new(136, 306);
/// The instructions a layer's term takes in the verifier's binding of its run: bound to the eq
/// table, then compacted to every challenge ([`bind_quads`]).
const BIND: FieldCost = FieldCost::new(220, 697);

/// The runs a layer of `terms` terms is cut into, in the field of `W` limbs: as many as its
/// evaluation's work pays for ([`par::tasks`]).
fn parts<const W: usize>(terms: usize) -> usize {
    par::tasks(TERM.at::<W>().of(terms))
}

/// A place in a layer's term sequence: delta `offset` of the segment of token `token` (the
/// sequence's end is token `tokens.len()`, offset 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct At {
    token: usize,
    offset: usize,
}

/// A run of a layer's terms, `from` up to `to` in its token sequence (a run may begin or end
/// inside a segment: an uncompressed layer is one segment of every term), the term before its
/// first (g, h0, h1; (0, 0, 0) before the layer's first, as Google's decoder starts), and its
/// count of terms.
pub(crate) struct TermRun {
    from: At,
    to: At,
    prev: [u32; 3],
    count: usize,
}

/// `a + d` component by component, wrapping, as Google's decoder adds deltas.
fn plus(a: [u32; 3], d: [u32; 3]) -> [u32; 3] {
    let ([a0, a1, a2], [d0, d1, d2]) = (a, d);
    [
        a0.wrapping_add(d0),
        a1.wrapping_add(d1),
        a2.wrapping_add(d2),
    ]
}

/// `f` on each delta of `layer`'s term sequence from `from` up to `to`, in order.
fn walk<F: SerializableField>(
    layer: &Layer<F>,
    from: At,
    to: At,
    mut f: impl FnMut(&TermDelta) -> Result<(), Error>,
) -> Result<(), Error> {
    let (deltas, segments, tokens) = (layer.deltas(), layer.delta_segments(), layer.delta_tokens());
    let mut at = from;
    while at < to {
        let &t = tokens.get(at.token).ok_or(DEFECT)?;
        let seg = segments.get(t as usize).ok_or(DEFECT)?;
        let end = if at.token == to.token {
            to.offset
        } else {
            seg.len()
        };
        for &d in seg.get(at.offset..end).ok_or(DEFECT)? {
            f(deltas.get(d as usize).ok_or(DEFECT)?)?;
        }
        at = At {
            token: at.token + 1,
            offset: 0,
        };
    }
    Ok(())
}

/// `layer`'s terms cut into at most `parts` runs of near-equal term counts, at any term (one
/// segment may hold them all), each with the term before it: the cut places from one walk over
/// the tokens, each run's summed delta (in as many groups of runs at once as that walk's work
/// pays for), then their prefix sums in order.
fn term_runs<F: SerializableField + Sync>(
    layer: &Layer<F>,
    parts: usize,
) -> Result<Vec<TermRun>, Error> {
    let segments = layer.delta_segments();
    let tokens = layer.delta_tokens();
    let end = At {
        token: tokens.len(),
        offset: 0,
    };
    let mut lens = Vec::with_capacity(tokens.len());
    for &t in tokens {
        lens.push(segments.get(t as usize).ok_or(DEFECT)?.len());
    }
    let total: usize = lens.iter().sum();
    let whole = TermRun {
        from: At {
            token: 0,
            offset: 0,
        },
        to: end,
        prev: [0; 3],
        count: total,
    };
    if parts <= 1 {
        return Ok(vec![whole]);
    }
    let target = total.div_ceil(parts).max(1);
    // The cut places: the first term of each run past the first.
    let mut cuts = vec![whole.from];
    let (mut before, mut goal) = (0usize, target);
    for (i, &len) in lens.iter().enumerate() {
        while goal < total && goal < before + len {
            cuts.push(At {
                token: i,
                offset: goal - before,
            });
            goal += target;
        }
        before += len;
    }
    cuts.push(end);
    let spans_of: Vec<(At, At)> = cuts
        .iter()
        .zip(cuts.iter().skip(1))
        .map(|(&a, &b)| (a, b))
        .collect();
    let sum = |(from, to): (At, At)| {
        let (mut s, mut n) = ([0u32; 3], 0usize);
        walk(layer, from, to, |d| {
            let [h0, h1] = d.h;
            s = plus(s, [d.g, h0, h1]);
            n += 1;
            Ok(())
        })
        .map(|()| (s, n))
    };
    let groups: Vec<&[(At, At)]> = spans(spans_of.len(), par::tasks(DELTA.of(total)))
        .into_iter()
        .filter_map(|g| spans_of.get(g))
        .collect();
    let sums: Vec<_> = par::map(groups, |g| g.iter().copied().map(sum).collect::<Vec<_>>())
        .into_iter()
        .flatten()
        .collect();
    let spans = spans_of;
    let mut runs = Vec::with_capacity(spans.len());
    let mut prev = [0u32; 3];
    for ((from, to), sum) in spans.into_iter().zip(sums) {
        let (s, count) = sum?;
        runs.push(TermRun {
            from,
            to,
            prev,
            count,
        });
        prev = plus(prev, s);
    }
    Ok(runs)
}

/// `layer`'s terms cut into runs ([`term_runs`]): as many as its evaluation's work pays for.
pub(crate) fn layer_runs<const W: usize, F: SerializableField + Sync>(
    layer: &Layer<F>,
) -> Result<Vec<TermRun>, Error> {
    term_runs(layer, parts::<W>(layer.num_terms()))
}

/// `cb(k, g, h0, h1)` for each term of `run`, in order: Google's `for_each_term` over the run's
/// place in the token sequence, from the term before it.
fn each_term<F, C>(
    layer: &Layer<F>,
    constants: &[F::E],
    run: &TermRun,
    mut cb: C,
) -> Result<(), Error>
where
    F: SerializableField,
    C: FnMut(&F::E, u32, u32, u32) -> Result<(), Error>,
{
    let mut p = run.prev;
    walk(layer, run.from, run.to, |d| {
        let [h0, h1] = d.h;
        p = plus(p, [d.g, h0, h1]);
        let k = constants.get(d.k_index as usize).ok_or(DEFECT)?;
        let [g, h0, h1] = p;
        cb(k, g, h0, h1)
    })
}

/// Adds the part of each buffer of `parts` (each from an offset) that falls in `at..at +
/// out.len()` into `out`.
fn add_parts<E>(
    out: &mut [E],
    at: usize,
    parts: &[(usize, Vec<E>)],
    add: &impl Fn(&mut E, &E),
) -> Result<(), Error> {
    let end = at + out.len();
    for (lo, buf) in parts {
        let hi = lo + buf.len();
        let (from, to) = (at.max(*lo), end.min(hi));
        if from >= to {
            continue;
        }
        let src = buf.get(from - lo..to - lo).ok_or(DEFECT)?;
        let dst = out.get_mut(from - at..to - at).ok_or(DEFECT)?;
        for (d, s) in dst.iter_mut().zip(src) {
            add(d, s);
        }
    }
    Ok(())
}

/// A vector of `n` elements, the sum of `parts` (each a buffer from an offset) block by block
/// of the vector, in as many blocks at once as the additions' work pays for.
fn assemble<E: Clone + Send + Sync>(
    n: usize,
    parts: &[(usize, Vec<E>)],
    zero: &E,
    add_cost: Cost,
    add: impl Fn(&mut E, &E) + Sync,
) -> Result<Vec<E>, Error> {
    let mut v = vec![zero.clone(); n];
    let added: usize = parts.iter().map(|(_, buf)| buf.len()).sum();
    let block = n.div_ceil(par::tasks(add_cost.of(added))).max(1);
    let blocks: Vec<(usize, &mut [E])> = v
        .chunks_mut(block)
        .enumerate()
        .map(|(i, b)| (i * block, b))
        .collect();
    for done in par::map(blocks, |(at, out)| add_parts(out, at, parts, &add)) {
        done?;
    }
    Ok(v)
}

/// One term of an evaluation: an assertion (k = 0) needs `w[h1] · w[h0] = 0`; every other term
/// adds `k · w[h1] · w[h0]` to output `g` (Google's `eval_quad`).
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn eval_term<const W: usize, F: RuntimeField<W>>(
    k: &F::E,
    g: usize,
    h0: u32,
    h1: u32,
    w: &[F::E],
    v: &mut [F::E],
    f: &F,
) -> Result<(), Error> {
    let wl = w.get(h1 as usize).ok_or(DEFECT)?;
    let wr = w.get(h0 as usize).ok_or(DEFECT)?;
    if f.is_zero(k) {
        if !f.is_zero(&f.mulf(wl, wr)) {
            return Err(UNSATISFIED);
        }
    } else {
        let mut x = k.clone();
        f.mul(&mut x, wl);
        f.mul(&mut x, wr);
        f.add(v.get_mut(g).ok_or(DEFECT)?, &x);
    }
    Ok(())
}

/// Google's `eval_quad`: layer `layer`'s `nv` outputs from its inputs `w`, its terms in the runs
/// `runs` ([`layer_runs`]); on several runs, each into a buffer of its own over the outputs it
/// reaches (found by a first pass over the run's decoded indices), at once, the buffers added
/// block by block.
fn eval_quad<const W: usize, F>(
    nv: usize,
    w: &[F::E],
    layer: &Layer<F>,
    runs: &[TermRun],
    constants: &[F::E],
    f: &F,
) -> Result<Vec<F::E>, Error>
where
    F: RuntimeField<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    if runs.len() <= 1 {
        let mut v = vec![f.zero(); nv];
        for run in runs {
            each_term(layer, constants, run, |k, g, h0, h1| {
                eval_term(k, g as usize, h0, h1, w, &mut v, f)
            })?;
        }
        return Ok(v);
    }
    let at_once = par::uneven(runs.iter().map(|run| TERM.at::<W>().of(run.count)));
    let runs: Vec<&TermRun> = runs.iter().collect();
    let bufs = par::map_if(
        at_once,
        runs,
        |run| -> Result<(usize, Vec<F::E>), Error> {
            let (mut lo, mut hi) = (u32::MAX, 0u32);
            each_term(layer, constants, run, |_, g, _, _| {
                (lo, hi) = (lo.min(g), hi.max(g));
                Ok(())
            })?;
            if lo > hi {
                return Ok((0, Vec::new()));
            }
            let mut buf = vec![f.zero(); (hi - lo) as usize + 1];
            each_term(layer, constants, run, |k, g, h0, h1| {
                let at = g.checked_sub(lo).ok_or(DEFECT)?;
                eval_term(k, at as usize, h0, h1, w, &mut buf, f)
            })?;
            Ok((lo as usize, buf))
        },
    )
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;
    if bufs.iter().any(|(lo, buf)| lo + buf.len() > nv) {
        return Err(DEFECT);
    }
    assemble(nv, &bufs, &f.zero(), ADD.at::<W>(), |d, s| f.add(d, s))
}

/// What the evaluation gives the proof: each layer's inputs, and each layer's runs of terms
/// ([`layer_runs`]), which the proof binds as the evaluation cut them.
pub(crate) struct Evaluated<E> {
    in_layers: Vec<Vec<E>>,
    runs: Vec<Vec<TermRun>>,
}

/// Google's `eval_circuit`: every layer's inputs, from the circuit's inputs `inputs` up, each
/// layer evaluated by [`eval_quad`]; the outputs must be zero (a witness the circuit holds).
pub(crate) fn eval_circuit<const W: usize, F>(
    inputs: Vec<F::E>,
    circuit: &Circuit<F>,
    f: &F,
) -> Result<Evaluated<F::E>, Error>
where
    F: RuntimeField<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    let layers = &circuit.raw.layers;
    let mut in_layers: Vec<Vec<F::E>> = layers.iter().map(|_| Vec::new()).collect();
    let mut runs: Vec<Vec<TermRun>> = layers.iter().map(|_| Vec::new()).collect();
    let mut w = inputs;
    for l in (0..layers.len()).rev() {
        let nv = match l.checked_sub(1) {
            Some(below) => layers.get(below).ok_or(DEFECT)?.nw(),
            None => circuit.raw.noutput,
        };
        let layer = layers.get(l).ok_or(DEFECT)?;
        let cut = layer_runs::<W, F>(layer)?;
        let v = eval_quad(nv, &w, layer, &cut, &circuit.raw.constants, f)?;
        *in_layers.get_mut(l).ok_or(DEFECT)? = std::mem::replace(&mut w, v);
        *runs.get_mut(l).ok_or(DEFECT)? = cut;
    }
    if w.iter().any(|x| !f.is_zero(x)) {
        return Err(UNSATISFIED);
    }
    Ok(Evaluated { in_layers, runs })
}

/// One eq table to fill ([`eq_tables`]): its `nv` values eq(g0, i) + alpha · eq(g1, i) over the
/// first `logv` challenges.
pub(crate) struct EqSpec<'a, E> {
    pub(crate) logv: usize,
    pub(crate) nv: usize,
    pub(crate) g0: &'a [E],
    pub(crate) g1: &'a [E],
    pub(crate) alpha: &'a E,
}

/// A piece of an eq table and the node of Google's `fill_recursive` tree it starts at: its
/// level, its count, its challenges and its two weights.
struct Piece<'a, E> {
    eq: &'a mut [E],
    l: usize,
    n: usize,
    g0: &'a [E],
    g1: &'a [E],
    w0: E,
    w1: E,
}

/// Google's `eq2` for each of `specs`: each table built by halves (`fill_recursive`), cut at the
/// top of its halving into as many pieces as its work pays for ([`par::tasks`]), and every piece
/// of every table filled at once when the pieces' work beside the largest pays for a region (one
/// region, so that a table's halves do not each fork). Each element is the product
/// `fill_recursive` makes, in its order.
pub(crate) fn eq_tables<const W: usize, F>(
    specs: &[EqSpec<'_, F::E>],
    f: &F,
) -> Result<Vec<Vec<F::E>>, Error>
where
    F: RuntimeField<W> + Sync,
    F::E: Send + Sync,
{
    let mut tables = Vec::with_capacity(specs.len());
    for s in specs {
        if s.nv == 0 || !sane_logw(s.logv) {
            return Err(DEFECT);
        }
        tables.push(vec![f.zero(); s.nv]);
    }
    let mut all = Vec::new();
    for (eq, s) in tables.iter_mut().zip(specs) {
        let most = s.nv.div_ceil(par::tasks(EQ.at::<W>().of(s.nv)));
        let top = Piece {
            eq,
            l: s.logv,
            n: s.nv,
            g0: s.g0,
            g1: s.g1,
            w0: f.one(),
            w1: s.alpha.clone(),
        };
        pieces(top, most, &mut all, f)?;
    }
    let fill_piece = |p: Piece<'_, F::E>| fill(p.eq, p.l, p.n, p.g0, p.g1, p.w0, p.w1, f);
    let at_once = par::uneven(all.iter().map(|p| EQ.at::<W>().of(p.n)));
    for done in par::map_if(at_once, all, fill_piece) {
        done?;
    }
    Ok(tables)
}

/// Google's `fill_recursive` tree from `p` walked down, in order, to pieces of at most `most`
/// elements, each pushed onto `out` with its node: `fill` on each gives the table.
fn pieces<'a, const W: usize, F>(
    p: Piece<'a, F::E>,
    most: usize,
    out: &mut Vec<Piece<'a, F::E>>,
    f: &F,
) -> Result<(), Error>
where
    F: RuntimeField<W>,
{
    let Piece {
        eq,
        l,
        n,
        g0,
        g1,
        w0,
        w1,
    } = p;
    let Some(nl) = l.checked_sub(1).filter(|_| n > most) else {
        out.push(Piece {
            eq,
            l,
            n,
            g0,
            g1,
            w0,
            w1,
        });
        return Ok(());
    };
    let s = 1usize.checked_shl(nl as u32).ok_or(DEFECT)?;
    let w0hi = f.mulf(&w0, g0.get(nl).ok_or(DEFECT)?);
    let w1hi = f.mulf(&w1, g1.get(nl).ok_or(DEFECT)?);
    let w0lo = f.subf(&w0, &w0hi);
    let w1lo = f.subf(&w1, &w1hi);
    let eq = eq.get_mut(..n).ok_or(DEFECT)?;
    let node = |eq, n, w0, w1| Piece {
        eq,
        l: nl,
        n,
        g0,
        g1,
        w0,
        w1,
    };
    if s < n {
        let (lo, hi) = eq.split_at_mut(s);
        pieces(node(lo, s, w0lo, w1lo), most, out, f)?;
        pieces(node(hi, n - s, w0hi, w1hi), most, out, f)
    } else {
        pieces(node(eq, n, w0lo, w1lo), most, out, f)
    }
}

/// Google's `fill_recursive`, in order.
#[allow(clippy::too_many_arguments)]
fn fill<const W: usize, F>(
    eq: &mut [F::E],
    l: usize,
    n: usize,
    g0: &[F::E],
    g1: &[F::E],
    w0: F::E,
    w1: F::E,
    f: &F,
) -> Result<(), Error>
where
    F: RuntimeField<W>,
{
    let Some(nl) = l.checked_sub(1) else {
        *eq.first_mut().ok_or(DEFECT)? = f.addf(&w0, &w1);
        return Ok(());
    };
    let s = 1usize.checked_shl(nl as u32).ok_or(DEFECT)?;
    let w0hi = f.mulf(&w0, g0.get(nl).ok_or(DEFECT)?);
    let w1hi = f.mulf(&w1, g1.get(nl).ok_or(DEFECT)?);
    let w0lo = f.subf(&w0, &w0hi);
    let w1lo = f.subf(&w1, &w1hi);
    let eq = eq.get_mut(..n).ok_or(DEFECT)?;
    if s < n {
        let (lo, hi) = eq.split_at_mut(s);
        fill(lo, nl, s, g0, g1, w0lo, w1lo, f)?;
        fill(hi, nl, n - s, g0, g1, w0hi, w1hi, f)
    } else {
        fill(eq, nl, n, g0, g1, w0lo, w1lo, f)
    }
}

/// A run of a bound quad's corners: each corner's (h0, h1) and value, in Morton order of
/// (h0, h1), indices distinct within the run.
struct CornerRun<E> {
    hc: Vec<[u32; 2]>,
    vc: Vec<E>,
}

/// A layer's quad bound to g (Google's `HQuad`), its corners cut into runs, each bound on its
/// own: Google's bindings are linear in the corners' values, and the runs are a partition of
/// its corners (a corner split by a cut of the terms, or a pair split by a cut of the corners,
/// is one corner in two runs, at the end of one and the start of the next), so the quad is the
/// sum of its runs, and so are a round's sums and the bound quad's value.
pub(crate) struct Corners<E> {
    runs: Vec<CornerRun<E>>,
}

/// A corner's index on `hand` and on the other hand.
fn hands(h: [u32; 2], hand: usize) -> (u32, u32) {
    let [h0, h1] = h;
    if hand == 0 {
        (h0, h1)
    } else {
        (h1, h0)
    }
}

/// A corner from its index on `hand` and on the other hand.
fn corner(on: u32, other: u32, hand: usize) -> [u32; 2] {
    if hand == 0 {
        [on, other]
    } else {
        [other, on]
    }
}

/// Whether corners `a` and `b`, in that order, bind together on `hand` (Google's `bind_h`): the
/// same index on the other hand, and on `hand` 2k then 2k + 1.
fn pair(a: [u32; 2], b: [u32; 2], hand: usize) -> bool {
    let ((ah, ao), (bh, bo)) = (hands(a, hand), hands(b, hand));
    ao == bo && ah >> 1 == bh >> 1 && ah.checked_add(1) == Some(bh)
}

/// Google's `HQuad::bind_h` of `run` on `hand` with challenge `r`, in place: each pair of
/// corners 2k, 2k + 1 on `hand` (the same on the other hand) becomes one corner k, its value the
/// affine interpolation at `r`, and each lone corner the interpolation with zero.
fn compact<const W: usize, F>(
    run: &mut CornerRun<F::E>,
    r: &F::E,
    hand: usize,
    f: &F,
) -> Result<(), Error>
where
    F: RuntimeField<W>,
{
    let n = run.hc.len();
    let (mut rd, mut wr) = (0, 0);
    while rd < n {
        let a = *run.hc.get(rd).ok_or(DEFECT)?;
        let (on, other) = hands(a, hand);
        let va = run.vc.get(rd).ok_or(DEFECT)?;
        let (v, step) = match run.hc.get(rd + 1) {
            Some(&b) if pair(a, b, hand) => {
                let vb = run.vc.get(rd + 1).ok_or(DEFECT)?;
                (affine_interpolation(r, va, vb, f), 2)
            }
            _ if on & 1 == 0 => (affine_interpolation_nz_z(r, va, f), 1),
            _ => (affine_interpolation_z_nz(r, va, f), 1),
        };
        *run.hc.get_mut(wr).ok_or(DEFECT)? = corner(on >> 1, other, hand);
        *run.vc.get_mut(wr).ok_or(DEFECT)? = v;
        wr += 1;
        rd += step;
    }
    run.hc.truncate(wr);
    run.vc.truncate(wr);
    Ok(())
}

/// Google's `HQuad::bind_g` of one run of `layer`'s terms on the eq table `dot`: each term's
/// value k · dot[g] (beta · dot[g] for an assertion), consecutive terms of one corner added into
/// one.
fn bind_run<const W: usize, F>(
    layer: &Layer<F>,
    constants: &[F::E],
    dot: &[F::E],
    beta: &F::E,
    run: &TermRun,
    f: &F,
) -> Result<CornerRun<F::E>, Error>
where
    F: RuntimeField<W> + SerializableField,
{
    let mut hc: Vec<[u32; 2]> = Vec::with_capacity(run.count);
    let mut vc: Vec<F::E> = Vec::with_capacity(run.count);
    // The last corner made (none yet: no corner is (u32::MAX, u32::MAX) in a valid layer, and a
    // term there finds no last value to add into).
    let mut last = [u32::MAX; 2];
    each_term(layer, constants, run, |k, g, h0, h1| {
        let d = dot.get(g as usize).ok_or(DEFECT)?;
        let v = if f.is_zero(k) {
            f.mulf(beta, d)
        } else {
            f.mulf(k, d)
        };
        match vc.last_mut() {
            Some(sum) if last == [h0, h1] => f.add(sum, &v),
            _ => {
                last = [h0, h1];
                hc.push(last);
                vc.push(v);
            }
        }
        Ok(())
    })?;
    Ok(CornerRun { hc, vc })
}

impl<E: Clone + Send + Sync> Corners<E> {
    /// The corners, over every run.
    fn len(&self) -> usize {
        self.runs.iter().map(|r| r.hc.len()).sum()
    }

    /// Runs too small to share (a round's work on all of them pays for no region) become one, a
    /// run's first corner added into the corner before it when they are one corner (Google adds
    /// consecutive equal corners into one).
    fn merge_small<const W: usize, F>(&mut self, f: &F)
    where
        F: RuntimeField<W, E = E>,
    {
        if self.runs.len() <= 1 || par::tasks(ROUND.at::<W>().of(self.len())) > 1 {
            return;
        }
        let mut one = CornerRun {
            hc: Vec::with_capacity(self.len()),
            vc: Vec::with_capacity(self.len()),
        };
        for run in std::mem::take(&mut self.runs) {
            for (k, (h, v)) in run.hc.into_iter().zip(run.vc).enumerate() {
                let joins = k == 0 && one.hc.last() == Some(&h);
                match one.vc.last_mut() {
                    Some(sum) if joins => f.add(sum, &v),
                    _ => {
                        one.hc.push(h);
                        one.vc.push(v);
                    }
                }
            }
        }
        self.runs = vec![one];
    }

    /// The runs in as many groups of consecutive runs as `work` pays for ([`par::tasks`]), at
    /// most one a run.
    fn groups(&mut self, work: par::Work) -> Vec<Vec<&mut CornerRun<E>>> {
        let n = self.runs.len();
        let mut runs = self.runs.iter_mut();
        spans(n, par::tasks(work))
            .into_iter()
            .map(|g| runs.by_ref().take(g.len()).collect())
            .collect()
    }

    /// Google's `HQuad::bind_h` on `hand` with challenge `r`: each run compacted on its own, in
    /// as many groups at once as the work pays for; then runs too small to share are one.
    fn bind_h<const W: usize, F>(&mut self, r: &E, hand: usize, f: &F) -> Result<(), Error>
    where
        F: RuntimeField<W, E = E> + Sync,
    {
        let groups = self.groups(COMPACT.at::<W>().of(self.len()));
        for done in par::map(groups, |g| {
            g.into_iter().try_for_each(|run| compact(run, r, hand, f))
        }) {
            done?;
        }
        self.merge_small(f);
        Ok(())
    }

    /// One round's sums on `hand` (the scatter qw[h_hand] += v · w_other[h_other] over the
    /// corners, then a0 and a2 against `w_hand`), the corners first bound to the previous
    /// round's challenge `r` on `bound_hand`: on several runs whose round's work pays for a
    /// region, both in one region, in as many groups of runs as the work pays for, each run
    /// compacting itself and taking its share of the sums ([`run_sums`]); otherwise in order,
    /// the runs then too small to share one, and on one run Google's loop ([`one_run_sums`]).
    #[allow(clippy::too_many_arguments)]
    fn round<const W: usize, F>(
        &mut self,
        r: &E,
        bound_hand: usize,
        hand: usize,
        w_hand: &[E],
        w_other: &[E],
        qw: &mut Vec<E>,
        f: &F,
    ) -> Result<Sums<E>, Error>
    where
        F: InterpolationField<W, E = E> + Sync,
    {
        let odd_last = odd_last(w_hand.len());
        let work = ROUND.at::<W>().of(self.len());
        if self.runs.len() > 1 && par::tasks(work) > 1 {
            let groups = self.groups(work);
            let shares = par::map(groups, |g| -> Result<Sums<E>, Error> {
                let shares = g.into_iter().map(|run| {
                    compact(run, r, bound_hand, f)?;
                    run_sums(run, hand, w_hand, w_other, odd_last, f)
                });
                add_shares(shares.collect::<Vec<_>>(), f)
            });
            let sums = add_shares(shares, f)?;
            self.merge_small(f);
            return Ok(sums);
        }
        for run in &mut self.runs {
            compact(run, r, bound_hand, f)?;
        }
        self.merge_small(f);
        self.sums(hand, w_hand, w_other, qw, f)
    }

    /// A round's sums on `hand` in order: Google's loop on one run, each run's share otherwise.
    fn sums<const W: usize, F>(
        &self,
        hand: usize,
        w_hand: &[E],
        w_other: &[E],
        qw: &mut Vec<E>,
        f: &F,
    ) -> Result<Sums<E>, Error>
    where
        F: RuntimeField<W, E = E>,
    {
        match self.runs.as_slice() {
            [run] => one_run_sums(run, hand, w_hand, w_other, qw, f),
            runs => {
                let odd_last = odd_last(w_hand.len());
                let shares = runs
                    .iter()
                    .map(|run| run_sums(run, hand, w_hand, w_other, odd_last, f));
                add_shares(shares, f)
            }
        }
    }

    /// The one corner left once every round is bound, at (0, 0): its value (Google's `scalar`),
    /// the sum of the runs' values, a run's first corner added into the one before it when they
    /// are one corner.
    fn scalar<const W: usize, F>(self, f: &F) -> Result<E, Error>
    where
        F: RuntimeField<W, E = E>,
    {
        let mut one: Option<([u32; 2], E)> = None;
        let mut corners = 0usize;
        for run in self.runs {
            for (k, (h, v)) in run.hc.into_iter().zip(run.vc).enumerate() {
                match &mut one {
                    Some((last, sum)) if k == 0 && *last == h => f.add(sum, &v),
                    _ => {
                        corners += 1;
                        one = Some((h, v));
                    }
                }
            }
        }
        match (corners, one) {
            (1, Some(([0, 0], v))) => Ok(v),
            _ => Err(DEFECT),
        }
    }
}

/// The wire left out of every pair when a hand has an odd count `n` of wires: the last.
fn odd_last(n: usize) -> Option<usize> {
    (n % 2 == 1).then(|| n - 1)
}

/// A round's sums, or a run's share of them (Google's `quad_round_poly`'s a0 and a2).
struct Sums<E> {
    a0: E,
    a2: E,
}

/// A run of corners just bound from its terms, and its share of round 0's sums.
struct RunBound<E> {
    run: CornerRun<E>,
    sums: Sums<E>,
}

/// A quad just bound from its terms, and round 0's sums.
struct QuadBound<E> {
    corners: Corners<E>,
    sums: Sums<E>,
}

/// The sums of the runs' shares of a round's sums, in order.
fn add_shares<const W: usize, F: RuntimeField<W>>(
    shares: impl IntoIterator<Item = Result<Sums<F::E>, Error>>,
    f: &F,
) -> Result<Sums<F::E>, Error> {
    let (mut a0, mut a2) = (f.zero(), f.zero());
    for s in shares {
        let share = s?;
        f.add(&mut a0, &share.a0);
        f.add(&mut a2, &share.a2);
    }
    Ok(Sums { a0, a2 })
}

/// The quad of `layer` bound to the eq table `dot` (Google's `HQuad::bind_g`), each run of
/// `runs` on its own, and with it round 0's sums on hand 0 over the shared wires `w`: on several
/// runs, each run binds its terms and takes its share of the sums at once (one region); on one,
/// in order, the sums by Google's loop.
#[allow(clippy::too_many_arguments)]
fn bind_first<const W: usize, F>(
    layer: &Layer<F>,
    constants: &[F::E],
    runs: &[TermRun],
    dot: &[F::E],
    beta: &F::E,
    w: &[F::E],
    qw: &mut Vec<F::E>,
    f: &F,
) -> Result<QuadBound<F::E>, Error>
where
    F: InterpolationField<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    if runs.len() <= 1 {
        let mut out = Vec::with_capacity(runs.len());
        for run in runs {
            out.push(bind_run(layer, constants, dot, beta, run, f)?);
        }
        let corners = Corners { runs: out };
        let sums = corners.sums(0, w, w, qw, f)?;
        return Ok(QuadBound { corners, sums });
    }
    let odd_last = odd_last(w.len());
    let at_once = par::uneven(runs.iter().map(|run| FIRST.at::<W>().of(run.count)));
    let runs: Vec<&TermRun> = runs.iter().collect();
    let made = par::map_if(
        at_once,
        runs,
        |run| -> Result<RunBound<F::E>, Error> {
            let c = bind_run(layer, constants, dot, beta, run, f)?;
            let s = run_sums(&c, 0, w, w, odd_last, f)?;
            Ok(RunBound { run: c, sums: s })
        },
    );
    let mut out = Vec::with_capacity(made.len());
    let mut shares = Vec::with_capacity(made.len());
    for m in made {
        let bound = m?;
        out.push(bound.run);
        shares.push(Ok(bound.sums));
    }
    let sums = add_shares(shares, f)?;
    let mut corners = Corners { runs: out };
    corners.merge_small(f);
    Ok(QuadBound { corners, sums })
}

/// The quad of `layer` bound to the eq table `dot`, every run of `runs` (Google's
/// `HQuad::bind_g`, for a layer of no round): at once on several runs.
fn bind_all<const W: usize, F>(
    layer: &Layer<F>,
    constants: &[F::E],
    runs: &[TermRun],
    dot: &[F::E],
    beta: &F::E,
    f: &F,
) -> Result<Corners<F::E>, Error>
where
    F: RuntimeField<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    let bound = |run: &TermRun| bind_run(layer, constants, dot, beta, run, f);
    let at_once = par::uneven(runs.iter().map(|run| FIRST.at::<W>().of(run.count)));
    let made = par::map_if(at_once, runs.iter().collect(), bound);
    Ok(Corners {
        runs: made.into_iter().collect::<Result<Vec<_>, _>>()?,
    })
}

/// Google's `quad_round_poly` over the pairs `pairs` of the scatter `qw` (indexed from `at`)
/// and the wires `w`: the partial sums a0 = Σ qw[2i] · w[2i] and
/// a2 = Σ (qw[2i+1] − qw[2i]) · (w[2i+1] − w[2i]), and, for an odd count of wires, the last one's
/// qw · w added to both, as Google adds it.
fn round_sums<const W: usize, F: RuntimeField<W>>(
    qw: &[F::E],
    at: usize,
    w: &[F::E],
    pairs: Range<usize>,
    odd_last: Option<usize>,
    f: &F,
) -> Result<(F::E, F::E), Error> {
    let mut a0 = f.zero_accum();
    let mut a2 = f.zero_accum();
    for i in pairs {
        let idx = 2 * i;
        let q0 = qw.get(idx - at).ok_or(DEFECT)?;
        let q1 = qw.get(idx + 1 - at).ok_or(DEFECT)?;
        let w0 = w.get(idx).ok_or(DEFECT)?;
        let w1 = w.get(idx + 1).ok_or(DEFECT)?;
        f.mac(&mut a0, q0, w0);
        f.mac(&mut a2, &f.subf(q1, q0), &f.subf(w1, w0));
    }
    if let Some(last) = odd_last {
        let q = qw.get(last - at).ok_or(DEFECT)?;
        let x = w.get(last).ok_or(DEFECT)?;
        f.mac(&mut a0, q, x);
        f.mac(&mut a2, q, x);
    }
    Ok((f.accum_reduce(&a0), f.accum_reduce(&a2)))
}

/// The round polynomial from its sums (Google's `quad_round_poly`'s end): g(0) = a0,
/// g(1) = sum − a0, g(2) by Horner's rule on c1 = g(1) − a0 − a2.
fn round_poly_of<const W: usize, F: InterpolationField<W>>(
    a0: F::E,
    a2: F::E,
    sum: &F::E,
    f: &F,
) -> Poly<3, W, F> {
    let mut g1 = sum.clone();
    f.sub(&mut g1, &a0);
    let mut c1 = g1.clone();
    f.sub(&mut c1, &a0);
    f.sub(&mut c1, &a2);
    let pt2 = f.poly_evaluation_point(2);
    let mut g2 = a2;
    f.mul(&mut g2, &pt2);
    f.add(&mut g2, &c1);
    f.mul(&mut g2, &pt2);
    f.add(&mut g2, &a0);
    Poly {
        evaluations: [a0, g1, g2],
    }
}

/// The scatter of `run`'s corners on `hand`, qw[h_hand − lo] += v · w_other[h_other], into `buf`.
fn scatter<const W: usize, F: RuntimeField<W>>(
    run: &CornerRun<F::E>,
    hand: usize,
    w_other: &[F::E],
    lo: usize,
    buf: &mut [F::E],
    f: &F,
) -> Result<(), Error> {
    for (&h, v) in run.hc.iter().zip(&run.vc) {
        let (on, other) = hands(h, hand);
        let dst = (on as usize).checked_sub(lo).ok_or(DEFECT)?;
        f.fma(
            buf.get_mut(dst).ok_or(DEFECT)?,
            v,
            w_other.get(other as usize).ok_or(DEFECT)?,
        );
    }
    Ok(())
}

/// A round's sums by Google's loop over one run: the scatter over every wire of `hand` into
/// `qw` (kept by the caller from round to round, Google's `qw`), then the sums over every pair.
fn one_run_sums<const W: usize, F: RuntimeField<W>>(
    run: &CornerRun<F::E>,
    hand: usize,
    w_hand: &[F::E],
    w_other: &[F::E],
    qw: &mut Vec<F::E>,
    f: &F,
) -> Result<Sums<F::E>, Error> {
    let n = w_hand.len();
    qw.clear();
    qw.resize(n, f.zero());
    scatter(run, hand, w_other, 0, qw, f)?;
    let (a0, a2) = round_sums(qw, 0, w_hand, 0..n / 2, odd_last(n), f)?;
    Ok(Sums { a0, a2 })
}

/// One run's share of a round's sums on `hand`: where the range of `hand`'s wires the run
/// reaches is no wider than its corners (corners in Morton order reach narrow ranges of the
/// last-bound hand), its scatter into a buffer of its own over the pairs that range touches,
/// then the sums over those pairs (the sums are linear in the scatter, and the scatter is zero
/// outside the range); where it is wider, corner by corner ([`corner_sums`]), which no buffer
/// bounds.
fn run_sums<const W: usize, F: RuntimeField<W>>(
    run: &CornerRun<F::E>,
    hand: usize,
    w_hand: &[F::E],
    w_other: &[F::E],
    odd_last: Option<usize>,
    f: &F,
) -> Result<Sums<F::E>, Error> {
    let (lo, hi) = run.hc.iter().fold((u32::MAX, 0u32), |(lo, hi), &h| {
        let (on, _) = hands(h, hand);
        (lo.min(on), hi.max(on))
    });
    if lo > hi {
        return Ok(Sums {
            a0: f.zero(),
            a2: f.zero(),
        });
    }
    let (lo, hi) = (lo as usize, hi as usize);
    if hi - lo >= run.hc.len() {
        return corner_sums(run, hand, w_hand, w_other, odd_last, f);
    }
    let n = w_hand.len();
    // The pairs the range touches, and the odd last wire if the range holds it.
    let at = lo & !1;
    let end = ((hi + 2) & !1).min(n);
    let pairs = at / 2..end.min(n & !1) / 2;
    let tail = odd_last.filter(|&last| last >= at && last < end);
    let mut buf = vec![f.zero(); end - at];
    scatter(run, hand, w_other, at, &mut buf, f)?;
    let (a0, a2) = round_sums(&buf, at, w_hand, pairs, tail, f)?;
    Ok(Sums { a0, a2 })
}

/// One run's share of a round's sums taken corner by corner, with no scatter: a corner c on
/// wire h of `hand` adds t = v · w_other[h_other] to qw[h], so it adds t · w[h] to a0 when h is
/// even, and t · (w[h] − w[h ± 1]) to a2 (the pair's difference, signed by h's place in it);
/// on the lone last wire of an odd count, t · w[h] to both, as Google's sums take it.
fn corner_sums<const W: usize, F: RuntimeField<W>>(
    run: &CornerRun<F::E>,
    hand: usize,
    w_hand: &[F::E],
    w_other: &[F::E],
    odd_last: Option<usize>,
    f: &F,
) -> Result<Sums<F::E>, Error> {
    let mut a0 = f.zero_accum();
    let mut a2 = f.zero_accum();
    for (&h, v) in run.hc.iter().zip(&run.vc) {
        let (on, other) = hands(h, hand);
        let on = on as usize;
        let t = f.mulf(v, w_other.get(other as usize).ok_or(DEFECT)?);
        let x = w_hand.get(on).ok_or(DEFECT)?;
        if odd_last == Some(on) {
            f.mac(&mut a0, &t, x);
            f.mac(&mut a2, &t, x);
        } else if on.is_multiple_of(2) {
            f.mac(&mut a0, &t, x);
            let y = w_hand.get(on + 1).ok_or(DEFECT)?;
            f.mac(&mut a2, &t, &f.subf(x, y));
        } else {
            let y = w_hand.get(on - 1).ok_or(DEFECT)?;
            f.mac(&mut a2, &t, &f.subf(x, y));
        }
    }
    Ok(Sums {
        a0: f.accum_reduce(&a0),
        a2: f.accum_reduce(&a2),
    })
}

/// Google's `dense::bind_out_of_place`: `v` halved at challenge `r` into a new vector,
/// out[i] = v[2i] + r · (v[2i+1] − v[2i]), an odd last element bound with zero.
fn halved<const W: usize, F: RuntimeField<W>>(
    v: &[F::E],
    r: &F::E,
    f: &F,
) -> Result<Vec<F::E>, Error> {
    let last = v.last().ok_or(DEFECT)?;
    let mut out: Vec<F::E> = v
        .chunks_exact(2)
        .map(|p| match p {
            [a, b] => affine_interpolation(r, a, b, f),
            _ => f.zero(),
        })
        .collect();
    if v.len() % 2 == 1 {
        out.push(affine_interpolation_nz_z(r, last, f));
    }
    Ok(out)
}

/// Google's `dense::bind`: `v` halved in place at challenge `r`, v[i] = v[2i] + r · (v[2i+1] −
/// v[2i]), an odd last element bound with zero.
fn bind_dense<const W: usize, F: RuntimeField<W>>(
    v: &mut Vec<F::E>,
    r: &F::E,
    f: &F,
) -> Result<(), Error> {
    let n = v.len();
    if n == 0 {
        return Err(DEFECT);
    }
    let half = n / 2;
    for i in 0..half {
        let x = affine_interpolation(
            r,
            v.get(2 * i).ok_or(DEFECT)?,
            v.get(2 * i + 1).ok_or(DEFECT)?,
            f,
        );
        *v.get_mut(i).ok_or(DEFECT)? = x;
    }
    if n % 2 == 1 {
        let x = affine_interpolation_nz_z(r, v.last().ok_or(DEFECT)?, f);
        *v.get_mut(half).ok_or(DEFECT)? = x;
        v.truncate(half + 1);
    } else {
        v.truncate(half);
    }
    Ok(())
}

/// The one element a fully bound vector holds (Google's `as_scalar`).
fn as_scalar<E: Clone>(v: &[E]) -> Result<E, Error> {
    match v {
        [x] => Ok(x.clone()),
        _ => Err(DEFECT),
    }
}

/// What a layer's sumcheck gives: its proof, its rounds' challenges per hand, the claims it
/// leaves (each hand's wires bound to one value), and its bound quad's value.
struct LayerOut<const W: usize, F: SerializableField> {
    proof: LayerProof<W, F>,
    challenges: [Vec<F::E>; 2],
    claims: [F::E; 2],
    bound_quad: F::E,
}

/// A layer's quad before its binding: the layer, the circuit's constants, the layer's runs of
/// terms ([`layer_runs`]), its eq table on the previous layer's challenges, and its beta.
struct Quad<'a, F: SerializableField> {
    layer: &'a Layer<F>,
    constants: &'a [F::E],
    runs: &'a [TermRun],
    dot: Vec<F::E>,
    beta: F::E,
}

/// Google's `layer`: the sumcheck of one layer over its wires `wires` (both hands the same
/// wires until hand 0's first binding), each round's polynomial padded with `pad`'s, its
/// challenge drawn from `transcript`, the wires and the corners bound to it; then the claims,
/// checked against the round's sum, padded and written. The quad is bound to its eq table with
/// round 0's sums ([`bind_first`]), and each later round's sums with the corners' binding to the
/// round before's challenge ([`Corners::round`]): one region a round where the work is shared.
#[allow(clippy::too_many_arguments)]
fn layer<const W: usize, F>(
    logw: usize,
    wires: Vec<F::E>,
    pad: &LayerProof<W, F>,
    transcript: &mut Transcript,
    quad: Quad<'_, F>,
    alpha: &F::E,
    claims: [F::E; 2],
    f: &F,
) -> Result<LayerOut<W, F>, Error>
where
    F: InterpolationField<W> + SupportsSampling<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    if !sane_logw(logw) || wires.len() as u64 > 1u64.checked_shl(logw as u32).unwrap_or(0) {
        return Err(DEFECT);
    }
    let mut challenges = [Vec::with_capacity(logw), Vec::with_capacity(logw)];
    let mut round_polys = [Vec::with_capacity(logw), Vec::with_capacity(logw)];
    let [c0, c1] = claims;
    let mut sum = c0;
    f.fma(&mut sum, alpha, &c1);
    // Hand 0's wires: the shared ones until its first binding.
    let mut w0: Option<Vec<F::E>> = None;
    let mut w1 = wires;
    // The scatter of one run's rounds, reused from round to round (Google's `qw`).
    let mut qw = Vec::new();
    // The bound quad once round 0 binds it, and the last challenge with its hand.
    let mut corners: Option<Corners<F::E>> = None;
    let mut last: Option<(F::E, usize)> = None;
    for round in 0..logw {
        if round >= MAX_LOGW {
            return Err(DEFECT);
        }
        for hand in 0..2 {
            let (w_hand, w_other): (&[F::E], &[F::E]) = match (hand, &w0) {
                (0, None) => (&w1, &w1),
                (0, Some(w0)) => (w0, &w1),
                (_, Some(w0)) => (&w1, w0),
                (_, None) => return Err(DEFECT),
            };
            let Sums { a0, a2 } = match (&mut corners, &last) {
                (Some(c), Some((r, bound))) => {
                    c.round(r, *bound, hand, w_hand, w_other, &mut qw, f)?
                }
                (None, None) => {
                    let bound = bind_first(
                        quad.layer,
                        quad.constants,
                        quad.runs,
                        &quad.dot,
                        &quad.beta,
                        w_hand,
                        &mut qw,
                        f,
                    )?;
                    corners = Some(bound.corners);
                    bound.sums
                }
                _ => return Err(DEFECT),
            };
            let evaluations = round_poly_of(a0, a2, &sum, f);
            let hp = pad.hp.get(hand).and_then(|h| h.get(round)).ok_or(DEFECT)?;
            let padded = evaluations.to_wire().sub(hp, f);
            let r = transcript.round(&padded, f);
            sum = evaluations.eval_lagrange(&r, f);
            // Hand 0's first binding halves the shared wires into a vector of its own; every
            // other binding halves its hand's wires in place (Google's `layer`).
            if hand == 0 {
                if let Some(v) = w0.as_mut() {
                    bind_dense(v, &r, f)?;
                } else {
                    w0 = Some(halved(&w1, &r, f)?);
                }
            } else {
                bind_dense(&mut w1, &r, f)?;
            }
            round_polys.get_mut(hand).ok_or(DEFECT)?.push(padded);
            challenges.get_mut(hand).ok_or(DEFECT)?.push(r.clone());
            last = Some((r, hand));
        }
    }
    let corners = match (corners, last) {
        (Some(mut c), Some((r, hand))) => {
            c.bind_h(&r, hand, f)?;
            c
        }
        (None, None) => bind_all(
            quad.layer,
            quad.constants,
            quad.runs,
            &quad.dot,
            &quad.beta,
            f,
        )?,
        _ => return Err(DEFECT),
    };
    let w0 = w0.unwrap_or_else(|| w1.clone());
    let next = [as_scalar(&w0)?, as_scalar(&w1)?];
    let bound_quad = corners.scalar(f)?;
    let [n0, n1] = &next;
    let mut expected = n0.clone();
    f.mul(&mut expected, n1);
    f.mul(&mut expected, &bound_quad);
    if sum != expected {
        return Err(UNSATISFIED);
    }
    let [p0, p1] = &pad.claims;
    let mut proof_claims = next.clone();
    let [q0, q1] = &mut proof_claims;
    f.sub(q0, p0);
    f.sub(q1, p1);
    transcript.end_layer(&proof_claims, f);
    Ok(LayerOut {
        proof: LayerProof {
            hp: round_polys,
            claims: proof_claims,
        },
        challenges,
        claims: next,
        bound_quad,
    })
}

/// Google's `prove_core`: the circuit's layers proved from the output down on `evaluated` (each
/// layer's inputs and runs of terms, from [`eval_circuit`]), each with its pad, the challenges of
/// each layer binding the next one's quad; returns the proof and each layer's bound quad (the
/// prover's `aux` for the symbolic verifier).
pub(crate) fn prove_core<const W: usize, F>(
    evaluated: Evaluated<F::E>,
    pad: &SumcheckProof<W, F>,
    circuit: &Circuit<F>,
    transcript: &mut Transcript,
    f: &F,
) -> Result<(SumcheckProof<W, F>, SumcheckProofAux<W, F>), Error>
where
    F: InterpolationField<W> + SupportsSampling<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    let layers = &circuit.raw.layers;
    let Evaluated { in_layers, runs } = evaluated;
    if in_layers.len() < layers.len()
        || runs.len() < layers.len()
        || pad.layers.len() < layers.len()
    {
        return Err(DEFECT);
    }
    let (_copies, g) = transcript.begin_circuit(f);
    let mut logv = circuit.raw.logv;
    let mut nv = circuit.raw.noutput;
    let first = g.get(..logv).ok_or(DEFECT)?.to_vec();
    let mut bindings = [first.clone(), first];
    let mut claims = [f.zero(), f.zero()];
    let mut proofs = Vec::with_capacity(layers.len());
    let mut bound_quad = Vec::with_capacity(layers.len());
    for (((clr, wires), runs), pad) in layers.iter().zip(in_layers).zip(&runs).zip(&pad.layers) {
        // The wires are padded with zeros: at least one, so that every binding has one.
        let wires = if wires.is_empty() {
            vec![f.zero()]
        } else {
            wires
        };
        let (alpha, beta) = transcript.begin_layer(f);
        let [b0, b1] = &bindings;
        let dot = eq_tables(
            &[EqSpec {
                logv,
                nv,
                g0: b0,
                g1: b1,
                alpha: &alpha,
            }],
            f,
        )?
        .pop()
        .ok_or(DEFECT)?;
        let quad = Quad {
            layer: clr,
            constants: &circuit.raw.constants,
            runs,
            dot,
            beta,
        };
        let out = layer(clr.logw(), wires, pad, transcript, quad, &alpha, claims, f)?;
        (logv, nv, bindings, claims) = (clr.logw(), clr.nw(), out.challenges, out.claims);
        bound_quad.push(out.bound_quad);
        proofs.push(out.proof);
    }
    Ok((
        SumcheckProof { layers: proofs },
        SumcheckProofAux { bound_quad },
    ))
}

/// One layer's quad for [`bind_quads`]: the layer, its eq table, its beta, its runs of terms
/// ([`layer_runs`]) and its rounds' challenges per hand.
pub(crate) struct QuadJob<'a, F: SerializableField> {
    pub(crate) layer: &'a Layer<F>,
    pub(crate) dot: &'a [F::E],
    pub(crate) beta: &'a F::E,
    pub(crate) runs: &'a [TermRun],
    pub(crate) lchal: &'a [Vec<F::E>; 2],
}

/// Every layer's bound quad, as Google's `bind_quad` binds it (the verifier's): each run of each
/// layer's terms bound to its eq table, then to each round's challenge of hand 0 and of hand 1,
/// on its own (Google's bindings are linear in the corners' values: [`Corners`]), every run of
/// every layer at once in one region when the work beside the largest run's pays for it; then
/// each layer's runs added into its one corner at (0, 0).
pub(crate) fn bind_quads<const W: usize, F>(
    jobs: &[QuadJob<'_, F>],
    constants: &[F::E],
    f: &F,
) -> Result<Vec<F::E>, Error>
where
    F: RuntimeField<W> + SerializableField + Sync,
    F::E: Send + Sync,
{
    let items: Vec<(usize, &TermRun)> = jobs
        .iter()
        .enumerate()
        .flat_map(|(k, j)| j.runs.iter().map(move |run| (k, run)))
        .collect();
    let one = |(k, run): (usize, &TermRun)| -> Result<(usize, CornerRun<F::E>), Error> {
        let j = jobs.get(k).ok_or(DEFECT)?;
        let mut c = bind_run(j.layer, constants, j.dot, j.beta, run, f)?;
        let [l0, l1] = j.lchal;
        for (c0, c1) in l0.iter().zip(l1).take(j.layer.logw()) {
            compact(&mut c, c0, 0, f)?;
            compact(&mut c, c1, 1, f)?;
        }
        Ok((k, c))
    };
    let at_once = par::uneven(items.iter().map(|(_, run)| BIND.at::<W>().of(run.count)));
    let done = par::map_if(at_once, items, one);
    let mut per: Vec<Vec<CornerRun<F::E>>> = jobs.iter().map(|_| Vec::new()).collect();
    for d in done {
        let (k, c) = d?;
        per.get_mut(k).ok_or(DEFECT)?.push(c);
    }
    per.into_iter()
        .map(|runs| Corners { runs }.scalar(f))
        .collect()
}
