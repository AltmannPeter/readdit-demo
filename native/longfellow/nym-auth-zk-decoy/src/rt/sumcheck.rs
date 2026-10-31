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
//! Google's circuit evaluation and sumcheck prover (`runtime_sumcheck`), with each layer's
//! independent work computed in parallel. Byte for byte Google's output.

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

const DEFECT: Error = Error::Internal("inconsistent");
const UNSATISFIED: Error = Error::Unsatisfied;

const TERM: FieldCost = FieldCost::new(166, 500);
const DELTA: Cost = Cost::ir(12);
const ADD: FieldCost = FieldCost::new(17, 32);
const EQ: FieldCost = FieldCost::new(147, 618);
const ROUND: FieldCost = FieldCost::new(103, 418);
const FIRST: FieldCost = FieldCost::new(104, 483);
const COMPACT: FieldCost = FieldCost::new(136, 306);
const BIND: FieldCost = FieldCost::new(220, 697);

fn parts<const W: usize>(terms: usize) -> usize {
    par::tasks(TERM.at::<W>().of(terms))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct At {
    token: usize,
    offset: usize,
}

pub(crate) struct TermRun {
    from: At,
    to: At,
    prev: [u32; 3],
    count: usize,
}

fn plus(a: [u32; 3], d: [u32; 3]) -> [u32; 3] {
    let ([a0, a1, a2], [d0, d1, d2]) = (a, d);
    [
        a0.wrapping_add(d0),
        a1.wrapping_add(d1),
        a2.wrapping_add(d2),
    ]
}

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

pub(crate) fn layer_runs<const W: usize, F: SerializableField + Sync>(
    layer: &Layer<F>,
) -> Result<Vec<TermRun>, Error> {
    term_runs(layer, parts::<W>(layer.num_terms()))
}

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

pub(crate) struct Evaluated<E> {
    in_layers: Vec<Vec<E>>,
    runs: Vec<Vec<TermRun>>,
}

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

pub(crate) struct EqSpec<'a, E> {
    pub(crate) logv: usize,
    pub(crate) nv: usize,
    pub(crate) g0: &'a [E],
    pub(crate) g1: &'a [E],
    pub(crate) alpha: &'a E,
}

struct Piece<'a, E> {
    eq: &'a mut [E],
    l: usize,
    n: usize,
    g0: &'a [E],
    g1: &'a [E],
    w0: E,
    w1: E,
}

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

struct CornerRun<E> {
    hc: Vec<[u32; 2]>,
    vc: Vec<E>,
}

pub(crate) struct Corners<E> {
    runs: Vec<CornerRun<E>>,
}

fn hands(h: [u32; 2], hand: usize) -> (u32, u32) {
    let [h0, h1] = h;
    if hand == 0 {
        (h0, h1)
    } else {
        (h1, h0)
    }
}

fn corner(on: u32, other: u32, hand: usize) -> [u32; 2] {
    if hand == 0 {
        [on, other]
    } else {
        [other, on]
    }
}

fn pair(a: [u32; 2], b: [u32; 2], hand: usize) -> bool {
    let ((ah, ao), (bh, bo)) = (hands(a, hand), hands(b, hand));
    ao == bo && ah >> 1 == bh >> 1 && ah.checked_add(1) == Some(bh)
}

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
    fn len(&self) -> usize {
        self.runs.iter().map(|r| r.hc.len()).sum()
    }

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

    fn groups(&mut self, work: par::Work) -> Vec<Vec<&mut CornerRun<E>>> {
        let n = self.runs.len();
        let mut runs = self.runs.iter_mut();
        spans(n, par::tasks(work))
            .into_iter()
            .map(|g| runs.by_ref().take(g.len()).collect())
            .collect()
    }

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

fn odd_last(n: usize) -> Option<usize> {
    (n % 2 == 1).then(|| n - 1)
}

struct Sums<E> {
    a0: E,
    a2: E,
}

struct RunBound<E> {
    run: CornerRun<E>,
    sums: Sums<E>,
}

struct QuadBound<E> {
    corners: Corners<E>,
    sums: Sums<E>,
}

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
    let at = lo & !1;
    let end = ((hi + 2) & !1).min(n);
    let pairs = at / 2..end.min(n & !1) / 2;
    let tail = odd_last.filter(|&last| last >= at && last < end);
    let mut buf = vec![f.zero(); end - at];
    scatter(run, hand, w_other, at, &mut buf, f)?;
    let (a0, a2) = round_sums(&buf, at, w_hand, pairs, tail, f)?;
    Ok(Sums { a0, a2 })
}

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

fn as_scalar<E: Clone>(v: &[E]) -> Result<E, Error> {
    match v {
        [x] => Ok(x.clone()),
        _ => Err(DEFECT),
    }
}

struct LayerOut<const W: usize, F: SerializableField> {
    proof: LayerProof<W, F>,
    challenges: [Vec<F::E>; 2],
    claims: [F::E; 2],
    bound_quad: F::E,
}

struct Quad<'a, F: SerializableField> {
    layer: &'a Layer<F>,
    constants: &'a [F::E],
    runs: &'a [TermRun],
    dot: Vec<F::E>,
    beta: F::E,
}

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
    let mut w0: Option<Vec<F::E>> = None;
    let mut w1 = wires;
    let mut qw = Vec::new();
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

pub(crate) struct QuadJob<'a, F: SerializableField> {
    pub(crate) layer: &'a Layer<F>,
    pub(crate) dot: &'a [F::E],
    pub(crate) beta: &'a F::E,
    pub(crate) runs: &'a [TermRun],
    pub(crate) lchal: &'a [Vec<F::E>; 2],
}

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
