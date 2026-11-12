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

//! Independent work at once under the `parallel` feature, in order without it (the pattern of
//! arkworks' `cfg_iter!`, which picks rayon's `par_iter` or `iter` by the feature).
//!
//! The output never depends on the thread count: each item's result is a function of the item
//! alone (and of its worker's state, for `map_init`, which `init` makes the same for every
//! worker), and the results come back in the items' order.
//!
//! **Whether work runs at once** is decided per call from its size, never measured at run time.
//! A site estimates a call's serial [`Work`] from the sizes it holds: its units times its
//! [`Cost`] per unit (instructions per unit, measured offline), with a size factor where a
//! unit's cost grows with its size. One constant, [`W_MIN`], is the work a parallel region pays
//! for. Work cut into even units runs as [`tasks`] tasks: one, on the calling thread, below twice
//! [`W_MIN`], else as many as the pool has threads but no more than one per [`W_MIN`] (or, when
//! each unit's output is its own and nothing is reduced afterwards, as [`pieces`]: up to four a
//! thread, for the pool to balance); uneven units run at once only when the work beside the
//! largest pays for the region ([`uneven`]); a site whose way at once does more work than its way
//! in order weighs the two ([`beats`]). The decision changes no output.

#![allow(dead_code)]

/// A call's serial work, estimated from its sizes, in instructions at one thread.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Work(u64);

/// The instructions one unit of a site's work takes at one thread, measured offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cost(u64);

impl Cost {
    /// `n` instructions a unit.
    pub const fn ir(n: u64) -> Cost {
        Cost(n)
    }

    /// The work of `units` units of this cost.
    pub fn of(self, units: usize) -> Work {
        Work(u64::try_from(units).unwrap_or(u64::MAX).saturating_mul(self.0))
    }
}

/// The instructions one unit of a site's work takes in each field the circuits are over: a
/// multiplication in P-256's fields costs several in GF(2^128).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldCost {
    gf2_128: Cost,
    p256: Cost,
}

impl FieldCost {
    /// `gf2_128` instructions a unit in GF(2^128), `p256` in P-256's base field.
    pub const fn new(gf2_128: u64, p256: u64) -> FieldCost {
        FieldCost { gf2_128: Cost(gf2_128), p256: Cost(p256) }
    }

    /// The cost a unit in a field of `W` 64-bit limbs, as the runtime types its fields:
    /// GF(2^128)'s 2, P-256's 4.
    pub const fn at<const W: usize>(self) -> Cost {
        if W <= 2 {
            self.gf2_128
        } else {
            self.p256
        }
    }
}

impl Work {
    /// No work.
    pub const ZERO: Work = Work(0);

    /// `n` instructions.
    pub const fn ir(n: u64) -> Work {
        Work(n)
    }

    /// This work and `other`.
    pub fn plus(self, other: Work) -> Work {
        Work(self.0.saturating_add(other.0))
    }

    /// This work `k` times.
    pub fn times(self, k: usize) -> Work {
        Work(self.0.saturating_mul(u64::try_from(k).unwrap_or(u64::MAX)))
    }
}

impl std::iter::Sum for Work {
    fn sum<I: Iterator<Item = Work>>(iter: I) -> Work {
        iter.fold(Work::ZERO, Work::plus)
    }
}

/// The least work a parallel region pays for: about 50 µs of serial work at one thread (a region
/// from a sleeping pool costs some tens of µs), at about 20 instructions a nanosecond.
pub const W_MIN: Work = Work(1_000_000);

/// The tasks `work`, cut into even units, runs as: one (on the calling thread) on one thread or
/// below twice [`W_MIN`], else as many as the pool has threads but at most one per [`W_MIN`], so
/// that every task pays for its share of the region.
pub fn tasks(work: Work) -> usize {
    let per = usize::try_from(work.0 / W_MIN.0.max(1)).unwrap_or(usize::MAX);
    threads().min(per).max(1)
}

/// The pieces `work`, cut into even units whose outputs are each their own (nothing to reduce
/// afterwards), runs as: one (on the calling thread) on one thread or below twice [`W_MIN`], else
/// as many as pay for their share of a region, up to [`PIECES_PER_THREAD`] a thread, so that the
/// pool balances pieces that take unequal times.
pub fn pieces(work: Work) -> usize {
    let per = usize::try_from(work.0 / W_MIN.0.max(1)).unwrap_or(usize::MAX);
    match (threads(), per) {
        (0 | 1, _) | (_, 0 | 1) => 1,
        (t, per) => t.saturating_mul(PIECES_PER_THREAD).min(per),
    }
}

/// The most pieces a thread is given by [`pieces`].
pub const PIECES_PER_THREAD: usize = 4;

/// Whether a unit of work `work` pays for its share of a region: at least [`W_MIN`].
pub fn pays(work: Work) -> bool {
    work >= W_MIN
}

/// Whether units of the works `works`, uneven, pay to run at once: on more than one thread, when
/// the work beside the largest unit's, which the overlap saves, is at least [`W_MIN`].
pub fn uneven(works: impl IntoIterator<Item = Work>) -> bool {
    let (total, largest) = works.into_iter().fold((Work::ZERO, Work::ZERO), |(t, l), w| (t.plus(w), l.max(w)));
    threads() > 1 && Work(total.0.saturating_sub(largest.0)) >= W_MIN
}

/// Whether units of the works `units` run at once, then `after` on the calling thread, beat
/// `serial`, the same result computed in order another way, by at least [`W_MIN`]: on more than
/// one thread, the region taking the largest unit's work or the threads' share of them all,
/// whichever is longer.
pub fn beats(serial: Work, units: impl IntoIterator<Item = Work>, after: Work) -> bool {
    let t = threads();
    if t < 2 {
        return false;
    }
    let (total, largest) = units.into_iter().fold((Work::ZERO, Work::ZERO), |(s, l), w| (s.plus(w), l.max(w)));
    let share = Work(total.0 / u64::try_from(t).unwrap_or(u64::MAX));
    let at_once = largest.max(share).plus(after);
    Work(serial.0.saturating_sub(at_once.0)) >= W_MIN
}

/// [`map`] when `at_once`, else `f` over the items in order on the calling thread.
pub fn map_if<T, U, F>(at_once: bool, items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync + Send,
{
    if at_once {
        map(items, f)
    } else {
        items.into_iter().map(f).collect()
    }
}

/// [`map_init`] when `at_once`, else `f` over the items in order with one state.
pub fn map_init_if<T, S, R, I, F>(at_once: bool, items: Vec<T>, init: I, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    I: Fn() -> S + Sync + Send,
    F: Fn(&mut S, T) -> R + Sync + Send,
{
    if at_once {
        map_init(items, init, f)
    } else {
        let mut state = init();
        items.into_iter().map(|t| f(&mut state, t)).collect()
    }
}

/// [`join`] when `at_once`, else `a()` then `b()` on the calling thread.
pub fn join_if<A, B, RA, RB>(at_once: bool, a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    if at_once {
        join(a, b)
    } else {
        (a(), b())
    }
}

/// The threads the work runs on: rayon's pool's with the feature, else 1.
pub fn threads() -> usize {
    #[cfg(feature = "parallel")]
    {
        rayon::current_num_threads()
    }
    #[cfg(not(feature = "parallel"))]
    {
        1
    }
}

/// `f(t)` for each item `t`, in the items' order. One item (or none) is mapped on the calling
/// thread: the pool would run it alone, after a hand-off to a worker and back.
pub fn map<T, U, F>(items: Vec<T>, f: F) -> Vec<U>
where
    T: Send,
    U: Send,
    F: Fn(T) -> U + Sync + Send,
{
    #[cfg(feature = "parallel")]
    if items.len() > 1 {
        use rayon::prelude::*;
        return items.into_par_iter().map(f).collect();
    }
    items.into_iter().map(f).collect()
}

/// `f(state, item)` for each item, in the items' order; each worker's state comes from `init`
/// (one state without the feature, or for one item, which is mapped on the calling thread).
pub fn map_init<T, S, R, I, F>(items: Vec<T>, init: I, f: F) -> Vec<R>
where
    T: Send,
    R: Send,
    I: Fn() -> S + Sync + Send,
    F: Fn(&mut S, T) -> R + Sync + Send,
{
    #[cfg(feature = "parallel")]
    if items.len() > 1 {
        use rayon::prelude::*;
        return items.into_par_iter().map_init(init, f).collect();
    }
    let mut state = init();
    items.into_iter().map(|t| f(&mut state, t)).collect()
}

/// `a()` and `b()`, at once with the feature.
pub fn join<A, B, RA, RB>(a: A, b: B) -> (RA, RB)
where
    A: FnOnce() -> RA + Send,
    B: FnOnce() -> RB + Send,
    RA: Send,
    RB: Send,
{
    #[cfg(feature = "parallel")]
    {
        rayon::join(a, b)
    }
    #[cfg(not(feature = "parallel"))]
    {
        (a(), b())
    }
}
