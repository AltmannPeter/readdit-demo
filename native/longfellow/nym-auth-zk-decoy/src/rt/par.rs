#![allow(dead_code)]
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
//! Independent work in parallel under the `parallel` feature (rayon), in order without it. The
//! output never depends on the thread count: each item's result is a function of the item
//! alone, and results come back in the items' order. Whether a call runs in parallel is decided
//! from its estimated work (units times a per-unit cost in instructions, measured offline).

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Work(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cost(u64);

impl Cost {
    pub const fn ir(n: u64) -> Cost {
        Cost(n)
    }

    pub fn of(self, units: usize) -> Work {
        Work(
            u64::try_from(units)
                .unwrap_or(u64::MAX)
                .saturating_mul(self.0),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldCost {
    gf2_128: Cost,
    p256: Cost,
}

impl FieldCost {
    pub const fn new(gf2_128: u64, p256: u64) -> FieldCost {
        FieldCost {
            gf2_128: Cost(gf2_128),
            p256: Cost(p256),
        }
    }

    pub const fn at<const W: usize>(self) -> Cost {
        if W <= 2 {
            self.gf2_128
        } else {
            self.p256
        }
    }
}

impl Work {
    pub const ZERO: Work = Work(0);

    pub const fn ir(n: u64) -> Work {
        Work(n)
    }

    pub fn plus(self, other: Work) -> Work {
        Work(self.0.saturating_add(other.0))
    }

    pub fn times(self, k: usize) -> Work {
        Work(self.0.saturating_mul(u64::try_from(k).unwrap_or(u64::MAX)))
    }
}

impl std::iter::Sum for Work {
    fn sum<I: Iterator<Item = Work>>(iter: I) -> Work {
        iter.fold(Work::ZERO, Work::plus)
    }
}

pub const W_MIN: Work = Work(1_000_000);

pub fn tasks(work: Work) -> usize {
    let per = usize::try_from(work.0 / W_MIN.0.max(1)).unwrap_or(usize::MAX);
    threads().min(per).max(1)
}

pub fn pieces(work: Work) -> usize {
    let per = usize::try_from(work.0 / W_MIN.0.max(1)).unwrap_or(usize::MAX);
    match (threads(), per) {
        (0 | 1, _) | (_, 0 | 1) => 1,
        (t, per) => t.saturating_mul(PIECES_PER_THREAD).min(per),
    }
}

pub const PIECES_PER_THREAD: usize = 4;

pub fn pays(work: Work) -> bool {
    work >= W_MIN
}

pub fn uneven(works: impl IntoIterator<Item = Work>) -> bool {
    let (total, largest) = works
        .into_iter()
        .fold((Work::ZERO, Work::ZERO), |(t, l), w| (t.plus(w), l.max(w)));
    threads() > 1 && Work(total.0.saturating_sub(largest.0)) >= W_MIN
}

pub fn beats(serial: Work, units: impl IntoIterator<Item = Work>, after: Work) -> bool {
    let t = threads();
    if t < 2 {
        return false;
    }
    let (total, largest) = units
        .into_iter()
        .fold((Work::ZERO, Work::ZERO), |(s, l), w| (s.plus(w), l.max(w)));
    let share = Work(total.0 / u64::try_from(t).unwrap_or(u64::MAX));
    let at_once = largest.max(share).plus(after);
    Work(serial.0.saturating_sub(at_once.0)) >= W_MIN
}

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
