//! vega-prover's own phases, for `/tech`'s profile: the library marks its phases with `tracing`
//! spans (sumcheck rounds, the Hyrax commitment and opening, the multi-scalar multiplications,
//! folding, …), which do nothing until a subscriber listens. [`record`] listens while one step
//! runs and returns the phases as a tree: per phase its name, how many times it ran, its total
//! time and, on one thread, the most heap it held above what was held when it began.
//!
//! The library's spans are created, entered and left at once and stay open until the end of the
//! scope that created them, which for phases run one after another in one function is the end of
//! that function. The library logs each phase's end itself: an `info!` event with `elapsed_ms` and
//! the phase's name as its message. So a phase lasts from its span's creation to that event, or to
//! the span's close when there is no event (a phase that is a whole function or loop body), and
//! its parent is the phase still running on the same thread when it was created. Phases that run on other threads (the
//! Multithreading switch) become roots of their own, and their heap is not reported: the heap
//! counter is shared by all threads.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde_json::{Value as Json, json};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata};

use crate::measure;

static ON: AtomicBool = AtomicBool::new(false);
static NEXT: AtomicU64 = AtomicU64::new(1);
static INSTALLED: OnceLock<bool> = OnceLock::new();

struct Open {
  name: &'static str,
  parent: Option<u64>,
  start: Instant,
  heap: usize,
  refs: usize,
  /** The phase's end as the library logged it, and its heap mark then (one thread only). */
  ended: Option<(Instant, Option<usize>)>,
}

/// An event's message (the phase name of an `elapsed_ms` event).
struct Message(Option<String>);

impl tracing::field::Visit for Message {
  fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
    if field.name() == "message" {
      self.0 = Some(value.to_string());
    }
  }
  fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
    if field.name() == "message" {
      self.0 = Some(format!("{value:?}"));
    }
  }
}

struct Closed {
  id: u64,
  name: &'static str,
  parent: Option<u64>,
  start: Instant,
  ms: f64,
  bytes: Option<usize>,
}

static OPEN: Mutex<Option<HashMap<u64, Open>>> = Mutex::new(None);
static CLOSED: Mutex<Vec<Closed>> = Mutex::new(Vec::new());

thread_local! {
  /// The phases open on this thread, innermost last, with the heap mark the outer one had.
  static STACK: RefCell<Vec<(u64, usize)>> = const { RefCell::new(Vec::new()) };
}

struct Phases;

impl tracing::Subscriber for Phases {
  fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
    if meta.is_span() || ends_phase(meta) { Interest::sometimes() } else { Interest::never() }
  }

  fn enabled(&self, meta: &Metadata<'_>) -> bool {
    (meta.is_span() || ends_phase(meta)) && ON.load(Relaxed)
  }

  fn new_span(&self, attrs: &Attributes<'_>) -> Id {
    let id = NEXT.fetch_add(1, Relaxed);
    let (heap, saved) = measure::span_enter();
    let parent = STACK.with(|s| {
      let mut s = s.borrow_mut();
      let parent = s.last().map(|(p, _)| *p);
      s.push((id, saved));
      parent
    });
    if let Ok(mut open) = OPEN.lock() {
      open
        .get_or_insert_with(HashMap::new)
        .insert(id, Open { name: attrs.metadata().name(), parent, start: Instant::now(), heap, refs: 1, ended: None });
    }
    Id::from_u64(id)
  }

  fn record(&self, _: &Id, _: &Record<'_>) {}
  fn record_follows_from(&self, _: &Id, _: &Id) {}
  /// A phase's end as the library logs it: the innermost running phase of that name on this
  /// thread ends now, and phases created after it are no longer its children.
  fn event(&self, event: &Event<'_>) {
    let mut message = Message(None);
    event.record(&mut message);
    let Some(name) = message.0 else { return };
    let now = Instant::now();
    let Ok(mut open) = OPEN.lock() else { return };
    let Some(map) = open.as_mut() else { return };
    STACK.with(|s| {
      let mut s = s.borrow_mut();
      let Some(pos) = s.iter().rposition(|(id, _)| map.get(id).is_some_and(|o| o.name == name)) else { return };
      let (id, saved) = s.remove(pos);
      // The heap mark is the phase's own only when it was the innermost running phase.
      let high = (pos == s.len()).then(|| measure::span_exit(saved));
      if let Some(o) = map.get_mut(&id) {
        o.ended = Some((now, high));
      }
    });
  }
  fn enter(&self, _: &Id) {}
  fn exit(&self, _: &Id) {}

  fn clone_span(&self, id: &Id) -> Id {
    if let Ok(mut open) = OPEN.lock()
      && let Some(o) = open.as_mut().and_then(|m| m.get_mut(&id.into_u64()))
    {
      o.refs += 1;
    }
    id.clone()
  }

  fn try_close(&self, id: Id) -> bool {
    let id = id.into_u64();
    let done = {
      let Ok(mut open) = OPEN.lock() else { return false };
      let Some(map) = open.as_mut() else { return false };
      let Some(o) = map.get_mut(&id) else { return false };
      o.refs -= 1;
      if o.refs > 0 {
        return false;
      }
      map.remove(&id)
    };
    let Some(o) = done else { return false };
    if let Some((end, high)) = o.ended {
      let ms = end.duration_since(o.start).as_secs_f64() * 1e3;
      if let Ok(mut closed) = CLOSED.lock() {
        closed.push(Closed { id, name: o.name, parent: o.parent, start: o.start, ms, bytes: high.map(|h| h.saturating_sub(o.heap)) });
      }
      return true;
    }
    let ms = o.start.elapsed().as_secs_f64() * 1e3;
    // The heap mark is this phase's only when it is the innermost open phase on this thread.
    let high = STACK.with(|s| {
      let mut s = s.borrow_mut();
      match s.last() {
        Some(&(top, saved)) if top == id => {
          s.pop();
          Some(measure::span_exit(saved))
        }
        _ => {
          s.retain(|(i, _)| *i != id);
          None
        }
      }
    });
    if let Ok(mut closed) = CLOSED.lock() {
      closed.push(Closed { id, name: o.name, parent: o.parent, start: o.start, ms, bytes: high.map(|h| h.saturating_sub(o.heap)) });
    }
    true
  }
}

/// An event that ends a phase: one with an `elapsed_ms` field (vega-prover's `info!` at a phase's end).
fn ends_phase(meta: &Metadata<'_>) -> bool {
  meta.is_event() && meta.fields().field("elapsed_ms").is_some()
}

/// Runs `f`, recording vega-prover's phases when `on`. `heap`: report each phase's heap (one
/// thread only). None when off, or when another tracing subscriber is already installed.
pub fn record<T>(on: bool, heap: bool, f: impl FnOnce() -> T) -> (T, Option<Json>) {
  if !on || !*INSTALLED.get_or_init(|| tracing::subscriber::set_global_default(Phases).is_ok()) {
    return (f(), None);
  }
  if let Ok(mut c) = CLOSED.lock() {
    c.clear();
  }
  if let Ok(mut o) = OPEN.lock() {
    *o = Some(HashMap::new());
  }
  ON.store(true, Relaxed);
  let out = f();
  ON.store(false, Relaxed);
  let closed = CLOSED.lock().map(|mut c| std::mem::take(&mut *c)).unwrap_or_default();
  (out, Some(tree(closed, heap)))
}

/// The phases as a tree, siblings of the same name merged: name, runs (`n`), total `ms`, the
/// most heap one run held (`mb`), children in order of first start.
fn tree(closed: Vec<Closed>, heap: bool) -> Json {
  let ids: std::collections::HashSet<u64> = closed.iter().map(|c| c.id).collect();
  let mut kids: HashMap<Option<u64>, Vec<&Closed>> = HashMap::new();
  for c in &closed {
    let parent = c.parent.filter(|p| ids.contains(p));
    kids.entry(parent).or_default().push(c);
  }
  for v in kids.values_mut() {
    v.sort_by_key(|c| c.start);
  }
  fn level(parents: &[&Closed], kids: &HashMap<Option<u64>, Vec<&Closed>>, heap: bool) -> Vec<Json> {
    // The children of every span in `parents`, grouped by name in order of first start.
    let mut order: Vec<&'static str> = Vec::new();
    let mut groups: HashMap<&'static str, Vec<&Closed>> = HashMap::new();
    let mut all: Vec<&Closed> = parents.iter().flat_map(|p| kids.get(&Some(p.id)).into_iter().flatten().copied()).collect();
    all.sort_by_key(|c| c.start);
    for c in all {
      if !groups.contains_key(c.name) {
        order.push(c.name);
      }
      groups.entry(c.name).or_default().push(c);
    }
    order.iter().map(|name| node(name, &groups[name], kids, heap)).collect()
  }
  fn node(name: &str, group: &[&Closed], kids: &HashMap<Option<u64>, Vec<&Closed>>, heap: bool) -> Json {
    let ms: f64 = group.iter().map(|c| c.ms).sum();
    let mb = if heap { group.iter().filter_map(|c| c.bytes).max().and_then(measure::mb) } else { None };
    json!({ "name": name, "n": group.len(), "ms": (ms * 100.0).round() / 100.0, "mb": mb, "children": level(group, kids, heap) })
  }
  let roots = kids.get(&None).cloned().unwrap_or_default();
  let mut order: Vec<&'static str> = Vec::new();
  let mut groups: HashMap<&'static str, Vec<&Closed>> = HashMap::new();
  for c in roots {
    if !groups.contains_key(c.name) {
      order.push(c.name);
    }
    groups.entry(c.name).or_default().push(c);
  }
  Json::Array(order.iter().map(|name| node(name, &groups[name], &kids, heap)).collect())
}
