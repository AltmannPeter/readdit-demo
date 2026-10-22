//! The addon's allocator: the system allocator, counting what it hands out for
//! `nym_bbs::measure` (each step's heap figure, `heap_mb`). The library crate forbids `unsafe`; an
//! allocator needs it, so it lives here.

use std::alloc::{GlobalAlloc, Layout, System};

use nym_bbs::measure::{heap_grew, heap_shrank};

struct Counting;

unsafe impl GlobalAlloc for Counting {
  unsafe fn alloc(&self, l: Layout) -> *mut u8 {
    let p = unsafe { System.alloc(l) };
    if !p.is_null() {
      heap_grew(l.size());
    }
    p
  }

  unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
    let p = unsafe { System.alloc_zeroed(l) };
    if !p.is_null() {
      heap_grew(l.size());
    }
    p
  }

  unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
    unsafe { System.dealloc(p, l) };
    heap_shrank(l.size());
  }

  unsafe fn realloc(&self, p: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
    let q = unsafe { System.realloc(p, l, new_size) };
    if !q.is_null() {
      if new_size > l.size() {
        heap_grew(new_size - l.size());
      } else {
        heap_shrank(l.size() - new_size);
      }
    }
    q
  }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;
