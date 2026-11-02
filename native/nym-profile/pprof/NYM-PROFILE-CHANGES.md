# pprof 0.15.0, as used by nym-profile

This is pprof 0.15.0 as published on crates.io (Apache-2.0, `LICENSE`), with two changes:

- `src/backtrace/frame_pointer.rs`: on macOS, `Trace::trace` first reports the interrupted
  instruction (`__pc` on arm64, `__rip` on x86-64), then walks the frame records as before. The
  published walker reports only the return addresses in the frame records, so the function a
  sample landed in was missing from its stack. Other targets are unchanged.
- `src/profiler.rs`: `write_thread_name` calls `pthread_getname_np` on macOS too. The published
  cfg asked for `target_env = "gnu"`, which macOS does not have, so every macOS sample carried its
  thread's id (a number) instead of its name (`longfellow-4-0`). Linux is unchanged.

nym-profile turns on the `frame-pointer` feature on macOS only. pprof's default unwinder there
(backtrace-rs, which calls the system libunwind from the SIGPROF handler) crashed Node with
SIGTRAP inside `libunwind::UnwindCursor::step` on macOS 26 (arm64), 2026-11-02. Apple's arm64 ABI
keeps frame pointers, so the frame-pointer walk needs no unwind tables. A leaf function that sets
up no frame record of its own still hides its caller: the stack goes from the leaf to its
caller's caller. On Linux, nym-profile uses pprof's default unwinder, as before.
