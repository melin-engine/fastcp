# fastcp

Fork of [smoltcp](https://github.com/smoltcp-rs/smoltcp) — a standalone, event-driven, zero-copy, no-heap, no_std TCP/IP stack written in Rust.

## Goal

Optimize fastcp for use as the TCP layer in an ultra-low-latency order matching engine based on the LMAX architecture, coupled with DPDK for kernel-bypass networking.

## Conventions

- Follow Rust best practices (idiomatic patterns, clippy clean, formatted with `cargo fmt`).
- Write unit tests for all non-trivial code.
- **Correctness is critical** — this stack underpins financial infrastructure. Correctness always comes first.
- **Reasonably optimized from the start** — minimize allocations, avoid locks on the hot path, favor cache-friendly data structures. Profile before micro-optimizing.
- **No `.unwrap()` in production code** — use proper error handling. `.unwrap()` is fine in tests.
- **No `#[ignore]` on tests** — fix failing tests, don't suppress them.
- **No silently ignored results** — do not use `let _ =` to discard `Result` values without a clear reason.
- **Comment data structure and type choices** — justify why a specific collection, data structure, or numeric type was chosen.
- **Tail latency matters** — measure p99/p99.9, not averages.

### Git

- **No co-authored commits** — do not add `Co-Authored-By` trailers.
- **Conventional Commits** — all commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) spec (e.g., `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`).
- **Never commit without explicit request** — do NOT commit unless the user explicitly asks.
- **Never push without explicit confirmation** — always ask before pushing.

## Constraints

- Stay compatible with the current smoltcp API as much as possible.

## Current bottlenecks to address

1. **Per-packet TCP state machine** — Without TSO/GRO, smoltcp processes every segment individually. The kernel batches via segmentation offload; we don't. This is the single-segment-at-a-time tax.

2. **No zero-copy send path** — Data is copied into socket buffers, then copied again into mbufs. Two copies per send where zero should suffice.

3. **Single-threaded everything** — The kernel spreads TCP work across softirq on multiple cores. We currently run everything on one core.

## Future considerations

- A disruptor-style (LMAX) architecture to spread load across multiple cores may eventually be needed, but is not a certainty yet.
