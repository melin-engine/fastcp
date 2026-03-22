# fastcp

Fork of [smoltcp](https://github.com/smoltcp-rs/smoltcp) — a standalone, event-driven, zero-copy, no-heap, no_std TCP/IP stack written in Rust.

## Goal

Optimize fastcp for use as the TCP layer in an ultra-low-latency order matching engine based on the LMAX architecture, coupled with DPDK for kernel-bypass networking.

## Constraints

- Stay compatible with the current smoltcp API as much as possible.

## Current bottlenecks to address

1. **Per-packet TCP state machine** — Without TSO/GRO, smoltcp processes every segment individually. The kernel batches via segmentation offload; we don't. This is the single-segment-at-a-time tax.

2. **No zero-copy send path** — Data is copied into socket buffers, then copied again into mbufs. Two copies per send where zero should suffice.

3. **Single-threaded everything** — The kernel spreads TCP work across softirq on multiple cores. We currently run everything on one core.

## Future considerations

- A disruptor-style (LMAX) architecture to spread load across multiple cores may eventually be needed, but is not a certainty yet.
