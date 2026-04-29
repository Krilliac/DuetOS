#pragma once

/*
 * Cross-TU surface for the Linux pipe / eventfd pools. The
 * read / write helpers take a pool index (the value stored in
 * LinuxFd::first_cluster) so DoRead / DoWrite / DoClose in
 * sibling TUs can dispatch on state without depending on the
 * pool internals.
 */

#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// Pipe pool — read/write/release. PipeAlloc lives inside
// syscall_pipe.cpp because only DoPipe2 calls it; the cross-
// TU surface is just the per-end ops.
i64 PipeRead(u32 idx, u64 user_dst, u64 len);
i64 PipeWrite(u32 idx, u64 user_src, u64 len);
void PipeReleaseRead(u32 idx);
void PipeReleaseWrite(u32 idx);
// Bump the read- / write-end refcount. Used by fork() for fd
// inheritance — the child gets its own LinuxFd slot pointing
// at the same pool entry; the corresponding end's refcount
// must climb so the pool entry stays live across a parent
// close while the child still holds the inherited fd.
void PipeRetainRead(u32 idx);
void PipeRetainWrite(u32 idx);

// Eventfd pool — read/write/release.
i64 EventfdRead(u32 idx, u64 user_dst, u64 len);
i64 EventfdWrite(u32 idx, u64 user_src, u64 len);
void EventfdRelease(u32 idx);
void EventfdRetain(u32 idx);

// Non-blocking readiness probes — used by epoll_wait. Each
// returns true iff a read on this end would proceed without
// blocking. PipeReadReady is true when the pipe has buffered
// bytes OR every writer has closed (read returns EOF without
// blocking). EventfdReady is true when counter > 0.
bool PipeReadReady(u32 idx);
bool PipeWriteReady(u32 idx);
bool EventfdReady(u32 idx);

// splice / tee fast-paths — pipe-to-pipe byte movement that
// stays inside the kernel-side ring buffers (no CopyFromUser /
// CopyToUser bounce). Returns the number of bytes transferred
// (≤ len), 0 on EOF, or a negative -EXX errno.
//
//   PipeSpliceFromPipe — single-iteration consume. Blocks once
//     if the source ring is empty AND writers remain. Returns
//     when something was moved or every writer has closed
//     (source-side EOF). Does NOT block if the destination ring
//     is full — partial transfer is the splice contract.
//
//   PipeTeeFromPipe — single-iteration peek. Same source-side
//     blocking as splice, but the source's tail / count stay
//     untouched (pure copy). Used by tee(2).
i64 PipeSpliceFromPipe(u32 dst_idx, u32 src_idx, u64 len);
i64 PipeTeeFromPipe(u32 dst_idx, u32 src_idx, u64 len);

} // namespace duetos::subsystems::linux::internal
