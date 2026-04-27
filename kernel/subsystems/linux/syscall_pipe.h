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

} // namespace duetos::subsystems::linux::internal
