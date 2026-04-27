#pragma once

/*
 * Linux inotify(7) — v0 in-kernel filesystem-event engine.
 *
 * Public surface:
 *   - InotifyPublish(): called by FS-mutation paths (file_route /
 *     fat32 / tmpfs) to fan an event out to every active inotify
 *     instance whose watch list covers the path.
 *   - DoInotifyInit / DoInotifyInit1: create a new inotify instance
 *     fd (LinuxFd state 10).
 *   - DoInotifyAddWatch / DoInotifyRmWatch: attach / detach watch
 *     entries on an instance.
 *   - InotifyRead / InotifyRelease / InotifyRetain: per-fd surface
 *     called from syscall_io.cpp / syscall_file.cpp / syscall_clone.cpp
 *     dispatch arms.
 *
 * v0 cap: 8 instances, 16 watches per instance, 32-event ring per
 * instance. Events are fixed-shape (struct inotify_event header +
 * NUL-terminated name). Path matching is exact: the watched path
 * must equal the published path verbatim. Sub-GAP: real Linux's
 * subtree-watch + per-event name suffix isn't honoured here (every
 * event reports the watched path itself; callers don't get the
 * mutated leaf if they watched the parent dir).
 */

#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// Linux IN_* event-mask bit subset.
constexpr u32 kInAccess = 0x00000001;
constexpr u32 kInModify = 0x00000002;
constexpr u32 kInAttrib = 0x00000004;
constexpr u32 kInCloseWrite = 0x00000008;
constexpr u32 kInCloseNowrite = 0x00000010;
constexpr u32 kInOpen = 0x00000020;
constexpr u32 kInMovedFrom = 0x00000040;
constexpr u32 kInMovedTo = 0x00000080;
constexpr u32 kInCreate = 0x00000100;
constexpr u32 kInDelete = 0x00000200;
constexpr u32 kInDeleteSelf = 0x00000400;
constexpr u32 kInMoveSelf = 0x00000800;
constexpr u32 kInIsDir = 0x40000000;

// Publish an FS-mutation event with `path` (volume-relative, no
// "/disk/<idx>" prefix expected) and `mask`. Walks every active
// inotify instance + watch under arch::Cli; matching watches get
// an event pushed onto their ring + their wq woken. Callable from
// any kernel context.
void InotifyPublish(const char* path, u32 mask);

// Per-LinuxFd surface (state 10).
i64 InotifyRead(u32 idx, u64 user_dst, u64 len);
void InotifyRelease(u32 idx);
void InotifyRetain(u32 idx);

} // namespace duetos::subsystems::linux::internal
