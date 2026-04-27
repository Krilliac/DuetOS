#pragma once

/*
 * Cross-TU surface for the Linux fanotify(7) engine. Fanotify
 * subscribes to the same FS-mutation publish-subscribe pipeline
 * that powers inotify; inotify.cpp's `InotifyPublish` calls the
 * helper below in the same loop.
 */

#include "util/types.h"

namespace duetos::subsystems::linux::internal
{

// Called from `InotifyPublish` to fan an FS-mutation event out
// to every active fanotify instance whose marks cover `path`.
// `in_mask` is the inotify-side mask (translates internally to
// the fanotify wire mask).
void FanotifyPublishFromInotify(const char* path, u32 in_mask);

// Per-LinuxFd surface (state 15).
i64 FanotifyRead(u32 idx, u64 user_dst, u64 len);
void FanotifyRetain(u32 idx);
void FanotifyRelease(u32 idx);

i64 DoFanotifyInit(u64 flags, u64 event_f_flags);
i64 DoFanotifyMark(u64 fd, u64 flags, u64 mask, u64 dirfd, u64 user_path);

} // namespace duetos::subsystems::linux::internal
