#pragma once

#include "util/types.h"

/*
 * DuetOS — audio-family syscall handlers, v0.
 *
 * Extracted from kernel/syscall/syscall.cpp so the dispatcher
 * switch stays a thin router and the audio backend / HDA glue
 * lives in one file with its includes (mirrors the
 * time_syscall.{h,cpp} split precedent — no ABI change).
 *
 * Syscalls covered:
 *   SYS_AUDIO_DEVICE_INFO (198) — HDA-output device presence +
 *                                 canonical 48k/stereo/16-bit caps
 *   SYS_AUDIO_WRITE       (210) — bounded-copy user PCM into the
 *                                 in-kernel HDA backend ring + RUN
 *
 * Each handler consumes a `TrapFrame*` and writes its result to
 * `frame->rax` (same contract as the inlined switch arms).
 *
 * Context: kernel, syscall gate (IRQ-off). SYS_AUDIO_WRITE busy-
 * copies via mm::CopyFromUser in stack-sized chunks; bounded.
 */

namespace duetos::arch
{
struct TrapFrame;
}

namespace duetos::core
{

void DoAudioDeviceInfo(arch::TrapFrame* frame);
void DoAudioWrite(arch::TrapFrame* frame);

} // namespace duetos::core
