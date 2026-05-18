#include "syscall/audio_syscall.h"

#include "arch/x86_64/traps.h"
#include "drivers/audio/audio.h"
#include "mm/paging.h"
#include "subsystems/audio/audio_backend.h"

namespace duetos::core
{

void DoAudioDeviceInfo(arch::TrapFrame* frame)
{
    // Count HDA-class controllers only — winmm waveOut has
    // no AC'97 / legacy backend wired today, so reporting
    // those would mislead the caller into opening a path
    // that returns ENODEV downstream. The first-device
    // capability questions answer the v0 canonical
    // 48 kHz / stereo / 16-bit format that HDA streams
    // ship with.
    u64 hda_count = 0;
    const u64 total = ::duetos::drivers::audio::AudioControllerCount();
    for (u64 i = 0; i < total; ++i)
    {
        if (::duetos::drivers::audio::AudioController(i).kind == ::duetos::drivers::audio::AudioKind::Hda)
            ++hda_count;
    }
    switch (frame->rdi)
    {
    case 0:
        frame->rax = hda_count;
        return;
    case 1:
        frame->rax = hda_count > 0 ? 48000ULL : 0ULL;
        return;
    case 2:
        frame->rax = hda_count > 0 ? 2ULL : 0ULL;
        return;
    case 3:
        frame->rax = hda_count > 0 ? 16ULL : 0ULL;
        return;
    default:
        frame->rax = 0;
        return;
    }
}

void DoAudioWrite(arch::TrapFrame* frame)
{
    namespace ab = ::duetos::subsystems::audio;
    const auto user_ptr = reinterpret_cast<const void*>(frame->rdi);
    u64 len = frame->rsi;
    if (user_ptr == nullptr || len < ab::kBytesPerFrame || !ab::IsActive())
    {
        frame->rax = 0;
        return;
    }
    const u64 cap = static_cast<u64>(ab::kBufferBytes);
    if (len > cap)
        len = cap;
    len -= len % ab::kBytesPerFrame; // whole frames only

    // Stream user PCM into the backend ring in stack-sized
    // chunks (no big kernel allocation): CopyFromUser bounces
    // each chunk, WritePcmS16Stereo lays it into the DMA ring.
    alignas(2) unsigned char bounce[2048];
    u64 moved = 0;
    u32 frame_off = 0;
    bool copy_ok = true;
    while (moved < len)
    {
        u64 step = len - moved;
        if (step > sizeof(bounce))
            step = sizeof(bounce);
        if (!mm::CopyFromUser(bounce, static_cast<const u8*>(user_ptr) + moved, step))
        {
            copy_ok = false;
            break;
        }
        const u32 frames = static_cast<u32>(step / ab::kBytesPerFrame);
        ab::WritePcmS16Stereo(reinterpret_cast<const i16*>(bounce), frames, frame_off);
        frame_off += frames;
        moved += step;
    }
    if (!copy_ok || moved == 0)
    {
        frame->rax = 0;
        return;
    }
    (void)ab::Start();
    frame->rax = frame_off; // frames accepted
}

} // namespace duetos::core
