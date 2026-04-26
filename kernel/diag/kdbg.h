#pragma once

#include "util/types.h"

/*
 * DuetOS — per-subsystem diagnostic channels.
 *
 * KDBG is a parallel layer to the klog severity ladder. klog levels
 * (Trace … Error) are about *importance*: a Warn from the network
 * stack is as loud as a Warn from the scheduler. KDBG channels are
 * about *focus*: enable Fat32Walker to get every dir-walker visit
 * line; leave the rest off so the log isn't a wall of slot dumps.
 *
 * Every KDBG_* macro:
 *   1. checks a single u32 mask (one load, one and, one branch),
 *   2. only emits a log line when the channel bit is set,
 *   3. compiles to `do {} while (0)` when DUETOS_KDBG_OFF is defined
 *      at translation-unit level (release-time hard kill).
 *
 * Channels are off at boot by default. Three ways to turn one on:
 *
 *   * runtime, from the shell:
 *         kdbg on  fat32-walker
 *         kdbg off all
 *         kdbg list
 *   * compile-time default mask:
 *         -DDUETOS_KDBG_DEFAULT_MASK=0x4001
 *   * code, anywhere:
 *         core::DbgEnable(static_cast<u32>(core::DbgChannel::Fat32Walker));
 *
 * The compile-time hard kill (-DDUETOS_KDBG_OFF) folds every macro
 * to a no-op so a release build pays exactly zero (no text segment,
 * no rodata, no per-call check).
 *
 * Output goes through the same klog sink at LogLevel::Debug, so it
 * lands in the ring buffer + serial console + framebuffer tee + any
 * file sink that's been installed. Channel name appears in the log
 * tag so `dmesg | grep fat32-walker` works.
 *
 * Context: kernel. Safe at any interrupt level — same path as klog.
 */

namespace duetos::core
{

enum class DbgChannel : u32
{
    None = 0,

    // FAT32
    Fat32Walker = 1u << 0,  // dir-walker visit-by-visit
    Fat32Append = 1u << 1,  // append/extend internals
    Fat32Lookup = 1u << 2,  // path-lookup steps
    Fat32Cluster = 1u << 3, // cluster alloc/free + FAT writes

    // Win32 / PE
    Win32Thunk = 1u << 4, // thunk dispatch
    Win32Batch = 1u << 5, // batch self-test per-flag
    Win32Wm = 1u << 6,    // window manager / WndProc
    Win32Heap = 1u << 7,  // HeapAlloc / Free
    PeLoad = 1u << 8,     // PE load steps
    PeReloc = 1u << 9,    // base-reloc walking
    PeImport = 1u << 10,  // import resolution
    PeExport = 1u << 11,  // EAT lookup
    DirectX = 1u << 12,   // d3d* + dxgi vtable hits

    // Networking
    Net = 1u << 13,
    NetTcp = 1u << 14,
    NetDns = 1u << 15,
    NetDhcp = 1u << 16,
    NetArp = 1u << 17,

    // Scheduling / process / IPC
    Sched = 1u << 18,
    SchedSwitch = 1u << 19, // every context switch
    Process = 1u << 20,     // create / destroy
    Ipc = 1u << 21,
    Sandbox = 1u << 22,

    // Memory / paging
    Mm = 1u << 23,
    MmFault = 1u << 24, // page-fault details

    // Drivers
    Storage = 1u << 25, // block-device cmds
    Usb = 1u << 26,
    Gpu = 1u << 27,
    Audio = 1u << 28,

    // Subsystems
    Gdi = 1u << 29,    // GDI paint internals
    Linux = 1u << 30,  // Linux ABI syscall args
    Health = 1u << 31, // runtime invariants

    All = 0xFFFFFFFFu,
};

/// Enable bits in the global mask. `mask` is a bitwise-or of one
/// or more `static_cast<u32>(DbgChannel::Foo)` values.
void DbgEnable(u32 mask);

/// Clear bits in the global mask.
void DbgDisable(u32 mask);

/// Replace the global mask outright.
void DbgSet(u32 mask);

/// Read the current mask.
u32 DbgMask();

/// Single-channel test. Cheap (one load, one and, one branch).
bool DbgIsEnabled(DbgChannel ch);

/// Human-readable channel name (e.g. "fat32-walker"). Returns
/// "(unknown)" for an out-of-range or composite mask.
const char* DbgChannelName(DbgChannel ch);

/// Inverse of DbgChannelName. Returns DbgChannel::None on miss.
/// Comparison is case-insensitive; both "fat32-walker" and
/// "Fat32Walker" resolve.
DbgChannel DbgChannelByName(const char* name);

/// Iterate all named channels in declaration order. Pass nullptr
/// at the start to get the first channel.
DbgChannel DbgChannelNext(DbgChannel cursor);

/// One-shot list dump to klog (Info level) — the shell `kdbg list`
/// command calls this. Each line: "  fat32-walker  : on / off".
void DbgListChannels();

// Emitters. These bypass the klog level threshold (we want the
// channel mask alone to gate output) but still write through the
// klog sink so colour/timestamps/ring-buffer behave normally.
void DbgEmit(DbgChannel ch, const char* subsys, const char* msg);
void DbgEmitV(DbgChannel ch, const char* subsys, const char* msg, u64 v);
void DbgEmit2V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b);
void DbgEmit3V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b,
               const char* lc, u64 c);
void DbgEmit4V(DbgChannel ch, const char* subsys, const char* msg, const char* la, u64 a, const char* lb, u64 b,
               const char* lc, u64 c, const char* ld, u64 d);
void DbgEmitS(DbgChannel ch, const char* subsys, const char* msg, const char* label, const char* str);

} // namespace duetos::core

// -----------------------------------------------------------------
// Macros — gate on channel bit, fall through to DbgEmit*.
//
// `ch` is the unqualified enumerator (e.g. `Fat32Walker`); the macro
// prepends the namespace + class. This lets call sites write
//      KDBG(Fat32Walker, "fs/fat32", "visit slot");
// without ceremony.
//
// Compile-time hard kill: define DUETOS_KDBG_OFF at the TU level
// (or via -DDUETOS_KDBG_OFF). Every macro folds to a no-op statement
// expression that the compiler eliminates entirely.
// -----------------------------------------------------------------

#ifdef DUETOS_KDBG_OFF

#define KDBG(ch, subsys, msg)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_V(ch, subsys, msg, v)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_2V(ch, subsys, msg, la, a, lb, b)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_3V(ch, subsys, msg, la, a, lb, b, lc, c)                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_4V(ch, subsys, msg, la, a, lb, b, lc, c, ld, d)                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_S(ch, subsys, msg, label, s)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
    } while (0)
#define KDBG_ON(ch) (false)

#else

#define KDBG(ch, subsys, msg)                                                                                          \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmit(::duetos::core::DbgChannel::ch, (subsys), (msg));                                  \
        }                                                                                                              \
    } while (0)

#define KDBG_V(ch, subsys, msg, v)                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmitV(::duetos::core::DbgChannel::ch, (subsys), (msg), (v));                            \
        }                                                                                                              \
    } while (0)

#define KDBG_2V(ch, subsys, msg, la, a, lb, b)                                                                         \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmit2V(::duetos::core::DbgChannel::ch, (subsys), (msg), (la), (a), (lb), (b));          \
        }                                                                                                              \
    } while (0)

#define KDBG_3V(ch, subsys, msg, la, a, lb, b, lc, c)                                                                  \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmit3V(::duetos::core::DbgChannel::ch, (subsys), (msg), (la), (a), (lb), (b), (lc),     \
                                      (c));                                                                            \
        }                                                                                                              \
    } while (0)

#define KDBG_4V(ch, subsys, msg, la, a, lb, b, lc, c, ld, d)                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmit4V(::duetos::core::DbgChannel::ch, (subsys), (msg), (la), (a), (lb), (b), (lc),     \
                                      (c), (ld), (d));                                                                 \
        }                                                                                                              \
    } while (0)

#define KDBG_S(ch, subsys, msg, label, s)                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))                                              \
        {                                                                                                              \
            ::duetos::core::DbgEmitS(::duetos::core::DbgChannel::ch, (subsys), (msg), (label), (s));                   \
        }                                                                                                              \
    } while (0)

#define KDBG_ON(ch) (::duetos::core::DbgIsEnabled(::duetos::core::DbgChannel::ch))

#endif // DUETOS_KDBG_OFF
