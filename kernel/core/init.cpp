/*
 * DuetOS — kernel init registry, v0 (plan A1).
 *
 * See `init.h` for the public contract. This TU owns the fixed-size
 * registry, the per-phase dispatcher, and the boot self-test.
 *
 * The registry is a single linear array indexed by registration
 * order. `RunPhase(p)` walks it in order, picking out rows whose
 * `phase == p`. With `kMaxInitcalls = 64` and ~13 phases, the
 * O(N*P) cost is irrelevant (boot is one-shot) and the data layout
 * stays trivially debuggable: a single dump prints the boot map.
 */

#include "core/init.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "diag/boot_observe.h"
#include "log/klog.h"
#include "util/result.h"
#include "util/types.h"

namespace duetos::core
{

namespace
{

InitcallRecord g_initcalls[kMaxInitcalls];
u32 g_initcall_count = 0;

bool PhaseInRange(Phase phase)
{
    return static_cast<u32>(phase) < static_cast<u32>(Phase::kPhaseCount);
}

const char* kPhaseNames[static_cast<u32>(Phase::kPhaseCount)] = {
    "earlycon",  "physmem", "paging", "heap",    "idt", "apic",     "time",
    "percpubsp", "sched",   "smp",    "drivers", "vfs", "userland",
};

} // namespace

const char* PhaseName(Phase phase)
{
    if (!PhaseInRange(phase))
    {
        return "?";
    }
    return kPhaseNames[static_cast<u32>(phase)];
}

Result<void> InitcallRegister(Phase phase, const char* name, InitcallFn fn)
{
    if (name == nullptr || fn == nullptr)
    {
        return Err{ErrorCode::InvalidArgument};
    }
    if (!PhaseInRange(phase))
    {
        return Err{ErrorCode::InvalidArgument};
    }
    if (g_initcall_count >= kMaxInitcalls)
    {
        return Err{ErrorCode::OutOfMemory};
    }

    InitcallRecord& rec = g_initcalls[g_initcall_count++];
    rec.phase = phase;
    rec.name = name;
    rec.fn = fn;
    rec.invoke_count = 0;
    rec.last_run_ticks = 0;
    rec.ran_ok = false;
    return {};
}

bool InitcallUnregister(const char* name)
{
    if (name == nullptr)
    {
        return false;
    }
    for (u32 i = 0; i < g_initcall_count; ++i)
    {
        // Pointer-equality match: every registrant passes a stable
        // string literal, and the unregister site uses the same one.
        if (g_initcalls[i].name == name)
        {
            for (u32 j = i + 1; j < g_initcall_count; ++j)
            {
                g_initcalls[j - 1] = g_initcalls[j];
            }
            --g_initcall_count;
            g_initcalls[g_initcall_count] = InitcallRecord{};
            return true;
        }
    }
    return false;
}

u32 InitcallCount()
{
    return g_initcall_count;
}

u32 InitcallCountForPhase(Phase phase)
{
    if (!PhaseInRange(phase))
    {
        return 0;
    }
    u32 count = 0;
    for (u32 i = 0; i < g_initcall_count; ++i)
    {
        if (g_initcalls[i].phase == phase)
        {
            ++count;
        }
    }
    return count;
}

const InitcallRecord* InitcallGet(u32 index)
{
    if (index >= g_initcall_count)
    {
        return nullptr;
    }
    return &g_initcalls[index];
}

Result<void> RunPhase(Phase phase)
{
    if (!PhaseInRange(phase))
    {
        return Err{ErrorCode::InvalidArgument};
    }

    // Single choke point: every phase boundary in the boot path runs
    // through here, so instrumenting RunPhase gives the full phase
    // ladder + watchdog + report without 13 edits in main.cpp.
    diag::BootPhaseEnter(phase);

    KLOG_INFO_2V("init", "RunPhase begin", "phase", static_cast<u64>(phase), "callbacks",
                 static_cast<u64>(InitcallCountForPhase(phase)));

    for (u32 i = 0; i < g_initcall_count; ++i)
    {
        InitcallRecord& rec = g_initcalls[i];
        if (rec.phase != phase)
        {
            continue;
        }

        KLOG_INFO_S("init", "invoke", "name", rec.name);
        Result<void> r = rec.fn();
        ++rec.invoke_count;
        rec.ran_ok = r.has_value();

        if (!rec.ran_ok)
        {
            KLOG_ERROR_V("init", "callback failed", static_cast<u64>(r.error()));
            diag::BootPhaseFailed(phase, static_cast<u32>(r.error()));
            return r;
        }
    }
    return {};
}

namespace
{

// Self-test scratch counters. File-static so the test functions can
// be free InitcallFns (matching the real registration shape) without
// needing a context pointer.
u32 g_st_a_calls = 0;
u32 g_st_b_calls = 0;
u32 g_st_c_calls = 0;
u32 g_st_order_seq = 0;
u32 g_st_a_seq = 0;
u32 g_st_b_seq = 0;
u32 g_st_c_seq = 0;

Result<void> SelfTestA()
{
    g_st_a_seq = ++g_st_order_seq;
    ++g_st_a_calls;
    return {};
}

Result<void> SelfTestB()
{
    g_st_b_seq = ++g_st_order_seq;
    ++g_st_b_calls;
    return {};
}

Result<void> SelfTestC()
{
    g_st_c_seq = ++g_st_order_seq;
    ++g_st_c_calls;
    return {};
}

Result<void> SelfTestFailing()
{
    return Err{ErrorCode::Unknown};
}

} // namespace

void InitSelfTest()
{
    arch::SerialWrite("[init] self-test: registering 3 callbacks across 3 phases.\n");

    // These RunPhase calls (incl. the deliberate Userland Err below)
    // exercise the registry, not the real boot path — keep them out
    // of the boot-observability ladder / exit-code machinery.
    diag::BootObserveSuppress(true);

    const u32 baseline_count = g_initcall_count;

    auto must_ok = [](const Result<void>& r, const char* what)
    {
        if (!r.has_value())
        {
            Panic("init self-test", what);
        }
    };

    must_ok(InitcallRegister(Phase::Earlycon, "init.selftest.a", SelfTestA), "register A");
    must_ok(InitcallRegister(Phase::Heap, "init.selftest.b", SelfTestB), "register B");
    must_ok(InitcallRegister(Phase::Drivers, "init.selftest.c", SelfTestC), "register C");

    if (g_initcall_count != baseline_count + 3)
    {
        Panic("init self-test", "registry count mismatch after 3 registers");
    }

    if (InitcallCountForPhase(Phase::Heap) < 1)
    {
        Panic("init self-test", "phase counter not seeing registered Heap row");
    }

    must_ok(RunPhase(Phase::Earlycon), "RunPhase Earlycon");
    must_ok(RunPhase(Phase::Heap), "RunPhase Heap");
    must_ok(RunPhase(Phase::Drivers), "RunPhase Drivers");

    if (g_st_a_calls != 1 || g_st_b_calls != 1 || g_st_c_calls != 1)
    {
        Panic("init self-test", "callback invocation counts wrong");
    }

    if (!(g_st_a_seq < g_st_b_seq && g_st_b_seq < g_st_c_seq))
    {
        Panic("init self-test", "phase order not preserved (A < B < C expected)");
    }

    // Negative path 1: bad arguments.
    Result<void> r_bad_name = InitcallRegister(Phase::Heap, nullptr, SelfTestA);
    Result<void> r_bad_fn = InitcallRegister(Phase::Heap, "x", nullptr);
    Result<void> r_bad_phase = InitcallRegister(static_cast<Phase>(99), "x", SelfTestA);
    if (r_bad_name.has_value() || r_bad_fn.has_value() || r_bad_phase.has_value())
    {
        Panic("init self-test", "InitcallRegister accepted bad arguments");
    }

    // Negative path 2: a failing callback halts the phase and surfaces the error.
    constexpr const char* kSelfTestFailRow = "init.selftest.fail";
    must_ok(InitcallRegister(Phase::Userland, kSelfTestFailRow, SelfTestFailing), "register failing");
    Result<void> r_fail = RunPhase(Phase::Userland);
    if (r_fail.has_value())
    {
        Panic("init self-test", "RunPhase returned Ok despite failing callback");
    }
    // Retire the failing row so it doesn't poison the late-boot
    // RunPhase(Userland) that picks up every real Userland self-test
    // (elf-loader-unwind, dll-loader, win32-custom, sched-loadbalance,
    // ...). Without retirement the late phase aborts on the
    // deliberate failure and skips every self-test registered after it.
    if (!InitcallUnregister(kSelfTestFailRow))
    {
        Panic("init self-test", "InitcallUnregister failed to retire the failing row");
    }

    diag::BootObserveSuppress(false);

    arch::SerialWrite("[init] self-test: 3 phases x 1 callback ran in order; failure path surfaces error. OK.\n");
}

void InitcallAutoRegister(Phase phase, const char* name, InitcallFn fn)
{
    // Constructor-time registration. Failures are non-fatal at
    // this stage because no panic surface is up — the registry-
    // full case is the only realistic failure, and KLOG_WARN
    // surfaces it once the log subsystem comes online.
    auto r = InitcallRegister(phase, name, fn);
    if (!r.has_value())
    {
        KLOG_WARN_S("init", "KERNEL_INITCALL registration failed", "name", name);
    }
}

// _init_array invocation (plan A1-followup). The linker script
// places one pointer per non-constinit C++ static constructor
// into [__init_array_start, __init_array_end); walking the
// range + invoking each pointer is the standard hosted-runtime
// behaviour. The kernel deliberately favors `constinit` globals
// (no constructors), so this table is typically empty / very
// short — the call is a no-op on a clean build but exists so a
// future TU that needs a real constructor doesn't silently get
// a half-initialised global.
//
// Linker symbols:
extern "C" void (*__init_array_start[])();
extern "C" void (*__init_array_end[])();

void RunInitArray()
{
    const u64 count = static_cast<u64>(__init_array_end - __init_array_start);
    arch::SerialWrite("[init] _init_array: ");
    arch::SerialWriteHex(count);
    arch::SerialWrite(" entries\n");
    for (u64 i = 0; i < count; ++i)
    {
        if (__init_array_start[i] != nullptr)
        {
            __init_array_start[i]();
        }
    }
}

} // namespace duetos::core
