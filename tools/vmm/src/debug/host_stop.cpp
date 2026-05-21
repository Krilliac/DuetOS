// host_stop.cpp — Host-attach guest-stop implementation.
// See host_stop.h for the ownership model and thread-safety contract.
#include "debug/host_stop.h"

#include <chrono>
#include <cstdio>
#include <intrin.h>
#include <thread>

#include "vmm.h"

namespace duetos::vmm
{

// ---------------------------------------------------------------------------
// Global definitions
// ---------------------------------------------------------------------------

GuestStopState       g_stop_state;
std::atomic<bool>    g_hostAttachOwns{false};

bool HostAttachOwnsDebug()
{
    return g_hostAttachOwns.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// HandleHostStop
// ---------------------------------------------------------------------------

bool HandleHostStop(Vmm& vmm, const WHV_RUN_VP_EXIT_CONTEXT& exit)
{
    const uint8_t et = exit.VpException.ExceptionType;

    // Only handle #BP (3) and #DB single-step (1).
    if (et != 1 && et != 3)
    {
        return false;
    }

    Partition& part = vmm.DbgPartition();

    // #BP: WHP leaves RIP pointing one byte past the int3.  Rewind so
    // that the next continue re-executes from the breakpoint address
    // (the byte will have been restored before resume).
    if (et == 3)
    {
        part.SetRip(0, exit.VpContext.Rip - 1);
    }

    // Snapshot the full register set into g_stop_state.
    // Layout mirrors the GDB stub's kRegs array: rax rbx rcx rdx rsi rdi
    // rbp rsp r8-r15, rip, rflags, cr2, cr3.
    {
        constexpr WHV_REGISTER_NAME kNames[] = {
            WHvX64RegisterRax,    WHvX64RegisterRbx,
            WHvX64RegisterRcx,    WHvX64RegisterRdx,
            WHvX64RegisterRsi,    WHvX64RegisterRdi,
            WHvX64RegisterRbp,    WHvX64RegisterRsp,
            WHvX64RegisterR8,     WHvX64RegisterR9,
            WHvX64RegisterR10,    WHvX64RegisterR11,
            WHvX64RegisterR12,    WHvX64RegisterR13,
            WHvX64RegisterR14,    WHvX64RegisterR15,
            WHvX64RegisterRip,    WHvX64RegisterRflags,
            WHvX64RegisterCr2,    WHvX64RegisterCr3,
        };
        constexpr uint32_t kN =
            static_cast<uint32_t>(sizeof(kNames) / sizeof(kNames[0]));

        WHV_REGISTER_VALUE v[kN] = {};
        part.GetRegisters(0, kNames, kN, v);

        g_stop_state.rax    = v[0].Reg64;
        g_stop_state.rbx    = v[1].Reg64;
        g_stop_state.rcx    = v[2].Reg64;
        g_stop_state.rdx    = v[3].Reg64;
        g_stop_state.rsi    = v[4].Reg64;
        g_stop_state.rdi    = v[5].Reg64;
        g_stop_state.rbp    = v[6].Reg64;
        g_stop_state.rsp    = v[7].Reg64;
        g_stop_state.r8     = v[8].Reg64;
        g_stop_state.r9     = v[9].Reg64;
        g_stop_state.r10    = v[10].Reg64;
        g_stop_state.r11    = v[11].Reg64;
        g_stop_state.r12    = v[12].Reg64;
        g_stop_state.r13    = v[13].Reg64;
        g_stop_state.r14    = v[14].Reg64;
        g_stop_state.r15    = v[15].Reg64;
        g_stop_state.rip    = v[16].Reg64;
        g_stop_state.rflags = v[17].Reg64;
        g_stop_state.cr2    = v[18].Reg64;
        g_stop_state.cr3    = v[19].Reg64;
    }

    g_stop_state.stop_reason = et;

    // Symbolise RIP.
    {
        std::string sym = vmm.DbgSymbols().Symbolize(g_stop_state.rip);
        std::snprintf(g_stop_state.rip_sym, sizeof(g_stop_state.rip_sym),
                      "%s", sym.c_str());
    }

    std::fprintf(stderr,
                 "[vmm/host-stop] guest stopped: rip=%s reason=%u "
                 "(call vmm_dbg::Run() / Step() to resume)\n",
                 g_stop_state.rip_sym,
                 static_cast<unsigned>(et));
    std::fflush(stderr);

    // Publish the stop to the host thread BEFORE invoking __debugbreak,
    // so that when VS halts the VMM the Watch window shows
    // g_stop_state.stopped == true (consistent with the stderr sentinel
    // above).  All other fields were written before this store; the
    // release-store publishes them as a unit.
    g_stop_state.stopped.store(true, std::memory_order_release);

    // Signal VS (or any attached native debugger) that the guest has
    // stopped.  The IsDebuggerPresent() guard is critical: headless /
    // CI runs must not crash on this path.
    if (IsDebuggerPresent())
    {
        __debugbreak();
    }

    // Spin until the host calls Step() or Run(), which clear `stopped`.
    while (g_stop_state.stopped.load(std::memory_order_acquire))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    return true;
}

} // namespace duetos::vmm
