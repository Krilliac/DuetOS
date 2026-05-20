// host_stop.h — Host-attach guest-stop state and arbiter.
//
// This header declares the shared POD that captures guest CPU state when
// the VMM's exception exit is claimed by a host Visual Studio session, the
// global predicate HostAttachOwnsDebug(), and the HandleHostStop() entry
// point called from Vmm::Run's exception handler.
//
// OWNERSHIP MODEL
//   g_hostAttachOwns defaults to false.  The VS Immediate-window user calls
//   vmm_dbg::Claim() to flip it true, after which every #BP/#DB exception
//   exit routes here instead of to the GDB stub.  vmm_dbg::Release() flips
//   it back.  The two paths are mutually exclusive.
//
// THREAD SAFETY
//   HandleHostStop() is called on the vCPU run thread.  The VS Immediate
//   window calls vmm_dbg::Step() / Run() on the host debugger thread.
//   g_stop_state.stopped is the rendezvous atomic: HandleHostStop() sets
//   it true and spins until the host clears it; Step()/Run() clear it.
//   All other fields of g_stop_state are written BEFORE stopped is set, and
//   read AFTER it is observed true — so no additional synchronisation is
//   needed for those fields.
#pragma once

#include <atomic>
#include <cstdint>

#include "../whp.h"

// Forward declaration — HandleHostStop needs the full exit context type
// but only Vmm& is forwarded here to keep include depth low.
namespace duetos::vmm
{
class Vmm;
}

namespace duetos::vmm
{

// ---------------------------------------------------------------------------
// GuestStopState — snapshot of guest CPU state at the point of each stop.
// Fields are written by the vCPU thread before setting `stopped`.
// Fields are read by the VS host thread after observing `stopped == true`.
// ---------------------------------------------------------------------------
struct GuestStopState
{
    // General-purpose registers snapshotted at stop.
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0;
    uint64_t rsi = 0, rdi = 0, rbp = 0, rsp = 0;
    uint64_t r8  = 0, r9  = 0, r10 = 0, r11 = 0;
    uint64_t r12 = 0, r13 = 0, r14 = 0, r15 = 0;
    uint64_t rip    = 0;
    uint64_t rflags = 0;
    uint64_t cr2    = 0;
    uint64_t cr3    = 0;

    // Symbolised form of RIP — e.g. "duetos::kernel::SomeFn+0x10".
    // Written before `stopped` is set; safe to read once stopped == true.
    char rip_sym[160] = {};

    // Exception type that triggered this stop (1 = #DB, 3 = #BP).
    uint8_t stop_reason = 0;

    // Rendezvous atomic. The vCPU thread sets stopped=true (release)
    // after writing all fields above; the host thread clears it via
    // Step() or Run() (after arming TF on the partition's RFLAGS when
    // stepping) to let the vCPU resume.
    std::atomic<bool> stopped{false};
};

// The single instance; defined in host_stop.cpp.
extern GuestStopState g_stop_state;

// Owned-by-host atomic; defined in host_stop.cpp.
// vmm_dbg::Claim()/Release() exchange this.
extern std::atomic<bool> g_hostAttachOwns;

// Returns true when the host-attach session has claimed the debug channel.
bool HostAttachOwnsDebug();

// Called from Vmm::Run's WHvRunVpExitReasonException case.
// Handles #BP (et==3) and #DB (et==1).  For any other exception type returns
// false so the caller falls through to legacy handling.
// Returns true (and breaks the caller's case) on success.
bool HandleHostStop(Vmm& vmm, const WHV_RUN_VP_EXIT_CONTEXT& exit);

} // namespace duetos::vmm
