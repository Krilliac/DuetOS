// vmm_dbg — VS Immediate-window debugger surface for the DuetOS VMM.
//
// These free functions are callable from Visual Studio's Immediate window
// while duetos-vmm.exe is paused at a native breakpoint. They resolve a
// guest-kernel symbol name through ElfSymbols + GuestMemory::HostPtr and
// read/write/symbolise the result on the host.
//
// USAGE (VS Immediate window):
//   duetos::vmm::vmm_dbg::ReadQ("g_ticks")
//   duetos::vmm::vmm_dbg::WriteB("g_log_level", 3)
//   duetos::vmm::vmm_dbg::Sym(0xffffffff80e6f770)
//   duetos::vmm::vmm_dbg::Dump("g_heap", 64)
//
// Symbol names may be either the exact mangled Itanium string stored in
// .symtab, or an unmangled short name (e.g. "g_ticks"). The lookup tries
// exact-match first, then falls back to an Itanium-length-prefix suffix
// scan so short names work without knowing the full mangled form.
//
// All functions are safe to call from any thread while the guest is paused.
// They are NOT re-entrant and NOT signal-safe.
#pragma once

#include <cstddef>
#include <cstdint>

namespace duetos::vmm::vmm_dbg
{

// ---------------------------------------------------------------------------
// Read typed values from a named guest symbol.
// Returns 0 / false if the symbol is not found or the GVA is unmapped.
// ---------------------------------------------------------------------------
uint64_t ReadQ(const char* name);   // 8 bytes
uint32_t ReadD(const char* name);   // 4 bytes
uint16_t ReadW(const char* name);   // 2 bytes
uint8_t  ReadB(const char* name);   // 1 byte

// ---------------------------------------------------------------------------
// Write typed values to a named guest symbol.
// Silent no-op if the symbol is not found or the GVA is unmapped.
// ---------------------------------------------------------------------------
void WriteQ(const char* name, uint64_t value);
void WriteD(const char* name, uint32_t value);
void WriteW(const char* name, uint16_t value);
void WriteB(const char* name, uint8_t  value);

// ---------------------------------------------------------------------------
// Sym — symbolise a guest virtual address.
// Returns a pointer into a thread-local scratch buffer that is
// overwritten on every call. Do NOT evaluate two Sym() (or one Sym()
// and one Dump()) calls in a single Immediate-window expression and
// then dereference both pointers — the second call will silently
// clobber the first's buffer and both `const char*`s will alias the
// SAME bytes (the second result). Copy the string before chaining.
// ---------------------------------------------------------------------------
const char* Sym(uint64_t guestAddr);

// ---------------------------------------------------------------------------
// Dump — hex-dump up to n bytes of a named guest symbol.
// n is capped at 256. Returns a pointer into a thread-local scratch
// buffer that is overwritten on every call. Do NOT evaluate two Dump()
// (or one Dump() and one Sym()) calls in a single Immediate-window
// expression and then dereference both pointers — the second call will
// silently clobber the first's buffer and both `const char*`s will alias
// the SAME bytes (the second result). Copy the string before chaining.
// ---------------------------------------------------------------------------
const char* Dump(const char* name, size_t n);

// ---------------------------------------------------------------------------
// Test seam — inject a resolver that bypasses Vmm::Active().
// Pass nullptr to restore the live resolver.
// Only the vmm-tests binary (built with VMM_DBG_NO_LIVE) uses this.
// ---------------------------------------------------------------------------
struct Resolver
{
    virtual ~Resolver() = default;
    virtual bool        FindSym(const char* name, uint64_t& va,
                                uint64_t& sz)                   = 0;
    virtual void*       HostPtrForGva(uint64_t gva, uint64_t len) = 0;
    virtual const char* Symbolize(uint64_t addr)                = 0;
};

void SetTestResolver(Resolver* r);

// ---------------------------------------------------------------------------
// Layer C — Host-attach session control (Immediate-window entrypoints).
//
// These functions let the developer claim exclusive ownership of the VMM's
// exception-exit path from a Visual Studio native-debugger session, plant
// software breakpoints in the guest kernel, and resume the guest one step
// or one run at a time.
//
// USAGE (VS Immediate window while duetos-vmm.exe is paused):
//   vmm_dbg::Claim()            // take over from the GDB stub
//   vmm_dbg::Bp("SchedulerTick") // plant 0xCC at the symbol's GVA
//   vmm_dbg::Run()              // resume free-run (re-plants all BPs)
//   vmm_dbg::Step()             // single-step (TF); re-plant on next stop
//   vmm_dbg::Clr("SchedulerTick") // remove the BP
//   vmm_dbg::Release()          // hand control back to the GDB stub
//
// THREADING
//   Claim/Release/Bp/Clr are called from the VS Immediate thread while the
//   vCPU thread is stopped at a native __debugbreak().  They are NOT
//   re-entrant across threads (the guest is paused; mutual exclusion is
//   ensured by the stopped atomic).
//   Step/Run unblock the vCPU thread; do NOT call them from a context where
//   the vCPU is still running.
//
// KNOWN LIMIT
//   A layer-C BP planted while Claim is active routes to HandleHostStop.
//   If the user calls Clr() while a BP is still live and then calls
//   Release(), the 0xCC byte is restored before control returns to the GDB
//   stub, so the GDB stub will not trip on it.  However, if the user calls
//   Release() WITHOUT first calling Clr() for every live BP, those bytes
//   remain 0xCC and the GDB stub will receive the #BP — it will not know
//   about the shadow entry and may mis-handle the stop.  Best practice:
//   Clr() all layer-C BPs before Release().
// ---------------------------------------------------------------------------

// Claim() atomically flips the exception-exit arbiter to host-attach mode.
// Returns "gdb-or-none" (prior owner was the GDB stub or no debugger) to
// confirm.  Prints a one-time warning to stderr if IsDebuggerPresent() is
// false — Claim() in a headless run would cause a hang on the first stop.
const char* Claim();

// Release() flips the arbiter back.  Returns "host" to confirm the prior
// owner.  Does NOT automatically clear planted BPs — call Clr() first.
const char* Release();

// Bp() plants a software breakpoint (0xCC) at the GVA of the named symbol.
// Uses the same exact→suffix symbol lookup as ReadQ/WriteQ.
// Returns true if the BP was planted; false if the symbol was not found or
// its GVA could not be translated.  On failure, outputs a note via
// OutputDebugStringA (visible in the VS Output window).
bool Bp(const char* name);

// Clr() removes a layer-C breakpoint planted by Bp(), restoring the
// original byte.  Returns true if the BP was found and removed.
bool Clr(const char* name);

// Step() arms single-step (EFLAGS.TF) and unblocks the vCPU for exactly
// one instruction.  Only acts if g_stop_state.stopped is true.
// If a layer-C BP sits at the current RIP, it is temporarily lifted (the
// shadow is kept so it is re-planted on the next stop).
void Step();

// Run() re-plants all layer-C BPs and unblocks the vCPU for free-run.
// Only acts if g_stop_state.stopped is true.
void Run();

} // namespace duetos::vmm::vmm_dbg
