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

} // namespace duetos::vmm::vmm_dbg
