// GuestKernelView population — resolves kernel symbol names to host
// pointers into the WHP-mapped guest physical RAM.
//
// MapSym<T> is the single workhorse:
//   1. Skip if the field is already mapped (idempotent across exits).
//   2. Find the symbol: exact name first, Itanium-suffix fallback for
//      anonymous-namespace mangled names (e.g. `g_ticks` lives as
//      `_ZN6duetos4arch12_GLOBAL__N_17g_ticksE`).
//   3. Translate the kernel virtual address to a guest physical address
//      via the WHP GVA→GPA page-walk.
//   4. Ask GuestMemory for the host-side backing pointer.
//
// The v1 field list is intentionally minimal — one `g_ticks` to prove
// the mechanism end-to-end. Additional fields follow the same pattern.
#include "guest_view.h"

#include "../vmm.h"

namespace duetos::vmm
{

namespace
{

// Resolve one kernel global of type T and store its host pointer in
// `outPtr`. No-op if `outPtr` is already non-null. On any failure
// (symbol not found, GPA translation fails, host-ptr null) `outPtr`
// remains nullptr — the caller will retry on the next guest exit.
template <typename T>
void MapSym(T*& outPtr, Vmm& vmm, const char* symName)
{
    if (outPtr != nullptr)
        return; // already mapped

    // Step 1: symbol lookup — exact first, suffix fallback for
    // Itanium-mangled anonymous-namespace globals.
    const ElfSymbols::Sym* sym = vmm.DbgFindSym(symName);
    if (sym == nullptr)
        sym = vmm.DbgSymbols().FindBySuffix(symName);
    if (sym == nullptr)
        return;

    // Step 2: GVA → GPA via the WHP page-walk.
    uint64_t gpa = 0;
    if (!vmm.DbgResolveGpa(sym->addr, gpa))
        return;

    // Step 3: GPA → host pointer via the WHP-mapped backing buffer.
    void* raw = vmm.DbgHostPtr(gpa, sizeof(T));
    if (raw == nullptr)
        return;

    outPtr = static_cast<T*>(raw);
}

} // namespace

void RefreshGuestView(GuestKernelView& view, Vmm& vmm)
{
    // duetos::arch::(anonymous namespace)::g_ticks
    // Mangled: _ZN6duetos4arch12_GLOBAL__N_17g_ticksE
    // FindBySuffix("g_ticks") resolves it without hard-coding the
    // mangled form. DbgFindSym tries exact match first (for the
    // unlikely case where a future build exports it unmangled).
    MapSym(view.g_ticks, vmm, "g_ticks");
}

} // namespace duetos::vmm
