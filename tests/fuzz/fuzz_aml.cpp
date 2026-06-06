// DuetOS — AML bytecode interpreter fuzz harness.
//
// AmlNamespaceBuild (kernel/acpi/aml.cpp) walks the AML byte stream
// of the DSDT and every SSDT to build the ACPI namespace (devices,
// methods, operation regions, field units, _S5 sleep package). Those
// bytes are supplied by platform firmware — and fully attacker-
// controlled on a malicious VM / cloud host that hands the guest a
// crafted DSDT. The recursive TermList decoder (PkgLength, NameString,
// Scope/Device/Method push, Buffer/Package, Field lists) now lives in
// the memory-safe no_std `duetos_aml` Rust crate; aml.cpp is a thin
// FFI caller plus the offset slicers the evaluator drives.
//
// The harness serves the fuzz input as the DSDT. The kernel's AML
// path reaches a table only through the AcpiMapTable / DsdtAddress /
// DsdtLength accessors, so this TU DEFINES those (the linker binds
// aml.cpp's references here, not to the real boot-time ACPI code).
// DsdtAddress() returns a sentinel "physical" 1 whenever an input
// is loaded; AcpiMapTable() hands back the raw input buffer. Then
// we drive the real public AmlNamespaceBuild(), pump the post-walk
// consumers (count/iterate/_S5/method-body) that re-decode bytes,
// and call AmlNamespaceShutdown() to clear the global namespace +
// "built" flag so the next iteration re-walks from clean state.
//
// This drives the real integrated path: a bounds/overflow bug in the
// Rust walker aborts as a libFuzzer crash (panic=abort staticlib
// shim), while ASan/UBSan guard the C++ orchestration + the offset
// slicers (PkgLength / field-width math in AmlMethodBody etc.).

#include "acpi/aml.h"

#include <cstddef>
#include <cstdint>

// The panic=abort Rust staticlib references the unwinder personality
// routine; it is never called under panic=abort, but the symbol must
// resolve at link time. fuzz_aml links no kernel-symbol stub TU, so
// it carries the one-liner itself (as fuzz_acpi does).
extern "C" void rust_eh_personality() {}

namespace
{
const duetos::u8* g_table = nullptr;
duetos::u32 g_table_len = 0;
} // namespace

// --- ACPI table accessors the AML walker links against ----------
//
// aml.cpp references these (declared in acpi/acpi.h). On a real
// boot they walk the firmware's mapped tables; here they project
// the single fuzz input as the one-and-only DSDT, no SSDTs.
namespace duetos::acpi
{
const void* AcpiMapTable(u64 phys, u64 /*len*/)
{
    // The walker maps the DSDT (sentinel phys == 1). Anything else
    // (an SSDT we never advertise) maps nowhere.
    return phys == 1 ? static_cast<const void*>(g_table) : nullptr;
}
u64 DsdtAddress()
{
    return g_table_len >= 36 ? 1 : 0;
}
u32 DsdtLength()
{
    return g_table_len;
}
u64 SsdtCount()
{
    return 0;
}
u64 SsdtAddress(u64 /*index*/)
{
    return 0;
}
u32 SsdtLength(u64 /*index*/)
{
    return 0;
}
} // namespace duetos::acpi

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // A whole ACPI table is a 36-byte header + body; below that the
    // walker rejects on the length gate, so there is nothing to
    // exercise. Cap the size so one input can't dwarf the budget.
    if (size < 36 || size > 262144)
        return 0;

    g_table = reinterpret_cast<const duetos::u8*>(data);
    g_table_len = static_cast<duetos::u32>(size);

    using namespace duetos::acpi;
    using duetos::u32;
    using duetos::u8;

    // Build the namespace from the fuzzed DSDT — the recursive
    // TermList walk under test.
    AmlNamespaceBuild();

    // Pump the post-walk consumers that re-decode table bytes:
    // every named entry's method body / name value, the region +
    // field indices, and the _S5 sleep-package decoder. These reach
    // AmlMethodBody / AmlNameValue / AmlReadS5 — additional byte
    // parsers layered on the same hostile input.
    const u32 n = AmlNamespaceCount();
    for (u32 i = 0; i < n; ++i)
    {
        const AmlNamespaceEntry* e = AmlNamespaceEntryAt(i);
        if (e == nullptr)
            continue;
        const u8* body = nullptr;
        u32 body_len = 0;
        u8 argc = 0;
        (void)AmlMethodBody(e, &body, &body_len, &argc);
        const u8* nval = nullptr;
        u32 nval_len = 0;
        (void)AmlNameValue(e, &nval, &nval_len);
    }
    (void)AmlRegionCount();
    (void)AmlFieldCount();

    u8 a = 0;
    u8 b = 0;
    (void)AmlReadS5(&a, &b);

    // Reset global namespace + "built" flag for the next input.
    (void)AmlNamespaceShutdown();

    g_table = nullptr;
    g_table_len = 0;
    return 0;
}
