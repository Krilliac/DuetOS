// DuetOS — ACPI firmware-table parser fuzz harness.
//
// The kernel boot path consumes a dozen ACPI tables that the
// platform firmware (or, on a VM / a malicious cloud host, an
// attacker) hands it byte-for-byte: the RSDP, the generic 36-byte
// table header + 8-bit additive checksum, and the per-table bodies
// for MADT (interrupt topology), FADT (power/SCI), MCFG (PCIe ECAM),
// HPET (timer), and SRAT (NUMA affinity). All of that byte parsing
// lives in the memory-safe no_std `duetos_acpi_rust` crate
// (kernel/acpi/acpi_rust/), reached through the C ABI in
// acpi_rust.h. A bounds/overflow bug the crate failed to guard
// surfaces as a Rust panic, which the panic=abort staticlib shim
// turns into a libFuzzer crash; ASan also catches any OOB the FFI
// boundary lets through.
//
// One input drives EVERY parser plus the two chained-entry walkers
// (MADT subtables, SRAT memory-affinity subtables) so a single
// corpus exercises the whole firmware-table ingest surface. The
// parsers all gate on signature + length, so a seed shaped like one
// table still drives the reject path of the others.
//
// The AML bytecode interpreter (DSDT/SSDT) is a separate, far larger
// C++ surface and is fuzzed by fuzz_aml — see that harness.

#include "acpi/acpi_rust/include/acpi_rust.h"

#include <cstddef>
#include <cstdint>

// The panic=abort Rust staticlib still emits a reference to the
// unwinder personality routine; it is never called under
// panic=abort, but the symbol must resolve at link time. The other
// Rust-backed harnesses get this from their kernel-symbol stub TU
// (e.g. host_shim/fs_stubs.cpp); fuzz_acpi links no kernel TU, so
// it carries the one-liner itself.
extern "C" void rust_eh_personality() {}

namespace
{
using namespace duetos::acpi::rust;
using duetos::u8;
using duetos::usize;

// Walk the MADT interrupt-controller-structure list the way
// AcpiParseMadt does: each subtable is {type:u8, length:u8, ...};
// advance by the length byte. The length-byte parser is the most
// attack-exposed loop in the MADT path — a zero / overlong length
// is exactly the malformed-firmware case the guard must survive.
void WalkMadt(const u8* buf, usize len)
{
    // MADT body starts past the 36-byte ACPI header + 8 bytes
    // (Local-APIC address + flags). Match the kernel's start offset.
    constexpr usize kMadtFirstEntry = 44;
    usize off = kMadtFirstEntry;
    for (int guard = 0; guard < 4096 && off + 2 <= len; ++guard)
    {
        DuetosAcpiMadtEntryHeader e{};
        if (!duetos_acpi_parse_madt_entry_header(buf, len, off, &e) || e.ok == 0)
            break;
        // Entry length < 2 would not advance the cursor — stop
        // rather than spin. A real parser must reject it; the loop
        // guard here only protects the harness, not the parser.
        if (e.length < 2)
            break;
        off += e.length;
    }
}

// Walk the SRAT static-resource-affinity subtable list. Subtables
// share the {type:u8, length:u8, ...} shape; the memory-affinity
// decoder only commits when type == Memory Affinity, but it is
// called at every offset so its type-gate + bounds checks run on
// hostile cursor positions.
void WalkSrat(const u8* buf, usize len)
{
    constexpr usize kSratFirstEntry = 48; // 36 header + 4 rev + 8 reserved
    usize off = kSratFirstEntry;
    for (int guard = 0; guard < 4096 && off + 2 <= len; ++guard)
    {
        DuetosAcpiSratMemoryAffinity ma{};
        (void)duetos_acpi_parse_srat_memory_affinity(buf, len, off, &ma);
        // Subtable length byte lives at off+1 for every SRAT type.
        const u8 sub_len = buf[off + 1];
        if (sub_len < 2)
            break;
        off += sub_len;
    }
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Cap the input so the chained walkers can't be handed a
    // multi-megabyte table that dwarfs the per-exec budget.
    if (size > 65536)
        return 0;

    const auto* buf = reinterpret_cast<const u8*>(data);
    const auto len = static_cast<usize>(size);

    DuetosAcpiRsdp rsdp{};
    (void)duetos_acpi_parse_rsdp(buf, len, &rsdp);

    DuetosAcpiTableHeader hdr{};
    (void)duetos_acpi_parse_table_header(buf, len, &hdr);

    DuetosAcpiFadt fadt{};
    (void)duetos_acpi_parse_fadt(buf, len, &fadt);

    DuetosAcpiHpet hpet{};
    (void)duetos_acpi_parse_hpet(buf, len, &hpet);

    // MCFG is an array of 16-byte entries past the header; walk a
    // bounded count so a crafted length can't drive an unbounded
    // index loop here while still reaching the deep entries.
    for (uint32_t idx = 0; idx < 1024; ++idx)
    {
        DuetosAcpiMcfgEntry mcfg{};
        if (!duetos_acpi_parse_mcfg_entry(buf, len, idx, &mcfg) || mcfg.ok == 0)
            break;
    }

    WalkMadt(buf, len);
    WalkSrat(buf, len);
    return 0;
}
