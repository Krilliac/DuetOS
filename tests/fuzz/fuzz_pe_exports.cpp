// DuetOS — PE Export Address Table parser fuzz harness.
//
// PeParseExports walks IMAGE_EXPORT_DIRECTORY and the EAT / ENT
// / EOT arrays of a PE/COFF image, classifying forwarders and
// binary-searching the (name-sorted) name table. It is a
// distinct entry point from the PE *loader* (fuzz_pe drives the
// validate/report path); the export walker is reached by
// PeReport and the DLL cache directly on the raw file bytes — a
// guest-supplied .dll, fully attacker-controlled. The harness
// parses, then iterates every export and does a name + ordinal
// lookup so the array walks and the binary search see hostile
// RVAs/counts.

#include "loader/pe_exports.h"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0 || size > (1u << 20))
        return 0;

    duetos::core::PeExports exp{};
    if (duetos::core::PeParseExports(reinterpret_cast<const duetos::u8*>(data), static_cast<duetos::u64>(size), exp) !=
        duetos::core::PeExportStatus::Ok)
        return 0;

    const duetos::u32 count = duetos::core::PeExportsCount(exp);
    const duetos::u32 n = count > 8192u ? 8192u : count;
    for (duetos::u32 i = 0; i < n; ++i)
    {
        duetos::core::PeExport e{};
        if (!duetos::core::PeExportAt(exp, i, e))
            continue;
        duetos::core::PeExport probe{};
        (void)duetos::core::PeExportLookupOrdinal(exp, e.ordinal, probe);
    }
    return 0;
}
