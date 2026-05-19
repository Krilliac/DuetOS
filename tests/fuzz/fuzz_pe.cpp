// DuetOS — PE/COFF loader parser fuzz harness.
//
// Pillar #1 of the project is "run Windows PE executables
// natively." Every untrusted .exe / .dll a guest hands the
// kernel flows through these byte-walking validators before a
// single page is mapped. They are the first place a malicious
// or corrupt PE can drive an OOB read or a length-overflow, so
// they are exactly the surface to fuzz.
//
// Targets (all pure, no allocation, no kernel state):
//   PeValidate          — full header + section-table walk
//   PeIsPe32            — DOS+COFF prefix walk
//   PeIsDynamicBase     — opt-header DllCharacteristics read
//   PePreferredBaseOf   — opt-header ImageBase read
//   PeImageSizeOf       — opt-header SizeOfImage read
//   PeReport            — every-directory diagnostic walker
//   PeQuickSummaryTo    — summary writer (callback sink)
//
// PeLoad / PeResolveImports* are NOT driven here: they mutate an
// AddressSpace and need the mm/proc kernel surface, which the
// host shim only stubs. The validators above gate every call to
// them, so a bug found here is a bug a real spawn path hits
// before the heavyweight path is even reached.

#include "loader/pe_loader.h"

#include <cstddef>
#include <cstdint>

using namespace duetos::core;

namespace
{
// PeQuickSummaryTo writes through a function pointer; give it a
// sink that touches every byte so a bad chunk pointer / length
// faults under ASan instead of being silently dropped.
volatile char g_sink;
void SummarySink(const char* chunk)
{
    if (!chunk)
        return;
    for (const char* p = chunk; *p; ++p)
        g_sink = *p;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    const auto* file = reinterpret_cast<const duetos::u8*>(data);
    const duetos::u64 len = static_cast<duetos::u64>(size);

    // Cheap prefix walkers first — these run on the spawn path
    // before PeValidate to pick the preload set / ASLR policy.
    (void)PeIsPe32(file, len);
    (void)PeIsDynamicBase(file, len);
    (void)PePreferredBaseOf(file, len);
    (void)PeImageSizeOf(file, len);

    // Full validator — the gate PeLoad sits behind.
    PeStatus st = PeValidate(file, len);
    (void)PeStatusName(st);

    // Diagnostic walkers. PeReport / PeQuickSummaryTo walk every
    // data directory (imports, relocs, TLS, load-config, …) and
    // are documented as "bails out silently on malformed bytes"
    // — fuzz proves that claim.
    PeReport(file, len);
    PeQuickSummaryTo(&SummarySink, file, len);

    return 0;
}
