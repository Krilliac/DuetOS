// Link stub for kernel symbols referenced by the GSP / AMD GFX
// firmware parsers' self-test path (which compiles into the TU
// but is never reached from the fuzz harness — the harness only
// drives NvidiaGspFwParse / AmdGfxFwParse).

#include "debug/probes.h"
#include "util/types.h"

namespace duetos::debug
{
void ProbeFire(ProbeId, ::duetos::u64, ::duetos::u64) {}
} // namespace duetos::debug
