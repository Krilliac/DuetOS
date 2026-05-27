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

// Each Rust staticlib pulls in `core` objects that reference the
// unwind personality even though we're panic=abort. Empty stub
// satisfies the linker for both fuzz_nvidia_gsp_fw + fuzz_amd_gfx_fw.
extern "C" void rust_eh_personality() {}
