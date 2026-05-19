// DuetOS — ELF64 loader parser fuzz harness.
//
// The ELF loader is the native peer of the PE loader: it consumes
// attacker-controlled executable bytes (the `exec` / `readelf`
// shell paths, and ElfLoad on the native spawn path). Its pure
// walkers are documented as "purely a byte-buffer walker — no
// allocation, no MMU", which is exactly the contract a fuzzer
// should hold them to.
//
// Targets:
//   ElfValidate          — header + program-header-table validate
//                           (delegates to the duetos_exec_meta
//                           Rust crate; fuzzed for free here)
//   ElfEntry             — e_entry read
//   ElfProgramHeaderInfo — phoff/phnum/phentsize read
//   ElfForEachPtLoad     — PT_LOAD segment walker (takes file_len)
//
// ElfEntry / ElfProgramHeaderInfo / ElfForEachPtLoad document
// "undefined behaviour if the buffer isn't valid per ElfValidate",
// so they are only driven after ElfValidate returns Ok — that is
// the real contract a caller must honour, and fuzzing it proves
// the validate→walk pipeline is OOB-free on the happy path. The
// raw walkers are ALSO driven on un-validated input below, because
// the public signatures take file_len and nothing in the type
// system stops a caller invoking them directly.

#include "loader/elf_loader.h"

#include <cstddef>
#include <cstdint>

using namespace duetos::core;

namespace
{
volatile duetos::u64 g_sink;
void SegSink(const ElfSegment& seg, void* /*cookie*/)
{
    // Touch every field so a bogus segment that slipped a bound
    // is observed under ASan rather than silently dropped.
    g_sink = seg.file_offset ^ seg.vaddr ^ seg.filesz ^ seg.memsz ^ seg.align ^ seg.flags;
}
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > (1u << 20))
        return 0;

    const auto* file = reinterpret_cast<const duetos::u8*>(data);
    const duetos::u64 len = static_cast<duetos::u64>(size);

    const ElfStatus st = ElfValidate(file, len);
    (void)ElfStatusName(st);

    if (st == ElfStatus::Ok)
    {
        // Documented-safe path: validated buffer, then the walkers
        // a real consumer (readelf / exec / ElfLoad) runs.
        (void)ElfEntry(file);
        duetos::u64 phoff = 0;
        duetos::u16 phnum = 0;
        duetos::u16 phentsize = 0;
        ElfProgramHeaderInfo(file, &phoff, &phnum, &phentsize);
        (void)ElfForEachPtLoad(file, len, &SegSink, nullptr);
    }

    // Direct-call path: the public API takes file_len, so a caller
    // CAN invoke the walker without ElfValidate. It must not OOB on
    // arbitrary bytes — file_len is there precisely to make that
    // safe.
    (void)ElfForEachPtLoad(file, len, &SegSink, nullptr);

    return 0;
}
