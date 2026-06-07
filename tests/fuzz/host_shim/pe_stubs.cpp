// Link stubs for kernel symbols referenced by pe_loader.cpp's
// heavyweight path (PeLoad / PeResolveImports*) but never by the
// pure parse/validate path the PE fuzzer exercises.
//
// pe_loader.cpp is one translation unit: compiling it emits code
// for PeLoad too, so the linker needs every mm/proc/security/
// win32 symbol PeLoad calls resolved even though fuzz_pe.cpp only
// drives PeValidate / PeReport / PeIsPe32 / … . Each stub aborts:
// if the fuzzed "pure" path ever reaches one of these, the
// function is not actually allocation-free / state-free and that
// divergence is itself a finding worth a crash.

#include "debug/probes.h"
#include "diag/fix_journal.h"
#include "diag/kdbg.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "security/guard.h"
#include "subsystems/win32/proc_env.h"
#include "subsystems/win32/thunks.h"
#include "util/random.h"

#include <cstdlib>

// The duetos_exec_meta staticlib pulls precompiled `core`, whose
// objects reference the unwind personality even though our shim is
// panic=abort. Nothing ever unwinds here (the panic handler calls
// abort()), so an empty personality satisfies the linker.
extern "C" void rust_eh_personality() {}

namespace
{
[[noreturn]] void Trap(const char* what)
{
    // A pure validator reached a PeLoad-only kernel sink. ASan /
    // libFuzzer record the SIGABRT with a reproducer.
    (void)what;
    abort();
}
} // namespace

namespace duetos::mm
{
void AddressSpaceMapUserPage(AddressSpace*, u64, PhysAddr, u64)
{
    Trap("AddressSpaceMapUserPage");
}
bool AddressSpaceUnmapUserPage(AddressSpace*, u64)
{
    Trap("AddressSpaceUnmapUserPage");
}
// MapSection's section-overlap reuse path (GS-03) re-stamps the shared page;
// the parse-driven harness never reaches a full section map, same as the
// MapUserPage stub above.
u64 AddressSpaceProbePteRaw(const AddressSpace*, u64)
{
    Trap("AddressSpaceProbePteRaw");
}
bool AddressSpaceProtectUserPage(AddressSpace*, u64, u64)
{
    Trap("AddressSpaceProtectUserPage");
}
PhysAddr AddressSpaceLookupUserFrame(const AddressSpace*, u64)
{
    Trap("AddressSpaceLookupUserFrame");
}
core::Result<PhysAddr> AllocateFrame()
{
    Trap("AllocateFrame");
}
core::Result<PhysAddr> AllocateContiguousFrames(u64)
{
    Trap("AllocateContiguousFrames");
}
void* PhysToVirt(PhysAddr)
{
    Trap("PhysToVirt");
}
// ElfLoad path (fuzz_elf reuses this TU). Never reached by the
// pure ElfValidate/ElfForEachPtLoad surface the harness drives.
core::Result<AddressSpace*> AddressSpaceCreate(u64)
{
    Trap("AddressSpaceCreate");
}
void AddressSpaceRelease(AddressSpace*)
{
    Trap("AddressSpaceRelease");
}
u64 FreeFramesCount()
{
    return 0;
}
void FrameAllocatorDrainPools() {}
void FrameAllocatorSetFailAfter(u64) {}
u64 FrameAllocatorGetFailAfter()
{
    return 0;
}
} // namespace duetos::mm

namespace duetos::core
{
u64 RandomU64()
{
    Trap("RandomU64");
}
bool DbgIsEnabled(DbgChannel)
{
    return false;
}
void DbgEmit(DbgChannel, const char*, const char*) {}
void DbgEmitV(DbgChannel, const char*, const char*, u64) {}
void DbgEmitS(DbgChannel, const char*, const char*, const char*, const char*) {}
void DbgEmit2V(DbgChannel, const char*, const char*, const char*, u64, const char*, u64) {}
void DbgEmit3V(DbgChannel, const char*, const char*, const char*, u64, const char*, u64, const char*, u64) {}
} // namespace duetos::core

namespace duetos::debug
{
void ProbeFire(ProbeId, u64, u64) {}
} // namespace duetos::debug

namespace duetos::diag
{
::duetos::core::Result<void> FixJournalRecord(FixDetector, const char*, const char*, u64, u64)
{
    return {};
}

// Code-path ledger flag — kernel-side defaults to 0 (disabled) and
// the kpath KPATH_* macros in pe_loader.cpp early-out on the load.
// Host fuzz harness keeps it 0 so no kpath tracking fires.
volatile ::duetos::u8 g_kpath_enabled = 0;
} // namespace duetos::diag

namespace duetos::loader
{
// ApiSet contract resolver — the static curated table is populated
// at kernel boot from a generator script. Host fuzz harness has no
// API-set table; returning false makes pe_loader.cpp treat every
// `api-ms-*` import as "no static contract", which routes through
// the regular DLL miss-logger and is the correct behaviour under
// fuzz (we're parsing PE bytes, not resolving real api-set names).
bool ApiSetResolveStatic(const char*, const char**)
{
    return false;
}
} // namespace duetos::loader

namespace duetos::security
{
bool Gate(const ImageDescriptor&)
{
    Trap("security::Gate");
}
} // namespace duetos::security

namespace duetos::win32
{
bool IsLikelyDataImport(const char*)
{
    Trap("IsLikelyDataImport");
}
void Win32ProcEnvPopulate(u8*, const char*, u64)
{
    Trap("Win32ProcEnvPopulate");
}
void Win32Thunks32Populate(u8*)
{
    Trap("Win32Thunks32Populate");
}
void Win32ThunksPopulate(u8*)
{
    Trap("Win32ThunksPopulate");
}
bool Win32ThunksLookupCatchAll(u64*)
{
    Trap("Win32ThunksLookupCatchAll");
}
bool Win32ThunksLookupDataCatchAll(u64*)
{
    Trap("Win32ThunksLookupDataCatchAll");
}
bool Win32ThunksLookupDataNamed(const char*, u64*)
{
    Trap("Win32ThunksLookupDataNamed");
}
bool Win32ThunksLookupKind(const char*, const char*, u64*, bool*)
{
    Trap("Win32ThunksLookupKind");
}
void Win32KuserSharedDataPopulate(u8*)
{
    Trap("Win32KuserSharedDataPopulate");
}
} // namespace duetos::win32
