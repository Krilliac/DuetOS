// Link stubs for the kernel symbols the FAT32 probe TUs reference
// (scheduler mutex, initcall registration, driver-domain
// registration, debug channel, FAT-attr serial pretty-printer)
// but that the host fuzz harness does not need to be real: the
// parser under test reads bytes via the block shim; locks are
// uncontended single-threaded, initcalls/domains are a no-op
// outside a booted kernel, and debug output is silenced.
//
// Kept separate from pe_stubs.cpp so the FS harnesses don't drag
// in the PE/win32/mm stub surface.

#include "util/result.h"
#include "util/types.h"

// The duetos_exfat staticlib pulls precompiled `core`, which
// references the unwind personality even though the shim is
// panic=abort. Nothing unwinds (the panic handler abort()s), so
// an empty personality satisfies the linker. (Same shim as
// pe_stubs.cpp's; harmless if both link — they never do.)
extern "C" void rust_eh_personality() {}

namespace duetos::core
{
// Mangling depends on the enum-class name + namespace only, not
// the underlying type — minimal forward decls suffice.
enum class DbgChannel : u32;
enum class Phase : u32;
using FaultDomainId = u32;
using InitcallFn = Result<void> (*)();

bool DbgIsEnabled(DbgChannel)
{
    return false;
}
void DbgEmitS(DbgChannel, const char*, const char*, const char*, const char*) {}
void InitcallAutoRegister(Phase, const char*, InitcallFn) {}
void SerialWriteFatAttr(u64) {}
} // namespace duetos::core

namespace duetos::sched
{
struct Task;
struct Mutex;
Task* CurrentTask()
{
    return nullptr;
}
void MutexLock(Mutex*) {}
void MutexUnlock(Mutex*) {}
} // namespace duetos::sched

namespace duetos::security
{
::duetos::core::FaultDomainId RegisterDriverDomain(const char*, ::duetos::core::Result<void> (*)(),
                                                   ::duetos::core::Result<void> (*)())
{
    return 0;
}
} // namespace duetos::security

namespace duetos::util
{
// exFAT name filter. The fuzzer never inspects the rendered
// string — a fixed safe glyph keeps the parser path exercised.
char Utf16CpToSafeAscii(u32)
{
    return '?';
}
} // namespace duetos::util
