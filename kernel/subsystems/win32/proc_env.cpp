#include "subsystems/win32/proc_env.h"

#include "time/tick.h"

namespace duetos::win32
{

namespace
{
// Write a little-endian u64 at `dst`.
inline void StoreLeU64(u8* dst, u64 value)
{
    for (u64 b = 0; b < 8; ++b)
        dst[b] = static_cast<u8>((value >> (b * 8)) & 0xFFULL);
}
// Write a little-endian u32 at `dst`.
inline void StoreLeU32(u8* dst, u32 value)
{
    for (u64 b = 0; b < 4; ++b)
        dst[b] = static_cast<u8>((value >> (b * 8)) & 0xFFU);
}
} // namespace

void Win32ProcEnvPopulate(u8* proc_env_page, const char* program_name, u64 module_base)
{
    if (proc_env_page == nullptr)
        return;

    // Caller is expected to have zeroed the frame, but be
    // defensive — populate only the specific fields we own,
    // leaving the rest at its incoming value.
    u8* const page = proc_env_page;

    // EXE module base — what GetModuleHandleW(NULL) hands back.
    // u64, little-endian. Read directly by the GetModuleHandleW
    // stub; no syscall on the hot path.
    StoreLeU64(page + kProcEnvModuleBaseOff, module_base);

    // argc = 1. Stored as a little-endian u32 at offset 0.
    page[kProcEnvArgcOff + 0] = 0x01;
    page[kProcEnvArgcOff + 1] = 0x00;
    page[kProcEnvArgcOff + 2] = 0x00;
    page[kProcEnvArgcOff + 3] = 0x00;

    // argv = &proc_env_page[kProcEnvArgvArrayOff] expressed in
    // user VA. Little-endian u64 at offset 0x08.
    const u64 argv_user_va = kProcEnvVa + kProcEnvArgvArrayOff;
    StoreLeU64(page + kProcEnvArgvPtrOff, argv_user_va);

    // Copy program_name into the string area (offset 0x40). Cap
    // at kProcEnvStringBudget - 1 to guarantee NUL termination.
    // A null / empty name becomes "a.exe" — Windows convention
    // for a program with no recorded argv[0].
    const char* name = (program_name != nullptr && program_name[0] != '\0') ? program_name : "a.exe";
    u64 copied = 0;
    while (copied + 1 < kProcEnvStringBudget)
    {
        const char c = name[copied];
        if (c == '\0')
            break;
        page[kProcEnvStringOff + copied] = static_cast<u8>(c);
        ++copied;
    }
    page[kProcEnvStringOff + copied] = 0;

    // argv[0] = &proc_env_page[kProcEnvStringOff] in user VA.
    const u64 argv0_user_va = kProcEnvVa + kProcEnvStringOff;
    StoreLeU64(page + kProcEnvArgvArrayOff, argv0_user_va);
    // argv[1] = NULL — already zero, but set explicitly so the
    // contract is visible in the page dump. Any callers that
    // walk argv until NULL (Win32 CRT + most Unix main())
    // stop here.
    StoreLeU64(page + kProcEnvArgvArrayOff + 8, 0);

    // Wide + ANSI command line. Both forms hold just the
    // program name; multi-arg cmdlines arrive when a real spawn
    // API plumbs argv through. Wide form is UTF-16LE — every
    // ASCII byte becomes the same byte followed by a 0x00
    // high-half byte; that covers every name we'd plausibly
    // emit for a v0 PE.
    {
        u8* const w = page + kProcEnvCmdlineWOff;
        u8* const a = page + kProcEnvCmdlineAOff;
        for (u64 i = 0; i < copied; ++i)
        {
            // Both buffers fit comfortably (256 / 128 wide chars,
            // 128 ascii); kProcEnvStringBudget already capped
            // `copied` at 255 so neither overflows.
            w[2 * i + 0] = static_cast<u8>(name[i]);
            w[2 * i + 1] = 0;
            a[i] = static_cast<u8>(name[i]);
        }
        // Wide NUL = 2 bytes of 0; ANSI NUL = 1 byte. Both
        // already-zeroed by caller, but write explicitly for
        // page-dump readability.
        w[2 * copied + 0] = 0;
        w[2 * copied + 1] = 0;
        a[copied] = 0;
    }

    // _acmdln / _wcmdln pointer-variable slots: store the VA of the
    // command-line STRING (at 0x380 / 0x300). A PE importing _wcmdln
    // by name reads the pointer from here, then walks the string the
    // pointer addresses. (See the header note: pointing the IAT slot
    // straight at the string buffer makes the CRT deref the string's
    // first chars as an address and #PF.)
    StoreLeU64(page + kProcEnvAcmdlnPtrOff, kProcEnvVa + kProcEnvCmdlineAOff);
    StoreLeU64(page + kProcEnvWcmdlnPtrOff, kProcEnvVa + kProcEnvCmdlineWOff);

    // Empty wide environment block. An env block is a
    // contiguous run of UTF-16LE `KEY=VALUE\0` entries, plus a
    // final extra NUL terminating the list. The minimum legal
    // empty block is two zero bytes (`\0\0`). Already zeroed
    // — touch nothing.
    (void)kProcEnvEnvBlockWOff; // documented; no init needed for empty form

    // Wide-CRT (wmainCRTStartup) startup data. Wide-entry exes
    // read __wargv / _wenviron via accessors that the UCRT then
    // dereferences; each must hand back a valid, non-NULL pointer
    // chain. Mirror the narrow argv block above:
    //   __wargv (0x700)   -> wargv[] (0x720) = { &cmdlineW, NULL }
    //   _wenviron (0x710) -> wenviron[] (0x740) = { NULL }
    // The wide cmdline at 0x300 already holds the program name as
    // UTF-16LE, so wargv[0] points at it.
    const u64 wargv_array_va = kProcEnvVa + kProcEnvWargvArrayOff;
    const u64 wenviron_array_va = kProcEnvVa + kProcEnvWenvironArrayOff;
    StoreLeU64(page + kProcEnvWargvPtrOff, wargv_array_va);
    StoreLeU64(page + kProcEnvWenvironPtrOff, wenviron_array_va);
    // wargv[0] = &cmdlineW (program name), wargv[1] = NULL.
    StoreLeU64(page + kProcEnvWargvArrayOff, kProcEnvVa + kProcEnvCmdlineWOff);
    StoreLeU64(page + kProcEnvWargvArrayOff + 8, 0);
    // wenviron[0] = NULL — empty environment. Already zeroed, but
    // write explicitly so the contract is visible in a page dump.
    StoreLeU64(page + kProcEnvWenvironArrayOff, 0);
    // Empty narrow env block ("\0\0") for _get_initial_environment.
    // Already zeroed by the caller — documented; no init needed.
    (void)kProcEnvNarrowEnvBlockOff;

    // Data-miss "fake object". PE data imports whose names the
    // stub table doesn't know (e.g. std::cout) get an IAT slot
    // of `kProcEnvVa + kProcEnvDataMissOff`. Dereferenced as
    // `mov rax, [cout_iat]`, the caller reads the u64 stored
    // here — which we set to `kProcEnvVa + kProcEnvDataMissOff
    // + 8`, a pointer into the same page, 8 bytes further in,
    // where everything remains zero.
    //
    // The MSVC virtual-dispatch idiom (`mov rax, [this]; movslq
    // rcx, [rax+4]; mov rdi, [rcx+this+0x48]; test rdi, rdi;
    // jle ...`) then walks:
    //
    //   rax = [data_miss] = data_miss + 8     ; mapped
    //   rcx = [rax + 4]   = 0                 ; zero-read
    //   rdi = [this + 0x48] = 0               ; zero-read
    //   test rdi, rdi -> jle TAKEN
    //
    // The caller takes its "uninitialised / empty-stream" error
    // branch instead of faulting. Good enough for the first pass
    // past an unstubbed `std::cout` — it doesn't print, but it
    // stops crashing.
    const u64 fake_obj_va = kProcEnvVa + kProcEnvDataMissOff + 8;
    StoreLeU64(page + kProcEnvDataMissOff, fake_obj_va);
}

void Win32KuserSharedDataPopulate(u8* kusd_page)
{
    if (kusd_page == nullptr)
        return;
    u8* const page = kusd_page;

    // Uptime in ms from the scheduler tick (100 Hz -> *10 ms/tick).
    const u64 uptime_ms = duetos::time::TicksToNs(duetos::time::TickCount()) / 1'000'000ULL;

    // TickCountMultiplier: the fixed Windows constant used by the
    // GetTickCount fast path (TickCountQuad * Multiplier >> 24 == ms).
    // We store TickCountQuad directly in ms, so a multiplier of
    // (1 << 24) makes the fast-path arithmetic an identity.
    StoreLeU32(page + kKusdTickCountMultiplierOff, 1u << 24);

    // TickCountQuad — milliseconds since boot. KSYSTEM_TIME-style
    // GetTickCount64 readers take this directly.
    StoreLeU64(page + kKusdTickCountQuadOff, uptime_ms);

    // InterruptTime — 100ns units since boot (KSYSTEM_TIME: LowPart,
    // High1Time, High2Time). Both High copies equal so a torn-read
    // retry loop converges immediately.
    const u64 interrupt_100ns = uptime_ms * 10'000ULL;
    StoreLeU32(page + kKusdInterruptTimeOff + 0, static_cast<u32>(interrupt_100ns & 0xFFFFFFFFULL));
    StoreLeU32(page + kKusdInterruptTimeOff + 4, static_cast<u32>(interrupt_100ns >> 32));
    StoreLeU32(page + kKusdInterruptTimeOff + 8, static_cast<u32>(interrupt_100ns >> 32));

    // SystemTime — 100ns units since 1601-01-01 (FILETIME epoch).
    // We don't have a wall clock, so anchor at a fixed plausible date
    // (2024-01-01 00:00:00 UTC) plus uptime. 2024-01-01 in FILETIME =
    // 0x01DA43B5DC9E0000. Both High copies equal (torn-read contract).
    const u64 base_2024 = 0x01DA43B5DC9E0000ULL;
    const u64 system_100ns = base_2024 + interrupt_100ns;
    StoreLeU32(page + kKusdSystemTimeOff + 0, static_cast<u32>(system_100ns & 0xFFFFFFFFULL));
    StoreLeU32(page + kKusdSystemTimeOff + 4, static_cast<u32>(system_100ns >> 32));
    StoreLeU32(page + kKusdSystemTimeOff + 8, static_cast<u32>(system_100ns >> 32));

    // OS version winver / GetVersionEx fast-paths may read: report
    // Windows 10 (10.0) so version-gated code takes its modern path.
    StoreLeU32(page + kKusdNtMajorVersionOff, 10);
    StoreLeU32(page + kKusdNtMinorVersionOff, 0);
}

} // namespace duetos::win32
