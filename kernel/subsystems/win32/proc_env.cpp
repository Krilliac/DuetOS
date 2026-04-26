#include "subsystems/win32/proc_env.h"

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

    // Empty wide environment block. An env block is a
    // contiguous run of UTF-16LE `KEY=VALUE\0` entries, plus a
    // final extra NUL terminating the list. The minimum legal
    // empty block is two zero bytes (`\0\0`). Already zeroed
    // — touch nothing.
    (void)kProcEnvEnvBlockWOff; // documented; no init needed for empty form

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

} // namespace duetos::win32
