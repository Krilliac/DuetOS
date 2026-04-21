#include "stubs.h"

namespace customos::win32
{

namespace
{

// ---------------------------------------------------------------
// Stub bytecode.
//
// Each entry is a handful of raw x86-64 instructions, packed
// back-to-back. The layout is:
//
//   offset 0x00:  ExitProcess stub  (9 bytes)
//
// Future entries append at the current end. IAT slots point
// at (kWin32StubsVa + entry.offset), so stable offsets matter
// only within a single boot — we regenerate + re-map the page
// per process anyway, no persistence between runs.
//
// The assembly is hand-assembled rather than emitted from a
// .S file because (a) it's trivial, (b) a .S file would be
// position-dependent and we want to drop these bytes into a
// runtime-allocated frame, (c) a .S file would mean a second
// user-mode target in the build which is a premature
// abstraction for v0.
// ---------------------------------------------------------------

constexpr u8 kStubsBytes[] = {
    // --- ExitProcess (offset 0x00) -----------------------------
    // Windows x64 ABI: first arg (uExitCode) in RCX.
    // CustomOS native ABI: syscall # in RAX, first arg in RDI,
    // SYS_EXIT = 0.
    0x48, 0x89, 0xCF, // 0x00 mov rdi, rcx      ; code
    0x31, 0xC0,       // 0x03 xor eax, eax      ; rax = 0 = SYS_EXIT
    0xCD, 0x80,       // 0x05 int 0x80
    0x0F, 0x0B,       // 0x07 ud2               ; unreachable
};

static_assert(sizeof(kStubsBytes) <= 4096, "Win32 stubs page fits in one 4 KiB page");

struct StubEntry
{
    const char* dll;
    const char* func;
    u32 offset;
};

constexpr StubEntry kStubsTable[] = {
    {"kernel32.dll", "ExitProcess", 0x00},
};

// Case-insensitive strcmp for ASCII. Win32 DLL name
// capitalisation is inconsistent (lld-link writes
// "kernel32.dll", MSVC's linker writes "KERNEL32.dll"); we
// match either.
bool AsciiCaseEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z')
            ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z')
            cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
            return false;
    }
    return *a == 0 && *b == 0;
}

bool AsciiEqual(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
        return false;
    while (*a != 0 && *b != 0)
    {
        if (*a++ != *b++)
            return false;
    }
    return *a == 0 && *b == 0;
}

} // namespace

void Win32StubsPopulate(u8* dst)
{
    if (dst == nullptr)
        return;
    for (u64 i = 0; i < sizeof(kStubsBytes); ++i)
        dst[i] = kStubsBytes[i];
}

bool Win32StubsLookup(const char* dll, const char* func, u64* out_va)
{
    if (dll == nullptr || func == nullptr || out_va == nullptr)
        return false;
    for (const StubEntry& e : kStubsTable)
    {
        if (!AsciiCaseEqual(e.dll, dll))
            continue;
        if (!AsciiEqual(e.func, func))
            continue;
        *out_va = kWin32StubsVa + e.offset;
        return true;
    }
    return false;
}

} // namespace customos::win32
