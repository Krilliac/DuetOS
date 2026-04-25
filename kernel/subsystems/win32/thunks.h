#pragma once

#include "../../core/types.h"

/*
 * DuetOS Win32 subsystem — IAT thunk page.
 *
 * ============================================================
 *  WHAT IS A "THUNK" HERE?
 * ============================================================
 *
 * When a Win32 PE imports `kernel32!ExitProcess`, the linker
 * emits an indirect call through an IAT slot
 * (`call qword ptr [iat+offset]`). Whatever 64-bit address sits
 * in that slot at runtime is what actually executes.
 *
 * On Windows, the loader fills each slot with the address of
 * the real exported function inside `kernel32.dll`. On DuetOS,
 * the PE loader fills each slot with the address of a small
 * piece of hand-assembled x86-64 code we call a *thunk*. The
 * thunk's job is to bridge two ABIs:
 *
 *   - Windows x64: first arg in RCX, second in RDX, third in R8,
 *     fourth in R9, rest on the stack at [rsp+0x28+]. RDI/RSI
 *     are callee-saved.
 *   - DuetOS native: syscall number in RAX, first arg in RDI,
 *     second in RSI, third in RDX, fourth in R10. Entered via
 *     `int 0x80`. RDI/RSI are scratch.
 *
 * A typical thunk is therefore very short — e.g. ExitProcess is
 * 9 bytes:
 *
 *     mov rdi, rcx        ; Windows arg0 -> DuetOS arg0
 *     xor eax, eax        ; SYS_EXIT = 0
 *     int 0x80            ; trap into the kernel
 *     ud2                 ; [[noreturn]]
 *
 * Some thunks are larger: stubbed file I/O wraps a CreateFileW
 * UTF-16 path strip into open(2)-shape arguments before issuing
 * the syscall; CreateThread saves+restores RDI/RSI around an
 * eight-arg shuffle into the SYS_THREAD_CREATE convention.
 *
 * "Thunk" is the standard Windows-loader term for this kind of
 * cross-ABI bridge code. It is *not* a stub in the placeholder
 * sense — every thunk in this file does real work. The handful
 * of genuine no-op stubs (return-zero / return-one / NOP-ret /
 * miss-logger) keep `kOffReturn*` / `kOffMissLogger` /
 * `kOffCritSecNop` names below to flag them as such.
 *
 * ============================================================
 *  WHY IS ALL THE BYTECODE IN ONE FILE? (yes, thousands of lines.)
 * ============================================================
 *
 * Three reasons, in order of importance:
 *
 *   1. *One contiguous code page.* All thunks live on a single
 *      R-X page mapped at `kWin32ThunksVa` in every Win32-imports
 *      process. The IAT slots store absolute VAs of the form
 *      `kWin32ThunksVa + offset`, so the offsets in the
 *      `kOff<Name>` constants below MUST be valid indices into
 *      one byte array. Splitting the array across translation
 *      units would mean computing offsets at link time, which
 *      kills the `constexpr` lookup table (`kThunksTable` is
 *      consteval-sorted into a hash for O(log N) lookup).
 *
 *   2. *No second user-mode build.* Hand-assembled bytes in a
 *      `constexpr u8[]` need only the host C++ compiler. A `.S`
 *      alternative would mean a second cross-compile target
 *      with its own linker script, plus extracting symbol
 *      offsets from the resulting object — for code that fits
 *      in ~5 KiB and rarely changes.
 *
 *   3. *Position-independent at runtime.* The bytes are copied
 *      verbatim into a freshly-allocated frame. There are no
 *      relocations to apply because every absolute VA the
 *      thunks reference (kWin32ThunksVa, kProcEnvVa, the
 *      thread-exit trampoline) is a kernel-controlled fixed
 *      address. Encoded once at compile time, used unchanged at
 *      every PE load.
 *
 * If you're scrolling through hundreds of `0x48, 0x89, 0xCF, ...`
 * comma-separated bytes wondering why this isn't compiled C++:
 * it is the *output* of a compiler, embedded into the kernel as
 * data. The C++ source is the assembly comments next to each
 * byte. Reading the file from top to bottom is the same as
 * reading a single linear `.text` section disassembled.
 *
 * ============================================================
 *  RESOLUTION FLOW (PE load -> live IAT)
 * ============================================================
 *
 *   PE loader walks each Import Directory entry
 *      |
 *      v
 *   `Win32ThunksLookupKind(dll, func, &va, &is_noop)`
 *      |  hit?  yes -> va = kWin32ThunksVa + kOff<Name>
 *      |        no  -> IsLikelyDataImport(func) ?
 *      |               yes -> Win32ThunksLookupDataCatchAll
 *      |                       (proc-env data-miss page)
 *      |               no  -> Win32ThunksLookupCatchAll
 *      |                       (miss-logger thunk)
 *      v
 *   IAT slot is written with `va`. Subsequent
 *   `call qword ptr [iat]` lands inside this thunk page.
 *
 * Lookup is done via a `consteval`-built sorted hash table over
 * (dll, func) keys, so each IAT entry costs ~log2(N) comparisons
 * during PE load and zero work afterwards.
 *
 * ============================================================
 *  PAGE LAYOUT
 * ============================================================
 *
 * The thunks page lives at a fixed user VA (kWin32ThunksVa =
 * 0x60000000) in every Win32-imports process — between the PE's
 * typical ImageBase (0x140000000) and the ring-3 stack
 * (0x7FFFE000). Chosen to not conflict with any ImageBase or
 * stack VA the kernel produces today.
 *
 * As of the 60-odd batches landed so far the bytes spill past 4
 * KiB, so the PE loader allocates two contiguous frames and
 * maps both R-X (see pe_loader.cpp's step-5 mapping). Companion
 * page is the per-process proc-env page at kProcEnvVa (see
 * proc_env.h) — that one is R-W + NX and holds argc/argv/cmdline
 * + a data-miss landing pad.
 */

namespace duetos::win32
{

inline constexpr u64 kWin32ThunksVa = 0x60000000ULL;

// VA of the thread-exit trampoline inside the thunks page.
// SYS_THREAD_CREATE handlers write this to [user_rsp] so a Win32
// thread proc that `ret`s off its entry point lands on the trampoline
// (which issues SYS_EXIT(retcode)) rather than #PF'ing at rip=0.
inline constexpr u64 kWin32ThreadExitTrampVa = kWin32ThunksVa + 0x8A6ULL;

/// Copy the compiled thunk bytes into `dst`. Caller supplies a
/// 2 * kPageSize buffer; we write exactly sizeof(kThunksBytes)
/// bytes starting at offset 0, leaving the rest zero. The page
/// must subsequently be mapped R-X at kWin32ThunksVa in the
/// process's address space.
void Win32ThunksPopulate(u8* dst);

/// Resolve an imported function to its thunk's user VA. Returns
/// true and writes to *out_va if the {dll, func} pair is known;
/// returns false otherwise.
///
/// DLL name match is case-insensitive (Win32 convention — the
/// linker capitalizes inconsistently, e.g. "KERNEL32.dll" vs
/// "kernel32.dll"). Function name match is case-sensitive
/// (Win32 convention).
bool Win32ThunksLookup(const char* dll, const char* func, u64* out_va);

/// As above, but also reports whether the matched thunk is a
/// "safe-ignore" stub — a thunk that returns a constant (0, 1,
/// current process handle) without doing any real work. The PE
/// loader uses this to emit a Warn-level log when an imported
/// symbol lands on such a stub, so one glance at the boot log
/// reveals which Win32 APIs a PE will silently misbehave on. The
/// same `out_va` is populated as the 3-arg form.
bool Win32ThunksLookupKind(const char* dll, const char* func, u64* out_va, bool* out_is_noop);

/// Catch-all thunk for any FUNCTION import the table doesn't know.
/// Points at the shared miss-logger thunk, so called-as-a-function
/// it returns 0 after emitting a `[win32-miss]` log line. Used for
/// imports whose names look like functions (no heuristic match for
/// the data pattern — see `IsLikelyDataImport`).
bool Win32ThunksLookupCatchAll(u64* out_va);

/// Catch-all landing pad for any DATA import the table doesn't
/// know. Returns the VA inside the proc-env page at
/// `kProcEnvVa + kProcEnvDataMissOff`. Dereferencing the resulting
/// IAT slot reads 0 (clean null), so the next-level `[ptr+offset]`
/// faults at a diagnosable cr2 rather than reading the miss-logger
/// opcode bytes as a pointer.
///
/// Used by the PE loader for imports whose mangled names match the
/// MSVC global-data pattern (`?...@@3...`). Distinct from
/// `Win32ThunksLookupCatchAll` so function imports still log through
/// the miss-logger and data imports don't.
bool Win32ThunksLookupDataCatchAll(u64* out_va);

/// Heuristic: does the mangled import name look like a DATA import
/// rather than a function import? Used by the PE loader to pick
/// between the two catch-all helpers when an import name isn't in
/// the thunk table. True for names matching MSVC's global-variable
/// mangling (`?name@...@@3<type>...`). False for everything else,
/// including plain C names and MSVC function mangling
/// (`?func@...@@QEAA...`).
bool IsLikelyDataImport(const char* func);

} // namespace duetos::win32
