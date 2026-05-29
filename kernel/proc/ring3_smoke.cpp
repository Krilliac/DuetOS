/*
 * DuetOS — ring-3 smoke + adversarial probe suite: implementation.
 *
 * Companion to ring3_smoke.h — see there for the menu of probes
 * (jail / nx / priv / badint / kread / dropcaps / cpu-hog / ...)
 * and how the Pentest GUI driver consumes their results.
 *
 * WHAT
 *   Spawns minimal ring-3 tasks built from hand-laid x86_64
 *   bytecode (no userland toolchain in the loop). Each task
 *   exercises one specific kernel boundary: a #PF on a kernel
 *   address from ring 3, a #UD from a privileged insn, a syscall
 *   denied by the cap bitmask, a deliberate frame-budget
 *   exhaustion, etc.
 *
 *   The kernel response (clean fault, killed task, syscall
 *   returns -1, or panic) is the test signal. AttackSim and the
 *   Pentest GUI consume those signals as red-team / blue-team
 *   evidence.
 *
 * HOW
 *   `WriteUserCodeFrame` lays a few hand-assembled instructions
 *   at the start of a frame, maps it as user-RX, points the
 *   task's user RIP at it, sets up a user RW stack, and lets
 *   the scheduler take over. Each `Spawn*Probe` is the same
 *   pattern with a different bytecode payload.
 *
 *   Bytecode helpers (`WriteImm32LE`, `WriteImm64LE`) sit at
 *   the top; the per-probe spawners follow. Fixture probes for
 *   cap/budget/CPU-hog testing live in their own banners.
 *
 * WHY THIS FILE IS LARGE
 *   Each probe is ~50-150 lines (frame setup + bytecode +
 *   capability config + expected-outcome assertion). v0 has
 *   ~15 probes. The adversarial suite is the kernel's primary
 *   "did your refactor break ring-3 isolation?" check, so each
 *   probe pays its weight.
 */

#include "proc/ring3_smoke.h"

#include "proc/spawn.h"

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/usermode.h"
#include "cpu/percpu.h"
#include "debug/inspect.h"
#include "fs/ramfs.h"
#include "generated_advapi32_dll.h"
#include "generated_bcrypt_dll.h"
#include "generated_comctl32_dll.h"
#include "generated_comdlg32_dll.h"
#include "generated_crypt32_dll.h"
#include "generated_dwmapi_dll.h"
#include "generated_customdll.h"
#include "generated_customdll2.h"
#include "generated_customdll_test.h"
#include "generated_d3d11_dll.h"
#include "generated_d3d12_dll.h"
#include "generated_d3d9_dll.h"
#include "generated_d3dcompiler_dll.h"
#include "generated_dbghelp_dll.h"
#include "generated_dxgi_dll.h"
#include "generated_gdi32_dll.h"
#include "generated_advapi32_32_dll.h"
#include "generated_bcrypt_32_dll.h"
#include "generated_comctl32_32_dll.h"
#include "generated_comdlg32_32_dll.h"
#include "generated_crypt32_32_dll.h"
#include "generated_gdi32_32_dll.h"
#include "generated_iphlpapi_32_dll.h"
#include "generated_kernel32_32_dll.h"
#include "generated_kernel32_dll.h"
#include "generated_msvcrt_32_dll.h"
#include "generated_pe32_miss_pe.h"
#include "generated_pe32_rich_pe.h"
#include "generated_shell32_32_dll.h"
#include "generated_shlwapi_32_dll.h"
#include "generated_user32_32_dll.h"
#include "generated_ws2_32_32_dll.h"
#include "generated_kernelbase_dll.h"
#include "generated_msvcp140_dll.h"
#include "generated_msvcrt_dll.h"
#include "generated_ntdll_dll.h"
#include "generated_ole32_dll.h"
#include "generated_oleaut32_dll.h"
#include "generated_psapi_dll.h"
#include "generated_reg_fopen_test.h"
#include "generated_shell32_dll.h"
#include "generated_shlwapi_dll.h"
#include "generated_iphlpapi_dll.h"
#include "generated_secur32_dll.h"
#include "generated_setupapi_dll.h"
#include "generated_d2d1_dll.h"
#include "generated_ddraw_dll.h"
#include "generated_dinput8_dll.h"
#include "generated_dsound_dll.h"
#include "generated_dwrite_dll.h"
#include "generated_xaudio2_8_dll.h"
#include "generated_xinput1_4_dll.h"
#include "generated_ucrtbase_dll.h"
#include "generated_user32_dll.h"
#include "generated_userenv_dll.h"
#include "generated_uxtheme_dll.h"
#include "generated_vcruntime140_dll.h"
#include "generated_version_dll.h"
#include "generated_winhttp_dll.h"
#include "generated_wininet_dll.h"
#include "generated_winmm_dll.h"
#include "generated_ws2_32_dll.h"
#include "generated_wtsapi32_dll.h"
#include "generated_hello_pe.h"
#include "generated_hello_winapi.h"
#include "generated_windowed_hello.h"
#include "generated_syscall_stress.h"
#include "generated_thread_stress.h"
#include "generated_codepage_smoke_pe.h"
#include "generated_com_smoke_pe.h"
#include "generated_crypto_smoke_pe.h"
#include "generated_dbghelp_smoke_pe.h"
#include "generated_debug_smoke_pe.h"
#include "generated_env_smoke_pe.h"
#include "generated_fs_smoke_pe.h"
#include "generated_handle_smoke_pe.h"
#include "generated_browser_pe_pe.h"
#include "generated_tls_pe_pe.h"
#include "generated_seh_pe_pe.h"
#include "generated_cxxeh_pe.h"
#include "generated_seh_try_pe.h"
#include "generated_sync_smoke_pe.h"
#include "generated_pe32_smoke_pe.h"
#include "generated_iphlpapi_smoke_pe.h"
#include "generated_mem_smoke_pe.h"
#include "generated_minibrowser_pe.h"
#include "generated_module_smoke_pe.h"
#include "generated_paths_smoke_pe.h"
#include "generated_process_smoke_pe.h"
#include "generated_registry_smoke_pe.h"
#include "generated_rng_smoke_pe.h"
#include "generated_string_smoke_pe.h"
#include "generated_time_smoke_pe.h"
#include "generated_version_smoke_pe.h"
#include "generated_winhttp_smoke_pe.h"
#include "generated_wininet_smoke_pe.h"
#include "generated_winkill_pe.h"
#include "generated_atom_smoke_pe.h"
#include "generated_console_smoke_pe.h"
#include "generated_critsec_smoke_pe.h"
#include "generated_crt_smoke_pe.h"
#include "generated_datetime_smoke_pe.h"
#include "generated_gdi_smoke_pe.h"
#include "generated_locale_smoke_pe.h"
#include "generated_msg_smoke_pe.h"
#include "generated_ntdll_smoke_pe.h"
#include "generated_pipe_smoke_pe.h"
#include "generated_resource_smoke_pe.h"
#include "generated_shell_smoke_pe.h"
#include "generated_tls_smoke_pe.h"
#include "generated_clipboard_smoke_pe.h"
#include "generated_fiber_smoke_pe.h"
#include "generated_interlock_smoke_pe.h"
#include "generated_mathlib_smoke_pe.h"
#include "generated_profile_smoke_pe.h"
#include "generated_stdio_smoke_pe.h"
#include "generated_userenv_smoke_pe.h"
#include "generated_windowclass_smoke_pe.h"
#include "generated_wow64_smoke_pe.h"
#include "generated_eventlog_smoke_pe.h"
#include "generated_heap_smoke_pe.h"
#include "generated_multimon_smoke_pe.h"
#include "generated_nls_smoke_pe.h"
#include "generated_power_smoke_pe.h"
#include "generated_services_smoke_pe.h"
#include "generated_sound_smoke_pe.h"
#include "generated_thread2_smoke_pe.h"
#include "generated_console2_smoke_pe.h"
#include "generated_dns_smoke_pe.h"
#include "generated_dwm_smoke_pe.h"
#include "generated_dxgi_smoke_pe.h"
#include "generated_ipc_smoke_pe.h"
#include "generated_jobobj_smoke_pe.h"
#include "generated_network2_smoke_pe.h"
#include "generated_uxtheme_smoke_pe.h"
#include "generated_accel_smoke_pe.h"
#include "generated_nt_smoke_pe.h"
#include "generated_perf_smoke_pe.h"
#include "generated_security_smoke_pe.h"
#include "generated_sleep_smoke_pe.h"
#include "generated_token_smoke_pe.h"
#include "generated_winerr_smoke_pe.h"
#include "generated_wts_smoke_pe.h"
#include "generated_conio_smoke_pe.h"
#include "generated_dde_smoke_pe.h"
#include "generated_drive_smoke_pe.h"
#include "generated_fpcontrol_smoke_pe.h"
#include "generated_gdiplus_smoke_pe.h"
#include "generated_locale2_smoke_pe.h"
#include "generated_mbcs_smoke_pe.h"
#include "generated_vol_smoke_pe.h"
#include "generated_asyn_smoke_pe.h"
#include "generated_enviro_smoke_pe.h"
#include "generated_scrap_smoke_pe.h"
#include "generated_setupapi_smoke_pe.h"
#include "generated_stream_smoke_pe.h"
#include "generated_trace_smoke_pe.h"
#include "generated_wmi_smoke_pe.h"
#include "generated_wndmsg_smoke_pe.h"
#include "generated_find_smoke_pe.h"
#include "generated_iocp2_smoke_pe.h"
#include "generated_proc2_smoke_pe.h"
#include "generated_select_smoke_pe.h"
#include "generated_signal_smoke_pe.h"
#include "generated_timer_smoke_pe.h"
#include "generated_pe_stress_pe.h"
#include "generated_net_loopback_smoke_pe.h"
#include "generated_winsock_ext_smoke_pe.h"
#include "generated_advapi_smoke_pe.h"
#include "generated_heap3_smoke_pe.h"
#include "generated_key_smoke_pe.h"
#include "generated_paths2_smoke_pe.h"
#include "generated_reg2_smoke_pe.h"
#include "generated_thread3_smoke_pe.h"
#include "generated_console3_smoke_pe.h"
#include "generated_disp_smoke_pe.h"
#include "generated_fs2_smoke_pe.h"
#include "generated_intl_smoke_pe.h"
#include "generated_mem2_smoke_pe.h"
#include "generated_svc_ctrl_smoke_pe.h"
#include "generated_sysinfo_smoke_pe.h"
#include "generated_wstr_smoke_pe.h"
#include "generated_advmem_smoke_pe.h"
#include "generated_com2_smoke_pe.h"
#include "generated_fs3_smoke_pe.h"
#include "generated_proc3_smoke_pe.h"
#include "generated_reg3_smoke_pe.h"
#include "generated_wstr2_smoke_pe.h"
#include "generated_xml_smoke_pe.h"
#include "generated_cap_smoke_pe.h"
#include "generated_debug2_smoke_pe.h"
#include "generated_handle2_smoke_pe.h"
#include "generated_prio_smoke_pe.h"
#include "generated_sock_opt_smoke_pe.h"
#include "generated_utf16_smoke_pe.h"
#include "generated_d2d1_smoke_pe.h"
#include "generated_d3d11_smoke_pe.h"
#include "generated_d3d12_smoke_pe.h"
#include "generated_d3d9_smoke_pe.h"
#include "generated_ddraw_smoke_pe.h"
#include "generated_dinput8_smoke_pe.h"
#include "generated_dsound_smoke_pe.h"
#include "generated_dwrite_smoke_pe.h"
#include "generated_dx_demo_pe.h"
#include "generated_dx_demo_window_pe.h"
#include "generated_xaudio2_smoke_pe.h"
#include "generated_xinput_smoke_pe.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/win32/heap.h"
#include "loader/compat_shim.h"
#include "loader/dll_loader.h"
#include "loader/elf_loader.h"
#include "log/klog.h"
#include "util/random.h"
#include "util/string.h"
#include "core/panic.h"
#include "loader/pe_loader.h"
#include "diag/log_names.h"
#include "proc/process.h"
#include "test/smoke_profile.h"

/*
 * Ring-3 smoke test, second iteration.
 *
 * The first version mapped its user code + stack pages into the ONE
 * global PML4 and registered them with the scheduler's per-task region
 * table for reaper-driven cleanup. Per-process address spaces have now
 * landed: this version creates a fresh `mm::AddressSpace` per task,
 * populates it with the same user code + stack mappings, and hands it
 * to `SchedCreateUser` so the scheduler flips CR3 to the AS on the
 * task's first switch-in.
 *
 * The chosen user VAs (0x40000000 for code, 0x40010000 for stack)
 * are now PER-PROCESS — every smoke task can use the same fixed VAs
 * without colliding, because each task has its own PML4. That's the
 * isolation property we wanted: spawn two smoke tasks back-to-back,
 * both succeed, both print "Hello from ring 3!\n" with their own
 * private code/stack frames behind those VAs.
 *
 * If isolation were broken (one shared PML4), the SECOND
 * `MapUserPage(virt=0x40000000, ...)` call would panic on the
 * "virt already mapped" assertion — which is exactly the assertion
 * we used to demonstrate isolation works while writing this slice.
 */

namespace duetos::core
{

namespace
{

// ASLR: per-process randomised base for the user code page. The
// stack sits 64 KiB above, and both fit in 32 bits (so the
// payload's imm32 fields can still encode absolute VAs).
//
// Range: [0x01000000, 0xEF000000), 16 MiB-aligned — 238 candidate
// bases, ~7.9 bits of entropy. Small, but each sandboxed process
// has its own layout and an attacker observing one process's
// layout learns nothing about a sibling's. The range is deliberately
// kept below 4 GiB so we don't need REX.W-imm64 forms in the
// payload — everything encodes as `mov r32, imm32` (which zero-
// extends to r64 for free on x86-64).
//
// The boot.S direct map at PDPT[0] covers [0, 1 GiB) as 2 MiB PS
// pages — we must NOT try to install 4 KiB user pages inside that
// range (MapPage panics on PS regions). So the lower bound is
// 0x40000000 in practice — but the AddressSpaceMapUserPage walker
// is on a per-process PML4 whose PDPT[0] is empty (we zero the
// user half at create), so the walker happily creates a fresh
// PD + PT and the 2 MiB-PS panic doesn't apply. Starting at
// 0x01000000 is safe.
constexpr u64 kAslrMinBase = 0x0000000001000000ULL;
constexpr u64 kAslrMaxBase = 0x00000000EF000000ULL;
constexpr u64 kAslrAlign = 0x0000000001000000ULL; // 16 MiB
constexpr u64 kStackOffsetFromCode = 0x10000;

// Offsets WITHIN the 4 KiB code page for string constants. Identical
// layout across processes — only the PAGE base is randomised.
constexpr u64 kMsgOffsetInCode = 0x80;
constexpr u64 kPath1OffsetInCode = 0xA0;
constexpr u64 kPath2OffsetInCode = 0xB0;

// Offsets WITHIN the 4 KiB stack page for scratch buffers.
constexpr u64 kReadBufOffsetInStack = 0x800;
constexpr u64 kStatOutOffsetInStack = 0xFF0;

// Pick a fresh 16 MiB-aligned base in [kAslrMinBase, kAslrMaxBase).
// Draws from the shared kernel entropy pool (RDSEED → RDRAND →
// splitmix) rather than the old per-file TSC-seeded splitmix —
// all consumers now share a single entropy source with
// observable stats via `rand -s`.
u64 AslrPickBase()
{
    const u64 range = (kAslrMaxBase - kAslrMinBase) / kAslrAlign;
    const u64 r = duetos::core::RandomU64() % range;
    return kAslrMinBase + r * kAslrAlign;
}

// Fixed offsets of string constants inside the user code page.
// Every offset below is encoded as a 32-bit immediate in the
// machine code — changing any of them here requires updating the
// matching byte in kUserCodeBytes too. The static_assert at the
// bottom bounds the instruction region so a new instruction byte
// can't silently overrun the first string.
constexpr u64 kUserMessageOffset = 0x80;   // "Hello from ring 3!\n"
constexpr u64 kUserStatPath1Offset = 0xA0; // "/etc/version"
constexpr u64 kUserStatPath2Offset = 0xB0; // "/welcome.txt"

constexpr char kUserMessage[] = "Hello from ring 3!\n";
constexpr char kUserStatPath1[] = "/etc/version";
constexpr char kUserStatPath2[] = "/welcome.txt";
constexpr u64 kUserMessageLen = sizeof(kUserMessage) - 1;

// Stack-page layout (offsets kReadBufOffsetInStack and
// kStatOutOffsetInStack above) is fixed across processes; only
// the stack page's BASE VA is randomised per process. SYS_STAT's
// output slot lives near the top of the stack, the SYS_READ
// destination buffer lives mid-page, and both are patched into
// the payload as absolute (stack_va + offset) values at spawn.

// User code. Order:
//   pause, pause,
//   SYS_STAT("/etc/version",  &stat_out),
//   SYS_STAT("/welcome.txt",  &stat_out),
//   SYS_READ("/etc/version",  read_buf, 128),
//     rax <- bytes_read (or -1)
//     rdx <- rax        (preserve length for the write that follows)
//   SYS_WRITE(1, read_buf, rdx),                  ; echoes the file
//   SYS_WRITE(1, "Hello from ring 3!\n", 19),     ; existing banner
//   SYS_YIELD,
//   SYS_EXIT(0), hlt.
//
// Same bytes in every task. Trusted pid gets:
//   - stat ok /etc/version (size=0x1b)
//   - stat miss /welcome.txt
//   - read ok /etc/version (bytes=0x1b) → /etc/version content echoed
//   - write "Hello from ring 3!"
// Sandbox pid gets:
//   - stat miss /etc/version        <- namespace jail
//   - stat ok /welcome.txt (size=0x30)
//   - read miss /etc/version        <- jail again, on the read path
//   - SYS_WRITE denied by cap check (sandbox lacks kCapSerialConsole)
//
// For the sandbox, after the failed read rax=-1 and the follow-up
// mov rdx, rax puts 0xFFFF_FFFF_FFFF_FFFF in rdx. The subsequent
// SYS_WRITE never touches that length because the cap check fires
// first and returns -1 — so even an invalid length is harmless.
// clang-format off
constexpr u8 kUserCodeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xF3, 0x90,                                                   // pause

    // SYS_STAT /etc/version
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // mov eax, 4    (SYS_STAT)
    0xBF, 0xA0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000A0 (path1)
    0xBE, 0xF0, 0x0F, 0x01, 0x40,                                 // mov esi, 0x40010FF0 (stat_out)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_STAT /welcome.txt
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // mov eax, 4    (SYS_STAT)
    0xBF, 0xB0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000B0 (path2)
    0xBE, 0xF0, 0x0F, 0x01, 0x40,                                 // mov esi, 0x40010FF0 (stat_out)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_READ /etc/version into read_buf (rax <- bytes_read or -1)
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // mov eax, 5    (SYS_READ)
    0xBF, 0xA0, 0x00, 0x00, 0x40,                                 // mov edi, 0x400000A0 (path1)
    0xBE, 0x00, 0x08, 0x01, 0x40,                                 // mov esi, 0x40010800 (read_buf)
    0xBA, 0x80, 0x00, 0x00, 0x00,                                 // mov edx, 128  (cap)
    0xCD, 0x80,                                                   // int 0x80

    // Preserve read length for the write below.
    0x48, 0x89, 0xC2,                                             // mov rdx, rax

    // SYS_WRITE(1, read_buf, rdx)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x00, 0x08, 0x01, 0x40,                                 // mov esi, 0x40010800 (read_buf)
    0xCD, 0x80,                                                   // int 0x80

    // SYS_WRITE(1, msg, kUserMessageLen)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x80, 0x00, 0x00, 0x40,                                 // mov esi, 0x40000080 (msg)
    0xBA, static_cast<u8>(kUserMessageLen), 0x00, 0x00, 0x00,     // mov edx, len
    0xCD, 0x80,                                                   // int 0x80

    // SYS_YIELD
    0xB8, 0x03, 0x00, 0x00, 0x00,                                 // mov eax, 3
    0xCD, 0x80,                                                   // int 0x80

    // SYS_EXIT(0)
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0xF4,                                                         // hlt (unreachable)
};
// clang-format on
static_assert(sizeof(kUserCodeBytes) <= kUserMessageOffset, "user code runs into the first string region");
static_assert(kUserMessageOffset + sizeof(kUserMessage) <= kUserStatPath1Offset, "msg overruns stat-path-1 region");
static_assert(kUserStatPath1Offset + sizeof(kUserStatPath1) <= kUserStatPath2Offset,
              "stat-path-1 overruns stat-path-2 region");

// ASLR patch table for the common smoke-task payload. Each entry says
// "at this offset inside the copy of kUserCodeBytes, overwrite the
// 4-byte imm32 with the absolute VA of (either code_base + off_in_code
// OR stack_base + off_in_stack)."
//
// The offsets below are derived from hand-tracing the payload byte
// sequence — see the comment above kUserCodeBytes for the instruction
// ordering. If the payload is ever re-ordered or extended, these
// offsets MUST be re-derived; the static_assert on the payload size
// gives a canary but doesn't protect against reshuffles. Keep them
// in lockstep.
enum class PatchBase : u8
{
    kCode,
    kStack,
};
struct PayloadPatch
{
    u16 bytecode_offset;
    u16 base_offset; // offset within the target page
    PatchBase base;
};

// NOTE: offsets point at the START of each imm32 field (the byte
// AFTER the mov opcode byte). e.g. the "BF A0 00 00 40" at bytecode
// offset 0x09 has imm32 starting at 0x0A.
constexpr PayloadPatch kPayloadPatches[] = {
    {0x0A, kPath1OffsetInCode, PatchBase::kCode},     // SYS_STAT #1: path1
    {0x0F, kStatOutOffsetInStack, PatchBase::kStack}, // SYS_STAT #1: statout
    {0x1B, kPath2OffsetInCode, PatchBase::kCode},     // SYS_STAT #2: path2
    {0x20, kStatOutOffsetInStack, PatchBase::kStack}, // SYS_STAT #2: statout
    {0x2C, kPath1OffsetInCode, PatchBase::kCode},     // SYS_READ: path1
    {0x31, kReadBufOffsetInStack, PatchBase::kStack}, // SYS_READ: readbuf
    {0x4A, kReadBufOffsetInStack, PatchBase::kStack}, // SYS_WRITE (dyn): readbuf
    {0x5B, kMsgOffsetInCode, PatchBase::kCode},       // SYS_WRITE (banner): msg
};

// Write a little-endian u32 into `buf` at byte offset `off`. Asserts
// the 4 bytes fit. Used by all payload patchers.
void WriteImm32LE(u8* buf, u64 off, u32 value)
{
    buf[off + 0] = static_cast<u8>(value & 0xFF);
    buf[off + 1] = static_cast<u8>((value >> 8) & 0xFF);
    buf[off + 2] = static_cast<u8>((value >> 16) & 0xFF);
    buf[off + 3] = static_cast<u8>((value >> 24) & 0xFF);
}

void WriteImm64LE(u8* buf, u64 off, u64 value)
{
    WriteImm32LE(buf, off, static_cast<u32>(value));
    WriteImm32LE(buf, off + 4, static_cast<u32>(value >> 32));
}

// Populate `frame` with the user-code-page contents via the kernel
// direct-map alias. Reaches the frame from the parent task's view —
// the AS this frame is going into doesn't have to be active.
// Patches every ASLR-affected imm32 so absolute VAs in the payload
// match the caller's randomly-chosen code_va / stack_va.
void WriteUserCodeFrame(mm::PhysAddr frame, u64 code_va, u64 stack_va)
{
    auto* code_direct = static_cast<u8*>(mm::PhysToVirt(frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kUserCodeBytes); ++i)
    {
        code_direct[i] = kUserCodeBytes[i];
    }
    for (u64 i = 0; i < kUserMessageLen; ++i)
    {
        code_direct[kUserMessageOffset + i] = static_cast<u8>(kUserMessage[i]);
    }
    for (u64 i = 0; i < sizeof(kUserStatPath1); ++i)
    {
        code_direct[kUserStatPath1Offset + i] = static_cast<u8>(kUserStatPath1[i]);
    }
    for (u64 i = 0; i < sizeof(kUserStatPath2); ++i)
    {
        code_direct[kUserStatPath2Offset + i] = static_cast<u8>(kUserStatPath2[i]);
    }

    // Apply ASLR patches. Each entry rewrites one imm32 field in
    // the payload so its absolute-VA reference targets the right
    // page at this process's chosen layout.
    for (const auto& p : kPayloadPatches)
    {
        const u64 base = (p.base == PatchBase::kCode) ? code_va : stack_va;
        const u64 target = base + p.base_offset;
        KASSERT(target <= 0xFFFFFFFFULL, "core/ring3", "ASLR target overflows imm32");
        WriteImm32LE(code_direct, p.bytecode_offset, static_cast<u32>(target));
    }
}

// Build a ring-3 task: allocate AS, allocate + populate code page,
// allocate stack page, install both into the AS, wrap the AS in a
// Process with the caller-supplied cap set, hand the Process to a
// new task. The reaper's ProcessRelease tears everything down at
// task death.
void SpawnRing3Task(const char* name, CapSet caps, const fs::RamfsNode* root, u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(frame_budget);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AddressSpaceCreate failed");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user code frame");
    }
    WriteUserCodeFrame(code_frame, code_va, stack_va);

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "failed to allocate user stack frame");
    }

    // Code: present + user, RX (no W, no NX). Stack: present + user
    // + writable + NX. Same flags as the pre-AS version — what's
    // different is they go into THIS AS's PML4 only, not the boot
    // PML4 or any sibling AS, AND their VAs are randomised per
    // process via ASLR.
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate(name, as, caps, root, code_va, stack_va, tick_budget);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed");
    }

    {
        // Atomic line: acquire serial lock for the whole multi-call
        // chain so another task printing concurrently can't split
        // the line at a SerialWrite boundary. The qemu-smoke ring3
        // profile asserts on the substring `queued task name="ring3-
        // smoke-B"` — which is corrupted on CI without this guard
        // when ring3-smoke-A is already running and printing.
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued task name=\"");
        SerialWrite(name);
        SerialWrite("\" pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" caps=");
        SerialWriteHex(proc->caps.bits);
        SerialWrite("(");
        duetos::core::SerialWriteCapBits(proc->caps.bits);
        SerialWrite(") code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" stack_va=");
        SerialWriteHex(stack_va);
        SerialWrite("\n");
    }

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
}

// Deprivilege demo: a trusted task that voluntarily drops its caps
// mid-flight via SYS_DROPCAPS, then attempts SYS_WRITE again.
// Demonstrates that caps can be irreversibly revoked — the
// canonical NO_NEW_PRIVS pattern.
//
// Payload layout:
//   offset 0x00: pause
//   offset 0x02: SYS_WRITE("pre-drop\n")   ; succeeds (trusted caps)
//   offset 0x18: SYS_DROPCAPS(0xFFFFFFFF)  ; drop every bit
//   offset 0x24: SYS_WRITE("post-drop!\n") ; denied by cap check
//   offset 0x3A: SYS_YIELD
//   offset 0x41: SYS_EXIT
//
// Strings:
//   offset 0x80: "pre-drop\n"      (9 bytes)
//   offset 0xA0: "post-drop!\n"    (11 bytes)
//
// clang-format off
constexpr char kDropcapsPreMsg[] = "[dropcaps-demo] pre-drop\n";
constexpr char kDropcapsPostMsg[] = "[dropcaps-demo] post-drop (should never print!)\n";
constexpr u64 kDropcapsPreOffset = 0x80;
constexpr u64 kDropcapsPostOffset = 0xC0;

constexpr u8 kDropcapsProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    // SYS_WRITE pre-drop
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x80, 0x00, 0x00, 0x40,                                 // mov esi, code_va + 0x80 (PATCHED)
    0xBA, static_cast<u8>(sizeof(kDropcapsPreMsg) - 1), 0x00, 0x00, 0x00,  // mov edx, len
    0xCD, 0x80,                                                   // int 0x80
    // SYS_DROPCAPS all caps
    0xB8, 0x06, 0x00, 0x00, 0x00,                                 // mov eax, 6 (SYS_DROPCAPS)
    0xBF, 0xFF, 0xFF, 0xFF, 0xFF,                                 // mov edi, 0xFFFFFFFF (drop everything)
    0xCD, 0x80,                                                   // int 0x80
    // SYS_WRITE post-drop (will be denied)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0xC0, 0x00, 0x00, 0x40,                                 // mov esi, code_va + 0xC0 (PATCHED)
    0xBA, static_cast<u8>(sizeof(kDropcapsPostMsg) - 1), 0x00, 0x00, 0x00,  // mov edx, len
    0xCD, 0x80,                                                   // int 0x80
    // SYS_YIELD
    0xB8, 0x03, 0x00, 0x00, 0x00,                                 // mov eax, 3
    0xCD, 0x80,                                                   // int 0x80
    // SYS_EXIT
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0xF4,                                                         // hlt
};
// clang-format on

// Offsets of imm32 fields that embed absolute user VAs. Patched
// at spawn against the ASLR-chosen code_va.
struct DropcapsPatch
{
    u16 bytecode_offset;
    u16 code_offset;
};
// imm32 sits at byte offset 13 of the SYS_WRITE #1 block
// (F3 90 pause, then B8 02 00 00 00, BF 01 00 00 00, BE <imm32>).
// SYS_WRITE #2 starts at offset 36 (after SYS_WRITE #1 ends at 24
// and SYS_DROPCAPS takes 12 more bytes), imm32 at 36+11 = 47.
constexpr DropcapsPatch kDropcapsPatches[] = {
    {0x0D, kDropcapsPreOffset},  // SYS_WRITE #1 msg ptr
    {0x2F, kDropcapsPostOffset}, // SYS_WRITE #2 msg ptr
};

void SpawnDropcapsProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "dropcaps code_va overflow");

    auto as_r = AddressSpaceCreate(kFrameBudgetTrusted);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for dropcaps probe");
    }
    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for dropcaps probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    // Zero-on-alloc means the page is already zeroed.
    for (u64 i = 0; i < sizeof(kDropcapsProbeBytes); ++i)
    {
        code_direct[i] = kDropcapsProbeBytes[i];
    }
    // Strings at their fixed offsets (include trailing NUL explicitly
    // though it's not read by SYS_WRITE — keeps the layout self-
    // documenting).
    for (u64 i = 0; i < sizeof(kDropcapsPreMsg); ++i)
    {
        code_direct[kDropcapsPreOffset + i] = static_cast<u8>(kDropcapsPreMsg[i]);
    }
    for (u64 i = 0; i < sizeof(kDropcapsPostMsg); ++i)
    {
        code_direct[kDropcapsPostOffset + i] = static_cast<u8>(kDropcapsPostMsg[i]);
    }
    // ASLR patches.
    for (const auto& p : kDropcapsPatches)
    {
        const u64 target = code_va + p.code_offset;
        WriteImm32LE(code_direct, p.bytecode_offset, static_cast<u32>(target));
    }

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for dropcaps probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Starts with FULL trusted caps — the point is to show
    // that a trusted task can voluntarily deprivilege.
    Process* proc = ProcessCreate("ring3-dropcaps-demo", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for dropcaps probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued dropcaps-demo pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite("\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-dropcaps-demo", proc);
}

// Dedicated hostile-syscall-spam payload: spins calling SYS_WRITE(fd=1)
// forever. Each iteration fails the kCapSerialConsole cap check and
// bumps the Process's sandbox_denials counter. Once the counter hits
// kSandboxDenialKillThreshold (100 denials ≈ a hundred iterations),
// the cap-check code calls FlagCurrentForKill() and the scheduler
// terminates the task at next resched.
//
// This is the "a malicious EXE retrying a blocked syscall" threat
// model in action. The existing ring3-smoke-sandbox only hits 2
// denials (well under threshold), so it's not a hostile probe
// per-se — just a compliance check. This task is explicitly hostile.
//
// Payload (16 bytes):
//   offset 0x00: pause
//   offset 0x02 loop: mov eax, 2            ; SYS_WRITE (5 bytes)
//   offset 0x07: mov edi, 1                 ; fd=1 (5 bytes)
//                                             — otherwise fd-check short-
//                                             circuits before the cap
//                                             check and we never bump
//                                             the denial counter.
//   offset 0x0C: int 0x80                   ; denied by cap check (2 b)
//   offset 0x0E: jmp loop                   ; rel8 = -14 (2 bytes)
//                                             — targets offset 2, skipping
//                                             the one-off `pause` prefix.
//
// Next_rip after the jmp = 0x10. disp = target(0x02) - next_rip(0x10)
// = -14 = 0xF2 (signed int8).
//
// clang-format off
constexpr u8 kHostileProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2    (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xCD, 0x80,                                                   // int 0x80
    0xEB, 0xF2,                                                   // jmp -14 (back to mov eax, 2)
};
// clang-format on

void SpawnHostileProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for hostile probe");
    }
    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for hostile probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kHostileProbeBytes); ++i)
    {
        code_direct[i] = kHostileProbeBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for hostile probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty caps — SYS_WRITE is the target, so we want the cap
    // check to reject. Tight tick budget too; denial counter
    // should fire LONG before the tick budget does (100 syscalls
    // in ring 3 is microseconds), but a generous floor protects
    // against a weird schedule.
    Process* proc = ProcessCreate("ring3-hostile-syscall", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for hostile probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued hostile-syscall probe pid=");
        SerialWriteHex(proc->pid);
        SerialWrite("\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-hostile-syscall", proc);
}

// Cross-PID VM-write probe. A sandbox process without kCapDebug
// spams `SYS_PROCESS_OPEN(pid=1)` — the entry point a malicious
// PE would use to grab a handle to another process before
// dropping into NtWriteVirtualMemory / NtSuspendThread /
// NtSetContextThread (the classic "thread hijack" sequence).
// Each call hits the kCapDebug gate, returns 0 (no handle),
// bumps `sandbox_denials`, and after kSandboxDenialKillThreshold
// the task is reaped via `KillReason::SandboxDenialThreshold`.
//
// What this proves: a ring-3 attacker that doesn't already have
// kCapDebug cannot OPEN another process — and without an open
// handle, every downstream cross-process syscall (VM_WRITE,
// THREAD_SUSPEND, THREAD_SET_CONTEXT) is unreachable. Closes
// the redteam matrix gap on cross-process tampering.
//
// Payload (16 bytes):
//   offset 0x00: pause                                    (2 bytes)
//   offset 0x02: mov eax, 131  (SYS_PROCESS_OPEN = 0x83)  (5 bytes)
//   offset 0x07: mov edi, 1    (target pid = 1)           (5 bytes)
//   offset 0x0C: int 0x80      (denied by kCapDebug gate) (2 bytes)
//   offset 0x0E: jmp -14       (back to mov eax)          (2 bytes)
//
// next_rip after jmp = 0x10. disp = target(0x02) - 0x10 = -14 = 0xF2.
//
// clang-format off
constexpr u8 kCrossPidProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xB8, 0x83, 0x00, 0x00, 0x00,                                 // mov eax, 131 (SYS_PROCESS_OPEN)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1   (target pid)
    0xCD, 0x80,                                                   // int 0x80
    0xEB, 0xF2,                                                   // jmp -14
};
// clang-format on

void SpawnCrossPidProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for cross-pid probe");
    }
    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for cross-pid probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kCrossPidProbeBytes); ++i)
    {
        code_direct[i] = kCrossPidProbeBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for cross-pid probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty caps — kCapDebug is the gate we're testing. Without
    // it SYS_PROCESS_OPEN returns 0; after 100 such denials the
    // sandbox-denial threshold kills the task. PASS criterion:
    // [sandbox] pid=N hit 0x64 denials (last cap=Debug) — no
    // foreign-process handle was ever returned.
    Process* proc = ProcessCreate("ring3-cross-pid-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for cross-pid probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued cross-pid probe pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" (SYS_PROCESS_OPEN flood, expect kCapDebug denials)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-cross-pid-probe", proc);
}

// Dedicated CPU-hog payload: spins in a tight `jmp $` loop so the
// scheduler's tick-budget check eventually triggers. A sandbox with
// a 50-tick budget reaches [sched] tick budget exhausted after
// roughly 500 ms of CPU time (100 Hz timer). Demonstrates the
// resource-quota layer of the sandbox: even if a malicious EXE
// gives up on probing the kernel and just burns CPU forever, the
// scheduler kills it.
//
// clang-format off
constexpr u8 kCpuHogBytes[] = {
    0xEB, 0xFE, // jmp $ (infinite loop)
};
// clang-format on

// Tight per-process budget so the test completes quickly under QEMU.
constexpr u64 kTickBudgetHog = 50;

void SpawnCpuHogProbe()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for cpu-hog probe");
    }
    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for cpu-hog");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kCpuHogBytes); ++i)
    {
        code_direct[i] = kCpuHogBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for cpu-hog");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);
    Process* proc =
        ProcessCreate("ring3-cpu-hog", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va, kTickBudgetHog);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for cpu-hog");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued cpu-hog task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" tick_budget=");
        SerialWriteHex(kTickBudgetHog);
        SerialWrite("\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-cpu-hog", proc);
}

// Dedicated syscall-storm payload: spins calling SYS_GETPID(=1) in a
// tight `int 0x80` loop. SYS_GETPID always succeeds (no caps, no args,
// returns the current task's pid), so unlike the hostile probe this
// is NOT a denial test — every iteration completes the user→kernel→
// user round trip. Tests the syscall-entry path under sustained load:
//   - SYSCALL/SYSRET MSR state holds across millions of entries
//   - per-CPU TSS / kernel-stack switch survives back-to-back transitions
//   - scheduler tick budget eventually fires (~50 ticks ≈ 500 ms at
//     100 Hz) before any kernel resource leaks visibly
//
// Distinct from `hog` (pure user-mode `jmp $`, never enters kernel) and
// from `hostile` (denied syscall path, killed by sandbox-denials
// counter at iteration ~100). Pass criterion: scheduler tick budget
// kills the task; kernel stays healthy and reaper recovers all frames.
//
// Payload (10 bytes):
//   offset 0x00: pause                          (F3 90)
//   offset 0x02 loop: mov eax, 1                (B8 01 00 00 00) — SYS_GETPID
//   offset 0x07: int 0x80                       (CD 80)
//   offset 0x09: jmp loop                       (EB F7) — rel8 = -9
//
// Next_rip after jmp = 0x0B. disp = 0x02 - 0x0B = -9 = 0xF7.
//
// clang-format off
constexpr u8 kSyscallStormBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xB8, 0x01, 0x00, 0x00, 0x00,                                 // mov eax, 1 (SYS_GETPID)
    0xCD, 0x80,                                                   // int 0x80
    0xEB, 0xF7,                                                   // jmp -9 (back to mov eax)
};
// clang-format on

void SpawnSyscallStormProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for syscall-storm probe");
    }
    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for syscall-storm");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kSyscallStormBytes); ++i)
    {
        code_direct[i] = kSyscallStormBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for syscall-storm");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty caps — SYS_GETPID isn't cap-gated, so this still loops
    // happily. Tight tick budget so the test completes quickly:
    // 50 ticks ≈ 500 ms of scheduled CPU at 100 Hz, more than
    // enough to verify the syscall path stays healthy under
    // back-to-back entries.
    Process* proc = ProcessCreate("ring3-syscall-storm", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for syscall-storm");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued syscall-storm probe pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" (expect tick-budget kill after sustained int 0x80)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-syscall-storm", proc);
}

// Dedicated NX-probe payload: jumps into its own NX stack page at
// 0x40010000. The stack is mapped with kPageNoExecute; instruction
// fetch from there triggers #PF with the "instruction fetch" bit
// (err_code bit 4) set. The kernel's ring-3 trap path turns the
// fault into a [task-kill] and reschedules. This is the DEP /
// NX-exec enforcement proof: we can directly observe "the CPU
// refused to execute bytes on a writable page." Without EFER.NXE
// being honored or without kPageNoExecute on the stack, the jump
// would succeed and the CPU would start executing random stack
// bytes.
//
// clang-format off
constexpr u8 kNxProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    // mov rax, 0x40010000
    0x48, 0xB8, 0x00, 0x00, 0x01, 0x40, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xE0,                                                   // jmp rax
    0x0F, 0x0B,                                                   // ud2 (belt-and-braces)
};
// clang-format on

void SpawnNxProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for nx probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for nx probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kNxProbeBytes); ++i)
    {
        code_direct[i] = kNxProbeBytes[i];
    }
    // Patch the "mov rax, 0x40010000" imm64 to match this process's
    // randomised stack VA. Without the patch, the `jmp rax` would
    // land at 0x40010000 — possibly unmapped in this AS (if ASLR
    // chose a different base), producing a not-present #PF rather
    // than the NX #PF we're trying to demonstrate. Imm64 sits 2
    // bytes into the payload (after `pause` + `48 B8` opcode).
    WriteImm64LE(code_direct, 4, stack_va);

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for nx probe");
    }

    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-nx-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for nx probe");
    }

    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued nx-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" stack_va=");
        SerialWriteHex(stack_va);
        SerialWrite("\n");
    }

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-nx-probe", proc);
}

// Dedicated jail-probe payload: immediately attempts to write into
// its own R-X code page at 0x40000000. The code page is mapped
// kPagePresent | kPageUser — no kPageWritable — so the store #PFs.
// The kernel's ring-3 exception path logs [task-kill] and calls
// SchedExit, terminating the task cleanly. The ud2 at the tail is
// belt-and-braces — if, impossibly, the write succeeded, ud2 raises
// #UD and the task still dies.
//
// clang-format off
// mov rax, <imm64 patched to code_va>   ; 48 B8 <8 bytes>
// mov dword ptr [rax], 0xDEADBEEF       ; C7 00 EF BE AD DE
// ud2                                   ; 0F 0B
//
// Uses rax as an unsigned 64-bit base so the store address is
// whatever code_va the ASLR picker chose, with no sign-extension
// gotcha (which `mov [disp32], imm32` has — disp32 is signed
// and anything ≥ 0x80000000 sign-extends into the kernel half).
// That guarantees the fault is "write to a RX page" — #PF
// err=0x7 (P + W + U) — rather than "wild pointer to unmapped
// kernel VA," regardless of which 16 MiB-aligned base ASLR
// picked.
constexpr u8 kJailProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                           // mov rax, <imm64 patched>
    0xC7, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,                           // mov dword ptr [rax], 0xDEADBEEF
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnJailProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "jail-probe code_va overflows imm32");

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for jail probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for jail probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kJailProbeBytes); ++i)
    {
        code_direct[i] = kJailProbeBytes[i];
    }
    // Patch the imm64 inside `mov rax, <imm64>`. imm64 starts at
    // byte offset 4:
    //   offset 0: pause F3 90
    //   offset 2: 48 B8 <imm64>  (REX.W mov rax, imm64)
    // imm64 begins at offset 4.
    WriteImm64LE(code_direct, 4, code_va);

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for jail probe");
    }

    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Empty cap set — the jail probe never gets a chance to issue
    // a syscall (it faults first), but if the fault path ever
    // regressed and the task reached int 0x80, denying caps
    // defence-in-depths that path too.
    Process* proc = ProcessCreate("ring3-jail-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for jail probe");
    }

    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued jail-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" stack_va=");
        SerialWriteHex(stack_va);
        SerialWrite("\n");
    }

    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-jail-probe", proc);
}

// Dedicated privileged-instruction probe: tries to execute `cli` from
// ring 3. IOPL is left at 0 in the iretq frame that runs every ring-3
// task (see usermode.S), so CPL(3) > IOPL(0) — the CPU must raise #GP
// on the `cli` attempt. If it didn't, a sandboxed task could globally
// disable interrupts and spin forever, starving every other process
// plus the reaper, taking the system down. Proving the #GP path kills
// the task (and only the task) is the sandbox invariant in action.
//
// Payload:
//   pause      ; 0xF3 0x90    — gives the scheduler a stable landing
//   cli        ; 0xFA         — privileged; #GP expected
//   ud2        ; 0x0F 0x0B    — belt-and-braces if cli regressed
//
// Expected: "[task-kill] ring-3 task took General protection fault —
// terminating" on COM1, followed by the same reap-and-destroy flow
// every other sandbox probe uses. Other workers (heartbeat, kbd-reader,
// idle) keep running — which they couldn't if `cli` had actually taken
// effect.
//
// clang-format off
constexpr u8 kPrivProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xFA,                                                         // cli (privileged → #GP from ring 3)
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnPrivProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for priv probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for priv probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kPrivProbeBytes); ++i)
    {
        code_direct[i] = kPrivProbeBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for priv probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-priv-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for priv probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued priv-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect #GP on cli)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-priv-probe", proc);
}

// Dedicated bad-int probe: issues `int 0x81` from ring 3. The IDT
// installs vectors 0..47 plus the DPL=3 gate at 0x80; vector 0x81 has
// a zero gate descriptor (present bit clear). Intel SDM Vol. 3A §6.11:
// executing `int N` when IDT[N] is not present raises #NP (vector 11)
// with error-code pointing at the offending gate. The ring-3 trap
// path logs and kills the task. This proves the kernel tolerates a
// user-driven interrupt instruction targeting an unconfigured vector
// — without the trap dispatcher's DPL-agnostic "any vector from
// ring 3 = kill the task" rule, an unhandled vector could triple-
// fault the box.
//
// Payload:
//   pause       ; 0xF3 0x90
//   int 0x81    ; 0xCD 0x81
//   ud2         ; 0x0F 0x0B
//
// clang-format off
constexpr u8 kBadIntProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0xCD, 0x81,                                                   // int 0x81 (gate not present)
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

void SpawnBadIntProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for bad-int probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for bad-int probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kBadIntProbeBytes); ++i)
    {
        code_direct[i] = kBadIntProbeBytes[i];
    }
    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for bad-int probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-badint-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for bad-int probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued bad-int-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect #GP/#NP on int 0x81)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-badint-probe", proc);
}

// Dedicated kernel-read probe: tries to load a byte from a kernel-
// half address (0xFFFFFFFF80000000, the higher-half kernel image
// base). The page walker finds a PTE that is Present but lacks the
// U/S bit, so a ring-3 read gets err=5 (P | U-fetch-on-non-U page).
// Kill path identical to every other user-mode fault.
//
// This is the "I have a gadget that leaks kernel addresses to ring 3"
// threat model in action: the attacker already knows a kernel
// symbol, can compute its VA, and tries to dereference it. The
// kernel's user-bit enforcement (set at boot_PML4 time) is the
// firewall between them.
//
// Payload:
//   pause            ; 0xF3 0x90
//   mov rax, <imm64> ; 0x48 0xB8 <8 bytes> — patched to 0xFFFFFFFF80000000
//   mov al,  [rax]   ; 0x8A 0x00
//   ud2              ; 0x0F 0x0B
//
// clang-format off
constexpr u8 kKernelReadProbeBytes[] = {
    0xF3, 0x90,                                                   // pause
    0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,                           // mov rax, <imm64 patched>
    0x8A, 0x00,                                                   // mov al, byte ptr [rax]
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on

constexpr u64 kKernelHigherHalfBase = 0xFFFFFFFF80000000ULL;

void SpawnKernelReadProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;

    auto as_r = AddressSpaceCreate(kFrameBudgetSandbox);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for kernel-read probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for kernel-read probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kKernelReadProbeBytes); ++i)
    {
        code_direct[i] = kKernelReadProbeBytes[i];
    }
    // Patch imm64 at byte offset 4 (after `pause` + `48 B8`).
    WriteImm64LE(code_direct, 4, kKernelHigherHalfBase);

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for kernel-read probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    Process* proc = ProcessCreate("ring3-kread-probe", as, CapSetEmpty(), fs::RamfsSandboxRoot(), code_va, stack_va,
                                  kTickBudgetSandbox);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for kernel-read probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued kread-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect #PF on kernel-half read)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-kread-probe", proc);
}

// Dedicated user-pointer fuzz probe: a TRUSTED ring-3 task that
// hands four deliberately wild user_buf values to SYS_WRITE in
// sequence. Each call must return -1 from `DoWrite` (via the
// `CopyFromUser` rejection path) without the kernel ever touching
// the bogus address. After the four attacks, the task issues one
// CONTROL SYS_WRITE with a valid pointer to a literal string —
// if the kernel survived all four wild attempts, the control
// message reaches COM1; if any of them corrupted state or
// panicked, the control print is missing from the boot log.
//
// Trusted caps are intentional: cap check must pass so the
// `CopyFromUser` machinery is exercised. The probes that send
// ring 3 with empty caps (hostile, jail, nx, ...) short-circuit
// at the cap check and never reach the pointer validators.
//
// Pointer choices:
//   1. NULL                — passes IsUserAddressRange (0 < kUserMax)
//                            but walker finds no PTE → false.
//   2. 0xFFFFFFFF80000000  — kernel image base, > kUserMax →
//                            IsUserAddressRange rejects up front.
//   3. 0xDEADBEEF00000000  — non-canonical hole, > kUserMax →
//                            IsUserAddressRange rejects up front.
//   4. 0x00007FFFFFFFFFFE  — last 2 bytes of user space + len=256
//                            crosses into kernel half →
//                            IsUserAddressRange rejects on the
//                            addr + len - 1 overflow check.
//
// Expected boot log (in this order):
//   [ring3] queued ptrfuzz-probe task pid=N
//   [ring3] task pid=N entering ring 3 ...
//   [ptrfuzz] passed                       <- the control print
//   [ts=...] [I] sys : exit rc val=0
//   [proc] destroy pid=N name="ring3-ptrfuzz-probe"
//
// A panic / triple fault / missing "[ptrfuzz] passed" is the
// failure signal — the kernel didn't survive one of the wild
// pointer attempts.
//
// clang-format off
constexpr char kPtrFuzzMsg[] = "[ptrfuzz] passed\n";
constexpr u64 kPtrFuzzMsgOffset = 0xC0; // string sits at code_va + 0xC0
constexpr u64 kPtrFuzzMsgLen = sizeof(kPtrFuzzMsg) - 1;

constexpr u8 kPtrFuzzProbeBytes[] = {
    0xF3, 0x90,                                                   // pause

    // ---- attack 1: SYS_WRITE(fd=1, buf=NULL, len=1) ---------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // mov esi, 0  (NULL)
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 2: SYS_WRITE(1, 0xFFFFFFFF80000000, 1) ------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF,   // mov rsi, 0xFFFFFFFF80000000
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 3: SYS_WRITE(1, 0xDEADBEEF00000000, 1) ------------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,   // mov rsi, 0xDEADBEEF00000000
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // mov edx, 1
    0xCD, 0x80,                                                   // int 0x80

    // ---- attack 4: SYS_WRITE(1, 0x7FFFFFFFFFFE, 256) — boundary --
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0x48, 0xBE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00,   // mov rsi, 0x00007FFFFFFFFFFE
    0xBA, 0x00, 0x01, 0x00, 0x00,                                 // mov edx, 256
    0xCD, 0x80,                                                   // int 0x80

    // ---- control: SYS_WRITE(1, code_va + 0xC0, kPtrFuzzMsgLen) ---
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // mov edi, 1
    0xBE, 0xC0, 0x00, 0x00, 0x40,                                 // mov esi, <patched: code_va+0xC0>
    0xBA, static_cast<u8>(kPtrFuzzMsgLen), 0x00, 0x00, 0x00,      // mov edx, len
    0xCD, 0x80,                                                   // int 0x80

    // ---- SYS_EXIT(0) ----------------------------------------------
    0x31, 0xC0,                                                   // xor eax, eax
    0x31, 0xFF,                                                   // xor edi, edi
    0xCD, 0x80,                                                   // int 0x80
    0x0F, 0x0B,                                                   // ud2
};
// clang-format on
static_assert(sizeof(kPtrFuzzProbeBytes) <= kPtrFuzzMsgOffset, "ptrfuzz code overruns msg region");
static_assert(kPtrFuzzMsgOffset + sizeof(kPtrFuzzMsg) <= mm::kPageSize, "ptrfuzz msg past end of page");

// Offset of the control SYS_WRITE's `mov esi, imm32` field. The
// payload is a fixed sequence so this is a constant; verify by
// hand if the byte sequence above is ever reordered. The byte at
// `kPtrFuzzCtrlSrcOffset - 1` MUST be 0xBE (the mov-esi-imm32
// opcode) — the spawn helper asserts that before patching.
//
// Hand-traced layout:
//   0x00 .. 0x01   pause                                   (  2)
//   0x02 .. 0x17   attack 1 — NULL ptr,        22 bytes
//   0x18 .. 0x32   attack 2 — kernel-half,     27 bytes
//   0x33 .. 0x4D   attack 3 — non-canonical,   27 bytes
//   0x4E .. 0x68   attack 4 — boundary cross,  27 bytes
//   0x69 .. 0x7E   control SYS_WRITE,          22 bytes
//                    0x69 .. 0x6D  mov eax, 2
//                    0x6E .. 0x72  mov edi, 1
//                    0x73 .. 0x77  mov esi, imm32  <- patched
//                                   ^ 0x73 = opcode 0xBE, imm32 at 0x74
//                    0x78 .. 0x7C  mov edx, len
//                    0x7D .. 0x7E  int 0x80
//   0x7F .. 0x86   SYS_EXIT(0) + ud2                       (  8)
constexpr u16 kPtrFuzzCtrlSrcOffset = 0x74; // imm32 starts at byte 0x74 (116)

void SpawnPtrFuzzProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "ptrfuzz code_va overflows imm32");

    auto as_r = AddressSpaceCreate(kFrameBudgetTrusted);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for ptrfuzz probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for ptrfuzz probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kPtrFuzzProbeBytes); ++i)
    {
        code_direct[i] = kPtrFuzzProbeBytes[i];
    }
    for (u64 i = 0; i < sizeof(kPtrFuzzMsg); ++i)
    {
        code_direct[kPtrFuzzMsgOffset + i] = static_cast<u8>(kPtrFuzzMsg[i]);
    }
    // Patch control-write source pointer with code_va + msg_offset.
    KASSERT(code_direct[kPtrFuzzCtrlSrcOffset - 1] == 0xBE, "core/ring3",
            "ptrfuzz patch: byte before ctrl-src offset is not the mov-esi-imm32 opcode");
    WriteImm32LE(code_direct, kPtrFuzzCtrlSrcOffset, static_cast<u32>(code_va + kPtrFuzzMsgOffset));

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for ptrfuzz probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps: cap check must PASS so the wild user pointers
    // actually reach `CopyFromUser`. With empty caps, every
    // SYS_WRITE would short-circuit at the cap check and the
    // pointer validator would never run.
    Process* proc = ProcessCreate("ring3-ptrfuzz-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for ptrfuzz probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued ptrfuzz-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect 4× -1 then [ptrfuzz] passed)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-ptrfuzz-probe", proc);
}

// writefuzz probe — the CopyToUser sibling of ptrfuzz. Ptrfuzz
// covers `SYS_WRITE`, which exercises `CopyFromUser`. This probe
// covers the write-direction of the pointer validator:
// `CopyToUser` inside `SYS_STAT` (writes a `u64` size) and
// `SYS_READ` (writes file bytes). A trusted task with
// `kCapFsRead` issues four syscalls that ALL hit valid lookups
// (so the call actually reaches `CopyToUser`) but supply wild
// DESTINATION pointers:
//
//   1. SYS_STAT(/etc/version, dst=NULL)
//      IsUserAddressRange(0, 8) passes (0 ≤ kUserMax); walker
//      finds no PTE → IsUserRangeAccessible → false → -1.
//   2. SYS_STAT(/etc/version, dst=0xFFFFFFFF80000000)
//      kernel-half, > kUserMax → range-check reject → -1.
//   3. SYS_READ(/etc/version, dst=0xDEADBEEF00000000, cap=128)
//      non-canonical, > kUserMax → range-check reject → -1.
//   4. SYS_READ(/etc/version, dst=0x7FFFFFFFFFFE, cap=256)
//      to_copy clamps to file_size (27 for /etc/version);
//      rsi + 26 = 0x800000000018 > kUserMax →
//      range-check reject → -1.
//
// Each call must return -1 WITHOUT the kernel writing a byte to
// the bogus address. After the four attacks, a control
// SYS_WRITE prints "[writefuzz] passed" — if any CopyToUser
// stumbled and actually attempted the write, the task would
// crash (or worse, the kernel would page-fault in the copy
// routine) and the control print would be missing.
//
// This closes the CopyToUser half of the pointer-validator story
// for the ring-3 adversarial pentest suite.

// clang-format off
constexpr char kWriteFuzzPath[] = "/etc/version";
constexpr char kWriteFuzzMsg[] = "[writefuzz] passed\n";
constexpr u64 kWriteFuzzPathOffset = 0x80; // NUL-terminated path in code page
constexpr u64 kWriteFuzzMsgOffset = 0xA0;  // control message in code page
constexpr u64 kWriteFuzzMsgLen = sizeof(kWriteFuzzMsg) - 1;

constexpr u8 kWriteFuzzProbeBytes[] = {
    0xF3, 0x90,                                                   // 0x00 pause

    // attack 1: SYS_STAT(path, NULL) — unmapped user VA
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // 0x02 mov eax, 4
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x07 mov edi, path (patched)
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // 0x0C mov esi, 0 (NULL)
    0xCD, 0x80,                                                   // 0x11 int 0x80

    // attack 2: SYS_STAT(path, 0xFFFFFFFF80000000) — kernel-half
    0xB8, 0x04, 0x00, 0x00, 0x00,                                 // 0x13 mov eax, 4
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x18 mov edi, path (patched)
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF, 0xFF, 0xFF,   // 0x1D mov rsi, 0xFFFFFFFF80000000
    0xCD, 0x80,                                                   // 0x27 int 0x80

    // attack 3: SYS_READ(path, 0xDEADBEEF00000000, 128) — non-canonical
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // 0x29 mov eax, 5
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x2E mov edi, path (patched)
    0x48, 0xBE, 0x00, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,   // 0x33 mov rsi, 0xDEADBEEF00000000
    0xBA, 0x80, 0x00, 0x00, 0x00,                                 // 0x3D mov edx, 128
    0xCD, 0x80,                                                   // 0x42 int 0x80

    // attack 4: SYS_READ(path, 0x00007FFFFFFFFFFE, 256) — boundary cross
    0xB8, 0x05, 0x00, 0x00, 0x00,                                 // 0x44 mov eax, 5
    0xBF, 0x80, 0x00, 0x00, 0x40,                                 // 0x49 mov edi, path (patched)
    0x48, 0xBE, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00,   // 0x4E mov rsi, 0x00007FFFFFFFFFFE
    0xBA, 0x00, 0x01, 0x00, 0x00,                                 // 0x58 mov edx, 256
    0xCD, 0x80,                                                   // 0x5D int 0x80

    // control: SYS_WRITE(1, msg, kWriteFuzzMsgLen)
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // 0x5F mov eax, 2
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // 0x64 mov edi, 1
    0xBE, 0xA0, 0x00, 0x00, 0x40,                                 // 0x69 mov esi, msg (patched)
    0xBA, static_cast<u8>(kWriteFuzzMsgLen), 0x00, 0x00, 0x00,    // 0x6E mov edx, len
    0xCD, 0x80,                                                   // 0x73 int 0x80

    // SYS_EXIT(0)
    0x31, 0xC0,                                                   // 0x75 xor eax, eax
    0x31, 0xFF,                                                   // 0x77 xor edi, edi
    0xCD, 0x80,                                                   // 0x79 int 0x80
    0x0F, 0x0B,                                                   // 0x7B ud2
};
// clang-format on
static_assert(sizeof(kWriteFuzzProbeBytes) <= kWriteFuzzPathOffset, "writefuzz code overruns path region");
static_assert(kWriteFuzzPathOffset + sizeof(kWriteFuzzPath) <= kWriteFuzzMsgOffset, "writefuzz path overruns msg");
static_assert(kWriteFuzzMsgOffset + sizeof(kWriteFuzzMsg) <= mm::kPageSize, "writefuzz msg past end of page");

// Patch offsets — the imm32 byte in each `mov edi/esi, imm32`
// sits one byte past the opcode. See the hand-traced layout in
// the payload comment block above. Re-derive if the sequence is
// ever reshuffled.
constexpr u16 kWriteFuzzPathPatchOffsets[] = {0x08, 0x19, 0x2F, 0x4A};
constexpr u16 kWriteFuzzMsgPatchOffset = 0x6A;

void SpawnWriteFuzzProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "writefuzz code_va overflows imm32");

    auto as_r = AddressSpaceCreate(kFrameBudgetTrusted);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for writefuzz probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for writefuzz probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
    {
        code_direct[i] = 0;
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzProbeBytes); ++i)
    {
        code_direct[i] = kWriteFuzzProbeBytes[i];
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzPath); ++i)
    {
        code_direct[kWriteFuzzPathOffset + i] = static_cast<u8>(kWriteFuzzPath[i]);
    }
    for (u64 i = 0; i < sizeof(kWriteFuzzMsg); ++i)
    {
        code_direct[kWriteFuzzMsgOffset + i] = static_cast<u8>(kWriteFuzzMsg[i]);
    }
    // Patch all four rdi path-pointer slots and the control rsi.
    for (u16 off : kWriteFuzzPathPatchOffsets)
    {
        KASSERT(code_direct[off - 1] == 0xBF, "core/ring3",
                "writefuzz patch: byte before path slot is not mov-edi opcode");
        WriteImm32LE(code_direct, off, static_cast<u32>(code_va + kWriteFuzzPathOffset));
    }
    KASSERT(code_direct[kWriteFuzzMsgPatchOffset - 1] == 0xBE, "core/ring3",
            "writefuzz patch: byte before ctrl-src slot is not mov-esi opcode");
    WriteImm32LE(code_direct, kWriteFuzzMsgPatchOffset, static_cast<u32>(code_va + kWriteFuzzMsgOffset));

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for writefuzz probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps: need kCapFsRead to reach the SYS_READ/SYS_STAT
    // implementations. With empty caps the cap gate would
    // short-circuit and CopyToUser would never run.
    Process* proc = ProcessCreate("ring3-writefuzz-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va,
                                  stack_va, kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for writefuzz probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued writefuzz-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect 4× -1 then [writefuzz] passed)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-writefuzz-probe", proc);
}

// ---- bp-probe: ring-3 exercise of SYS_BP_INSTALL / SYS_BP_REMOVE. -----
//
// A trusted task that installs a HW execute breakpoint on an
// instruction in its own code page, then executes that instruction
// (a `nop` at code_va + kBpProbeTargetOffset), expects the kernel
// to log `HW BP hit` for its pid, then removes the BP and prints
// `[bp-probe] passed via HW BP`. Expected serial log sequence:
//
//   [ring3] queued bp-probe task pid=N
//   [ring3] task pid=N entering ring 3 ...
//   [I] debug/bp : HW BP installed   addr=<target>   id=<id>
//   [I] debug/bp : HW BP hit   addr=<target>   hits=0x1 (1)
//   [I] debug/bp : HW BP removed id   val=<id>
//   [bp-probe] passed via HW BP
//   [I] sys : exit rc val=0x0
//   [proc] destroy pid=N name="ring3-bp-probe"
//
// Failure modes caught:
//   * `SYS_BP_INSTALL` cap-gate bug → rax=-1 → probe still prints
//     the passed-msg but the kernel log lacks the `HW BP hit` line.
//   * Context-switch save/restore bug → BP misses on the specific
//     CPU the task ended up running on → no `HW BP hit` line.
//   * DR7 enable-bit pack bug → BP doesn't arm → no hit.
//
// clang-format off
constexpr char kBpProbeMsg[] = "[bp-probe] passed via HW BP\n";
constexpr u64 kBpProbeMsgOffset = 0x80;
constexpr u64 kBpProbeMsgLen = sizeof(kBpProbeMsg) - 1;
constexpr u64 kBpProbeTargetOffset = 0x19; // byte offset of the BP's `nop`

constexpr u8 kBpProbeBytes[] = {
    // ---- SYS_BP_INSTALL(va=<TARGET>, kind=1, len=1) ---------
    0xB8, 0x26, 0x00, 0x00, 0x00,                                 // 0x00 mov eax, 38 (SYS_BP_INSTALL)
    0xBF, 0x00, 0x00, 0x00, 0x00,                                 // 0x05 mov edi, <TARGET_VA>  (patched)
    0xBE, 0x01, 0x00, 0x00, 0x00,                                 // 0x0A mov esi, 1 (HwExecute)
    0xBA, 0x01, 0x00, 0x00, 0x00,                                 // 0x0F mov edx, 1 (len)
    0xCD, 0x80,                                                   // 0x14 int 0x80 → rax = bp_id
    0x49, 0x89, 0xC4,                                             // 0x16 mov r12, rax (save bp_id)

    // ---- BP target: a single nop at code_va + kBpProbeTargetOffset.
    // The kernel's #DB handler logs the hit; we just keep going.
    0x90,                                                         // 0x19 nop  (HW BP fires here)

    // ---- SYS_BP_REMOVE(id=r12) ------------------------------
    0xB8, 0x27, 0x00, 0x00, 0x00,                                 // 0x1A mov eax, 39 (SYS_BP_REMOVE)
    0x4C, 0x89, 0xE7,                                             // 0x1F mov rdi, r12
    0xCD, 0x80,                                                   // 0x22 int 0x80

    // ---- SYS_WRITE(1, code_va + MSG_OFFSET, MSG_LEN) --------
    0xB8, 0x02, 0x00, 0x00, 0x00,                                 // 0x24 mov eax, 2 (SYS_WRITE)
    0xBF, 0x01, 0x00, 0x00, 0x00,                                 // 0x29 mov edi, 1 (fd)
    0xBE, 0x00, 0x00, 0x00, 0x00,                                 // 0x2E mov esi, <MSG_VA>  (patched)
    0xBA, static_cast<u8>(kBpProbeMsgLen), 0x00, 0x00, 0x00,      // 0x33 mov edx, len
    0xCD, 0x80,                                                   // 0x38 int 0x80

    // ---- SYS_EXIT(0) ----------------------------------------
    0x31, 0xC0,                                                   // 0x3A xor eax, eax
    0x31, 0xFF,                                                   // 0x3C xor edi, edi
    0xCD, 0x80,                                                   // 0x3E int 0x80
    0x0F, 0x0B,                                                   // 0x40 ud2
};
// clang-format on
static_assert(sizeof(kBpProbeBytes) <= kBpProbeMsgOffset, "bp-probe code overruns msg region");
static_assert(kBpProbeMsgOffset + sizeof(kBpProbeMsg) <= mm::kPageSize, "bp-probe msg past end of page");

// Imm32 patch offsets — hand-verified above. The byte immediately
// preceding each imm32 MUST be the expected opcode (0xBF for
// mov edi, 0xBE for mov esi); asserted in the spawn helper.
constexpr u16 kBpProbeInstallTargetOffset = 0x06; // imm32 at 0x06 (opcode 0xBF at 0x05)
constexpr u16 kBpProbeWriteSrcOffset = 0x2F;      // imm32 at 0x2F (opcode 0xBE at 0x2E)

void SpawnBpProbeTask()
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    const u64 code_va = AslrPickBase();
    const u64 stack_va = code_va + kStackOffsetFromCode;
    KASSERT(code_va <= 0xFFFFFFFFULL, "core/ring3", "bp-probe code_va overflows imm32");

    auto as_r = AddressSpaceCreate(kFrameBudgetTrusted);
    AddressSpace* as = as_r.has_value() ? as_r.value() : nullptr;
    if (as == nullptr)
    {
        Panic("core/ring3", "AS create failed for bp-probe");
    }

    const PhysAddr code_frame = TryAllocateFrame().value_or(kNullFrame);
    if (code_frame == kNullFrame)
    {
        Panic("core/ring3", "code frame alloc failed for bp-probe");
    }
    auto* code_direct = static_cast<u8*>(PhysToVirt(code_frame));
    for (u64 i = 0; i < mm::kPageSize; ++i)
        code_direct[i] = 0;
    for (u64 i = 0; i < sizeof(kBpProbeBytes); ++i)
        code_direct[i] = kBpProbeBytes[i];
    for (u64 i = 0; i < sizeof(kBpProbeMsg); ++i)
        code_direct[kBpProbeMsgOffset + i] = static_cast<u8>(kBpProbeMsg[i]);

    // Patch the install target and write-source VAs. Opcode
    // sanity checks first — if the byte layout above ever gets
    // shuffled, we want an explicit panic rather than a wrong
    // address silently slipping through.
    KASSERT(code_direct[kBpProbeInstallTargetOffset - 1] == 0xBF, "core/ring3",
            "bp-probe patch: byte before install-target offset is not mov-edi-imm32 opcode");
    KASSERT(code_direct[kBpProbeWriteSrcOffset - 1] == 0xBE, "core/ring3",
            "bp-probe patch: byte before write-src offset is not mov-esi-imm32 opcode");
    WriteImm32LE(code_direct, kBpProbeInstallTargetOffset, static_cast<u32>(code_va + kBpProbeTargetOffset));
    WriteImm32LE(code_direct, kBpProbeWriteSrcOffset, static_cast<u32>(code_va + kBpProbeMsgOffset));

    const PhysAddr stack_frame = TryAllocateFrame().value_or(kNullFrame);
    if (stack_frame == kNullFrame)
    {
        Panic("core/ring3", "stack frame alloc failed for bp-probe");
    }
    AddressSpaceMapUserPage(as, code_va, code_frame, kPagePresent | kPageUser);
    AddressSpaceMapUserPage(as, stack_va, stack_frame, kPagePresent | kPageWritable | kPageUser | kPageNoExecute);

    // Trusted caps include kCapSerialConsole (for the final
    // SYS_WRITE) and kCapDebug (gating the new BP syscalls).
    Process* proc = ProcessCreate("ring3-bp-probe", as, CapSetTrusted(), fs::RamfsTrustedRoot(), code_va, stack_va,
                                  kTickBudgetTrusted);
    if (proc == nullptr)
    {
        Panic("core/ring3", "ProcessCreate failed for bp-probe");
    }
    {
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] queued bp-probe task pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" code_va=");
        SerialWriteHex(code_va);
        SerialWrite(" (expect HW BP hit then [bp-probe] passed)\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, "ring3-bp-probe", proc);
}

} // namespace

bool SpawnOnDemand(const char* kind)
{
    if (kind == nullptr || kind[0] == '\0')
        return false;
    if (StrEqual(kind, "hello"))
    {
        SpawnRing3Task("ring3-cmd-hello", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                       kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "sandbox"))
    {
        CapSet caps = CapSetEmpty();
        CapSetAdd(caps, kCapFsRead);
        SpawnRing3Task("ring3-cmd-sandbox", caps, fs::RamfsSandboxRoot(), mm::kFrameBudgetSandbox, kTickBudgetSandbox);
        return true;
    }
    if (StrEqual(kind, "jail"))
    {
        SpawnJailProbeTask();
        return true;
    }
    if (StrEqual(kind, "nx"))
    {
        SpawnNxProbeTask();
        return true;
    }
    if (StrEqual(kind, "hog"))
    {
        SpawnCpuHogProbe();
        return true;
    }
    if (StrEqual(kind, "syscallstorm"))
    {
        SpawnSyscallStormProbeTask();
        return true;
    }
    if (StrEqual(kind, "hostile"))
    {
        SpawnHostileProbe();
        return true;
    }
    if (StrEqual(kind, "crosspid"))
    {
        SpawnCrossPidProbe();
        return true;
    }
    if (StrEqual(kind, "dropcaps"))
    {
        SpawnDropcapsProbe();
        return true;
    }
    if (StrEqual(kind, "priv"))
    {
        SpawnPrivProbeTask();
        return true;
    }
    if (StrEqual(kind, "badint"))
    {
        SpawnBadIntProbeTask();
        return true;
    }
    if (StrEqual(kind, "kread"))
    {
        SpawnKernelReadProbeTask();
        return true;
    }
    if (StrEqual(kind, "ptrfuzz"))
    {
        SpawnPtrFuzzProbeTask();
        return true;
    }
    if (StrEqual(kind, "writefuzz"))
    {
        SpawnWriteFuzzProbeTask();
        return true;
    }
    if (StrEqual(kind, "hellope"))
    {
        SpawnPeFile("ring3-hello-pe", fs::generated::kBinHelloPeBytes, fs::generated::kBinHelloPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "winhello"))
    {
        // First Win32 PE: imports ExitProcess, gets resolved
        // through the kernel-hosted stub page, exits with
        // code 42. "Exit rc=0x2a" in the serial log confirms
        // the full IAT resolution chain worked.
        SpawnPeFile("ring3-hello-winapi", fs::generated::kBinHelloWinapiBytes, fs::generated::kBinHelloWinapiBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "winkill"))
    {
        // Real-world PE that the v0 loader cannot execute.
        // SpawnPeFile's diagnostic pre-pass still fires
        // (PeReport logs imports/relocs/TLS), then the load is
        // rejected with a typed status code. The point is the
        // serial log, not a running process.
        SpawnPeFile("ring3-winkill", fs::generated::kBinWinKillBytes, fs::generated::kBinWinKillBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "threads"))
    {
        // thread_stress.exe — exercises CreateThread +
        // CreateEventW + SetEvent + WaitForSingleObject.
        // Expected exit: 0xABCDE on success.
        SpawnPeFile("ring3-thread-stress", fs::generated::kBinThreadStressBytes,
                    fs::generated::kBinThreadStressBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "browser"))
    {
        // mini_browser.exe — minimal WinSock 2 PE that does an
        // HTTP/1.0 GET to www.google.com. Imports kernel32 +
        // ws2_32. Exits with rc=0 on success; rc=2..6 maps to
        // the failing WinSock step. The point is to surface
        // exactly which WS2_32 thunks are missing and to drive
        // their implementation iteratively.
        SpawnPeFile("ring3-mini-browser", fs::generated::kBinMiniBrowserBytes, fs::generated::kBinMiniBrowserBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "browser2") || StrEqual(kind, "wininet"))
    {
        // browser_pe.exe — WinInet-based browser. Imports kernel32 +
        // wininet; the kernel-side wininet thunks do real HTTP/1.1
        // GET via the same kernel socket pool ws2_32 uses. Prints
        // status code, content-type, content-length, and the first
        // body line for each of three URLs.
        SpawnPeFile("ring3-browser-pe", fs::generated::kBinBrowserPeBytes, fs::generated::kBinBrowserPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    if (StrEqual(kind, "pe32"))
    {
        // pe32_smoke.exe — minimal PE32 (i386) test image. The
        // kernel's loader recognises PE32 (Layer 1 of 32-bit PE
        // support) but rejects MapAndRun with the typed status
        // `PeStatus::Pe32ExecutionNotReady` until Layers 4 (i386
        // DLL set) and 5 (pointer marshalling) land. The boot
        // log carries a "loader/pe:Pe32ExecutionNotReady" pin so
        // the reject signal is visible. SpawnPeFile's diagnostic
        // PeReport pre-pass walks the PE32's headers + imports so
        // the gap inventory is filled out from the live boot.
        SpawnPeFile("ring3-pe32-smoke", fs::generated::kBinPe32SmokeBytes, fs::generated::kBinPe32SmokeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        return true;
    }
    return false;
}

void StartRing3SmokeTask()
{
    // Three ring-3 tasks, all using the SAME user VAs (0x40000000
    // code, 0x40010000 stack) in their own private address spaces.
    // Per-AS isolation means the VA "collisions" aren't collisions
    // at all.
    //
    //   - ring3-smoke-A, ring3-smoke-B: trusted profile (full cap
    //     set). Both print "Hello from ring 3!" via SYS_WRITE and
    //     exit cleanly.
    //
    //   - ring3-smoke-sandbox: empty cap set. Same user payload,
    //     but SYS_WRITE(fd=1) is denied by the cap check in the
    //     syscall dispatcher — the kernel logs
    //       "[sys] denied syscall=SYS_WRITE pid=N cap=SerialConsole"
    //     and returns -1 to ring 3. The user code ignores the
    //     return value (SYS_YIELD + SYS_EXIT follow unconditionally)
    //     so the task exits cleanly. Demonstrates that a process
    //     with zero ambient authority cannot reach the kernel
    //     serial console even though it shares the int 0x80 gate
    //     with trusted processes — the gate is open, the caps
    //     aren't.
    // Trusted tasks run off the rich ramfs root (/etc/version,
    // /bin/hello reachable). Their SYS_WRITE ⇒ "Hello from ring 3!"
    // succeeds because they hold kCapSerialConsole.
    //
    // Sandbox task runs off the one-file root (only
    // /welcome.txt exists there). It holds ZERO caps, so:
    //   - SYS_WRITE is denied by the cap check.
    //   - SYS_STAT would be denied too, if the user payload
    //     issued one (today's payload doesn't — the next bite
    //     adds per-task payloads so the sandbox actively tries
    //     a jail-escape and gets logged).
    // Sandbox gets kCapFsRead so SYS_STAT reaches the namespace
    // layer — with an empty cap set, the cap check would short-
    // circuit and we'd never exercise VfsLookup against the
    // sandbox root. Granting the cap lets the demo prove that
    // EVEN WITH the cap, Process::root bounds what the process
    // can name: "/etc/version" in the sandbox root simply does
    // not exist.
    CapSet sandbox_caps = CapSetEmpty();
    CapSetAdd(sandbox_caps, kCapFsRead);

    // The ring3-smoke trio runs under profile=Ring3 (and the
    // always-on profile=None bare-metal full boot). PE-only and
    // Linux-only smokes skip the trio so their wall budget covers
    // exactly one scenario.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::Ring3))
    {
        SpawnRing3Task("ring3-smoke-A", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                       kTickBudgetTrusted);
        SpawnRing3Task("ring3-smoke-B", CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted,
                       kTickBudgetTrusted);
        SpawnRing3Task("ring3-smoke-sandbox", sandbox_caps, fs::RamfsSandboxRoot(), mm::kFrameBudgetSandbox,
                       kTickBudgetSandbox);
    }

    // Skip the security / fuzz probe block under a hypervisor:
    // every probe spawn allocates a new AS + page, queues a Task,
    // schedules it long enough to take its expected fault, and
    // routes through the reaper. On a CPU-bound dev box that's
    // microseconds; on an oversubscribed CI runner under KVM it
    // adds tens of seconds of guest-CPU time the boot smoke
    // doesn't need (the boot-smoke critical path checks PE-loader
    // output, not the security walls). Bare metal still runs the
    // full probe suite. Same for the windowed-hello PE further
    // down — its 20-second Sleep is a screenshot harness aid that
    // burns 20s of kernel time CI doesn't have.
    const bool emulator = ::duetos::arch::IsEmulator();
    if (!emulator)
    {
        // Jail-probe task: writes to its own RX code page. Expected
        // outcome is the kernel's ring-3 trap handler terminating the
        // task via SchedExit and emitting [task-kill] on COM1. If the
        // kernel instead panics / halts here, the sandboxing contract
        // is broken: a user-mode fault must never bring down the OS.
        SpawnJailProbeTask();
        SpawnNxProbeTask();
        SpawnCpuHogProbe();
        // Hostile-syscall probe: retries a blocked SYS_WRITE forever.
        // After 100 cap denials, the sandbox-denial threshold kills
        // the task. Boot log shows `[sandbox] pid=N hit 100 denials`.
        SpawnHostileProbe();
        // Cross-PID probe: retries SYS_PROCESS_OPEN(pid=1) forever
        // without kCapDebug. The cap gate denies every call; after
        // 100 denials the task is reaped. Closes the redteam matrix
        // gap on classic Win32 cross-process tampering (any
        // attacker reaching VM_WRITE / SUSPEND / SET_CONTEXT must
        // first OPEN, and OPEN is gated).
        SpawnCrossPidProbe();
        // Dropcaps demo: trusted task drops its caps mid-flight and
        // verifies subsequent SYS_WRITE is denied.
        SpawnDropcapsProbe();
        // Priv-instruction probe: `cli` from ring 3 → #GP → task-kill.
        // Proves CPL(3) > IOPL(0) enforcement is live — a sandboxed
        // process cannot globally mask interrupts.
        SpawnPrivProbeTask();
        // Bad-int probe: `int 0x81` → gate-not-present → task-kill.
        // Proves the trap dispatcher catches any ring-3 vector, not
        // just the architectural 0..31 it installs handlers for.
        SpawnBadIntProbeTask();
        // Kernel-read probe: ring 3 dereferences a higher-half kernel
        // VA → #PF (U/S mismatch) → task-kill. Proves the user-bit
        // firewall between ring 3 and the kernel image.
        SpawnKernelReadProbeTask();
        // Ptrfuzz probe: trusted task hands four wild user pointers
        // to SYS_WRITE in sequence. Proves `CopyFromUser` rejection
        // path is robust — kernel never touches a bad address. Final
        // control message confirms the task survived intact.
        SpawnPtrFuzzProbeTask();
        // Writefuzz probe: trusted task hands four wild DESTINATION
        // pointers to SYS_STAT + SYS_READ. Proves `CopyToUser`
        // rejection path is robust — no byte ever lands at a bad VA.
        SpawnWriteFuzzProbeTask();
        // Bp-probe: trusted task installs a HW execute breakpoint on
        // its own nop via SYS_BP_INSTALL, fires it once, removes via
        // SYS_BP_REMOVE. Proves per-task DR save/restore, the
        // kCapDebug gate, and the syscall surface.
        SpawnBpProbeTask();
    }
    // First PE executable on the system. Freestanding, compiled
    // from userland/apps/hello_pe/hello.c by the host clang +
    // lld-link rule in kernel/CMakeLists.txt. Exercises the v0
    // PE loader: DOS + NT header parse, section map, entry
    // point dispatch. Expected output: "[hello-pe] Hello from a
    // PE executable!" then clean exit.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::PeHello))
    {
        SpawnPeFile("ring3-hello-pe", fs::generated::kBinHelloPeBytes, fs::generated::kBinHelloPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // T6-01: static TLS + TLS-callback PE. Exercises the
        // loader's IMAGE_TLS_DIRECTORY path: template copy,
        // TEB.ThreadLocalStoragePointer wiring, and the
        // callback-before-entry trampoline. Prints
        // [tls_pe] RESULT PASS on success.
        SpawnPeFile("ring3-tls-pe", fs::generated::kBinTlsPeBytes, fs::generated::kBinTlsPeBytes_len, CapSetTrusted(),
                    fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // T6-02 slice 1: SEH foundation. Exercises real
        // RtlCaptureContext + table-based RtlLookupFunctionEntry
        // (.pdata parse). Prints [seh_pe] RESULT PASS on success.
        SpawnPeFile("ring3-seh-pe", fs::generated::kBinSehPeBytes, fs::generated::kBinSehPeBytes_len, CapSetTrusted(),
                    fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // T6-02 slice 3: real MSVC __try/__except/__finally over
        // CPU faults (clang-windows-msvc -fasync-exceptions). Drives
        // the frame-based __C_specific_handler / RtlUnwindEx /
        // RtlRestoreContext path the mingw seh_pe smoke can't
        // express. Prints [seh_try] RESULT PASS on success.
        SpawnPeFile("ring3-seh-try-pe", fs::generated::kBinSehTryPeBytes, fs::generated::kBinSehTryPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // Slice 6: real MSVC C++ EH. Drives vcruntime140's
        // __CxxFrameHandler3 + _CxxThrowException over the ntdll
        // two-pass dispatch/unwind engine: int/class throw+catch,
        // destructor unwind, catch(...). Prints [cxxeh] RESULT PASS.
        SpawnPeFile("ring3-cxxeh-pe", fs::generated::kBinCxxEhPeBytes, fs::generated::kBinCxxEhPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // Win10 API breadth (synchronization): CONDITION_VARIABLE +
        // CRITICAL_SECTION, WaitOnAddress/WakeByAddress (kernel
        // SYS_WAIT_ON_ADDRESS futex), InitOnceBeginInitialize across
        // real threads. Prints [sync_smoke] RESULT PASS on success.
        SpawnPeFile("ring3-sync-smoke", fs::generated::kBinSyncSmokeBytes, fs::generated::kBinSyncSmokeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    }
    // First Win32 PE that gets RESOLVED (not just reported)
    // by the kernel. Imports kernel32.dll!ExitProcess, hits
    // the stub page, exits with code 42.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::PeWinapi))
    {
        SpawnPeFile("ring3-hello-winapi", fs::generated::kBinHelloWinapiBytes, fs::generated::kBinHelloWinapiBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    }
    // Browser profile: the WinInet browser PE then the WinSock
    // browser PE. browser_pe.exe drives InternetOpenA /
    // InternetOpenUrlA / HttpQueryInfoA / InternetReadFile; the
    // kernel wininet thunks do a real HTTP/1.1 GET over the socket
    // pool (qemu SLIRP has a DHCP lease by bringup), falling back
    // to a fixed body when egress is blocked. mini_browser.exe
    // drives the raw WSAStartup / gethostbyname / socket / connect
    // / send / recv path. Runs under emulator (unlike the legacy
    // !emulator zoo below) because it's the explicit `smoke=browser`
    // scenario — the whole point is to exercise it under QEMU.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::Browser))
    {
        SpawnPeFile("ring3-browser-pe", fs::generated::kBinBrowserPeBytes, fs::generated::kBinBrowserPeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        SpawnPeFile("ring3-mini-browser", fs::generated::kBinMiniBrowserBytes, fs::generated::kBinMiniBrowserBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    }

    // The four PE smokes below cover thread / syscall / DLL /
    // registry-fopen surface. None of their stdout lines are
    // checked by the qemu-smoke critical path (only hello-pe,
    // hello-winapi, and winkill are). On bare metal they're cheap
    // enough to keep in the always-on set, but each one pays for
    // a per-process AS, ~38-DLL preload table, and an entry-point
    // run — under emulator-with-trapping-MMIO that adds tens of
    // seconds of guest time the boot smoke doesn't have. Gate
    // them under !emulator alongside the security probes above.
    if (!emulator)
    {
        // Thread-stress PE: CreateThread + CreateEventW + SetEvent +
        // WaitForSingleObject round-trip. Exercises the Win32 →
        // SYS_THREAD_CREATE path. Expected exit: 0xABCDE on success.
        SpawnPeFile("ring3-thread-stress", fs::generated::kBinThreadStressBytes,
                    fs::generated::kBinThreadStressBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // Syscall-stress PE: coverage — OutputDebugStringA,
        // ExitThread, GetProcessTimes/GetThreadTimes/GetSystemTimes,
        // GlobalMemoryStatusEx, WaitForMultipleObjects. Expected exit:
        // 0xCAFE on success.
        SpawnPeFile("ring3-syscall-stress", fs::generated::kBinSyscallStressBytes,
                    fs::generated::kBinSyscallStressBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // DLL-loader end-to-end fixture. Imports
        // CustomAdd / CustomMul / CustomVersion from customdll.dll;
        // the kernel DLL loader maps the DLL into the process's AS
        // before PeLoad runs and ResolveImports patches each IAT
        // slot with the DLL's export VA directly. Expected exit:
        // 0x1234 on success (= CustomAdd(0x1000, 0x0234)), 0xBAD0
        // if any of the three DLL call results don't match.
        SpawnPeFile("ring3-customdll-test", fs::generated::kBinCustomDllTestBytes,
                    fs::generated::kBinCustomDllTestBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // Registry + fopen end-to-end fixture. Exercises the real
        // registry in advapi32.dll + real fopen/fread in ucrtbase.dll.
        SpawnPeFile("ring3-reg-fopen-test", fs::generated::kBinRegFopenTestBytes,
                    fs::generated::kBinRegFopenTestBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                    mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    }
    // Real-world Windows PE diagnostic attempt. Expected to
    // reject (most imports unresolved) — the value is the
    // PeReport log line showing the full import / reloc / TLS
    // gap.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::PeWinkill))
    {
        SpawnPeFile("ring3-winkill", fs::generated::kBinWinKillBytes, fs::generated::kBinWinKillBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // module_smoke exercises LoadLibraryW for both the
        // already-preloaded fast path (kernel32.dll) and the
        // disk-load slow path (customdll2.dll via
        // SYS_DLL_LOAD_FROM_PATH + /lib/customdll2.dll). Under
        // emulator customdll2 is NOT in the preload set
        // (essential=false) so the second LoadLibraryW call
        // genuinely triggers the new syscall.
        SpawnPeFile("ring3-module-smoke", fs::generated::kBinModuleSmokeBytes, fs::generated::kBinModuleSmokeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
    }
    // mini-browser + the surface-coverage PE zoo + dx-demo block
    // below run alongside the ring3 trio: under profile=None
    // (local dev / full bare-metal boot) and profile=Ring3 (CI's
    // ring3 scenario). The Bringup profile's contract is "nothing
    // user-facing runs; just bringup + sentinel + exit", and
    // PeHello / PeWinapi / PeWinkill / Linux profiles are meant
    // to run exactly ONE focused scenario each — none of them
    // should drag ~70 unrelated surface PEs along. Same gate as
    // the trio above keeps all those contracts honest.
    //
    // Inside the gate the work splits two ways:
    //   - !emulator: the surface-coverage zoo + windowed-hello.
    //     Each Win32-imports PE pays ~38-DLL preload (~15s guest)
    //     + entry-point run; 70+ of them under TCG (no KVM)
    //     overflows any sane wall budget. Same reasoning the
    //     existing thread/syscall/customdll/regfopen quartet uses
    //     a few lines up. Bare metal still runs the full set.
    //   - profile=None only: dx-demo-window. The screenshot
    //     harness (tools/qemu/screenshot.sh -> tools/qemu/run.sh)
    //     boots without a smoke profile and needs the cube on
    //     screen to BitBlt. CI's profile=Ring3 doesn't check the
    //     cube and can't afford the 17s Sleep + 38-DLL preload
    //     under TCG.
    if (::duetos::test::SmokeProfileShouldSpawn(::duetos::test::SmokeTarget::Ring3))
    {
        // pe32_smoke.exe runs in BOTH emulator and bare metal — it's
        // a single tiny image (~6 KiB) and the loader rejects it
        // immediately with Pe32ExecutionNotReady, so it costs
        // microseconds of CPU and adds one diagnostic line to the
        // boot transcript. Keeping it always-on means CI catches
        // any regression in the Layer 1..3 PE32 recognition path.
        SpawnPeFile("ring3-pe32-smoke", fs::generated::kBinPe32SmokeBytes, fs::generated::kBinPe32SmokeBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // pe32_rich — exercises one import per preloaded i386 DLL.
        // Boot transcript shows a "[pe-resolve] via-dll" line for
        // each, plus "[pe32-rich] <dll> ok" runtime confirmation,
        // proving the full Layer 4 surface works end-to-end.
        SpawnPeFile("ring3-pe32-rich", fs::generated::kBinPe32RichBytes, fs::generated::kBinPe32RichBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        // pe32_miss — calls an unresolved Win32 import to validate
        // the 32-bit Win32 thunks page. Process exits with code
        // 0xDEAD0042 in the boot log.
        SpawnPeFile("ring3-pe32-miss", fs::generated::kBinPe32MissBytes, fs::generated::kBinPe32MissBytes_len,
                    CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        if (!emulator)
        {
            // mini_browser.exe — minimal WinSock 2 PE that does an HTTP/1.0
            // GET to www.google.com. Imports kernel32 + ws2_32; the
            // kernel-side ws2_32 thunks route through SYS_SOCKET_OP into
            // the native net stack.
            SpawnPeFile("ring3-mini-browser", fs::generated::kBinMiniBrowserBytes,
                        fs::generated::kBinMiniBrowserBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            // Surface-coverage smoke PEs. Each prints a per-API PASS/FAIL
            // line on serial; the boot transcript is the gap inventory.
            SpawnPeFile("ring3-crypto-smoke", fs::generated::kBinCryptoSmokeBytes,
                        fs::generated::kBinCryptoSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-paths-smoke", fs::generated::kBinPathsSmokeBytes, fs::generated::kBinPathsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-time-smoke", fs::generated::kBinTimeSmokeBytes, fs::generated::kBinTimeSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-iphlpapi-smoke", fs::generated::kBinIphlpapiSmokeBytes,
                        fs::generated::kBinIphlpapiSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wininet-smoke", fs::generated::kBinWininetSmokeBytes,
                        fs::generated::kBinWininetSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            // browser_pe.exe — WinInet-based browser. Drives the same
            // Open → Connect → Request → Send → Read → Close flow any
            // real Win32 browser uses, layered on userland/libs/wininet
            // (which now performs real HTTP/1.1 GETs over the kernel
            // socket pool rather than returning a canned response).
            SpawnPeFile("ring3-browser-pe", fs::generated::kBinBrowserPeBytes, fs::generated::kBinBrowserPeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-string-smoke", fs::generated::kBinStringSmokeBytes,
                        fs::generated::kBinStringSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-mem-smoke", fs::generated::kBinMemSmokeBytes, fs::generated::kBinMemSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-fs-smoke", fs::generated::kBinFsSmokeBytes, fs::generated::kBinFsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-registry-smoke", fs::generated::kBinRegistrySmokeBytes,
                        fs::generated::kBinRegistrySmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-handle-smoke", fs::generated::kBinHandleSmokeBytes,
                        fs::generated::kBinHandleSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-process-smoke", fs::generated::kBinProcessSmokeBytes,
                        fs::generated::kBinProcessSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-module-smoke", fs::generated::kBinModuleSmokeBytes,
                        fs::generated::kBinModuleSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-env-smoke", fs::generated::kBinEnvSmokeBytes, fs::generated::kBinEnvSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-debug-smoke", fs::generated::kBinDebugSmokeBytes, fs::generated::kBinDebugSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-codepage-smoke", fs::generated::kBinCodepageSmokeBytes,
                        fs::generated::kBinCodepageSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-rng-smoke", fs::generated::kBinRngSmokeBytes, fs::generated::kBinRngSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-version-smoke", fs::generated::kBinVersionSmokeBytes,
                        fs::generated::kBinVersionSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-com-smoke", fs::generated::kBinComSmokeBytes, fs::generated::kBinComSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dbghelp-smoke", fs::generated::kBinDbghelpSmokeBytes,
                        fs::generated::kBinDbghelpSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-winhttp-smoke", fs::generated::kBinWinhttpSmokeBytes,
                        fs::generated::kBinWinhttpSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-crt-smoke", fs::generated::kBinCrtSmokeBytes, fs::generated::kBinCrtSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-critsec-smoke", fs::generated::kBinCritsecSmokeBytes,
                        fs::generated::kBinCritsecSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-tls-smoke", fs::generated::kBinTlsSmokeBytes, fs::generated::kBinTlsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-atom-smoke", fs::generated::kBinAtomSmokeBytes, fs::generated::kBinAtomSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-console-smoke", fs::generated::kBinConsoleSmokeBytes,
                        fs::generated::kBinConsoleSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-datetime-smoke", fs::generated::kBinDatetimeSmokeBytes,
                        fs::generated::kBinDatetimeSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-locale-smoke", fs::generated::kBinLocaleSmokeBytes,
                        fs::generated::kBinLocaleSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-gdi-smoke", fs::generated::kBinGdiSmokeBytes, fs::generated::kBinGdiSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-msg-smoke", fs::generated::kBinMsgSmokeBytes, fs::generated::kBinMsgSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-pipe-smoke", fs::generated::kBinPipeSmokeBytes, fs::generated::kBinPipeSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-resource-smoke", fs::generated::kBinResourceSmokeBytes,
                        fs::generated::kBinResourceSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-ntdll-smoke", fs::generated::kBinNtdllSmokeBytes, fs::generated::kBinNtdllSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-shell-smoke", fs::generated::kBinShellSmokeBytes, fs::generated::kBinShellSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-userenv-smoke", fs::generated::kBinUserenvSmokeBytes,
                        fs::generated::kBinUserenvSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-interlock-smoke", fs::generated::kBinInterlockSmokeBytes,
                        fs::generated::kBinInterlockSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-fiber-smoke", fs::generated::kBinFiberSmokeBytes, fs::generated::kBinFiberSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-profile-smoke", fs::generated::kBinProfileSmokeBytes,
                        fs::generated::kBinProfileSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-clipboard-smoke", fs::generated::kBinClipboardSmokeBytes,
                        fs::generated::kBinClipboardSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-windowclass-smoke", fs::generated::kBinWindowclassSmokeBytes,
                        fs::generated::kBinWindowclassSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wow64-smoke", fs::generated::kBinWow64SmokeBytes, fs::generated::kBinWow64SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-mathlib-smoke", fs::generated::kBinMathlibSmokeBytes,
                        fs::generated::kBinMathlibSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-stdio-smoke", fs::generated::kBinStdioSmokeBytes, fs::generated::kBinStdioSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-nls-smoke", fs::generated::kBinNlsSmokeBytes, fs::generated::kBinNlsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-services-smoke", fs::generated::kBinServicesSmokeBytes,
                        fs::generated::kBinServicesSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-eventlog-smoke", fs::generated::kBinEventlogSmokeBytes,
                        fs::generated::kBinEventlogSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-sound-smoke", fs::generated::kBinSoundSmokeBytes, fs::generated::kBinSoundSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-multimon-smoke", fs::generated::kBinMultimonSmokeBytes,
                        fs::generated::kBinMultimonSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-power-smoke", fs::generated::kBinPowerSmokeBytes, fs::generated::kBinPowerSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-heap-smoke", fs::generated::kBinHeapSmokeBytes, fs::generated::kBinHeapSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-thread2-smoke", fs::generated::kBinThread2SmokeBytes,
                        fs::generated::kBinThread2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-ipc-smoke", fs::generated::kBinIpcSmokeBytes, fs::generated::kBinIpcSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-jobobj-smoke", fs::generated::kBinJobobjSmokeBytes,
                        fs::generated::kBinJobobjSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-console2-smoke", fs::generated::kBinConsole2SmokeBytes,
                        fs::generated::kBinConsole2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dns-smoke", fs::generated::kBinDnsSmokeBytes, fs::generated::kBinDnsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-network2-smoke", fs::generated::kBinNetwork2SmokeBytes,
                        fs::generated::kBinNetwork2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dxgi-smoke", fs::generated::kBinDxgiSmokeBytes, fs::generated::kBinDxgiSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dwm-smoke", fs::generated::kBinDwmSmokeBytes, fs::generated::kBinDwmSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-uxtheme-smoke", fs::generated::kBinUxthemeSmokeBytes,
                        fs::generated::kBinUxthemeSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-token-smoke", fs::generated::kBinTokenSmokeBytes, fs::generated::kBinTokenSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-security-smoke", fs::generated::kBinSecuritySmokeBytes,
                        fs::generated::kBinSecuritySmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-perf-smoke", fs::generated::kBinPerfSmokeBytes, fs::generated::kBinPerfSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-accel-smoke", fs::generated::kBinAccelSmokeBytes, fs::generated::kBinAccelSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wts-smoke", fs::generated::kBinWtsSmokeBytes, fs::generated::kBinWtsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-winerr-smoke", fs::generated::kBinWinerrSmokeBytes,
                        fs::generated::kBinWinerrSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-sleep-smoke", fs::generated::kBinSleepSmokeBytes, fs::generated::kBinSleepSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-nt-smoke", fs::generated::kBinNtSmokeBytes, fs::generated::kBinNtSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-vol-smoke", fs::generated::kBinVolSmokeBytes, fs::generated::kBinVolSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-drive-smoke", fs::generated::kBinDriveSmokeBytes, fs::generated::kBinDriveSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-conio-smoke", fs::generated::kBinConioSmokeBytes, fs::generated::kBinConioSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-mbcs-smoke", fs::generated::kBinMbcsSmokeBytes, fs::generated::kBinMbcsSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-fpcontrol-smoke", fs::generated::kBinFpcontrolSmokeBytes,
                        fs::generated::kBinFpcontrolSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-locale2-smoke", fs::generated::kBinLocale2SmokeBytes,
                        fs::generated::kBinLocale2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-gdiplus-smoke", fs::generated::kBinGdiplusSmokeBytes,
                        fs::generated::kBinGdiplusSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dde-smoke", fs::generated::kBinDdeSmokeBytes, fs::generated::kBinDdeSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-stream-smoke", fs::generated::kBinStreamSmokeBytes,
                        fs::generated::kBinStreamSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-setupapi-smoke", fs::generated::kBinSetupapiSmokeBytes,
                        fs::generated::kBinSetupapiSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-asyn-smoke", fs::generated::kBinAsynSmokeBytes, fs::generated::kBinAsynSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wndmsg-smoke", fs::generated::kBinWndmsgSmokeBytes,
                        fs::generated::kBinWndmsgSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-scrap-smoke", fs::generated::kBinScrapSmokeBytes, fs::generated::kBinScrapSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-trace-smoke", fs::generated::kBinTraceSmokeBytes, fs::generated::kBinTraceSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wmi-smoke", fs::generated::kBinWmiSmokeBytes, fs::generated::kBinWmiSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-enviro-smoke", fs::generated::kBinEnviroSmokeBytes,
                        fs::generated::kBinEnviroSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-select-smoke", fs::generated::kBinSelectSmokeBytes,
                        fs::generated::kBinSelectSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-proc2-smoke", fs::generated::kBinProc2SmokeBytes, fs::generated::kBinProc2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-find-smoke", fs::generated::kBinFindSmokeBytes, fs::generated::kBinFindSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-iocp2-smoke", fs::generated::kBinIocp2SmokeBytes, fs::generated::kBinIocp2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-signal-smoke", fs::generated::kBinSignalSmokeBytes,
                        fs::generated::kBinSignalSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-timer-smoke", fs::generated::kBinTimerSmokeBytes, fs::generated::kBinTimerSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-pe-stress", fs::generated::kBinPeStressBytes, fs::generated::kBinPeStressBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-net-loopback", fs::generated::kBinNetLoopbackSmokeBytes,
                        fs::generated::kBinNetLoopbackSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-winsock-ext-smoke", fs::generated::kBinWinsockExtSmokeBytes,
                        fs::generated::kBinWinsockExtSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-key-smoke", fs::generated::kBinKeySmokeBytes, fs::generated::kBinKeySmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-reg2-smoke", fs::generated::kBinReg2SmokeBytes, fs::generated::kBinReg2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-paths2-smoke", fs::generated::kBinPaths2SmokeBytes,
                        fs::generated::kBinPaths2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-advapi-smoke", fs::generated::kBinAdvapiSmokeBytes,
                        fs::generated::kBinAdvapiSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-heap3-smoke", fs::generated::kBinHeap3SmokeBytes, fs::generated::kBinHeap3SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-thread3-smoke", fs::generated::kBinThread3SmokeBytes,
                        fs::generated::kBinThread3SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wstr-smoke", fs::generated::kBinWstrSmokeBytes, fs::generated::kBinWstrSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-intl-smoke", fs::generated::kBinIntlSmokeBytes, fs::generated::kBinIntlSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-disp-smoke", fs::generated::kBinDispSmokeBytes, fs::generated::kBinDispSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-svc-ctrl-smoke", fs::generated::kBinSvcCtrlSmokeBytes,
                        fs::generated::kBinSvcCtrlSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-sysinfo-smoke", fs::generated::kBinSysinfoSmokeBytes,
                        fs::generated::kBinSysinfoSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-mem2-smoke", fs::generated::kBinMem2SmokeBytes, fs::generated::kBinMem2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-fs2-smoke", fs::generated::kBinFs2SmokeBytes, fs::generated::kBinFs2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-console3-smoke", fs::generated::kBinConsole3SmokeBytes,
                        fs::generated::kBinConsole3SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-xml-smoke", fs::generated::kBinXmlSmokeBytes, fs::generated::kBinXmlSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-reg3-smoke", fs::generated::kBinReg3SmokeBytes, fs::generated::kBinReg3SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-proc3-smoke", fs::generated::kBinProc3SmokeBytes, fs::generated::kBinProc3SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-com2-smoke", fs::generated::kBinCom2SmokeBytes, fs::generated::kBinCom2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-advmem-smoke", fs::generated::kBinAdvmemSmokeBytes,
                        fs::generated::kBinAdvmemSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-wstr2-smoke", fs::generated::kBinWstr2SmokeBytes, fs::generated::kBinWstr2SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-fs3-smoke", fs::generated::kBinFs3SmokeBytes, fs::generated::kBinFs3SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-cap-smoke", fs::generated::kBinCapSmokeBytes, fs::generated::kBinCapSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-utf16-smoke", fs::generated::kBinUtf16SmokeBytes, fs::generated::kBinUtf16SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-handle2-smoke", fs::generated::kBinHandle2SmokeBytes,
                        fs::generated::kBinHandle2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-sock-opt-smoke", fs::generated::kBinSockOptSmokeBytes,
                        fs::generated::kBinSockOptSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-prio-smoke", fs::generated::kBinPrioSmokeBytes, fs::generated::kBinPrioSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-debug2-smoke", fs::generated::kBinDebug2SmokeBytes,
                        fs::generated::kBinDebug2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            // DirectX v0 smoke suite — exercises the existing d3d{9,11,12}
            // Clear+Present pipelines through real COM vtable calls plus the
            // new dinput8/xinput/xaudio2/dsound/ddraw/d2d1/dwrite peripheral
            // DLLs.
            SpawnPeFile("ring3-d3d11-smoke", fs::generated::kBinD3d11SmokeBytes, fs::generated::kBinD3d11SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-d3d12-smoke", fs::generated::kBinD3d12SmokeBytes, fs::generated::kBinD3d12SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-d3d9-smoke", fs::generated::kBinD3d9SmokeBytes, fs::generated::kBinD3d9SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dinput8-smoke", fs::generated::kBinDinput8SmokeBytes,
                        fs::generated::kBinDinput8SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-xinput-smoke", fs::generated::kBinXinputSmokeBytes,
                        fs::generated::kBinXinputSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-xaudio2-smoke", fs::generated::kBinXaudio2SmokeBytes,
                        fs::generated::kBinXaudio2SmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dsound-smoke", fs::generated::kBinDsoundSmokeBytes,
                        fs::generated::kBinDsoundSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-ddraw-smoke", fs::generated::kBinDdrawSmokeBytes, fs::generated::kBinDdrawSmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-d2d1-smoke", fs::generated::kBinD2d1SmokeBytes, fs::generated::kBinD2d1SmokeBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            SpawnPeFile("ring3-dwrite-smoke", fs::generated::kBinDwriteSmokeBytes,
                        fs::generated::kBinDwriteSmokeBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            // dx_demo: the comprehensive DirectX exercise — pre-transforms a
            // 24-vertex cube to clip space and rasterizes it through D3D9 (FF
            // transforms), D3D11 and D3D12 (CPU-pretransformed verts), then
            // reads back the back-buffer pixels and asserts at least one face
            // is visible per backend.
            SpawnPeFile("ring3-dx-demo", fs::generated::kBinDxDemoBytes, fs::generated::kBinDxDemoBytes_len,
                        CapSetTrusted(), fs::RamfsTrustedRoot(), mm::kFrameBudgetTrusted, kTickBudgetTrusted);
            // Windowing v0 proof: a freestanding PE that imports
            // user32!CreateWindowExA + ShowWindow + MessageBoxA and
            // calls them. The Win32 → SYS_WIN_CREATE bridge turns
            // those into real compositor-managed windows. Expected
            // serial log lines: [msgbox] ... then [win] create pid=...
            // hwnd=N rect=(500,400 420x220) title="WINDOWED HELLO".
            // Sleep(20s) keeps the window visible long enough for the
            // screenshot script's settle window to capture it. The
            // 20-second Sleep is HPET-real-time even under HLT idle,
            // and the boot smoke doesn't check the [msgbox] /
            // [win create] output (the screenshot harness does, on
            // bare-metal-equivalent runs) — already covered by the
            // outer `!emulator` gate.
            SpawnPeFile("ring3-windowed-hello", fs::generated::kBinWindowedHelloBytes,
                        fs::generated::kBinWindowedHelloBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        } // end !emulator gate
        // dx_demo_window: visible 3D cube via D3D11 swap chain bound to
        // a real HWND. Sleep(17s) keeps the window on-screen long enough
        // for tools/qemu/screenshot.sh to capture the painted back-buffer
        // BitBlt. Spawned for profile=None only — that's the screenshot
        // harness path (tools/qemu/run.sh with no DUETOS_SMOKE_PROFILE),
        // which boots into emulator + needs the cube on screen. Under a
        // smoke profile (Ring3 in particular) the cube isn't asserted by
        // the harness and the 17s Sleep + 38-DLL preload would burn the
        // whole wall budget on TCG without contributing any signal.
        if (::duetos::test::SmokeProfileGet() == ::duetos::test::SmokeProfile::None)
        {
            SpawnPeFile("ring3-dx-demo-window", fs::generated::kBinDxDemoWindowBytes,
                        fs::generated::kBinDxDemoWindowBytes_len, CapSetTrusted(), fs::RamfsTrustedRoot(),
                        mm::kFrameBudgetTrusted, kTickBudgetTrusted);
        }
    } // end SmokeProfileShouldSpawn(Ring3) gate
    Log(LogLevel::Info, "core/ring3",
        "ring3 smoke tasks queued (incl cpu-hog + hostile + dropcaps + priv + badint + kread + "
        "ptrfuzz + writefuzz + hellope + winkill-report + thread-stress + syscall-stress + "
        "customdll-test)");
    // Canonical PE-compat smoke battery anchor. ctest's
    // duetos-boot-smoke greps for this exact line to confirm
    // every surface-coverage PE spawn fired and the battery
    // completed. The line is intentionally bare-bones — a
    // single grep-able sentinel beats a structured PASS/FAIL
    // tally that depends on every PE emitting in a uniform
    // shape (they don't; each one prints its own PASS/FAIL
    // per-API). The per-PE pass/fail signal stays in the
    // existing expected[] list in ctest-boot-smoke.sh.
    arch::SerialWrite("[pe-compat-smoke] battery complete\n");
}

} // namespace duetos::core
