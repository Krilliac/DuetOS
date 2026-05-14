/*
 * DuetOS — canonical ring-3 process spawn API: implementation.
 *
 * Companion to spawn.h — see there for the contract and the
 * rationale for living outside `proc/ring3_smoke.{h,cpp}`. The
 * four entry points (`Ring3UserEntry`, `SpawnElfFile`,
 * `SpawnElfLinux`, `SpawnPeFile`) are the kernel's only
 * loader-bridging surface for turning in-RAM image bytes into a
 * running ring-3 process. Every non-probe caller — shell `exec`,
 * SYS_SPAWN, the desktop /APPS launcher, init's user-shell
 * launch, live-update's reload, the Linux smoke fixtures — goes
 * through this TU.
 */

#include "proc/spawn.h"

#include "arch/x86_64/gdt.h"
#include "arch/x86_64/hypervisor.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/usermode.h"
#include "core/init.h"
#include "core/panic.h"
#include "cpu/percpu.h"
#include "debug/inspect.h"
#include "fs/fat32.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "mm/kheap.h"
#include "loader/dll_loader.h"
#include "loader/elf_loader.h"
#include "loader/pe_loader.h"
#include "log/klog.h"
#include "mm/address_space.h"
#include "mm/frame_allocator.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "proc/process.h"
#include "sched/sched.h"
#include "subsystems/win32/heap.h"
#include "util/random.h"

// Win32 DLL preload table — every Win32-imports PE gets these
// pre-loaded into its AS BEFORE PeLoad runs so ResolveImports
// can walk their EATs. The list is authoritative; adding a new
// preload DLL is a one-line append once the blob is embedded via
// CMake.
#include "generated_advapi32_dll.h"
#include "generated_advapi32_32_dll.h"
#include "generated_bcrypt_dll.h"
#include "generated_bcrypt_32_dll.h"
#include "generated_comctl32_dll.h"
#include "generated_comctl32_32_dll.h"
#include "generated_comdlg32_dll.h"
#include "generated_comdlg32_32_dll.h"
#include "generated_crypt32_dll.h"
#include "generated_crypt32_32_dll.h"
#include "generated_customdll.h"
#include "generated_customdll2.h"
#include "generated_d2d1_dll.h"
#include "generated_d3d11_dll.h"
#include "generated_d3d12_dll.h"
#include "generated_d3d9_dll.h"
#include "generated_d3dcompiler_dll.h"
#include "generated_dbghelp_dll.h"
#include "generated_ddraw_dll.h"
#include "generated_dinput8_dll.h"
#include "generated_dsound_dll.h"
#include "generated_dwmapi_dll.h"
#include "generated_dwrite_dll.h"
#include "generated_dxgi_dll.h"
#include "generated_gdi32_dll.h"
#include "generated_gdi32_32_dll.h"
#include "generated_iphlpapi_dll.h"
#include "generated_iphlpapi_32_dll.h"
#include "generated_kernel32_dll.h"
#include "generated_kernel32_32_dll.h"
#include "generated_kernelbase_dll.h"
#include "generated_msvcp140_dll.h"
#include "generated_msvcrt_dll.h"
#include "generated_msvcrt_32_dll.h"
#include "generated_ntdll_dll.h"
#include "generated_ole32_dll.h"
#include "generated_oleaut32_dll.h"
#include "generated_psapi_dll.h"
#include "generated_secur32_dll.h"
#include "generated_setupapi_dll.h"
#include "generated_shell32_dll.h"
#include "generated_shell32_32_dll.h"
#include "generated_shlwapi_dll.h"
#include "generated_shlwapi_32_dll.h"
#include "generated_ucrtbase_dll.h"
#include "generated_user32_dll.h"
#include "generated_user32_32_dll.h"
#include "generated_userenv_dll.h"
#include "generated_uxtheme_dll.h"
#include "generated_vcruntime140_dll.h"
#include "generated_version_dll.h"
#include "generated_winhttp_dll.h"
#include "generated_wininet_dll.h"
#include "generated_winmm_dll.h"
#include "generated_ws2_32_dll.h"
#include "generated_ws2_32_32_dll.h"
#include "generated_wtsapi32_dll.h"
#include "generated_xaudio2_8_dll.h"
#include "generated_xinput1_4_dll.h"

namespace duetos::core
{

// Entry point for every ring-3 task created via SchedCreateUser.
// Runs in ring 0 on a fresh kernel stack with the task's own AS
// already loaded in CR3 (Schedule() flipped it on first switch-in).
// Reads user_code_va / user_stack_va from CurrentProcess() so a
// caller-configured layout (ASLR'd smoke tasks, ELF-loaded tasks
// at 0x400000 / 0x7FFFE000, etc.) is picked up automatically.
//
// Exposed via spawn.h so non-ring3 callers (syscall dispatch,
// shell `exec`, the desktop launcher) can hand it to
// SchedCreateUser too.
[[noreturn]] void Ring3UserEntry(void*)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;

    const u64 kstack_top = sched::SchedCurrentKernelStackTop();
    if (kstack_top == 0)
    {
        Panic("core/ring3", "SchedCurrentKernelStackTop returned 0");
    }
    arch::TssSetRsp0(kstack_top);
    // Mirror into the per-CPU slot used by the Linux-ABI syscall
    // entry stub. See kernel/cpu/percpu.h for the field; same
    // pattern as the scheduler's context-switch path.
    cpu::CurrentCpu()->kernel_rsp = kstack_top;

    Process* proc = CurrentProcess();
    if (proc == nullptr)
    {
        Panic("core/ring3", "Ring3UserEntry without a Process");
    }
    const u64 code_va = proc->user_code_va;
    // Both SysV and Microsoft x64 ABIs expect rsp % 16 == 8 on
    // function entry — i.e., the caller has already pushed an
    // 8-byte return address before the call. When we iretq
    // into user code, no return address has been pushed, so
    // rsp would be exactly page-aligned (%16 == 0) without
    // this adjustment and any movaps against rsp-relative
    // offsets inside the function prologue would #GP. Bias
    // rsp by -8 once, up front, so the ring-3 entry point
    // sees the same layout it would on a CALL.
    //
    // Linux-ABI tasks override this via proc->user_rsp_init —
    // the loader has pre-populated argc/argv/envp/auxv at the
    // top of the stack page and picked an rsp that lands user
    // _start on `argc` (which satisfies its own 16-alignment
    // requirement without the -8 bias, since the Linux initial
    // stack shape has argc at a 16-aligned boundary).
    const u64 stack_top = (proc->user_rsp_init != 0) ? proc->user_rsp_init : (proc->user_stack_va + mm::kPageSize - 8);

    SerialWrite("[ring3] task pid=");
    SerialWriteHex(sched::CurrentTaskId());
    SerialWrite(" entering ring 3 rip=");
    SerialWriteHex(code_va);
    SerialWrite(" rsp=");
    SerialWriteHex(stack_top);
    if (proc->user_is_pe32)
        SerialWrite(" mode=pe32");
    if (proc->user_gs_base != 0)
    {
        SerialWrite(" gs_base=");
        SerialWriteHex(proc->user_gs_base);
    }
    SerialWrite("\n");

    if (proc->user_is_pe32)
    {
        // PE32 (i386) task: enter compat mode via the 32-bit user
        // CS (0x3B). FSBASE = TEB VA so fs:[0x18] (Self) /
        // fs:[0x30] (PEB) reads in compat mode hit the TEB page
        // the loader mapped at proc->user_gs_base. Pass via rdx
        // (third arg).
        arch::EnterUserMode32(code_va, stack_top, proc->user_gs_base);
    }
    arch::EnterUserModeWithGs(code_va, stack_top, proc->user_gs_base);
}

u64 SpawnElfFile(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                 u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (elf_bytes == nullptr || elf_len == 0 || root == nullptr)
    {
        return 0;
    }
    // Auto-detect Linux-ABI binaries by EI_OSABI byte at ELF
    // offset 7. ELFOSABI_LINUX = 3. Most gcc/clang output uses
    // ELFOSABI_SYSV = 0 (which we treat as native); only binaries
    // explicitly marked Linux route through SpawnElfLinux so the
    // caller's intent is preserved for ambiguous inputs. When a
    // richer discriminator lands (PT_INTERP sniffing,
    // `.note.ABI-tag` parsing), add it here.
    if (elf_len > 7 && elf_bytes[7] == 3)
    {
        return SpawnElfLinux(name, elf_bytes, elf_len, caps, root, frame_budget, tick_budget);
    }
    // Fire the `inspect arm` latch if the operator armed it
    // before spawning. No-op when unarmed; one-shot when armed.
    duetos::debug::InspectOnSpawn(name, elf_bytes, elf_len);
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    const ElfLoadResult r = ElfLoad(elf_bytes, elf_len, as);
    if (!r.ok)
    {
        // ElfLoad may have installed partial mappings; Release
        // walks the AS's user-region table and frees whatever
        // landed.
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    SerialWrite("[ring3] elf spawn name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" entry=");
    SerialWriteHex(r.entry_va);
    SerialWrite(" stack_top=");
    SerialWriteHex(r.stack_top);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

u64 SpawnElfLinux(const char* name, const u8* elf_bytes, u64 elf_len, CapSet caps, const fs::RamfsNode* root,
                  u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (elf_bytes == nullptr || elf_len == 0 || root == nullptr)
    {
        return 0;
    }
    duetos::debug::InspectOnSpawn(name, elf_bytes, elf_len);
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    const ElfLoadResult r = ElfLoad(elf_bytes, elf_len, as);
    if (!r.ok)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    // Flip the ABI flavor + seed Linux heap/mmap anchors. The ELF
    // loader doesn't know which ABI the image targets; we decide
    // here. kAbiLinux steers this task's `syscall` instructions
    // through subsystems::linux::LinuxSyscallDispatch instead of
    // the native int-0x80 table.
    //
    // brk base: well past any reasonable static ELF's highest
    // PT_LOAD. Our smokes load at 0x400078; 256 MiB past that is
    // plenty of headroom without poking into the 0x7fffe000
    // stack. A future loader pass will compute this from the
    // max p_vaddr+p_memsz; v0 hard-codes.
    //
    // mmap cursor: 112 TiB up — well clear of everything else
    // in the user half.
    proc->abi_flavor = kAbiLinux;
    proc->linux_brk_base = 0x0000'0000'1000'0000ull; // 256 MiB
    proc->linux_brk_current = proc->linux_brk_base;
    proc->linux_mmap_cursor = 0x0000'7000'0000'0000ull;

    // Populate the top of the user stack with a Linux-ABI initial
    // layout. Musl's _start reads from rsp; the layout is
    // (rsp -> higher addresses):
    //
    //   [rsp_init +  0]: argc = 0
    //   [rsp_init +  8]: argv[0] = NULL
    //   [rsp_init + 16]: envp[0] = NULL
    //   [rsp_init + 24]: AT_PAGESZ  = 6
    //   [rsp_init + 32]: page size  = 4096
    //   [rsp_init + 40]: AT_RANDOM  = 25
    //   [rsp_init + 48]: rand_ptr   = rsp_init + 72
    //   [rsp_init + 56]: AT_NULL    = 0
    //   [rsp_init + 64]: auxv end   = 0
    //   [rsp_init + 72]: 16 bytes of xorshift-mixed rdtsc entropy
    //   [rsp_init + 88]: 8 bytes pad (keep rsp_init 16-aligned)
    //
    // 96 bytes total. musl uses AT_PAGESZ for mmap bookkeeping
    // and AT_RANDOM as a stack-cookie / pointer-mangling seed.
    // AT_PHDR / AT_EXECFN are not supplied; musl skips what it
    // can't find and pulls program-header info from the ELF it
    // loaded itself (works for static binaries).
    const PhysAddr stack_frame = AddressSpaceLookupUserFrame(as, r.stack_va);
    if (stack_frame != kNullFrame)
    {
        auto* stack_direct = static_cast<u8*>(PhysToVirt(stack_frame));
        const u64 off = mm::kPageSize - 96;
        for (u64 i = 0; i < 96; ++i)
            stack_direct[off + i] = 0;
        const u64 rsp_init = r.stack_top - 96;

        auto put_u64 = [&](u64 at, u64 v)
        {
            for (u64 i = 0; i < 8; ++i)
                stack_direct[off + at + i] = static_cast<u8>(v >> (i * 8));
        };
        // argc / argv[0] / envp[0] already zeroed.
        // Aux vector.
        put_u64(24, 6);             // AT_PAGESZ
        put_u64(32, 4096);          // page size
        put_u64(40, 25);            // AT_RANDOM
        put_u64(48, rsp_init + 72); // pointer (user VA) to random block
        put_u64(56, 0);             // AT_NULL
        put_u64(64, 0);             // terminator value
        // Fill the 16-byte AT_RANDOM block from the kernel
        // entropy pool. Linux userland libc (glibc, musl)
        // consumes these bytes for stack-cookie + pointer
        // obfuscation at startup, so real entropy here gives
        // a ported userland the same hardening it expects on
        // bare Linux.
        duetos::core::RandomFillBytes(stack_direct + off + 72, 16);
        proc->user_rsp_init = rsp_init;
    }

    SerialWrite("[ring3] linux elf spawn name=\"");
    SerialWrite(name);
    SerialWrite("\" pid=");
    SerialWriteHex(proc->pid);
    SerialWrite(" entry=");
    SerialWriteHex(r.entry_va);
    SerialWrite(" stack_top=");
    SerialWriteHex(r.stack_top);
    SerialWrite("\n");
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

// PE twin of SpawnElfFile. Parses a PE/COFF image with the
// v0 loader, maps its sections + a stack page into a fresh
// AddressSpace, and enqueues a ring-3 task to enter it. The
// process-level glue (Process / Ring3UserEntry / EnterUserMode)
// does NOT care whether the image came from an ELF or a PE —
// once the entry_va + stack_top are set, the ring-3 transition
// is identical.
u64 SpawnPeFile(const char* name, const u8* pe_bytes, u64 pe_len, CapSet caps, const fs::RamfsNode* root,
                u64 frame_budget, u64 tick_budget)
{
    using arch::SerialWrite;
    using arch::SerialWriteHex;
    using namespace duetos::mm;

    if (pe_bytes == nullptr || pe_len == 0 || root == nullptr)
    {
        return 0;
    }
    duetos::debug::InspectOnSpawn(name, pe_bytes, pe_len);
    // Diagnostic pre-pass — sections, imports, relocs, TLS. Skip
    // under a hypervisor: every line is N port-IO writes that
    // trap out of KVM (or, on TCG, runs at TCG speed). For
    // ring3-winkill alone this is ~500-1000 lines; the qemu-smoke
    // CI doesn't check any [pe-report] output, so paying the cost
    // there directly squeezes the wall-clock budget for no signal.
    // Bare metal still gets the full diagnostic dump.
    const bool emulator_pe_report = ::duetos::arch::IsEmulator();
    if (!emulator_pe_report)
    {
        SerialWrite("[ring3] pe report name=\"");
        SerialWrite(name);
        SerialWrite("\"\n");
        PeReport(pe_bytes, pe_len);
    }

    // PeLoad handles both Ok and ImportsPresent (the latter
    // by walking the IAT and patching via the Win32 stub
    // table). Any other non-Ok status is fatal — log and
    // bail. For ImportsPresent we don't bail here; PeLoad may
    // still fail if a specific import isn't in the stub
    // table, at which point ok=false and we fall through to
    // the generic "load failed" cleanup below.
    const PeStatus vs = PeValidate(pe_bytes, pe_len);
    if (vs != PeStatus::Ok && vs != PeStatus::ImportsPresent && vs != PeStatus::TlsPresent)
    {
        SerialWrite("[ring3] pe reject name=\"");
        SerialWrite(name);
        SerialWrite("\" reason=");
        SerialWrite(PeStatusName(vs));
        SerialWrite("\n");
        return 0;
    }
    // Bitness probe: drives the preload-set pick below. PE32 (i386)
    // images get the i386 DLL set (currently just kernel32_32.dll);
    // PE32+ images get the existing 44-DLL preload list.
    const bool pe_is_pe32 = duetos::core::PeIsPe32(pe_bytes, pe_len);
    AddressSpace* as = AddressSpaceCreate(frame_budget);
    if (as == nullptr)
    {
        return 0;
    }
    // Per-process ASLR: pick a 64 KiB-aligned delta in [0, 64 MiB).
    // 10 bits of entropy × 64 KiB = 1024 possible positions. Kept
    // modest so the shifted ImageBase can't collide with the
    // fixed-VA subsystem regions (win32 heap at 0x50000000, stubs
    // at 0x60000000, proc-env at 0x65000000, TEB at 0x70000000,
    // stack ending at 0x80000000). A PE's preferred base is
    // typically 0x140000000 — well above those — so adding up to
    // ~64 MiB keeps us safely in the 0x140000000..0x144000000
    // band.
    //
    // ASLR is gated on IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    // (Win32 PEs without `/DYNAMICBASE` load at their preferred
    // base — the assumption being that they may have hard-coded
    // addresses they expect to find populated). PEs built with
    // modern MSVC defaults all set this flag.
    const bool dynamic_base = duetos::core::PeIsDynamicBase(pe_bytes, pe_len);
    const u64 entropy = duetos::core::RandomU64();
    const u64 aslr_delta = dynamic_base ? (entropy & 0x3FF) * (64ULL * 1024) : 0ULL;

    // Pre-load the per-spawn DLL set into
    // `as` BEFORE PeLoad runs so ResolveImports can consult
    // their EATs. Each DllImage lives on this stack frame for
    // the duration of PeLoad; after ProcessCreate we copy them
    // into the Process's permanent dll_images[] table. Only
    // preload when the PE has imports (vs == ImportsPresent) —
    // freestanding PEs don't need DLLs and would pay the frame
    // cost for nothing.
    //
    // The table below is the authoritative list of DLLs that
    // every Win32-imports PE gets pre-loaded. Adding a new DLL
    // here is a one-line append once the blob is embedded via
    // CMake. `kPreloadSlotCap` caps the stack-local array size;
    // bump if the list grows past it.
    constexpr u64 kPreloadSlotCap = 56;
    struct PreloadDllEntry
    {
        const char* label; // diagnostic name for boot-log
        const u8* bytes;   // kernel direct-map pointer to the blob
        u64 len;           // blob size in bytes
        bool essential;    // false = skip under arch::IsEmulator() to
                           //         keep the per-PE preload chain
                           //         short on CI (each DllLoad is a
                           //         page alloc + PE parse + EAT walk;
                           //         under TCG/oversubscribed-KVM that
                           //         compounds to seconds of guest
                           //         time per PE × 2 Win32 PEs left
                           //         in the post-trim emulator path).
                           //         "essential" = the 3 essential
                           //         PEs (hello-pe, hello-winapi,
                           //         winkill) actually walk one of
                           //         this DLL's exports during their
                           //         imported-function chain.
    };
    // `static` so the array lives in .rodata and the
    // initializer doesn't compile to a runtime memcpy from a
    // template — the kernel doesn't link libc.
    static const PreloadDllEntry preload_set[] = {
        // customdll{,2}.dll — fixtures for ring3-customdll-test,
        // which is itself gated under !emulator. Skip the preload
        // when the consumer isn't going to spawn.
        {"customdll.dll", fs::generated::kBinCustomDllBytes, fs::generated::kBinCustomDllBytes_len,
         /*essential=*/false},
        {"customdll2.dll", fs::generated::kBinCustomDll2Bytes, fs::generated::kBinCustomDll2Bytes_len,
         /*essential=*/false},
        // kernel32.dll — 32 exports covering process/thread
        // identity, pseudo-handles, last-error, terminators,
        // safe-ignore shims, GetStdHandle, Sleep /
        // SwitchToThread / GetTickCount(64), and the full
        // Interlocked* family (32 + 64-bit). The via-DLL path in
        // ResolveImports matches kernel32.dll BEFORE falling
        // through to the hand-assembled stubs page. Stubs stay
        // as dead-code fallback; sweep later.
        {"kernel32.dll", fs::generated::kBinKernel32DllBytes, fs::generated::kBinKernel32DllBytes_len,
         /*essential=*/true},
        // vcruntime140.dll — memset / memcpy / memmove. Every
        // MSVC-built PE calls these for struct copy / zero-init
        // / CRT startup. The via-DLL path now fires for each.
        {"vcruntime140.dll", fs::generated::kBinVcruntime140DllBytes, fs::generated::kBinVcruntime140DllBytes_len,
         /*essential=*/true},
        // msvcrt.dll — string intrinsics
        // (strlen / strcmp / strcpy / strchr + wide variants).
        // Retires the corresponding flat stubs.
        {"msvcrt.dll", fs::generated::kBinMsvcrtDllBytes, fs::generated::kBinMsvcrtDllBytes_len,
         /*essential=*/true},
        // ucrtbase.dll — UCRT runtime: heap
        // (malloc/free/calloc/realloc/_aligned_*), terminators
        // (exit/_exit), CRT startup shims (_initterm,
        // _set_app_type, ...), string intrinsics. Retires the
        // corresponding flat stubs.
        {"ucrtbase.dll", fs::generated::kBinUcrtbaseDllBytes, fs::generated::kBinUcrtbaseDllBytes_len,
         /*essential=*/true},
        // ntdll.dll — Nt* / Zw* / Rtl* / Ldr* / __chkstk.
        // 108 exports. Retires the prior ntdll flat stubs.
        // Zw* are same-DLL forwarders to Nt*;
        // STATUS_NOT_IMPLEMENTED aliases centralise on
        // NtReturnNotImpl.
        {"ntdll.dll", fs::generated::kBinNtdllDllBytes, fs::generated::kBinNtdllDllBytes_len,
         /*essential=*/true},
        // dbghelp.dll — 11 Sym* / StackWalk / MiniDumpWriteDump
        // no-ops. Callers check returns; v0 has no PDB parser
        // or stack walker.
        {"dbghelp.dll", fs::generated::kBinDbghelpDllBytes, fs::generated::kBinDbghelpDllBytes_len,
         /*essential=*/true},
        // msvcp140.dll — 17 C++ std:: throw helpers + ostream
        // stubs via mangled-name .def aliases. Throw paths
        // terminate with SYS_EXIT(3).
        {"msvcp140.dll", fs::generated::kBinMsvcp140DllBytes, fs::generated::kBinMsvcp140DllBytes_len,
         /*essential=*/true},
        // kernelbase.dll — pure forwarders to kernel32.dll
        // (44 entries). Resolved at IAT-patch time via the
        // forwarder chaser.
        {"kernelbase.dll", fs::generated::kBinKernelbaseDllBytes, fs::generated::kBinKernelbaseDllBytes_len,
         /*essential=*/true},
        // advapi32.dll — Reg* (not-found),
        // token/privilege (success), GetUserName* (constant),
        // SystemFunction036 (deterministic RNG). 25 exports.
        {"advapi32.dll", fs::generated::kBinAdvapi32DllBytes, fs::generated::kBinAdvapi32DllBytes_len,
         /*essential=*/true},
        // Small stub DLLs for misc support surface. Most
        // return "not found" / success sentinels;
        // CoTaskMem* + SysAllocString alias the process heap.
        {"shlwapi.dll", fs::generated::kBinShlwapiDllBytes, fs::generated::kBinShlwapiDllBytes_len,
         /*essential=*/true},
        {"shell32.dll", fs::generated::kBinShell32DllBytes, fs::generated::kBinShell32DllBytes_len,
         /*essential=*/true},
        {"ole32.dll", fs::generated::kBinOle32DllBytes, fs::generated::kBinOle32DllBytes_len,
         /*essential=*/true},
        {"oleaut32.dll", fs::generated::kBinOleaut32DllBytes, fs::generated::kBinOleaut32DllBytes_len,
         /*essential=*/false},
        // winmm.dll — perf-counter / GetTickCount routes for
        // hello-winapi's [perf-counter] required-signature line.
        {"winmm.dll", fs::generated::kBinWinmmDllBytes, fs::generated::kBinWinmmDllBytes_len,
         /*essential=*/true},
        {"bcrypt.dll", fs::generated::kBinBcryptDllBytes, fs::generated::kBinBcryptDllBytes_len,
         /*essential=*/true},
        {"psapi.dll", fs::generated::kBinPsapiDllBytes, fs::generated::kBinPsapiDllBytes_len,
         /*essential=*/true},
        // DirectX v0 — d3d9/d3d11/d3d12/dxgi all carry real
        // COM-vtable implementations of the Clear-and-Present
        // pipeline (see userland/libs/d3d*/). Marked essential so
        // the d3d{9,11,12}_smoke + dxgi_smoke PEs find their
        // exports under the emulator preload trim. SYS_GFX_TRACE
        // counters tick from inside each Present.
        {"d3d9.dll", fs::generated::kBinD3d9DllBytes, fs::generated::kBinD3d9DllBytes_len,
         /*essential=*/true},
        {"d3d11.dll", fs::generated::kBinD3d11DllBytes, fs::generated::kBinD3d11DllBytes_len,
         /*essential=*/true},
        {"d3d12.dll", fs::generated::kBinD3d12DllBytes, fs::generated::kBinD3d12DllBytes_len,
         /*essential=*/true},
        {"dxgi.dll", fs::generated::kBinDxgiDllBytes, fs::generated::kBinDxgiDllBytes_len,
         /*essential=*/true},
        {"d3dcompiler.dll", fs::generated::kBinD3dcompilerDllBytes, fs::generated::kBinD3dcompilerDllBytes_len,
         /*essential=*/false},
        {"user32.dll", fs::generated::kBinUser32DllBytes, fs::generated::kBinUser32DllBytes_len,
         /*essential=*/true},
        {"gdi32.dll", fs::generated::kBinGdi32DllBytes, fs::generated::kBinGdi32DllBytes_len,
         /*essential=*/true},
        // Networking / crypto / common UI / version / setup.
        // ws2_32 is essential because mini_browser.exe imports it
        // and we exercise WSAStartup / gethostbyname / socket /
        // connect / send / recv / closesocket / WSACleanup as a
        // live HTTP probe to www.google.com.
        {"ws2_32.dll", fs::generated::kBinWs2_32DllBytes, fs::generated::kBinWs2_32DllBytes_len,
         /*essential=*/true},
        {"wininet.dll", fs::generated::kBinWininetDllBytes, fs::generated::kBinWininetDllBytes_len,
         /*essential=*/true},
        {"winhttp.dll", fs::generated::kBinWinhttpDllBytes, fs::generated::kBinWinhttpDllBytes_len,
         /*essential=*/true},
        {"crypt32.dll", fs::generated::kBinCrypt32DllBytes, fs::generated::kBinCrypt32DllBytes_len,
         /*essential=*/false},
        {"comctl32.dll", fs::generated::kBinComctl32DllBytes, fs::generated::kBinComctl32DllBytes_len,
         /*essential=*/false},
        {"comdlg32.dll", fs::generated::kBinComdlg32DllBytes, fs::generated::kBinComdlg32DllBytes_len,
         /*essential=*/false},
        {"version.dll", fs::generated::kBinVersionDllBytes, fs::generated::kBinVersionDllBytes_len,
         /*essential=*/true},
        {"setupapi.dll", fs::generated::kBinSetupapiDllBytes, fs::generated::kBinSetupapiDllBytes_len,
         /*essential=*/true},
        // Six more support DLLs — IP helper, user env,
        // terminal services, DWM, theming, SSPI.
        {"iphlpapi.dll", fs::generated::kBinIphlpapiDllBytes, fs::generated::kBinIphlpapiDllBytes_len,
         /*essential=*/true},
        {"userenv.dll", fs::generated::kBinUserenvDllBytes, fs::generated::kBinUserenvDllBytes_len,
         /*essential=*/true},
        {"wtsapi32.dll", fs::generated::kBinWtsapi32DllBytes, fs::generated::kBinWtsapi32DllBytes_len,
         /*essential=*/true},
        {"dwmapi.dll", fs::generated::kBinDwmapiDllBytes, fs::generated::kBinDwmapiDllBytes_len,
         /*essential=*/true},
        {"uxtheme.dll", fs::generated::kBinUxthemeDllBytes, fs::generated::kBinUxthemeDllBytes_len,
         /*essential=*/true},
        {"secur32.dll", fs::generated::kBinSecur32DllBytes, fs::generated::kBinSecur32DllBytes_len,
         /*essential=*/false},
        // DirectX peripheral DLLs v0 — input/audio/2D-blit/Direct2D/
        // DirectWrite. Marked essential so the matching smoke PEs find
        // their exports under the emulator preload trim.
        {"dinput8.dll", fs::generated::kBinDinput8DllBytes, fs::generated::kBinDinput8DllBytes_len,
         /*essential=*/true},
        {"xinput1_4.dll", fs::generated::kBinXinput1_4DllBytes, fs::generated::kBinXinput1_4DllBytes_len,
         /*essential=*/true},
        {"xaudio2_8.dll", fs::generated::kBinXaudio2_8DllBytes, fs::generated::kBinXaudio2_8DllBytes_len,
         /*essential=*/true},
        {"dsound.dll", fs::generated::kBinDsoundDllBytes, fs::generated::kBinDsoundDllBytes_len,
         /*essential=*/true},
        {"ddraw.dll", fs::generated::kBinDdrawDllBytes, fs::generated::kBinDdrawDllBytes_len,
         /*essential=*/true},
        {"d2d1.dll", fs::generated::kBinD2d1DllBytes, fs::generated::kBinD2d1DllBytes_len,
         /*essential=*/true},
        {"dwrite.dll", fs::generated::kBinDwriteDllBytes, fs::generated::kBinDwriteDllBytes_len,
         /*essential=*/true},
    };
    constexpr u64 kPreloadEntryCount = sizeof(preload_set) / sizeof(preload_set[0]);
    static_assert(kPreloadEntryCount <= kPreloadSlotCap, "Preload DLL list exceeds stack-local cap");

    // 32-bit (PE32) preload set. Today just one entry —
    // kernel32_32.dll — enough for pe32_smoke's ExitProcess
    // import. Grows as PE32 callers need more. Mapped at the same
    // ImageBase the DLL was built with (low 4 GiB).
    static const PreloadDllEntry preload_set_pe32[] = {
        {"kernel32.dll", fs::generated::kBinKernel32_32DllBytes, fs::generated::kBinKernel32_32DllBytes_len,
         /*essential=*/true},
        {"msvcrt.dll", fs::generated::kBinMsvcrt_32DllBytes, fs::generated::kBinMsvcrt_32DllBytes_len,
         /*essential=*/true},
        {"user32.dll", fs::generated::kBinUser32_32DllBytes, fs::generated::kBinUser32_32DllBytes_len,
         /*essential=*/true},
        {"gdi32.dll", fs::generated::kBinGdi32_32DllBytes, fs::generated::kBinGdi32_32DllBytes_len,
         /*essential=*/true},
        /* All PE32 stubs marked essential — they're each ~2-3 KiB
         * and DllLoad is microseconds. Skipping any of them under
         * emulator would leave the PE32 IAT walker falling back to
         * the (unmapped-for-PE32) Win32 thunks catch-all on every
         * unresolved import, defeating the whole point of the
         * 32-bit DLL set. */
        {"advapi32.dll", fs::generated::kBinAdvapi32_32DllBytes, fs::generated::kBinAdvapi32_32DllBytes_len,
         /*essential=*/true},
        {"comctl32.dll", fs::generated::kBinComctl32_32DllBytes, fs::generated::kBinComctl32_32DllBytes_len,
         /*essential=*/true},
        {"comdlg32.dll", fs::generated::kBinComdlg32_32DllBytes, fs::generated::kBinComdlg32_32DllBytes_len,
         /*essential=*/true},
        {"crypt32.dll", fs::generated::kBinCrypt32_32DllBytes, fs::generated::kBinCrypt32_32DllBytes_len,
         /*essential=*/true},
        {"iphlpapi.dll", fs::generated::kBinIphlpapi_32DllBytes, fs::generated::kBinIphlpapi_32DllBytes_len,
         /*essential=*/true},
        {"shell32.dll", fs::generated::kBinShell32_32DllBytes, fs::generated::kBinShell32_32DllBytes_len,
         /*essential=*/true},
        {"shlwapi.dll", fs::generated::kBinShlwapi_32DllBytes, fs::generated::kBinShlwapi_32DllBytes_len,
         /*essential=*/true},
        {"ws2_32.dll", fs::generated::kBinWs2_32_32DllBytes, fs::generated::kBinWs2_32_32DllBytes_len,
         /*essential=*/true},
        {"bcrypt.dll", fs::generated::kBinBcrypt_32DllBytes, fs::generated::kBinBcrypt_32DllBytes_len,
         /*essential=*/true},
    };
    constexpr u64 kPreloadPe32EntryCount = sizeof(preload_set_pe32) / sizeof(preload_set_pe32[0]);
    static_assert(kPreloadPe32EntryCount <= kPreloadSlotCap, "PE32 preload list exceeds cap");

    // Pick the bitness-correct list.
    const PreloadDllEntry* active_set = pe_is_pe32 ? preload_set_pe32 : preload_set;
    const u64 active_count = pe_is_pe32 ? kPreloadPe32EntryCount : kPreloadEntryCount;

    // Intentionally NOT value-initialised: zero-init of a 4-entry
    // DllImage array (~400 bytes) makes clang emit memset, which
    // the kernel doesn't link. We only ever read entries
    // [0..preloaded_count); each slot we read is fully assigned
    // just above the increment.
    DllImage preloaded_dlls[kPreloadSlotCap];
    u64 preloaded_count = 0;
    if (vs == PeStatus::ImportsPresent)
    {
        for (u64 i = 0; i < active_count; ++i)
        {
            // Under emulator: only preload entries marked
            // essential. The 3 PEs the boot smoke actually
            // checks (hello-pe, hello-winapi, winkill) walk
            // imports out of kernel32 / vcruntime140 / msvcrt /
            // ucrtbase / ntdll / dbghelp / msvcp140 / kernelbase /
            // advapi32 / winmm — every other DLL in the table is
            // a stub that the runtime never reaches. Skipping
            // them here trims ~26 DllLoads × 2 import-bearing PEs
            // off the post-bringup wall budget.
            if (emulator_pe_report && !active_set[i].essential)
            {
                continue;
            }
            // Per-DLL ASLR: gated on the DLL's own
            // IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE bit (every
            // modern MSVC-built DLL has it). 0..1 MiB jitter (8
            // bits × 4 KiB) drawn from RandomU64. Collision check
            // below ensures two DLLs with close preferred bases
            // (e.g. vcruntime140 at 0x10300000, xinput1_4 at
            // 0x10280000 — only 0.5 MiB apart) don't end up
            // mapped on top of each other after the jitter shifts
            // them. Without this, the second DllLoad silently
            // overwrites the first's pages and any IAT slot that
            // points into the first DLL's range now reads garbage
            // — typically manifesting as a ring-3 #GP/#UD/#PF at a
            // valid-looking RIP inside a previously-loaded DLL.
            const bool dll_dynamic_base = duetos::core::PeIsDynamicBase(active_set[i].bytes, active_set[i].len);
            u64 dll_aslr_delta = 0;
            DllLoadResult dll{};
            dll.status = DllLoadStatus::HeaderParseFailed;
            constexpr u32 kMaxRollAttempts = 32;
            for (u32 attempt = 0; attempt < kMaxRollAttempts; ++attempt)
            {
                const u64 dll_entropy = duetos::core::RandomU64();
                const u64 trial_delta = dll_dynamic_base ? (dll_entropy & 0xFF) * 4096ULL : 0ULL;
                // Peek at the would-be base+size so we can test
                // for overlap with already-loaded DLLs without
                // actually mapping pages. PeImageSizeOf returns 0
                // on parse failure; let DllLoad re-detect that.
                const u64 trial_size = duetos::core::PeImageSizeOf(active_set[i].bytes, active_set[i].len);
                const u64 trial_pref = duetos::core::PePreferredBaseOf(active_set[i].bytes, active_set[i].len);
                if (trial_size == 0 || trial_pref == 0)
                {
                    dll_aslr_delta = trial_delta;
                    dll = DllLoad(active_set[i].bytes, active_set[i].len, as, dll_aslr_delta);
                    break;
                }
                const u64 trial_base = trial_pref + trial_delta;
                bool collides = false;
                for (u64 j = 0; j < preloaded_count; ++j)
                {
                    const u64 a_start = preloaded_dlls[j].base_va;
                    const u64 a_end = a_start + preloaded_dlls[j].size;
                    const u64 b_start = trial_base;
                    const u64 b_end = b_start + trial_size;
                    if (a_start < b_end && b_start < a_end)
                    {
                        collides = true;
                        break;
                    }
                }
                if (collides && dll_dynamic_base)
                {
                    // Re-roll. Falls through to the no-jitter path
                    // on the last attempt to avoid an infinite
                    // wedge if 32 random pulls all collide.
                    if (attempt + 1 < kMaxRollAttempts)
                        continue;
                }
                dll_aslr_delta = trial_delta;
                dll = DllLoad(active_set[i].bytes, active_set[i].len, as, dll_aslr_delta);
                break;
            }
            if (dll.status == DllLoadStatus::Ok)
            {
                preloaded_dlls[preloaded_count] = dll.image;
                ++preloaded_count;
                SerialWrite("[ring3] pre-loaded ");
                SerialWrite(active_set[i].label);
                SerialWrite(" base=");
                SerialWriteHex(dll.image.base_va);
                SerialWrite(" aslr_delta=");
                SerialWriteHex(dll_aslr_delta);
                SerialWrite(" (pre-PeLoad — visible to ResolveImports)\n");
            }
            else
            {
                SerialWrite("[ring3] ");
                SerialWrite(active_set[i].label);
                SerialWrite(" DllLoad failed for \"");
                SerialWrite(name);
                SerialWrite("\" status=");
                SerialWrite(DllLoadStatusName(dll.status));
                SerialWrite(" — this DLL's exports won't be resolvable via-DLL\n");
            }
        }
    }

    // ----------------------------------------------------------
    // /lib/ ramfs DLL fallback. After the curated preload_set
    // above, walk the trusted `/lib/` directory and dynamically
    // load any *.dll file that isn't already in the preloaded
    // set. Mirrors what SYS_DLL_LOAD_FROM_PATH does at runtime
    // for LoadLibraryW callers — but here at PE-load time so
    // *statically*-imported DLLs not in the curated preload
    // also resolve via-DLL.
    //
    // The motivating case: a user drops a vendored Win32 DLL
    // (UnityPlayer.dll, a third-party plugin, etc.) into /lib/
    // and the loader picks it up without needing a CMake / embed
    // dance. The DLL still has to be a well-formed PE the
    // existing DllLoad understands.
    //
    // Skip:
    //   - the firmware directory entry (not a DLL)
    //   - any file whose name doesn't end in ".dll"
    //   - any DLL whose name already matches a preloaded entry
    //     (case-insensitive, suffix-tolerant — mirrors the
    //     match used in ResolveImports via-DLL path)
    if (preloaded_count < kPreloadSlotCap)
    {
        const fs::RamfsNode* lib_dir = fs::VfsLookup(fs::RamfsTrustedRoot(), "/lib", 8);
        if (lib_dir != nullptr && lib_dir->children != nullptr)
        {
            auto ends_with_dll_ci = [](const char* name)
            {
                u32 n = 0;
                while (name[n] != '\0')
                    ++n;
                if (n < 4)
                    return false;
                const char* t = name + n - 4;
                auto lo = [](char c) -> char { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
                return t[0] == '.' && lo(t[1]) == 'd' && lo(t[2]) == 'l' && lo(t[3]) == 'l';
            };
            auto base_name_ci_eq = [](const char* a, const char* b) -> bool
            {
                u32 i = 0;
                auto lo = [](char c) -> char { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
                while (a[i] != '\0' && b[i] != '\0')
                {
                    if (lo(a[i]) != lo(b[i]))
                        return false;
                    ++i;
                }
                return a[i] == b[i];
            };

            for (u64 k = 0; lib_dir->children[k] != nullptr && preloaded_count < kPreloadSlotCap; ++k)
            {
                const fs::RamfsNode* child = lib_dir->children[k];
                if (child->type != fs::RamfsNodeType::kFile)
                    continue;
                if (child->name == nullptr || child->file_bytes == nullptr || child->file_size == 0)
                    continue;
                if (!ends_with_dll_ci(child->name))
                    continue;
                // Skip if a DLL with this name is already preloaded.
                bool already = false;
                for (u64 j = 0; j < preloaded_count; ++j)
                {
                    if (!preloaded_dlls[j].has_exports)
                        continue;
                    const char* ename = PeExportsDllName(preloaded_dlls[j].exports);
                    if (ename != nullptr && base_name_ci_eq(ename, child->name))
                    {
                        already = true;
                        break;
                    }
                }
                if (already)
                    continue;
                // ASLR + collision-roll: same shape as the
                // curated preload above, but smaller — we
                // expect /lib/ to hold a handful of v0 DLLs.
                const bool dyn_base = duetos::core::PeIsDynamicBase(child->file_bytes, child->file_size);
                u64 lib_aslr_delta = 0;
                DllLoadResult dyn{};
                dyn.status = DllLoadStatus::HeaderParseFailed;
                constexpr u32 kMaxLibRoll = 32;
                for (u32 attempt = 0; attempt < kMaxLibRoll; ++attempt)
                {
                    const u64 trial = dyn_base ? (duetos::core::RandomU64() & 0xFF) * 4096ULL : 0ULL;
                    const u64 size = duetos::core::PeImageSizeOf(child->file_bytes, child->file_size);
                    const u64 pref = duetos::core::PePreferredBaseOf(child->file_bytes, child->file_size);
                    if (size == 0 || pref == 0)
                    {
                        lib_aslr_delta = trial;
                        dyn = DllLoad(child->file_bytes, child->file_size, as, lib_aslr_delta);
                        break;
                    }
                    bool collides = false;
                    for (u64 j = 0; j < preloaded_count; ++j)
                    {
                        const u64 a_start = preloaded_dlls[j].base_va;
                        const u64 a_end = a_start + preloaded_dlls[j].size;
                        const u64 b_start = pref + trial;
                        const u64 b_end = b_start + size;
                        if (a_start < b_end && b_start < a_end)
                        {
                            collides = true;
                            break;
                        }
                    }
                    if (collides && dyn_base && attempt + 1 < kMaxLibRoll)
                        continue;
                    lib_aslr_delta = trial;
                    dyn = DllLoad(child->file_bytes, child->file_size, as, lib_aslr_delta);
                    break;
                }
                if (dyn.status == DllLoadStatus::Ok)
                {
                    preloaded_dlls[preloaded_count] = dyn.image;
                    ++preloaded_count;
                    SerialWrite("[ring3] /lib auto-preload ");
                    SerialWrite(child->name);
                    SerialWrite(" base=");
                    SerialWriteHex(dyn.image.base_va);
                    SerialWrite(" (pre-PeLoad — visible to ResolveImports)\n");
                }
                else
                {
                    SerialWrite("[ring3] /lib skip ");
                    SerialWrite(child->name);
                    SerialWrite(" DllLoad failed: ");
                    SerialWrite(DllLoadStatusName(dyn.status));
                    SerialWrite("\n");
                }
            }
        }
    }

    // ----------------------------------------------------------
    // FAT32 `/lib/` DLL fallback. Lets a user install a vendored
    // Windows DLL via plain shell commands (wget -> unzip ->
    // place under /lib/) without rebuilding the kernel. Mirrors
    // the ramfs /lib/ scan above; the on-disk version uses a
    // small static cache so the same DLL isn't re-read + leaked
    // for every spawn.
    //
    // Cache: 16 slots, never freed. Per-DLL allocations land in
    // KMalloc and the AS borrows the pointer for the life of the
    // process. v0 simplification — a real refcount + free path
    // is a follow-on. The cache is keyed by the on-disk
    // filename; FAT32 short-name preservation makes that stable.
    {
        struct Fat32DllCacheEntry
        {
            char name[24];
            u8* bytes;
            u32 len;
        };
        static Fat32DllCacheEntry s_lib_cache[16] = {};

        auto find_cached = [&](const char* fname) -> Fat32DllCacheEntry*
        {
            for (auto& e : s_lib_cache)
            {
                if (e.bytes == nullptr)
                    continue;
                u32 i = 0;
                while (e.name[i] != '\0' && fname[i] != '\0' && e.name[i] == fname[i])
                    ++i;
                if (e.name[i] == fname[i])
                    return &e;
            }
            return nullptr;
        };
        auto add_to_cache = [&](const char* fname, u8* bytes, u32 len) -> bool
        {
            for (auto& e : s_lib_cache)
            {
                if (e.bytes != nullptr)
                    continue;
                u32 i = 0;
                while (fname[i] != '\0' && i + 1 < sizeof(e.name))
                {
                    e.name[i] = fname[i];
                    ++i;
                }
                e.name[i] = '\0';
                e.bytes = bytes;
                e.len = len;
                return true;
            }
            return false;
        };

        auto ends_with_dll = [](const char* fn)
        {
            u32 n = 0;
            while (fn[n] != '\0')
                ++n;
            if (n < 4)
                return false;
            const char* t = fn + n - 4;
            auto lo = [](char c) -> char { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
            return t[0] == '.' && lo(t[1]) == 'd' && lo(t[2]) == 'l' && lo(t[3]) == 'l';
        };

        if (preloaded_count < kPreloadSlotCap)
        {
            const fs::fat32::Volume* vol = fs::fat32::Fat32Volume(0);
            if (vol != nullptr)
            {
                // Walk /LIB on FAT32. ListDir reports each entry's
                // attributes + filename; .dll files get loaded.
                // FAT32 is case-insensitive — match on either
                // "lib" or "LIB".
                fs::fat32::DirEntry lib_dir{};
                bool have_lib = fs::fat32::Fat32LookupPath(vol, "/LIB", &lib_dir);
                if (!have_lib)
                    have_lib = fs::fat32::Fat32LookupPath(vol, "/lib", &lib_dir);
                if (have_lib && (lib_dir.attributes & 0x10) != 0)
                {
                    constexpr u32 kMaxFatDllListing = 32;
                    fs::fat32::DirEntry kids[kMaxFatDllListing];
                    const u32 count =
                        fs::fat32::Fat32ListDirByCluster(vol, lib_dir.first_cluster, kids, kMaxFatDllListing);
                    for (u32 ki = 0; ki < count && preloaded_count < kPreloadSlotCap; ++ki)
                    {
                        const auto& kid = kids[ki];
                        if ((kid.attributes & 0x10) != 0)
                            continue; // directory
                        if (!ends_with_dll(kid.name))
                            continue;
                        if (kid.size_bytes == 0 || kid.size_bytes > 64 * 1024 * 1024)
                            continue; // cap at 64 MiB per DLL
                        // Try cache.
                        u8* bytes = nullptr;
                        u32 len = 0;
                        if (auto* hit = find_cached(kid.name); hit != nullptr)
                        {
                            bytes = hit->bytes;
                            len = hit->len;
                        }
                        else
                        {
                            auto* buf = static_cast<u8*>(mm::KMalloc(kid.size_bytes));
                            if (buf == nullptr)
                                continue;
                            const auto rc = fs::fat32::Fat32ReadFile(vol, &kid, buf, kid.size_bytes);
                            if (rc != static_cast<i64>(kid.size_bytes))
                            {
                                mm::KFree(buf);
                                continue;
                            }
                            if (!add_to_cache(kid.name, buf, kid.size_bytes))
                            {
                                mm::KFree(buf);
                                continue;
                            }
                            bytes = buf;
                            len = kid.size_bytes;
                        }
                        // Skip if a DLL with this name is already preloaded.
                        bool already = false;
                        for (u64 j = 0; j < preloaded_count; ++j)
                        {
                            if (!preloaded_dlls[j].has_exports)
                                continue;
                            const char* ename = PeExportsDllName(preloaded_dlls[j].exports);
                            if (ename == nullptr)
                                continue;
                            // case-insensitive prefix match — FAT32
                            // short names are uppercase, EAT names may be
                            // mixed case.
                            u32 i = 0;
                            auto lo = [](char c) -> char
                            { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; };
                            while (ename[i] != '\0' && kid.name[i] != '\0' && lo(ename[i]) == lo(kid.name[i]))
                                ++i;
                            if (ename[i] == kid.name[i])
                            {
                                already = true;
                                break;
                            }
                        }
                        if (already)
                            continue;
                        const bool dyn_base = duetos::core::PeIsDynamicBase(bytes, len);
                        u64 lib_aslr_delta = 0;
                        DllLoadResult dyn{};
                        dyn.status = DllLoadStatus::HeaderParseFailed;
                        constexpr u32 kMaxFatRoll = 32;
                        for (u32 attempt = 0; attempt < kMaxFatRoll; ++attempt)
                        {
                            const u64 trial = dyn_base ? (duetos::core::RandomU64() & 0xFF) * 4096ULL : 0ULL;
                            const u64 size = duetos::core::PeImageSizeOf(bytes, len);
                            const u64 pref = duetos::core::PePreferredBaseOf(bytes, len);
                            if (size == 0 || pref == 0)
                            {
                                lib_aslr_delta = trial;
                                dyn = DllLoad(bytes, len, as, lib_aslr_delta);
                                break;
                            }
                            bool collides = false;
                            for (u64 j = 0; j < preloaded_count; ++j)
                            {
                                const u64 a_start = preloaded_dlls[j].base_va;
                                const u64 a_end = a_start + preloaded_dlls[j].size;
                                const u64 b_start = pref + trial;
                                const u64 b_end = b_start + size;
                                if (a_start < b_end && b_start < a_end)
                                {
                                    collides = true;
                                    break;
                                }
                            }
                            if (collides && dyn_base && attempt + 1 < kMaxFatRoll)
                                continue;
                            lib_aslr_delta = trial;
                            dyn = DllLoad(bytes, len, as, lib_aslr_delta);
                            break;
                        }
                        if (dyn.status == DllLoadStatus::Ok)
                        {
                            preloaded_dlls[preloaded_count] = dyn.image;
                            ++preloaded_count;
                            SerialWrite("[ring3] /FAT32-lib auto-preload ");
                            SerialWrite(kid.name);
                            SerialWrite(" base=");
                            SerialWriteHex(dyn.image.base_va);
                            SerialWrite("\n");
                        }
                    }
                }
            }
        }
    }

    const DllImage* dll_array = preloaded_count > 0 ? preloaded_dlls : nullptr;
    const PeLoadResult r = PeLoad(pe_bytes, pe_len, as, name, aslr_delta, dll_array, preloaded_count);
    if (!r.ok)
    {
        // PeLoad rejected the image. Without surfacing this, a
        // failing spawn vanishes silently — there's no log line
        // between "starting spawn" and the next process's banner.
        // KLOG_WARN so it always shows in any sensible loglevel
        // and respects production demotion; the verbose detail
        // (entry/stack/image_base) goes to KLOG_DEBUG so it only
        // surfaces in debug builds when an operator's hunting.
        KLOG_WARN("ring3", "PeLoad failed");
        KLOG_DEBUG_S("ring3", "  failing image", "name", name);
        KLOG_DEBUG_V("ring3", "  observed entry_va", r.entry_va);
        KLOG_DEBUG_V("ring3", "  observed stack_va", r.stack_va);
        KLOG_DEBUG_V("ring3", "  observed image_base", r.image_base);
        AddressSpaceRelease(as);
        return 0;
    }
    Process* proc = ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget);
    if (proc == nullptr)
    {
        AddressSpaceRelease(as);
        return 0;
    }
    // PE loader now maps a multi-page stack; Ring3UserEntry's
    // default rsp = user_stack_va + PAGE - 8 would land at the
    // BOTTOM of that range. Override with a Windows-ABI rsp
    // near the top: the x64 Win64 ABI says at function entry
    // rsp is of form `16n + 8` and [rsp] holds the return
    // address with [rsp+8..rsp+0x28] being 32 bytes of caller-
    // reserved shadow space the callee is free to spill argN
    // into. MSVC's entry prolog does exactly that, so an rsp
    // of stack_top - 8 faults immediately because rsp+8 is
    // one byte above the mapped stack. Start at stack_top-0x48
    // (72 bytes = 64 slack + 8) so the whole prolog window fits
    // comfortably inside the top stack page. 0x48 mod 16 = 8,
    // satisfying the 16n+8 rule.
    proc->user_rsp_init = r.stack_top - 0x48;
    proc->user_gs_base = r.teb_va;
    proc->user_is_pe32 = r.is_pe32;
    /* Record the post-ASLR EXE base so SYS_DLL_BASE_BY_NAME
     * with an empty / NULL name can return it for
     * GetModuleHandleW(NULL). */
    proc->pe_image_base = r.image_base;
    // Transfer any catch-all IAT miss (slot_va -> name) entries
    // the loader queued during ResolveImports. This arms the
    // runtime miss-logger: on the first call to an unstubbed
    // import, SYS_WIN32_MISS_LOG can decode the IAT slot VA back
    // to the function name via this table.
    PeLoadDrainIatMisses(proc);
    // Apply the per-PE app-compat sidecar, if any. Looks for
    // `<name>.duetcompat` next to the PE under the process's
    // ramfs root. No-op when the file is absent — the default
    // policy is "every override flag off, kernel acts as it did
    // before app-compat existed."
    duetos::core::compat::ApplySidecar(proc, root, name);
    // Per-process Win32 heap. Only initialised for PEs that
    // actually imported anything — a freestanding PE like
    // /bin/hello.exe doesn't call HeapAlloc and shouldn't burn
    // the 16 frames the heap region costs.
    if (r.imports_resolved)
    {
        if (!win32::Win32HeapInit(proc))
        {
            SerialWrite("[ring3] win32 heap init failed for \"");
            SerialWrite(name);
            SerialWrite("\"\n");
            AddressSpaceRelease(as);
            return 0;
        }
        // The DLLs were pre-loaded BEFORE PeLoad so
        // ResolveImports could consult their EATs. Now
        // that the Process exists, copy each DllImage into its
        // permanent `dll_images[]` table so
        // SYS_DLL_PROC_ADDRESS / ProcessResolveDllExportByBase
        // can reach them too. The pre-PeLoad slots are stack
        // locals about to go out of scope; the per-Process copies
        // are the long-lived record.
        for (u64 i = 0; i < preloaded_count; ++i)
        {
            if (!ProcessRegisterDllImage(proc, preloaded_dlls[i]))
            {
                SerialWrite("[ring3] DLL register failed for \"");
                SerialWrite(name);
                SerialWrite("\" (table full?)\n");
                break;
            }
        }
        if (preloaded_count > 0)
        {
            SerialWrite("[ring3] registered ");
            SerialWriteHex(preloaded_count);
            SerialWrite(" DLL(s) pid=");
            SerialWriteHex(proc->pid);
            SerialWrite("\n");
        }
    }
    {
        // Atomic line — see the matching guard in SpawnRing3Task.
        // Required for the qemu-smoke pe-* signature
        // `pe spawn name="ring3-..."` to remain a single substring.
        arch::SerialLineGuard guard;
        SerialWrite("[ring3] pe spawn name=\"");
        SerialWrite(name);
        SerialWrite("\" pid=");
        SerialWriteHex(proc->pid);
        SerialWrite(" entry=");
        SerialWriteHex(r.entry_va);
        SerialWrite(" image_base=");
        SerialWriteHex(r.image_base);
        SerialWrite(" stack_top=");
        SerialWriteHex(r.stack_top);
        SerialWrite("\n");
    }
    sched::SchedCreateUser(&Ring3UserEntry, nullptr, name, proc);
    return proc->pid;
}

} // namespace duetos::core
