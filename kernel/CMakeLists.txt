# CustomOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.
#
# The embedded symbol table (used by the panic dump path to resolve RIPs to
# function/file/line) needs a two-stage build:
#
#   1. Link `customos-kernel-stage1.elf` with a stub symbol table. Every
#      function / data symbol in this image already sits at its final VA
#      because the generated TU is pinned to the end of the kernel source
#      list — rodata growth in stage 2 happens strictly AFTER every other
#      symbol.
#
#   2. Run `tools/gen-symbols.sh` against stage 1 to produce
#      `symbols_generated.cpp`, a sorted `{addr, size, line, name, file}`
#      table, and relink the final `customos-kernel.elf` with it in place
#      of the stub.
#
# The final image is what the ISO target packages. Stage 1 is a throwaway.

set(CUSTOMOS_KERNEL_SHARED_SOURCES
    core/auth.cpp
    core/heartbeat.cpp
    core/hexdump.cpp
    core/klog.cpp
    core/login.cpp
    core/main.cpp
    core/panic.cpp
    core/process.cpp
    core/reboot.cpp
    core/recovery.cpp
    core/elf_loader.cpp
    core/pe_loader.cpp
    core/pe_exports.cpp
    core/dll_loader.cpp
    core/dll_loader_selftest.cpp
    core/random.cpp
    core/result.cpp
    core/ring3_smoke.cpp
    core/runtime_checker.cpp
    subsystems/graphics/graphics.cpp
    subsystems/linux/ring3_smoke.cpp
    subsystems/linux/syscall.cpp
    subsystems/linux/syscall_entry.S
    subsystems/translation/translate.cpp
    subsystems/win32/event_syscall.cpp
    subsystems/win32/file_syscall.cpp
    subsystems/win32/heap.cpp
    subsystems/win32/heap_syscall.cpp
    subsystems/win32/mutex_syscall.cpp
    subsystems/win32/stubs.cpp
    subsystems/win32/thread_syscall.cpp
    subsystems/win32/tls_syscall.cpp
    subsystems/win32/vmap_syscall.cpp
    core/shell.cpp
    core/stack_canary.cpp
    core/symbols.cpp
    core/fault_domain.cpp
    core/syscall.cpp
    core/time_syscall.cpp
    debug/bp_syscall.cpp
    debug/extable.cpp
    acpi/acpi.cpp
    apps/calculator.cpp
    apps/clock.cpp
    apps/files.cpp
    apps/notes.cpp
    arch/x86_64/ap_trampoline.S
    arch/x86_64/boot.S
    acpi/aml.cpp
    arch/x86_64/cpu_info.cpp
    arch/x86_64/hypervisor.cpp
    arch/x86_64/exceptions.S
    arch/x86_64/gdt.cpp
    arch/x86_64/hpet.cpp
    arch/x86_64/idt.cpp
    arch/x86_64/ioapic.cpp
    arch/x86_64/lapic.cpp
    arch/x86_64/nmi_watchdog.cpp
    arch/x86_64/pic.cpp
    arch/x86_64/retpoline_thunks.S
    arch/x86_64/rtc.cpp
    arch/x86_64/serial.cpp
    arch/x86_64/smbios.cpp
    arch/x86_64/smp.cpp
    arch/x86_64/thermal.cpp
    arch/x86_64/timer.cpp
    arch/x86_64/traps.cpp
    arch/x86_64/usermode.S
    cpu/percpu.cpp
    debug/breakpoints.cpp
    debug/inspect.cpp
    debug/probes.cpp
    debug/syscall_scan.cpp
    drivers/input/ps2kbd.cpp
    drivers/input/ps2mouse.cpp
    drivers/audio/audio.cpp
    drivers/audio/pcspk.cpp
    drivers/gpu/bochs_vbe.cpp
    drivers/gpu/gpu.cpp
    drivers/gpu/virtio_gpu.cpp
    drivers/net/net.cpp
    drivers/pci/pci.cpp
    drivers/power/power.cpp
    drivers/storage/ahci.cpp
    drivers/storage/block.cpp
    drivers/storage/nvme.cpp
    drivers/usb/hid_descriptor.cpp
    drivers/usb/msc_scsi.cpp
    drivers/usb/usb.cpp
    drivers/usb/xhci.cpp
    drivers/video/calendar.cpp
    drivers/video/console.cpp
    drivers/video/cursor.cpp
    drivers/video/font8x8.cpp
    drivers/video/framebuffer.cpp
    drivers/video/menu.cpp
    drivers/video/taskbar.cpp
    drivers/video/theme.cpp
    drivers/video/widget.cpp
    fs/exfat.cpp
    fs/ext4.cpp
    fs/fat32.cpp
    fs/file_route.cpp
    fs/gpt.cpp
    fs/ntfs.cpp
    fs/ramfs.cpp
    fs/tmpfs.cpp
    fs/vfs.cpp
    mm/address_space.cpp
    mm/frame_allocator.cpp
    mm/kheap.cpp
    mm/kstack.cpp
    mm/page.cpp
    mm/paging.cpp
    mm/user_copy.S
    net/stack.cpp
    sched/context_switch.S
    sched/sched.cpp
    security/attack_sim.cpp
    security/guard.cpp
    security/pentest_gui.cpp
    sync/spinlock.cpp
)

# core/stack_canary.cpp provides __stack_chk_fail and the
# RandomizeStackCanary helper. The latter updates the cookie at
# runtime; if ANY function in this file gets compiled with stack
# protection, the prologue/epilogue would sample __stack_chk_guard
# before/after the update and mismatch. The source uses
# __attribute__((no_stack_protector)) on the two functions that
# care; -fno-stack-protector on the whole TU is belt + braces.
set_source_files_properties(
    core/stack_canary.cpp
    PROPERTIES COMPILE_OPTIONS "-fno-stack-protector"
)

# ----------------------------------------------------------------------------
# Host-side userland build: userland/apps/hello_pe/hello.c is compiled
# with clang targeting x86_64-pc-windows-msvc and linked by lld-link
# into a real freestanding PE/COFF .exe. The bytes are embedded into a
# C++ constexpr u8 header that ramfs.cpp includes, so /bin/hello.exe
# appears on the boot filesystem without a disk backend.
#
# This relies on host clang + lld-link + python3 being present, which
# the dev container ships with. A future slice will guard this with a
# CMake probe and fall back to a hand-laid byte array if the
# toolchain is missing.
# ----------------------------------------------------------------------------
set(CUSTOMOS_HELLO_PE_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_pe/hello.c")
set(CUSTOMOS_HELLO_PE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_pe.h")
set(CUSTOMOS_HELLO_PE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-pe.sh")
set(CUSTOMOS_EMBED_BLOB_SCRIPT "${CMAKE_SOURCE_DIR}/tools/embed-blob.py")

add_custom_command(
    OUTPUT "${CUSTOMOS_HELLO_PE_HEADER}"
    COMMAND "${CUSTOMOS_HELLO_PE_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_HELLO_PE_HEADER}"
    DEPENDS
        "${CUSTOMOS_HELLO_PE_SRC}"
        "${CUSTOMOS_HELLO_PE_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello.exe (freestanding PE)"
    VERBATIM
)

# ramfs.cpp includes the generated header. Add it to the shared
# source list so BOTH stages see the dependency and the custom
# command fires on first configure.
list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_HELLO_PE_HEADER}")

# ----------------------------------------------------------------------------
# Embed a real Windows PE (windows-kill.exe, a small standalone
# Win32 console utility — 79 KiB, 12 DLL deps, 100 imported
# functions, TLS callbacks). This is NOT a file we can run: v0
# has no Win32 subsystem, no ntdll, nothing to resolve the
# imports against. But the kernel PE loader's diagnostic path
# (PeReport) exercises every directory on this image, giving a
# concrete gap report on boot.
#
# This is the tractable substitute for "download Chrome and try
# to run it": real Windows PE, real imports, but small enough
# that embedding it into a constexpr u8 array doesn't balloon
# the kernel.
# ----------------------------------------------------------------------------
set(CUSTOMOS_WINKILL_SRC "${CMAKE_SOURCE_DIR}/userland/apps/windows_kill/windows-kill.exe")
set(CUSTOMOS_WINKILL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_winkill_pe.h")

add_custom_command(
    OUTPUT "${CUSTOMOS_WINKILL_HEADER}"
    COMMAND python3
            "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
            "${CUSTOMOS_WINKILL_SRC}"
            "${CUSTOMOS_WINKILL_HEADER}"
            kBinWinKillBytes
            --namespace "customos::fs::generated"
    DEPENDS
        "${CUSTOMOS_WINKILL_SRC}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding real Windows PE /bin/windows-kill.exe"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_WINKILL_HEADER}")

# ----------------------------------------------------------------------------
# Third PE fixture: hello_winapi.exe — first userland program
# that talks to the CustomOS Win32 subsystem through a real
# Import Directory. Built via llvm-dlltool (kernel32.lib) +
# clang + lld-link. See tools/build-hello-winapi.sh and
# .claude/knowledge/pe-subsystem-v0.md for the layered
# mechanism.
# ----------------------------------------------------------------------------
set(CUSTOMOS_HELLO_WINAPI_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/hello.c")
# Every .def file in the hello_winapi dir becomes a separate
# import library feeding lld-link. Glob-dependency means adding
# a new .def (e.g. for a future DLL stub set) automatically
# triggers a rebuild without touching this CMakeLists.
file(GLOB CUSTOMOS_HELLO_WINAPI_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/*.def")
set(CUSTOMOS_HELLO_WINAPI_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_winapi.h")
set(CUSTOMOS_HELLO_WINAPI_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-winapi.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_HELLO_WINAPI_HEADER}"
    COMMAND "${CUSTOMOS_HELLO_WINAPI_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_HELLO_WINAPI_HEADER}"
    DEPENDS
        "${CUSTOMOS_HELLO_WINAPI_SRC}"
        ${CUSTOMOS_HELLO_WINAPI_DEFS}
        "${CUSTOMOS_HELLO_WINAPI_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello_winapi.exe (Win32 import path)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_HELLO_WINAPI_HEADER}")

# ----------------------------------------------------------------------------
# Fourth PE fixture: thread_stress.exe — exercises CreateThread,
# CreateEventW, SetEvent, WaitForSingleObject round-trip. Verifies
# the batch-50 SYS_THREAD_CREATE wiring works end-to-end: main
# creates a child thread, child writes a sentinel + signals an
# event, main wakes + checks the sentinel.
# ----------------------------------------------------------------------------
set(CUSTOMOS_THREAD_STRESS_SRC "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress/hello.c")
file(GLOB CUSTOMOS_THREAD_STRESS_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress/*.def")
set(CUSTOMOS_THREAD_STRESS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_thread_stress.h")
set(CUSTOMOS_THREAD_STRESS_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-thread-stress.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_THREAD_STRESS_HEADER}"
    COMMAND "${CUSTOMOS_THREAD_STRESS_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_THREAD_STRESS_HEADER}"
    DEPENDS
        "${CUSTOMOS_THREAD_STRESS_SRC}"
        ${CUSTOMOS_THREAD_STRESS_DEFS}
        "${CUSTOMOS_THREAD_STRESS_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/thread_stress.exe (CreateThread path)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_THREAD_STRESS_HEADER}")

# ----------------------------------------------------------------------------
# Fifth PE fixture: syscall_stress.exe — exercises the batch-51
# Win32 API additions: OutputDebugStringA, ExitThread,
# GetProcessTimes / GetThreadTimes / GetSystemTimes,
# GlobalMemoryStatusEx, WaitForMultipleObjects.
# ----------------------------------------------------------------------------
set(CUSTOMOS_SYSCALL_STRESS_SRC "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress/hello.c")
file(GLOB CUSTOMOS_SYSCALL_STRESS_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress/*.def")
set(CUSTOMOS_SYSCALL_STRESS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_syscall_stress.h")
set(CUSTOMOS_SYSCALL_STRESS_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-syscall-stress.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_SYSCALL_STRESS_HEADER}"
    COMMAND "${CUSTOMOS_SYSCALL_STRESS_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_SYSCALL_STRESS_HEADER}"
    DEPENDS
        "${CUSTOMOS_SYSCALL_STRESS_SRC}"
        ${CUSTOMOS_SYSCALL_STRESS_DEFS}
        "${CUSTOMOS_SYSCALL_STRESS_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/syscall_stress.exe (batch 51 API coverage)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_SYSCALL_STRESS_HEADER}")

# ----------------------------------------------------------------------------
# Test fixture for the stage-2 EAT parser + DLL loader: a tiny
# freestanding Windows DLL with three exported C functions
# (CustomAdd, CustomMul, CustomVersion). Built by clang +
# lld-link /dll /noentry, no CRT, no imports. The kernel self-
# test in kernel_main (DllLoaderSelfTest) parses the embedded
# bytes via PeParseExports and DllLoad to confirm name + ordinal
# lookups return the expected RVAs.
# ----------------------------------------------------------------------------
set(CUSTOMOS_CUSTOMDLL_SRC "${CMAKE_SOURCE_DIR}/userland/libs/customdll/customdll.c")
set(CUSTOMOS_CUSTOMDLL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll.h")
set(CUSTOMOS_CUSTOMDLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_CUSTOMDLL_HEADER}"
    COMMAND "${CUSTOMOS_CUSTOMDLL_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_CUSTOMDLL_HEADER}"
    DEPENDS
        "${CUSTOMOS_CUSTOMDLL_SRC}"
        "${CUSTOMOS_CUSTOMDLL_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding customdll.dll (EAT parser fixture)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_CUSTOMDLL_HEADER}")

# ----------------------------------------------------------------------------
# Second test DLL for the stage-2 slice 9 multi-DLL preload path.
# Exports CustomDouble(int) -> int at load base 0x10010000.
# Deliberately disjoint exports from customdll.dll so a call to
# CustomDouble HAS to reach the second entry in the preload
# array — proves the resolver walks past the first DLL on miss.
# ----------------------------------------------------------------------------
set(CUSTOMOS_CUSTOMDLL2_SRC "${CMAKE_SOURCE_DIR}/userland/libs/customdll2/customdll2.c")
set(CUSTOMOS_CUSTOMDLL2_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll2.h")
set(CUSTOMOS_CUSTOMDLL2_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll2.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_CUSTOMDLL2_HEADER}"
    COMMAND "${CUSTOMOS_CUSTOMDLL2_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_CUSTOMDLL2_HEADER}"
    DEPENDS
        "${CUSTOMOS_CUSTOMDLL2_SRC}"
        "${CUSTOMOS_CUSTOMDLL2_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding customdll2.dll (multi-DLL preload fixture)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_CUSTOMDLL2_HEADER}")

# ----------------------------------------------------------------------------
# Userland kernel32.dll — stage-2 slice 10 kicks off the
# retirement of flat-stubs-page entries into real userland
# code. First export: GetCurrentProcessId. Future slices
# extend kernel32.c with more entry points; every addition
# retires the matching stub (which stays compiled as a
# fallback but becomes unreachable via slice-6's via-DLL
# priority).
# ----------------------------------------------------------------------------
set(CUSTOMOS_KERNEL32_SRC "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32.c")
set(CUSTOMOS_KERNEL32_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_kernel32_dll.h")
set(CUSTOMOS_KERNEL32_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-kernel32-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_KERNEL32_HEADER}"
    COMMAND "${CUSTOMOS_KERNEL32_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_KERNEL32_HEADER}"
    DEPENDS
        "${CUSTOMOS_KERNEL32_SRC}"
        "${CUSTOMOS_KERNEL32_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding kernel32.dll (first stub retirement)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_KERNEL32_HEADER}")

# ----------------------------------------------------------------------------
# Userland vcruntime140.dll — stage-2 slice 13. Retires the
# batch-5 memset/memcpy/memmove flat stubs. Every MSVC-built
# PE calls these routinely (struct copy / zero-init / CRT
# startup), so the via-DLL path fires heavily.
# ----------------------------------------------------------------------------
set(CUSTOMOS_VCRUNTIME140_SRC "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/vcruntime140.c")
set(CUSTOMOS_VCRUNTIME140_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_vcruntime140_dll.h")
set(CUSTOMOS_VCRUNTIME140_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-vcruntime140-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_VCRUNTIME140_HEADER}"
    COMMAND "${CUSTOMOS_VCRUNTIME140_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_VCRUNTIME140_HEADER}"
    DEPENDS
        "${CUSTOMOS_VCRUNTIME140_SRC}"
        "${CUSTOMOS_VCRUNTIME140_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding vcruntime140.dll (memset/memcpy/memmove retirement)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_VCRUNTIME140_HEADER}")

# ----------------------------------------------------------------------------
# Userland msvcrt.dll — stage-2 slice 14. Retires the string
# intrinsics (strlen / strcmp / strcpy / strchr + wide
# variants) from the flat stubs.
# ----------------------------------------------------------------------------
set(CUSTOMOS_MSVCRT_SRC "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt/msvcrt.c")
set(CUSTOMOS_MSVCRT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_msvcrt_dll.h")
set(CUSTOMOS_MSVCRT_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-msvcrt-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_MSVCRT_HEADER}"
    COMMAND "${CUSTOMOS_MSVCRT_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_MSVCRT_HEADER}"
    DEPENDS
        "${CUSTOMOS_MSVCRT_SRC}"
        "${CUSTOMOS_MSVCRT_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding msvcrt.dll (string intrinsics retirement)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_MSVCRT_HEADER}")

# ----------------------------------------------------------------------------
# Userland ntdll.dll — stage-2 slice 24. Retires the batch-42+
# Nt* / Zw* / Rtl* / Ldr* / __chkstk surface. 108 exports
# total (Zw* aliases emitted as same-DLL forwarders).
# ----------------------------------------------------------------------------
set(CUSTOMOS_NTDLL_SRC "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll.c")
set(CUSTOMOS_NTDLL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_ntdll_dll.h")
set(CUSTOMOS_NTDLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-ntdll-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_NTDLL_HEADER}"
    COMMAND "${CUSTOMOS_NTDLL_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_NTDLL_HEADER}"
    DEPENDS
        "${CUSTOMOS_NTDLL_SRC}"
        "${CUSTOMOS_NTDLL_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding ntdll.dll (Nt* / Zw* / Rtl* / Ldr* retirement)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_NTDLL_HEADER}")

# ----------------------------------------------------------------------------
# Userland dbghelp.dll — stage-2 slice 25. 11 Sym* / StackWalk
# / MiniDumpWriteDump no-ops; callers always check return.
# ----------------------------------------------------------------------------
set(CUSTOMOS_DBGHELP_SRC "${CMAKE_SOURCE_DIR}/userland/libs/dbghelp/dbghelp.c")
set(CUSTOMOS_DBGHELP_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_dbghelp_dll.h")
set(CUSTOMOS_DBGHELP_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-dbghelp-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_DBGHELP_HEADER}"
    COMMAND "${CUSTOMOS_DBGHELP_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_DBGHELP_HEADER}"
    DEPENDS
        "${CUSTOMOS_DBGHELP_SRC}"
        "${CUSTOMOS_DBGHELP_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding dbghelp.dll (Sym* no-ops)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_DBGHELP_HEADER}")

# ----------------------------------------------------------------------------
# Userland msvcp140.dll — stage-2 slice 26. 17 mangled C++
# std:: names (throw helpers + ostream + iostate) via .def.
# ----------------------------------------------------------------------------
set(CUSTOMOS_MSVCP140_SRC "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.c")
set(CUSTOMOS_MSVCP140_DEF "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.def")
set(CUSTOMOS_MSVCP140_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_msvcp140_dll.h")
set(CUSTOMOS_MSVCP140_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-msvcp140-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_MSVCP140_HEADER}"
    COMMAND "${CUSTOMOS_MSVCP140_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_MSVCP140_HEADER}"
    DEPENDS
        "${CUSTOMOS_MSVCP140_SRC}"
        "${CUSTOMOS_MSVCP140_DEF}"
        "${CUSTOMOS_MSVCP140_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding msvcp140.dll (C++ std throw + ostream helpers)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_MSVCP140_HEADER}")

# ----------------------------------------------------------------------------
# Userland kernelbase.dll — stage-2 slice 27. Forwarder-only
# DLL: every export cross-forwards to kernel32.dll via the
# slice-8 chaser in the kernel loader.
# ----------------------------------------------------------------------------
set(CUSTOMOS_KERNELBASE_SRC "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.c")
set(CUSTOMOS_KERNELBASE_DEF "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.def")
set(CUSTOMOS_KERNELBASE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_kernelbase_dll.h")
set(CUSTOMOS_KERNELBASE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-kernelbase-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_KERNELBASE_HEADER}"
    COMMAND "${CUSTOMOS_KERNELBASE_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${CUSTOMOS_KERNELBASE_HEADER}"
    DEPENDS "${CUSTOMOS_KERNELBASE_SRC}" "${CUSTOMOS_KERNELBASE_DEF}" "${CUSTOMOS_KERNELBASE_SCRIPT}" "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding kernelbase.dll (forwarders -> kernel32)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_KERNELBASE_HEADER}")

# ----------------------------------------------------------------------------
# Userland advapi32.dll — stage-2 slice 27. 25 exports: Reg*
# (all return "not found"), token/privilege (pretend success),
# GetUserName* (constant), SystemFunction036 (deterministic).
# ----------------------------------------------------------------------------
set(CUSTOMOS_ADVAPI32_SRC "${CMAKE_SOURCE_DIR}/userland/libs/advapi32/advapi32.c")
set(CUSTOMOS_ADVAPI32_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_advapi32_dll.h")
set(CUSTOMOS_ADVAPI32_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-advapi32-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_ADVAPI32_HEADER}"
    COMMAND "${CUSTOMOS_ADVAPI32_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${CUSTOMOS_ADVAPI32_HEADER}"
    DEPENDS "${CUSTOMOS_ADVAPI32_SRC}" "${CUSTOMOS_ADVAPI32_SCRIPT}" "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding advapi32.dll (Reg* / token / GetUserName / RtlGenRandom)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_ADVAPI32_HEADER}")

# ----------------------------------------------------------------------------
# Stage-2 slice 28 — seven small stub DLLs built via a generic
# helper (tools/build-stub-dll.sh). Each DLL has a small hand-
# written .c source + an export list passed on the CMake cmd-
# line.
# ----------------------------------------------------------------------------
set(CUSTOMOS_STUB_DLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-stub-dll.sh")

macro(customos_stub_dll name base_va exports)
    set(_src "${CMAKE_SOURCE_DIR}/userland/libs/${name}/${name}.c")
    set(_header "${CMAKE_CURRENT_BINARY_DIR}/generated_${name}_dll.h")
    add_custom_command(
        OUTPUT "${_header}"
        COMMAND "${CUSTOMOS_STUB_DLL_SCRIPT}"
                "${CMAKE_SOURCE_DIR}" "${_header}" "${name}" "${base_va}" "${exports}"
        DEPENDS "${_src}" "${CUSTOMOS_STUB_DLL_SCRIPT}" "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Compiling + embedding ${name}.dll"
        VERBATIM
    )
    list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${_header}")
    set(CUSTOMOS_${name}_HEADER "${_header}" PARENT_SCOPE_UNUSED)
endmacro()

customos_stub_dll(shlwapi 0x100B0000 "PathAddBackslashW,PathAppendW,PathCombineW,PathFileExistsA,PathFileExistsW,PathFindExtensionA,PathFindExtensionW,PathFindFileNameA,PathFindFileNameW,PathIsDirectoryW,PathRemoveFileSpecW,PathStripPathW,StrCmpNW,StrCmpW,StrStrIW,StrStrW")
customos_stub_dll(shell32 0x100C0000 "CommandLineToArgvW,ExtractIconW,ExtractIconExW,SHCreateDirectoryW,SHCreateDirectoryExW,SHFileOperationW,SHGetFolderPathA,SHGetFolderPathW,SHGetKnownFolderPath,SHGetPathFromIDListW,SHGetSpecialFolderPathW,ShellExecuteW,ShellExecuteExW")
customos_stub_dll(ole32 0x100D0000 "CoInitialize,CoInitializeEx,CoUninitialize,OleInitialize,OleUninitialize,CoCreateInstance,CoCreateInstanceEx,CoGetClassObject,CLSIDFromString,CLSIDFromProgID,IIDFromString,StringFromCLSID,CoTaskMemAlloc,CoTaskMemFree,CoTaskMemRealloc")
customos_stub_dll(oleaut32 0x100E0000 "VariantInit,VariantClear,SysAllocString,SysFreeString,SysStringLen")
customos_stub_dll(winmm 0x100F0000 "timeGetTime,timeBeginPeriod,timeEndPeriod,timeGetDevCaps,timeSetEvent,timeKillEvent,PlaySoundW,mciSendStringW")
customos_stub_dll(bcrypt 0x10100000 "BCryptOpenAlgorithmProvider,BCryptCloseAlgorithmProvider,BCryptCreateHash,BCryptHashData,BCryptFinishHash,BCryptDestroyHash,BCryptGetProperty,BCryptGenRandom")
customos_stub_dll(psapi 0x10110000 "EnumProcesses,EnumProcessModules,GetMappedFileNameW,GetModuleBaseNameW,GetModuleFileNameExW,GetProcessMemoryInfo,QueryWorkingSet")

# ----------------------------------------------------------------------------
# Userland ucrtbase.dll — stage-2 slice 15. Retires the
# UCRT runtime stubs: heap alloc (malloc/free/calloc/realloc
# /_aligned_*), terminators (exit/_exit), CRT startup shims
# (_initterm/_initterm_e/_cexit/_c_exit/_set_app_type/
# __setusermatherr/_configthreadlocale), plus string
# intrinsics aliased from msvcrt.
# ----------------------------------------------------------------------------
set(CUSTOMOS_UCRTBASE_SRC "${CMAKE_SOURCE_DIR}/userland/libs/ucrtbase/ucrtbase.c")
set(CUSTOMOS_UCRTBASE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_ucrtbase_dll.h")
set(CUSTOMOS_UCRTBASE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-ucrtbase-dll.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_UCRTBASE_HEADER}"
    COMMAND "${CUSTOMOS_UCRTBASE_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_UCRTBASE_HEADER}"
    DEPENDS
        "${CUSTOMOS_UCRTBASE_SRC}"
        "${CUSTOMOS_UCRTBASE_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding ucrtbase.dll (heap + exit + CRT startup retirement)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_UCRTBASE_HEADER}")

# ----------------------------------------------------------------------------
# Sixth PE fixture: customdll_test.exe — first userland program
# that imports from a real loaded DLL (customdll.dll) rather
# than from the flat stubs page. Exercises stage-2 slice 6's
# via-DLL IAT resolution path end-to-end.
# ----------------------------------------------------------------------------
set(CUSTOMOS_CUSTOMDLL_TEST_SRC "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test/hello.c")
file(GLOB CUSTOMOS_CUSTOMDLL_TEST_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test/*.def")
set(CUSTOMOS_CUSTOMDLL_TEST_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll_test.h")
set(CUSTOMOS_CUSTOMDLL_TEST_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll-test.sh")

add_custom_command(
    OUTPUT "${CUSTOMOS_CUSTOMDLL_TEST_HEADER}"
    COMMAND "${CUSTOMOS_CUSTOMDLL_TEST_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${CUSTOMOS_CUSTOMDLL_TEST_HEADER}"
    DEPENDS
        "${CUSTOMOS_CUSTOMDLL_TEST_SRC}"
        ${CUSTOMOS_CUSTOMDLL_TEST_DEFS}
        "${CUSTOMOS_CUSTOMDLL_TEST_SCRIPT}"
        "${CUSTOMOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/customdll_test.exe (stage-2 slice 6 fixture)"
    VERBATIM
)

list(APPEND CUSTOMOS_KERNEL_SHARED_SOURCES "${CUSTOMOS_CUSTOMDLL_TEST_HEADER}")

set(CUSTOMOS_KERNEL_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/linker.ld")

# Shared link flags — applied identically to both stages so the symbol
# addresses extracted from stage 1 are valid for stage 2.
function(customos_apply_kernel_link_flags target)
    target_link_options(${target} PRIVATE
        -T${CUSTOMOS_KERNEL_LINKER_SCRIPT}
        -Wl,--gc-sections
        -Wl,--no-undefined
        -Wl,-n
    )
    set_target_properties(${target} PROPERTIES
        LINK_DEPENDS "${CUSTOMOS_KERNEL_LINKER_SCRIPT}"
    )
endfunction()

# ----------------------------------------------------------------------------
# Stage 1: kernel with a stub symbol table. Throwaway — only exists so
# gen-symbols.sh has a linked ELF to read addresses out of.
#
# IMPORTANT: `symbols_stub.cpp` MUST be the last source in this list so
# the linker places its (near-empty) .rodata contribution at the very
# end of .rodata. The stage-2 kernel swaps in `symbols_generated.cpp`
# in the same trailing slot; rodata grows tail-ward and every other
# symbol's VA is preserved.
# ----------------------------------------------------------------------------
add_executable(customos-kernel-stage1
    ${CUSTOMOS_KERNEL_SHARED_SOURCES}
    core/symbols_stub.cpp
)
set_target_properties(customos-kernel-stage1 PROPERTIES
    OUTPUT_NAME "customos-kernel-stage1.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    # Stage 1 is internal plumbing — don't install or package it.
    EXCLUDE_FROM_ALL FALSE
)
target_include_directories(customos-kernel-stage1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
customos_apply_kernel_link_flags(customos-kernel-stage1)

# ----------------------------------------------------------------------------
# Generate symbols_generated.cpp from the stage-1 ELF.
#
# gen-symbols.sh reads every higher-half function symbol, resolves
# addr -> (file, line) via addr2line, and emits a sorted-by-address
# `{addr, size, line, name, file}` table. The resulting TU is what the
# stage-2 kernel links against.
# ----------------------------------------------------------------------------
set(CUSTOMOS_SYMBOLS_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/symbols_generated.cpp")

add_custom_command(
    OUTPUT "${CUSTOMOS_SYMBOLS_GENERATED}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
            "$<TARGET_FILE:customos-kernel-stage1>"
            "${CUSTOMOS_SYMBOLS_GENERATED}"
            "${CMAKE_SOURCE_DIR}"
    DEPENDS customos-kernel-stage1 "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
    COMMENT "Extracting kernel symbol table from stage-1 ELF"
    VERBATIM
)

# ----------------------------------------------------------------------------
# Stage 2: final kernel. Same source set as stage 1, but the stub is
# replaced by the generated TU. The generated TU defines the same
# three extern "C" symbols the resolver looks up, now populated with
# real data.
# ----------------------------------------------------------------------------
add_executable(customos-kernel
    ${CUSTOMOS_KERNEL_SHARED_SOURCES}
    "${CUSTOMOS_SYMBOLS_GENERATED}"
)

# Deliberate-panic build flag, consumed by kernel_main and triggered
# by tools/test-panic.sh. OFF for normal builds — the demo panic
# halts the kernel on purpose and must not ship in a release preset.
option(CUSTOMOS_PANIC_DEMO "Insert a deliberate Panic() at end of kernel_main (test-panic.sh)" OFF)
if(CUSTOMOS_PANIC_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_PANIC_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_PANIC_DEMO=1)
endif()

# Deliberate stack-smash build flag. Enables a small in-kernel_main
# block that overruns a local array past its stack canary, forcing
# __stack_chk_fail to fire on return. Intended for verifying the
# canary infrastructure works end-to-end; OFF for normal builds.
option(CUSTOMOS_CANARY_DEMO "Insert a deliberate stack smash at end of kernel_main (verifies stack-canary panic path)" OFF)
if(CUSTOMOS_CANARY_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_CANARY_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_CANARY_DEMO=1)
endif()

# Red-team attack-simulation flag. Runs the AttackSim suite once
# at the end of kernel_main, exercising every runtime-checker
# detector by performing the attack a rootkit would and
# verifying the detector catches it. OFF for normal boot — the
# simulations escalate the security guard to Enforce mode and
# the block write-guard to Deny, which would poison every
# subsequent image load / sensitive-LBA write for the session.
option(CUSTOMOS_ATTACK_SIM "Run the AttackSim red-team suite at end of kernel_main" OFF)
if(CUSTOMOS_ATTACK_SIM)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_ATTACK_SIM=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_ATTACK_SIM=1)
endif()


# Deliberate-CPU-exception build flag, consumed by kernel_main and
# triggered by tools/test-trap.sh. Executes `ud2` to take a #UD fault
# so the trap dispatcher's crash-dump path can be verified end-to-end
# (extractable BEGIN/END record, symbolized RIP, backtrace). OFF for
# normal builds.
option(CUSTOMOS_TRAP_DEMO "Execute ud2 at end of kernel_main to take #UD (test-trap.sh)" OFF)
if(CUSTOMOS_TRAP_DEMO)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_TRAP_DEMO=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_TRAP_DEMO=1)
endif()


# Initial boot mode: desktop (windowed shell) vs TTY (fullscreen
# framebuffer console). Runtime toggle with Ctrl+Alt+T works
# regardless of this flag; it only affects what the user sees
# when the kernel first hits kernel_main's compose phase. Useful
# for an install / rescue build that prefers text-first UX.
option(CUSTOMOS_BOOT_TTY "Boot straight into TTY mode instead of the windowed desktop" OFF)
if(CUSTOMOS_BOOT_TTY)
    target_compile_definitions(customos-kernel          PRIVATE CUSTOMOS_BOOT_TTY=1)
    target_compile_definitions(customos-kernel-stage1   PRIVATE CUSTOMOS_BOOT_TTY=1)
endif()

set_target_properties(customos-kernel PROPERTIES
    OUTPUT_NAME "customos-kernel.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(customos-kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

customos_apply_kernel_link_flags(customos-kernel)

# ----------------------------------------------------------------------------
# Bootable ISO — uses GRUB as a third-party loader until our own UEFI boot
# loader exists. If grub-mkrescue / xorriso aren't installed, the kernel
# still builds; only the `customos-iso` target is skipped, with a status
# message explaining what to install.
# ----------------------------------------------------------------------------

find_program(GRUB_MKRESCUE grub-mkrescue)
find_program(XORRISO       xorriso)

if(GRUB_MKRESCUE AND XORRISO)
    set(CUSTOMOS_ISO_STAGE  "${CMAKE_CURRENT_BINARY_DIR}/iso-stage")
    set(CUSTOMOS_ISO_OUTPUT "${CMAKE_BINARY_DIR}/customos.iso")
    set(CUSTOMOS_GRUB_CFG   "${CMAKE_SOURCE_DIR}/boot/grub/grub.cfg")

    add_custom_command(
        OUTPUT "${CUSTOMOS_ISO_OUTPUT}"

        # Lay out the ISO root exactly the way grub.cfg expects.
        COMMAND ${CMAKE_COMMAND} -E rm -rf  "${CUSTOMOS_ISO_STAGE}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${CUSTOMOS_ISO_STAGE}/boot/grub"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:customos-kernel>"
                                         "${CUSTOMOS_ISO_STAGE}/boot/customos-kernel.elf"
        COMMAND ${CMAKE_COMMAND} -E copy "${CUSTOMOS_GRUB_CFG}"
                                         "${CUSTOMOS_ISO_STAGE}/boot/grub/grub.cfg"

        # Produce the ISO. grub-mkrescue embeds the i386-pc boot image so the
        # result is bootable on both legacy BIOS (via QEMU's default SeaBIOS)
        # and — when GRUB's EFI modules are present on the host — UEFI.
        COMMAND ${GRUB_MKRESCUE} --compress=xz -o "${CUSTOMOS_ISO_OUTPUT}"
                                 "${CUSTOMOS_ISO_STAGE}"

        DEPENDS customos-kernel "${CUSTOMOS_GRUB_CFG}"
        COMMENT "Building bootable customos.iso"
        VERBATIM
    )

    add_custom_target(customos-iso ALL
        DEPENDS "${CUSTOMOS_ISO_OUTPUT}"
    )
else()
    message(STATUS "customos-iso target disabled (grub-mkrescue or xorriso not found).")
    message(STATUS "  Install with: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools")
endif()
