# DuetOS kernel.
#
# Produces a single bare-metal x86_64 ELF that a Multiboot2-compliant loader
# (GRUB, Limine, or QEMU's built-in `-kernel` with a Multiboot2-aware fork)
# can load at physical 1 MiB and hand control to `_start` in boot.S.
#
# The embedded symbol table (used by the panic dump path to resolve RIPs to
# function/file/line) needs a two-stage build:
#
#   1. Link `duetos-kernel-stage1.elf` with a stub symbol table. Every
#      function / data symbol in this image already sits at its final VA
#      because the generated TU is pinned to the end of the kernel source
#      list — rodata growth in stage 2 happens strictly AFTER every other
#      symbol.
#
#   2. Run `tools/gen-symbols.sh` against stage 1 to produce
#      `symbols_generated.cpp`, a sorted `{addr, size, line, name, file}`
#      table, and relink the final `duetos-kernel.elf` with it in place
#      of the stub.
#
# The final image is what the ISO target packages. Stage 1 is a throwaway.

set(DUETOS_KERNEL_SHARED_SOURCES
    core/auth.cpp
    core/cleanroom_trace.cpp
    core/crprobe.cpp
    core/diag_decode.cpp
    core/heartbeat.cpp
    core/hexdump.cpp
    core/klog.cpp
    core/kdbg.cpp
    core/log_names.cpp
    core/login.cpp
    core/main.cpp
    core/panic.cpp
    core/process.cpp
    core/reboot.cpp
    core/recovery.cpp
    core/elf_loader.cpp
    core/firmware_loader.cpp
    core/pe_loader.cpp
    core/pe_exports.cpp
    core/dll_loader.cpp
    core/dll_loader_selftest.cpp
    core/random.cpp
    core/result.cpp
    core/ring3_smoke.cpp
    core/runtime_checker.cpp
    core/string.cpp
    subsystems/graphics/graphics.cpp
    subsystems/linux/ring3_smoke.cpp
    subsystems/linux/syscall.cpp
    subsystems/linux/syscall_entry.S
    subsystems/translation/translate.cpp
    subsystems/win32/custom.cpp
    subsystems/win32/custom_selftest.cpp
    subsystems/win32/event_syscall.cpp
    subsystems/win32/file_syscall.cpp
    subsystems/win32/gdi_objects.cpp
    subsystems/win32/heap.cpp
    subsystems/win32/heap_syscall.cpp
    subsystems/win32/mutex_syscall.cpp
    subsystems/win32/nt_coverage.cpp
    subsystems/win32/proc_env.cpp
    subsystems/win32/thunks.cpp
    subsystems/win32/thread_syscall.cpp
    subsystems/win32/tls_syscall.cpp
    subsystems/win32/vmap_syscall.cpp
    subsystems/win32/window_syscall.cpp
    core/shell.cpp
    core/stack_canary.cpp
    core/symbols.cpp
    core/fault_domain.cpp
    core/syscall.cpp
    core/syscall_names.cpp
    core/time_syscall.cpp
    debug/bp_syscall.cpp
    debug/extable.cpp
    acpi/acpi.cpp
    apps/calculator.cpp
    apps/clock.cpp
    apps/files.cpp
    apps/gfxdemo.cpp
    apps/gfxdemo_modes.cpp
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
    drivers/net/bcm43xx.cpp
    drivers/net/iwlwifi.cpp
    drivers/net/net.cpp
    drivers/net/rtl88xx.cpp
    drivers/pci/pci.cpp
    drivers/power/power.cpp
    drivers/storage/ahci.cpp
    drivers/storage/block.cpp
    drivers/storage/nvme.cpp
    drivers/usb/hid_descriptor.cpp
    drivers/usb/cdc_ecm.cpp
    drivers/usb/msc_scsi.cpp
    drivers/usb/rndis.cpp
    drivers/usb/usb.cpp
    drivers/usb/xhci.cpp
    drivers/usb/xhci_complete.cpp
    drivers/usb/xhci_input.cpp
    drivers/usb/xhci_speed.cpp
    drivers/video/calendar.cpp
    drivers/video/console.cpp
    drivers/video/cursor.cpp
    drivers/video/font8x8.cpp
    drivers/video/framebuffer.cpp
    drivers/video/menu.cpp
    drivers/video/netpanel.cpp
    drivers/video/taskbar.cpp
    drivers/video/theme.cpp
    drivers/video/widget.cpp
    fs/exfat.cpp
    fs/ext4.cpp
    fs/fat32.cpp
    fs/fat32_create.cpp
    fs/fat32_dir.cpp
    fs/fat32_lookup.cpp
    fs/fat32_read.cpp
    fs/fat32_selftest.cpp
    fs/fat32_write.cpp
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
    net/net_smoke.cpp
    net/stack.cpp
    net/wifi.cpp
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
set(DUETOS_HELLO_PE_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_pe/hello.c")
set(DUETOS_HELLO_PE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_pe.h")
set(DUETOS_HELLO_PE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-pe.sh")
set(DUETOS_EMBED_BLOB_SCRIPT "${CMAKE_SOURCE_DIR}/tools/embed-blob.py")

add_custom_command(
    OUTPUT "${DUETOS_HELLO_PE_HEADER}"
    COMMAND "${DUETOS_HELLO_PE_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_HELLO_PE_HEADER}"
    DEPENDS
        "${DUETOS_HELLO_PE_SRC}"
        "${DUETOS_HELLO_PE_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello.exe (freestanding PE)"
    VERBATIM
)

# ramfs.cpp includes the generated header. Add it to the shared
# source list so BOTH stages see the dependency and the custom
# command fires on first configure.
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_HELLO_PE_HEADER}")

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
set(DUETOS_WINKILL_SRC "${CMAKE_SOURCE_DIR}/userland/apps/windows_kill/windows-kill.exe")
set(DUETOS_WINKILL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_winkill_pe.h")

add_custom_command(
    OUTPUT "${DUETOS_WINKILL_HEADER}"
    COMMAND python3
            "${DUETOS_EMBED_BLOB_SCRIPT}"
            "${DUETOS_WINKILL_SRC}"
            "${DUETOS_WINKILL_HEADER}"
            kBinWinKillBytes
            --namespace "duetos::fs::generated"
    DEPENDS
        "${DUETOS_WINKILL_SRC}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Embedding real Windows PE /bin/windows-kill.exe"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_WINKILL_HEADER}")

# ----------------------------------------------------------------------------
# Third PE fixture: hello_winapi.exe — first userland program
# that talks to the DuetOS Win32 subsystem through a real
# Import Directory. Built via llvm-dlltool (kernel32.lib) +
# clang + lld-link. See tools/build-hello-winapi.sh and
# .claude/knowledge/pe-subsystem-v0.md for the layered
# mechanism.
# ----------------------------------------------------------------------------
set(DUETOS_HELLO_WINAPI_SRC "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/hello.c")
# Every .def file in the hello_winapi dir becomes a separate
# import library feeding lld-link. Glob-dependency means adding
# a new .def (e.g. for a future DLL stub set) automatically
# triggers a rebuild without touching this CMakeLists.
file(GLOB DUETOS_HELLO_WINAPI_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/hello_winapi/*.def")
set(DUETOS_HELLO_WINAPI_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_hello_winapi.h")
set(DUETOS_HELLO_WINAPI_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-hello-winapi.sh")

add_custom_command(
    OUTPUT "${DUETOS_HELLO_WINAPI_HEADER}"
    COMMAND "${DUETOS_HELLO_WINAPI_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_HELLO_WINAPI_HEADER}"
    DEPENDS
        "${DUETOS_HELLO_WINAPI_SRC}"
        ${DUETOS_HELLO_WINAPI_DEFS}
        "${DUETOS_HELLO_WINAPI_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/hello_winapi.exe (Win32 import path)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_HELLO_WINAPI_HEADER}")

# ----------------------------------------------------------------------------
# Fourth PE fixture: thread_stress.exe — exercises CreateThread,
# CreateEventW, SetEvent, WaitForSingleObject round-trip. Verifies
# the batch-50 SYS_THREAD_CREATE wiring works end-to-end: main
# creates a child thread, child writes a sentinel + signals an
# event, main wakes + checks the sentinel.
# ----------------------------------------------------------------------------
set(DUETOS_THREAD_STRESS_SRC "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress/hello.c")
file(GLOB DUETOS_THREAD_STRESS_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/thread_stress/*.def")
set(DUETOS_THREAD_STRESS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_thread_stress.h")
set(DUETOS_THREAD_STRESS_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-thread-stress.sh")

add_custom_command(
    OUTPUT "${DUETOS_THREAD_STRESS_HEADER}"
    COMMAND "${DUETOS_THREAD_STRESS_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_THREAD_STRESS_HEADER}"
    DEPENDS
        "${DUETOS_THREAD_STRESS_SRC}"
        ${DUETOS_THREAD_STRESS_DEFS}
        "${DUETOS_THREAD_STRESS_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/thread_stress.exe (CreateThread path)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_THREAD_STRESS_HEADER}")

# ----------------------------------------------------------------------------
# Fifth PE fixture: syscall_stress.exe — exercises the batch-51
# Win32 API additions: OutputDebugStringA, ExitThread,
# GetProcessTimes / GetThreadTimes / GetSystemTimes,
# GlobalMemoryStatusEx, WaitForMultipleObjects.
# ----------------------------------------------------------------------------
set(DUETOS_SYSCALL_STRESS_SRC "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress/hello.c")
file(GLOB DUETOS_SYSCALL_STRESS_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/syscall_stress/*.def")
set(DUETOS_SYSCALL_STRESS_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_syscall_stress.h")
set(DUETOS_SYSCALL_STRESS_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-syscall-stress.sh")

add_custom_command(
    OUTPUT "${DUETOS_SYSCALL_STRESS_HEADER}"
    COMMAND "${DUETOS_SYSCALL_STRESS_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_SYSCALL_STRESS_HEADER}"
    DEPENDS
        "${DUETOS_SYSCALL_STRESS_SRC}"
        ${DUETOS_SYSCALL_STRESS_DEFS}
        "${DUETOS_SYSCALL_STRESS_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/syscall_stress.exe (batch 51 API coverage)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_SYSCALL_STRESS_HEADER}")

# ----------------------------------------------------------------------------
# Sixth PE fixture: windowed_hello.exe — first PE that creates a
# real window via the user32 → SYS_WIN_CREATE bridge. Proves the
# windowing v0 slice end-to-end: import-resolved user32!
# CreateWindowExA lands in the kernel compositor + paints.
# ----------------------------------------------------------------------------
set(DUETOS_WINDOWED_HELLO_SRC "${CMAKE_SOURCE_DIR}/userland/apps/windowed_hello/hello.c")
file(GLOB DUETOS_WINDOWED_HELLO_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/windowed_hello/*.def")
set(DUETOS_WINDOWED_HELLO_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_windowed_hello.h")
set(DUETOS_WINDOWED_HELLO_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-windowed-hello.sh")

add_custom_command(
    OUTPUT "${DUETOS_WINDOWED_HELLO_HEADER}"
    COMMAND "${DUETOS_WINDOWED_HELLO_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_WINDOWED_HELLO_HEADER}"
    DEPENDS
        "${DUETOS_WINDOWED_HELLO_SRC}"
        ${DUETOS_WINDOWED_HELLO_DEFS}
        "${DUETOS_WINDOWED_HELLO_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/windowed_hello.exe (user32 window bridge)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_WINDOWED_HELLO_HEADER}")

# ----------------------------------------------------------------------------
# Test fixture for the stage-2 EAT parser + DLL loader: a tiny
# freestanding Windows DLL with three exported C functions
# (CustomAdd, CustomMul, CustomVersion). Built by clang +
# lld-link /dll /noentry, no CRT, no imports. The kernel self-
# test in kernel_main (DllLoaderSelfTest) parses the embedded
# bytes via PeParseExports and DllLoad to confirm name + ordinal
# lookups return the expected RVAs.
# ----------------------------------------------------------------------------
set(DUETOS_CUSTOMDLL_SRC "${CMAKE_SOURCE_DIR}/userland/libs/customdll/customdll.c")
set(DUETOS_CUSTOMDLL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll.h")
set(DUETOS_CUSTOMDLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll.sh")

add_custom_command(
    OUTPUT "${DUETOS_CUSTOMDLL_HEADER}"
    COMMAND "${DUETOS_CUSTOMDLL_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_CUSTOMDLL_HEADER}"
    DEPENDS
        "${DUETOS_CUSTOMDLL_SRC}"
        "${DUETOS_CUSTOMDLL_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding customdll.dll (EAT parser fixture)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_CUSTOMDLL_HEADER}")

# ----------------------------------------------------------------------------
# Second test DLL for the stage-2 slice 9 multi-DLL preload path.
# Exports CustomDouble(int) -> int at load base 0x10010000.
# Deliberately disjoint exports from customdll.dll so a call to
# CustomDouble HAS to reach the second entry in the preload
# array — proves the resolver walks past the first DLL on miss.
# ----------------------------------------------------------------------------
set(DUETOS_CUSTOMDLL2_SRC "${CMAKE_SOURCE_DIR}/userland/libs/customdll2/customdll2.c")
set(DUETOS_CUSTOMDLL2_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll2.h")
set(DUETOS_CUSTOMDLL2_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll2.sh")

add_custom_command(
    OUTPUT "${DUETOS_CUSTOMDLL2_HEADER}"
    COMMAND "${DUETOS_CUSTOMDLL2_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_CUSTOMDLL2_HEADER}"
    DEPENDS
        "${DUETOS_CUSTOMDLL2_SRC}"
        "${DUETOS_CUSTOMDLL2_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding customdll2.dll (multi-DLL preload fixture)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_CUSTOMDLL2_HEADER}")

# ----------------------------------------------------------------------------
# Userland kernel32.dll — stage-2 slice 10 kicks off the
# retirement of flat-stubs-page entries into real userland
# code. First export: GetCurrentProcessId. Future slices
# extend kernel32.c with more entry points; every addition
# retires the matching stub (which stays compiled as a
# fallback but becomes unreachable via slice-6's via-DLL
# priority).
# ----------------------------------------------------------------------------
set(DUETOS_KERNEL32_SRC "${CMAKE_SOURCE_DIR}/userland/libs/kernel32/kernel32.c")
set(DUETOS_KERNEL32_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_kernel32_dll.h")
set(DUETOS_KERNEL32_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-kernel32-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_KERNEL32_HEADER}"
    COMMAND "${DUETOS_KERNEL32_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_KERNEL32_HEADER}"
    DEPENDS
        "${DUETOS_KERNEL32_SRC}"
        "${DUETOS_KERNEL32_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding kernel32.dll (first stub retirement)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_KERNEL32_HEADER}")

# ----------------------------------------------------------------------------
# Userland vcruntime140.dll — stage-2 slice 13. Retires the
# batch-5 memset/memcpy/memmove flat stubs. Every MSVC-built
# PE calls these routinely (struct copy / zero-init / CRT
# startup), so the via-DLL path fires heavily.
# ----------------------------------------------------------------------------
set(DUETOS_VCRUNTIME140_SRC "${CMAKE_SOURCE_DIR}/userland/libs/vcruntime140/vcruntime140.c")
set(DUETOS_VCRUNTIME140_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_vcruntime140_dll.h")
set(DUETOS_VCRUNTIME140_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-vcruntime140-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_VCRUNTIME140_HEADER}"
    COMMAND "${DUETOS_VCRUNTIME140_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_VCRUNTIME140_HEADER}"
    DEPENDS
        "${DUETOS_VCRUNTIME140_SRC}"
        "${DUETOS_VCRUNTIME140_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding vcruntime140.dll (memset/memcpy/memmove retirement)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_VCRUNTIME140_HEADER}")

# ----------------------------------------------------------------------------
# Userland msvcrt.dll — stage-2 slice 14. Retires the string
# intrinsics (strlen / strcmp / strcpy / strchr + wide
# variants) from the flat stubs.
# ----------------------------------------------------------------------------
set(DUETOS_MSVCRT_SRC "${CMAKE_SOURCE_DIR}/userland/libs/msvcrt/msvcrt.c")
set(DUETOS_MSVCRT_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_msvcrt_dll.h")
set(DUETOS_MSVCRT_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-msvcrt-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_MSVCRT_HEADER}"
    COMMAND "${DUETOS_MSVCRT_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_MSVCRT_HEADER}"
    DEPENDS
        "${DUETOS_MSVCRT_SRC}"
        "${DUETOS_MSVCRT_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding msvcrt.dll (string intrinsics retirement)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_MSVCRT_HEADER}")

# ----------------------------------------------------------------------------
# Userland ntdll.dll — stage-2 slice 24. Retires the batch-42+
# Nt* / Zw* / Rtl* / Ldr* / __chkstk surface. 108 exports
# total (Zw* aliases emitted as same-DLL forwarders).
# ----------------------------------------------------------------------------
set(DUETOS_NTDLL_SRC "${CMAKE_SOURCE_DIR}/userland/libs/ntdll/ntdll.c")
set(DUETOS_NTDLL_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_ntdll_dll.h")
set(DUETOS_NTDLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-ntdll-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_NTDLL_HEADER}"
    COMMAND "${DUETOS_NTDLL_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_NTDLL_HEADER}"
    DEPENDS
        "${DUETOS_NTDLL_SRC}"
        "${DUETOS_NTDLL_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding ntdll.dll (Nt* / Zw* / Rtl* / Ldr* retirement)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_NTDLL_HEADER}")

# ----------------------------------------------------------------------------
# Userland dbghelp.dll — stage-2 slice 25. 11 Sym* / StackWalk
# / MiniDumpWriteDump no-ops; callers always check return.
# ----------------------------------------------------------------------------
set(DUETOS_DBGHELP_SRC "${CMAKE_SOURCE_DIR}/userland/libs/dbghelp/dbghelp.c")
set(DUETOS_DBGHELP_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_dbghelp_dll.h")
set(DUETOS_DBGHELP_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-dbghelp-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_DBGHELP_HEADER}"
    COMMAND "${DUETOS_DBGHELP_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_DBGHELP_HEADER}"
    DEPENDS
        "${DUETOS_DBGHELP_SRC}"
        "${DUETOS_DBGHELP_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding dbghelp.dll (Sym* no-ops)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_DBGHELP_HEADER}")

# ----------------------------------------------------------------------------
# Userland msvcp140.dll — stage-2 slice 26. 17 mangled C++
# std:: names (throw helpers + ostream + iostate) via .def.
# ----------------------------------------------------------------------------
set(DUETOS_MSVCP140_SRC "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.c")
set(DUETOS_MSVCP140_DEF "${CMAKE_SOURCE_DIR}/userland/libs/msvcp140/msvcp140.def")
set(DUETOS_MSVCP140_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_msvcp140_dll.h")
set(DUETOS_MSVCP140_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-msvcp140-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_MSVCP140_HEADER}"
    COMMAND "${DUETOS_MSVCP140_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_MSVCP140_HEADER}"
    DEPENDS
        "${DUETOS_MSVCP140_SRC}"
        "${DUETOS_MSVCP140_DEF}"
        "${DUETOS_MSVCP140_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding msvcp140.dll (C++ std throw + ostream helpers)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_MSVCP140_HEADER}")

# ----------------------------------------------------------------------------
# Userland kernelbase.dll — stage-2 slice 27. Forwarder-only
# DLL: every export cross-forwards to kernel32.dll via the
# slice-8 chaser in the kernel loader.
# ----------------------------------------------------------------------------
set(DUETOS_KERNELBASE_SRC "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.c")
set(DUETOS_KERNELBASE_DEF "${CMAKE_SOURCE_DIR}/userland/libs/kernelbase/kernelbase.def")
set(DUETOS_KERNELBASE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_kernelbase_dll.h")
set(DUETOS_KERNELBASE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-kernelbase-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_KERNELBASE_HEADER}"
    COMMAND "${DUETOS_KERNELBASE_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${DUETOS_KERNELBASE_HEADER}"
    DEPENDS "${DUETOS_KERNELBASE_SRC}" "${DUETOS_KERNELBASE_DEF}" "${DUETOS_KERNELBASE_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding kernelbase.dll (forwarders -> kernel32)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_KERNELBASE_HEADER}")

# ----------------------------------------------------------------------------
# Userland advapi32.dll — stage-2 slice 27. 25 exports: Reg*
# (all return "not found"), token/privilege (pretend success),
# GetUserName* (constant), SystemFunction036 (deterministic).
# ----------------------------------------------------------------------------
set(DUETOS_ADVAPI32_SRC "${CMAKE_SOURCE_DIR}/userland/libs/advapi32/advapi32.c")
set(DUETOS_ADVAPI32_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_advapi32_dll.h")
set(DUETOS_ADVAPI32_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-advapi32-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_ADVAPI32_HEADER}"
    COMMAND "${DUETOS_ADVAPI32_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${DUETOS_ADVAPI32_HEADER}"
    DEPENDS "${DUETOS_ADVAPI32_SRC}" "${DUETOS_ADVAPI32_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding advapi32.dll (Reg* / token / GetUserName / RtlGenRandom)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_ADVAPI32_HEADER}")

# ----------------------------------------------------------------------------
# Stage-2 slice 28 — seven small stub DLLs built via a generic
# helper (tools/build-stub-dll.sh). Each DLL has a small hand-
# written .c source + an export list passed on the CMake cmd-
# line.
# ----------------------------------------------------------------------------
set(DUETOS_STUB_DLL_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-stub-dll.sh")

macro(duetos_stub_dll name base_va exports)
    set(_src "${CMAKE_SOURCE_DIR}/userland/libs/${name}/${name}.c")
    set(_header "${CMAKE_CURRENT_BINARY_DIR}/generated_${name}_dll.h")
    add_custom_command(
        OUTPUT "${_header}"
        COMMAND "${DUETOS_STUB_DLL_SCRIPT}"
                "${CMAKE_SOURCE_DIR}" "${_header}" "${name}" "${base_va}" "${exports}"
        DEPENDS "${_src}" "${DUETOS_STUB_DLL_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
        COMMENT "Compiling + embedding ${name}.dll"
        VERBATIM
    )
    list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${_header}")
    set(DUETOS_${name}_HEADER "${_header}" PARENT_SCOPE_UNUSED)
endmacro()

duetos_stub_dll(shlwapi 0x100B0000 "PathAddBackslashW,PathAppendW,PathCombineW,PathFileExistsA,PathFileExistsW,PathFindExtensionA,PathFindExtensionW,PathFindFileNameA,PathFindFileNameW,PathIsDirectoryW,PathRemoveFileSpecW,PathStripPathW,StrCmpNW,StrCmpW,StrStrIW,StrStrW")
duetos_stub_dll(shell32 0x100C0000 "CommandLineToArgvW,ExtractIconW,ExtractIconExW,SHCreateDirectoryW,SHCreateDirectoryExW,SHFileOperationW,SHGetFolderPathA,SHGetFolderPathW,SHGetKnownFolderPath,SHGetPathFromIDListW,SHGetSpecialFolderPathW,ShellExecuteW,ShellExecuteExW")
duetos_stub_dll(ole32 0x100D0000 "CoInitialize,CoInitializeEx,CoUninitialize,OleInitialize,OleUninitialize,CoCreateInstance,CoCreateInstanceEx,CoGetClassObject,CLSIDFromString,CLSIDFromProgID,IIDFromString,StringFromCLSID,CoTaskMemAlloc,CoTaskMemFree,CoTaskMemRealloc")
duetos_stub_dll(oleaut32 0x100E0000 "VariantInit,VariantClear,SysAllocString,SysFreeString,SysStringLen")
duetos_stub_dll(winmm 0x100F0000 "timeGetTime,timeBeginPeriod,timeEndPeriod,timeGetDevCaps,timeSetEvent,timeKillEvent,PlaySoundW,mciSendStringW")
duetos_stub_dll(bcrypt 0x10100000 "BCryptOpenAlgorithmProvider,BCryptCloseAlgorithmProvider,BCryptCreateHash,BCryptHashData,BCryptFinishHash,BCryptDestroyHash,BCryptGetProperty,BCryptGenRandom")
duetos_stub_dll(psapi 0x10110000 "EnumProcesses,EnumProcessModules,GetMappedFileNameW,GetModuleBaseNameW,GetModuleFileNameExW,GetProcessMemoryInfo,QueryWorkingSet")

# --- DirectX v0 — real COM-vtable d3d9/d3d11/d3d12/dxgi DLLs that
#     produce working Clear-and-Present pipelines via SYS_GDI_BITBLT.
#     See userland/libs/dx_shared.h + .claude/knowledge/directx-v0.md.
duetos_stub_dll(d3d9 0x10120000 "Direct3DCreate9,Direct3DCreate9Ex")
duetos_stub_dll(d3d11 0x10130000 "D3D11CreateDevice,D3D11CreateDeviceAndSwapChain")
duetos_stub_dll(d3d12 0x10140000 "D3D12CreateDevice,D3D12GetDebugInterface,D3D12SerializeRootSignature")
duetos_stub_dll(dxgi 0x10150000 "CreateDXGIFactory,CreateDXGIFactory1,CreateDXGIFactory2,DXGIGetDebugInterface,DXGIGetDebugInterface1,DXGIDeclareAdapterRemovalSupport")
duetos_stub_dll(user32 0x10160000 "BeginPaint,Beep,CallWindowProcA,CallWindowProcW,CharLowerW,CharUpperW,ClientToScreen,ClipCursor,CloseClipboard,CreateCaret,CreateWindowExA,CreateWindowExW,DefWindowProcA,DefWindowProcW,DestroyCaret,DestroyWindow,DispatchMessageA,DispatchMessageW,EmptyClipboard,EndPaint,EnumWindows,FindWindowA,FindWindowExA,FindWindowExW,FindWindowW,GetActiveWindow,GetAsyncKeyState,GetCapture,GetCaretBlinkTime,GetClientRect,GetClipboardData,GetCursorPos,GetDesktopWindow,GetFocus,GetForegroundWindow,GetKeyState,GetMessageA,GetMessageW,GetParent,GetProcessWindowStation,GetSysColor,GetSystemMetrics,GetWindow,GetWindowLongA,GetWindowLongPtrA,GetWindowLongPtrW,GetWindowLongW,GetWindowRect,GetWindowTextA,GetWindowTextW,HideCaret,InvalidateRect,IsWindow,KillTimer,LoadAcceleratorsA,LoadAcceleratorsW,LoadBitmapA,LoadBitmapW,LoadCursorA,LoadCursorW,LoadIconA,LoadIconW,LoadImageA,LoadImageW,LoadMenuA,LoadMenuW,LoadStringA,LoadStringW,MessageBeep,MessageBoxA,MessageBoxExA,MessageBoxExW,MessageBoxW,MoveWindow,OpenClipboard,PeekMessageA,PeekMessageW,PostMessageA,PostMessageW,PostQuitMessage,PostThreadMessageA,PostThreadMessageW,RegisterClassA,RegisterClassExA,RegisterClassExW,RegisterClassW,ReleaseCapture,ScreenToClient,SendMessageA,SendMessageW,SendNotifyMessageA,SendNotifyMessageW,SetActiveWindow,SetCapture,SetCaretBlinkTime,SetCaretPos,SetClipboardData,SetCursor,SetCursorPos,SetFocus,SetForegroundWindow,SetParent,SetTimer,SetWindowLongA,SetWindowLongPtrA,SetWindowLongPtrW,SetWindowLongW,SetWindowPos,SetWindowTextA,SetWindowTextW,ShowCaret,ShowCursor,ShowWindow,TranslateAcceleratorA,TranslateAcceleratorW,TranslateMessage,UnregisterClassA,UnregisterClassW,UpdateWindow,ValidateRect")
duetos_stub_dll(gdi32 0x10180000 "BitBlt,CreateBitmap,CreateBrushIndirect,CreateCompatibleBitmap,CreateCompatibleDC,CreateDIBSection,CreateDIBitmap,CreateFontA,CreateFontIndirectA,CreateFontIndirectW,CreateFontW,CreatePen,CreateSolidBrush,DeleteDC,DeleteObject,DrawTextA,DrawTextW,Ellipse,ExtTextOutA,ExtTextOutW,FillRect,FrameRect,GetDC,GetObjectA,GetObjectW,GetPixel,GetStockObject,GetWindowDC,LineTo,MoveToEx,Polygon,Polyline,Rectangle,ReleaseDC,RestoreDC,SaveDC,SelectObject,SetBkColor,SetBkMode,SetMapMode,SetPixel,SetPixelV,SetTextAlign,SetTextColor,StretchBlt,TextOutA,TextOutW")

# --- Stage-2 slice 31 — networking / crypto / common UI / version / setup ---
duetos_stub_dll(ws2_32 0x10190000 "WSAStartup,WSACleanup,WSAGetLastError,WSASetLastError,socket,closesocket,bind,listen,connect,accept,send,recv,sendto,recvfrom,shutdown,setsockopt,getsockopt,select,htons,ntohs,htonl,ntohl,inet_addr,gethostbyname,gethostname,getaddrinfo,freeaddrinfo")
duetos_stub_dll(wininet 0x101A0000 "InternetOpenA,InternetOpenW,InternetConnectA,HttpOpenRequestA,HttpSendRequestA,InternetReadFile,InternetCloseHandle,InternetOpenUrlA")
duetos_stub_dll(winhttp 0x101B0000 "WinHttpOpen,WinHttpConnect,WinHttpOpenRequest,WinHttpSendRequest,WinHttpReceiveResponse,WinHttpReadData,WinHttpCloseHandle")
duetos_stub_dll(crypt32 0x101C0000 "CertOpenStore,CertCloseStore,CertFindCertificateInStore,CertFreeCertificateContext,CryptAcquireContextA,CryptReleaseContext,CryptGenRandom,CryptProtectData,CryptUnprotectData")
duetos_stub_dll(comctl32 0x101D0000 "InitCommonControls,InitCommonControlsEx,CreateStatusWindowA,CreateStatusWindowW,PropertySheetA,PropertySheetW,ImageList_Create,ImageList_Destroy")
duetos_stub_dll(comdlg32 0x101E0000 "GetOpenFileNameA,GetOpenFileNameW,GetSaveFileNameA,GetSaveFileNameW,ChooseColorA,ChooseColorW,ChooseFontA,ChooseFontW,PrintDlgA,PrintDlgW,CommDlgExtendedError")
duetos_stub_dll(version 0x101F0000 "GetFileVersionInfoSizeA,GetFileVersionInfoSizeW,GetFileVersionInfoA,GetFileVersionInfoW,VerQueryValueA,VerQueryValueW")
duetos_stub_dll(setupapi 0x10200000 "SetupDiGetClassDevsA,SetupDiGetClassDevsW,SetupDiDestroyDeviceInfoList,SetupDiEnumDeviceInfo,SetupOpenInfFileA,SetupOpenInfFileW,SetupCloseInfFile")

# --- Stage-2 slice 33 — six more support DLLs ---
duetos_stub_dll(iphlpapi 0x10210000 "GetAdaptersInfo,GetAdaptersAddresses,GetIfTable,GetNumberOfInterfaces,IcmpSendEcho,IcmpCreateFile,IcmpCloseHandle")
duetos_stub_dll(userenv 0x10220000 "GetUserProfileDirectoryA,GetUserProfileDirectoryW,GetAllUsersProfileDirectoryW,CreateEnvironmentBlock,DestroyEnvironmentBlock,LoadUserProfileW,UnloadUserProfile")
duetos_stub_dll(wtsapi32 0x10230000 "WTSQuerySessionInformationA,WTSQuerySessionInformationW,WTSFreeMemory,WTSEnumerateSessionsW,WTSRegisterSessionNotification,WTSUnRegisterSessionNotification")
duetos_stub_dll(dwmapi 0x10240000 "DwmIsCompositionEnabled,DwmEnableComposition,DwmExtendFrameIntoClientArea,DwmGetWindowAttribute,DwmSetWindowAttribute,DwmFlush")
duetos_stub_dll(uxtheme 0x10250000 "OpenThemeData,CloseThemeData,IsThemeActive,IsAppThemed,SetWindowTheme,GetThemeSysFont,DrawThemeBackground,DrawThemeText")
duetos_stub_dll(secur32 0x10260000 "AcquireCredentialsHandleA,FreeCredentialsHandle,InitializeSecurityContextA,DeleteSecurityContext,GetUserNameExA,GetUserNameExW")

# ----------------------------------------------------------------------------
# Userland ucrtbase.dll — stage-2 slice 15. Retires the
# UCRT runtime stubs: heap alloc (malloc/free/calloc/realloc
# /_aligned_*), terminators (exit/_exit), CRT startup shims
# (_initterm/_initterm_e/_cexit/_c_exit/_set_app_type/
# __setusermatherr/_configthreadlocale), plus string
# intrinsics aliased from msvcrt.
# ----------------------------------------------------------------------------
set(DUETOS_UCRTBASE_SRC "${CMAKE_SOURCE_DIR}/userland/libs/ucrtbase/ucrtbase.c")
set(DUETOS_UCRTBASE_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_ucrtbase_dll.h")
set(DUETOS_UCRTBASE_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-ucrtbase-dll.sh")

add_custom_command(
    OUTPUT "${DUETOS_UCRTBASE_HEADER}"
    COMMAND "${DUETOS_UCRTBASE_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_UCRTBASE_HEADER}"
    DEPENDS
        "${DUETOS_UCRTBASE_SRC}"
        "${DUETOS_UCRTBASE_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding ucrtbase.dll (heap + exit + CRT startup retirement)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_UCRTBASE_HEADER}")

# ----------------------------------------------------------------------------
# Sixth PE fixture: customdll_test.exe — first userland program
# that imports from a real loaded DLL (customdll.dll) rather
# than from the flat stubs page. Exercises stage-2 slice 6's
# via-DLL IAT resolution path end-to-end.
# ----------------------------------------------------------------------------
set(DUETOS_CUSTOMDLL_TEST_SRC "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test/hello.c")
file(GLOB DUETOS_CUSTOMDLL_TEST_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/customdll_test/*.def")
set(DUETOS_CUSTOMDLL_TEST_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_customdll_test.h")
set(DUETOS_CUSTOMDLL_TEST_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-customdll-test.sh")

add_custom_command(
    OUTPUT "${DUETOS_CUSTOMDLL_TEST_HEADER}"
    COMMAND "${DUETOS_CUSTOMDLL_TEST_SCRIPT}"
            "${CMAKE_SOURCE_DIR}"
            "${DUETOS_CUSTOMDLL_TEST_HEADER}"
    DEPENDS
        "${DUETOS_CUSTOMDLL_TEST_SRC}"
        ${DUETOS_CUSTOMDLL_TEST_DEFS}
        "${DUETOS_CUSTOMDLL_TEST_SCRIPT}"
        "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding /bin/customdll_test.exe (stage-2 slice 6 fixture)"
    VERBATIM
)

list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_CUSTOMDLL_TEST_HEADER}")

# --- Stage-2 slice 34 — real-registry + real-fopen test fixture ---
set(DUETOS_REG_FOPEN_TEST_SRC "${CMAKE_SOURCE_DIR}/userland/apps/reg_fopen_test/hello.c")
file(GLOB DUETOS_REG_FOPEN_TEST_DEFS
    "${CMAKE_SOURCE_DIR}/userland/apps/reg_fopen_test/*.def")
set(DUETOS_REG_FOPEN_TEST_HEADER "${CMAKE_CURRENT_BINARY_DIR}/generated_reg_fopen_test.h")
set(DUETOS_REG_FOPEN_TEST_SCRIPT "${CMAKE_SOURCE_DIR}/tools/build-reg-fopen-test.sh")
add_custom_command(
    OUTPUT "${DUETOS_REG_FOPEN_TEST_HEADER}"
    COMMAND "${DUETOS_REG_FOPEN_TEST_SCRIPT}" "${CMAKE_SOURCE_DIR}" "${DUETOS_REG_FOPEN_TEST_HEADER}"
    DEPENDS "${DUETOS_REG_FOPEN_TEST_SRC}" ${DUETOS_REG_FOPEN_TEST_DEFS}
            "${DUETOS_REG_FOPEN_TEST_SCRIPT}" "${DUETOS_EMBED_BLOB_SCRIPT}"
    COMMENT "Compiling + embedding reg_fopen_test.exe (registry + fopen fixture)"
    VERBATIM
)
list(APPEND DUETOS_KERNEL_SHARED_SOURCES "${DUETOS_REG_FOPEN_TEST_HEADER}")

set(DUETOS_KERNEL_LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/arch/x86_64/linker.ld")

# Shared link flags — applied identically to both stages so the symbol
# addresses extracted from stage 1 are valid for stage 2.
function(duetos_apply_kernel_link_flags target)
    target_link_options(${target} PRIVATE
        -T${DUETOS_KERNEL_LINKER_SCRIPT}
        -Wl,--gc-sections
        -Wl,--no-undefined
        -Wl,-n
    )
    set_target_properties(${target} PROPERTIES
        LINK_DEPENDS "${DUETOS_KERNEL_LINKER_SCRIPT}"
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
add_executable(duetos-kernel-stage1
    ${DUETOS_KERNEL_SHARED_SOURCES}
    core/symbols_stub.cpp
)
set_target_properties(duetos-kernel-stage1 PROPERTIES
    OUTPUT_NAME "duetos-kernel-stage1.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
    # Stage 1 is internal plumbing — don't install or package it.
    EXCLUDE_FROM_ALL FALSE
)
target_include_directories(duetos-kernel-stage1 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)
duetos_apply_kernel_link_flags(duetos-kernel-stage1)

# ----------------------------------------------------------------------------
# Generate symbols_generated.cpp from the stage-1 ELF.
#
# gen-symbols.sh reads every higher-half function symbol, resolves
# addr -> (file, line) via addr2line, and emits a sorted-by-address
# `{addr, size, line, name, file}` table. The resulting TU is what the
# stage-2 kernel links against.
# ----------------------------------------------------------------------------
set(DUETOS_SYMBOLS_GENERATED "${CMAKE_CURRENT_BINARY_DIR}/symbols_generated.cpp")

add_custom_command(
    OUTPUT "${DUETOS_SYMBOLS_GENERATED}"
    COMMAND "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
            "$<TARGET_FILE:duetos-kernel-stage1>"
            "${DUETOS_SYMBOLS_GENERATED}"
            "${CMAKE_SOURCE_DIR}"
    DEPENDS duetos-kernel-stage1 "${CMAKE_SOURCE_DIR}/tools/gen-symbols.sh"
    COMMENT "Extracting kernel symbol table from stage-1 ELF"
    VERBATIM
)

# ----------------------------------------------------------------------------
# Stage 2: final kernel. Same source set as stage 1, but the stub is
# replaced by the generated TU. The generated TU defines the same
# three extern "C" symbols the resolver looks up, now populated with
# real data.
# ----------------------------------------------------------------------------
add_executable(duetos-kernel
    ${DUETOS_KERNEL_SHARED_SOURCES}
    "${DUETOS_SYMBOLS_GENERATED}"
)

# Deliberate-panic build flag, consumed by kernel_main and triggered
# by tools/test-panic.sh. OFF for normal builds — the demo panic
# halts the kernel on purpose and must not ship in a release preset.
option(DUETOS_PANIC_DEMO "Insert a deliberate Panic() at end of kernel_main (test-panic.sh)" OFF)
if(DUETOS_PANIC_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_PANIC_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_PANIC_DEMO=1)
endif()

# Deliberate stack-smash build flag. Enables a small in-kernel_main
# block that overruns a local array past its stack canary, forcing
# __stack_chk_fail to fire on return. Intended for verifying the
# canary infrastructure works end-to-end; OFF for normal builds.
option(DUETOS_CANARY_DEMO "Insert a deliberate stack smash at end of kernel_main (verifies stack-canary panic path)" OFF)
if(DUETOS_CANARY_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_CANARY_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_CANARY_DEMO=1)
endif()

# Red-team attack-simulation flag. Runs the AttackSim suite once
# at the end of kernel_main, exercising every runtime-checker
# detector by performing the attack a rootkit would and
# verifying the detector catches it. OFF for normal boot — the
# simulations escalate the security guard to Enforce mode and
# the block write-guard to Deny, which would poison every
# subsequent image load / sensitive-LBA write for the session.
option(DUETOS_ATTACK_SIM "Run the AttackSim red-team suite at end of kernel_main" OFF)
if(DUETOS_ATTACK_SIM)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_ATTACK_SIM=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_ATTACK_SIM=1)
endif()


# Deliberate-CPU-exception build flag, consumed by kernel_main and
# triggered by tools/test-trap.sh. Executes `ud2` to take a #UD fault
# so the trap dispatcher's crash-dump path can be verified end-to-end
# (extractable BEGIN/END record, symbolized RIP, backtrace). OFF for
# normal builds.
option(DUETOS_TRAP_DEMO "Execute ud2 at end of kernel_main to take #UD (test-trap.sh)" OFF)
if(DUETOS_TRAP_DEMO)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_TRAP_DEMO=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_TRAP_DEMO=1)
endif()


# Initial boot mode: desktop (windowed shell) vs TTY (fullscreen
# framebuffer console). Runtime toggle with Ctrl+Alt+T works
# regardless of this flag; it only affects what the user sees
# when the kernel first hits kernel_main's compose phase. Useful
# for an install / rescue build that prefers text-first UX.
option(DUETOS_BOOT_TTY "Boot straight into TTY mode instead of the windowed desktop" OFF)
if(DUETOS_BOOT_TTY)
    target_compile_definitions(duetos-kernel          PRIVATE DUETOS_BOOT_TTY=1)
    target_compile_definitions(duetos-kernel-stage1   PRIVATE DUETOS_BOOT_TTY=1)
endif()

set_target_properties(duetos-kernel PROPERTIES
    OUTPUT_NAME "duetos-kernel.elf"
    C_STANDARD 17
    CXX_STANDARD 23
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO
)

target_include_directories(duetos-kernel PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

duetos_apply_kernel_link_flags(duetos-kernel)

# ----------------------------------------------------------------------------
# Bootable ISO — uses GRUB as a third-party loader until our own UEFI boot
# loader exists. If grub-mkrescue / xorriso aren't installed, the kernel
# still builds; only the `duetos-iso` target is skipped, with a status
# message explaining what to install.
# ----------------------------------------------------------------------------

find_program(GRUB_MKRESCUE grub-mkrescue)
find_program(XORRISO       xorriso)

if(GRUB_MKRESCUE AND XORRISO)
    set(DUETOS_ISO_STAGE  "${CMAKE_CURRENT_BINARY_DIR}/iso-stage")
    set(DUETOS_ISO_OUTPUT "${CMAKE_BINARY_DIR}/duetos.iso")
    set(DUETOS_GRUB_CFG   "${CMAKE_SOURCE_DIR}/boot/grub/grub.cfg")

    add_custom_command(
        OUTPUT "${DUETOS_ISO_OUTPUT}"

        # Lay out the ISO root exactly the way grub.cfg expects.
        COMMAND ${CMAKE_COMMAND} -E rm -rf  "${DUETOS_ISO_STAGE}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DUETOS_ISO_STAGE}/boot/grub"
        COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:duetos-kernel>"
                                         "${DUETOS_ISO_STAGE}/boot/duetos-kernel.elf"
        COMMAND ${CMAKE_COMMAND} -E copy "${DUETOS_GRUB_CFG}"
                                         "${DUETOS_ISO_STAGE}/boot/grub/grub.cfg"

        # Produce the ISO. grub-mkrescue embeds the i386-pc boot image so the
        # result is bootable on both legacy BIOS (via QEMU's default SeaBIOS)
        # and — when GRUB's EFI modules are present on the host — UEFI.
        COMMAND ${GRUB_MKRESCUE} --compress=xz -o "${DUETOS_ISO_OUTPUT}"
                                 "${DUETOS_ISO_STAGE}"

        DEPENDS duetos-kernel "${DUETOS_GRUB_CFG}"
        COMMENT "Building bootable duetos.iso"
        VERBATIM
    )

    add_custom_target(duetos-iso ALL
        DEPENDS "${DUETOS_ISO_OUTPUT}"
    )
else()
    message(STATUS "duetos-iso target disabled (grub-mkrescue or xorriso not found).")
    message(STATUS "  Install with: sudo apt-get install -y grub-common grub-pc-bin xorriso mtools")
endif()
