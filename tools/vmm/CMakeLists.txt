# ---------------------------------------------------------------------------
# duetos-vmm — bespoke Windows Hypervisor Platform VMM for DuetOS.
#
# WHAT
#   A from-scratch Type-2 VMM tailored to DuetOS. It boots the *unmodified*
#   freestanding kernel ELF as a hardware-virtualised guest via the Windows
#   Hypervisor Platform (WHP), emulating only the firmware/devices DuetOS
#   actually probes, and exposing host-side introspection + a GDB-remote
#   that Visual Studio attaches to.
#
# WHY A SEPARATE PROJECT
#   The kernel build is freestanding (clang, x86_64-unknown-none-elf,
#   -nostdlib, -mcmodel=kernel). The VMM is the polar opposite: a hosted
#   MSVC Windows .exe linking WinHvPlatform.lib. They cannot share a
#   toolchain or a CMake cache, so this directory is its OWN project root
#   — it is deliberately NOT add_subdirectory()'d from the top-level
#   DuetOS CMakeLists. Configure it standalone:
#
#     cmake -S tools/vmm -B tools/vmm/build -G "Visual Studio 17 2022" -A x64
#     cmake --build tools/vmm/build --config Debug
#
#   Or just open tools/vmm/ as a CMake folder in Visual Studio 2022.
#
# ISOLATION
#   This project includes ZERO kernel headers. It treats the kernel as an
#   opaque ELF + a serial/ACPI/Multiboot2 contract. It is host tooling
#   under tools/, outside the kernel entirely — kernel subsystem-isolation
#   rules do not apply, and nothing here can be linked into a kernel TU.
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.25)

project(duetos-vmm
    VERSION     0.0.1
    LANGUAGES   CXX
    DESCRIPTION "Bespoke WHP virtual machine monitor for DuetOS")

if(NOT WIN32)
    # The VMM can only be *built* and *run* on Windows: it links
    # WinHvPlatform.lib and calls the WHP API. Fail loudly on other
    # hosts instead of producing a broken half-configured tree — the
    # DuetOS dev host is Linux, so this is the expected outcome there.
    message(FATAL_ERROR
        "duetos-vmm is Windows-only (Windows Hypervisor Platform).\n"
        "Configure and build this project on a Windows host with the\n"
        "\"Windows Hypervisor Platform\" optional feature enabled.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(duetos-vmm
    src/main.cpp
    src/vmm.cpp
    src/whp.cpp
    src/guest_memory.cpp
    src/guest_memory_fb.cpp
    src/elf64.cpp
    src/multiboot2.cpp
    src/acpi.cpp
    src/mmio_emulator.cpp
    src/devices/serial16550.cpp
    src/devices/pit8254.cpp
    src/devices/ioapic.cpp
    src/devices/ps2_i8042.cpp
    src/input/ps2_encode.cpp
    src/debug/gdb_server.cpp
    src/debug/elf_symbols.cpp
    src/debug/exit_trace.cpp
    src/debug/introspect.cpp
    src/debug/record.cpp
    src/display/window.cpp
)

target_include_directories(duetos-vmm PRIVATE src)

# WinHvPlatform.lib ships with the Windows SDK; the loader resolves
# WinHvPlatform.dll from System32 at runtime. Onecore covers the
# umbrella import lib on recent SDKs; WinHvPlatform is the explicit one.
target_link_libraries(duetos-vmm PRIVATE WinHvPlatform ws2_32 user32 gdi32)

if(MSVC)
    target_compile_options(duetos-vmm PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(duetos-vmm PRIVATE
        NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)
endif()

enable_testing()
add_subdirectory(tests)
