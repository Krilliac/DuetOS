cmake_minimum_required(VERSION 3.25)

# Toolchain must be set via -DCMAKE_TOOLCHAIN_FILE (or a preset). Detect
# that early so a plain `cmake -B build` fails loudly instead of trying
# to build kernel code with the host toolchain.
if(NOT CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR
        "DuetOS must be configured via a preset.\n"
        "  cmake --preset x86_64-debug    # or x86_64-release\n"
        "Plain `cmake -B build` is not supported — the kernel is freestanding.")
endif()

project(DuetOS
    VERSION   0.0.1
    LANGUAGES C CXX ASM
    DESCRIPTION "DuetOS — from-scratch x86_64 OS with native PE execution")

# Pinned by the active preset. Today x86_64 is the only value; aarch64 lands
# behind its own preset + toolchain file when that tier opens up.
set(DUETOS_ARCH "x86_64" CACHE STRING "Target architecture")
if(NOT DUETOS_ARCH STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported DUETOS_ARCH: ${DUETOS_ARCH}")
endif()

# Turn on folder organization in multi-config generators.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Every target in this tree is freestanding. Reject any accidental attempt
# to link against a hosted runtime.
set(CMAKE_C_EXTENSIONS   OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

# Sub-projects append their output into this, so the top-level build
# driver can produce the disk image.
set(DUETOS_ARTIFACTS "" CACHE INTERNAL "Accumulated build artifacts")

# Cleanroom-trace survey mode. OFF by default. When ON, the kernel
# auto-dumps the cleanroom-trace ring buffer to COM1 once all
# subsystems are online, and `/etc/profile` runs `crtrace show 256`
# at shell startup. Useful for headless RE / CI surveys where you
# want the trace contents without typing at the console. See
# tools/cleanroom/run-trace-survey.sh for the canonical harness.
option(DUETOS_CRTRACE_SURVEY "Enable cleanroom-trace boot-time + profile auto-dump" OFF)
if(DUETOS_CRTRACE_SURVEY)
    add_compile_definitions(DUETOS_CRTRACE_SURVEY=1)
endif()

# ----------------------------------------------------------------------------
# Build flavor — the central per-build-type axis.
#
# The kernel exposes a single `kBuildFlavor` constexpr (in
# kernel/util/build_config.h) that downstream code keys debug-only
# instrumentation off via `if constexpr (kBuildFlavor == BuildFlavor::Debug)`.
# Every per-flavor knob below ALSO gets its own option so a user who
# wants e.g. a release build with assertions on can turn just that one
# back on without flipping the whole flavor.
#
# Defaults are biased per CMAKE_BUILD_TYPE:
#   Debug   → instrumentation ON, optimizer Og, KASLR ON, asserts ON,
#             boot self-tests ON, lock-order audit ON, cap-gate audit Full,
#             klog default level Debug.
#   Release → instrumentation OFF, optimizer O2, KASLR ON, asserts OFF,
#             boot self-tests OFF, lock-order audit OFF, cap-gate audit
#             Sample, klog default level Info.
#
# Granular options can override the per-flavor default. The compile-time
# defines they emit are consumed by kernel/util/build_config.h, which is
# the single source of truth every TU includes.
# ----------------------------------------------------------------------------
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(_duetos_is_debug ON)
else()
    set(_duetos_is_debug OFF)
endif()

# Mirror the build flavor into a compile-time integer so build_config.h
# can derive constexpr knobs. 1 = Debug, 2 = Release. Anything else
# (RelWithDebInfo, MinSizeRel) maps to Release for instrumentation
# defaults — debugging is best done with the dedicated Debug preset.
if(_duetos_is_debug)
    add_compile_definitions(DUETOS_BUILD_FLAVOR=1)
else()
    add_compile_definitions(DUETOS_BUILD_FLAVOR=2)
endif()

# Per-flavor option blocks. Each option's default falls out of the build
# type; the user can flip them explicitly on the cmake command line or
# in a derived preset (see CMakePresets.json).

# Boot self-tests — the InitcallRegister(Earlycon, ...) blocks at the top
# of kernel_main that exercise Result<T,E>, freestanding string ops, the
# hexdump formatter, and the VA-region classifier. Pure tests with no
# real-init side effect. Always pass on a healthy build, so release
# images can skip them and shave the boot log.
option(DUETOS_BOOT_SELFTESTS
    "Run pure-test SelfTest functions during kernel_main boot"
    ${_duetos_is_debug})
if(DUETOS_BOOT_SELFTESTS)
    add_compile_definitions(DUETOS_BOOT_SELFTESTS=1)
endif()

# Kernel assertions. KASSERT(cond, "msg") panics on false in debug,
# compiles to nothing in release. A release-with-asserts preset keeps
# the optimizer at O2 and turns this back on for paranoid production
# builds.
option(DUETOS_ASSERTS
    "Compile KASSERT() invocations into the kernel image"
    ${_duetos_is_debug})
if(DUETOS_ASSERTS)
    add_compile_definitions(DUETOS_ASSERTS=1)
endif()

# Lock-order auditor. When ON, every spinlock/mutex acquire records the
# (lock, owner_cpu) pair into a per-CPU stack; releases pop it. A
# subsequent acquire that would create a back-edge in the lock-order
# graph triggers a one-shot warn (not a panic — the audit is advisory).
# Compiles away to a no-op when OFF.
option(DUETOS_LOCK_ORDER_AUDIT
    "Track lock acquire/release order; warn on inversions"
    ${_duetos_is_debug})
if(DUETOS_LOCK_ORDER_AUDIT)
    add_compile_definitions(DUETOS_LOCK_ORDER_AUDIT=1)
endif()

# Capability-gate audit mode. Every cap-gated syscall passes through a
# trace hook that, depending on this knob, emits:
#   Off    — no trace; the gate does the cap check and returns.
#   Sample — every Nth call (default 1024) emits a one-line trace.
#   Full   — every call emits a trace. Verbose; debug-only.
set(DUETOS_CAP_AUDIT "Sample" CACHE STRING
    "Capability-gate audit verbosity: Off | Sample | Full")
set_property(CACHE DUETOS_CAP_AUDIT PROPERTY STRINGS "Off" "Sample" "Full")
if(DUETOS_CAP_AUDIT STREQUAL "Off")
    add_compile_definitions(DUETOS_CAP_AUDIT=0)
elseif(DUETOS_CAP_AUDIT STREQUAL "Full")
    add_compile_definitions(DUETOS_CAP_AUDIT=2)
else()
    # Sample — also the default for unrecognised values.
    add_compile_definitions(DUETOS_CAP_AUDIT=1)
endif()

# Default klog runtime threshold. The compile-time floor stays at Trace
# (so release binaries can dial Trace back ON via `loglevel t`); this
# knob picks the BOOT-TIME runtime threshold. Levels: Trace=0 Debug=1
# Info=2 Warn=3 Error=4. Debug builds default to Debug; release builds
# default to Info — release images shouldn't print per-tick driver
# noise unless the operator asks for it.
if(_duetos_is_debug)
    set(_duetos_klog_default 1)
else()
    set(_duetos_klog_default 2)
endif()
set(DUETOS_KLOG_DEFAULT "${_duetos_klog_default}" CACHE STRING
    "Boot-time runtime klog threshold (0=Trace 1=Debug 2=Info 3=Warn 4=Error)")
add_compile_definitions(DUETOS_KLOG_DEFAULT=${DUETOS_KLOG_DEFAULT})

# KASLR — the kernel-image randomization pass at boot. ON in both
# flavors by default, but flip-able for the rare debug session where
# reproducible RIPs across reboots beat probabilistic protection.
# (Today this is a placeholder define; the actual KASLR implementation
# is tracked in .claude/knowledge/post-debug-recommendations-plan.md.)
option(DUETOS_KASLR
    "Randomize the kernel image base on boot (placeholder; ON by default)"
    ON)
if(DUETOS_KASLR)
    add_compile_definitions(DUETOS_KASLR=1)
endif()

# Link-time optimization. Off by default in debug (longer link time
# obscures debug iteration); on by default in release if lld supports
# it. Today we don't pass any LTO flags; this option is in place so a
# future preset can flip it without touching the toolchain file.
option(DUETOS_LTO
    "Enable link-time optimization for kernel image"
    OFF)
if(DUETOS_LTO)
    add_compile_definitions(DUETOS_LTO=1)
endif()

message(STATUS "DuetOS build flavor    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  boot self-tests      : ${DUETOS_BOOT_SELFTESTS}")
message(STATUS "  KASSERT              : ${DUETOS_ASSERTS}")
message(STATUS "  lock-order audit     : ${DUETOS_LOCK_ORDER_AUDIT}")
message(STATUS "  cap-gate audit       : ${DUETOS_CAP_AUDIT}")
message(STATUS "  klog default level   : ${DUETOS_KLOG_DEFAULT}")
message(STATUS "  KASLR                : ${DUETOS_KASLR}")
message(STATUS "  LTO                  : ${DUETOS_LTO}")

add_subdirectory(kernel)

# ----------------------------------------------------------------------------
# Test harness — boots the built kernel in QEMU and greps the serial log for
# the set of expected boot signatures emitted by the ring3 smoke probes.
#
# The test runs only if the QEMU launcher script is present (it is installed
# on-demand; see CLAUDE.md's "live-test runtime tooling" section). When the
# tools are missing `ctest` just skips with an informative message instead
# of failing.
#
# SparkEngine inspires the shape here: a single comprehensive smoke test
# that exercises the full boot path, rather than per-subsystem unit tests
# that would require a hosted test runtime the kernel can't provide.
# ----------------------------------------------------------------------------
enable_testing()

set(DUETOS_QEMU_RUN "${CMAKE_SOURCE_DIR}/tools/qemu/run.sh")
set(DUETOS_SMOKE_DRIVER "${CMAKE_SOURCE_DIR}/tools/test/ctest-boot-smoke.sh")

add_test(NAME duetos-boot-smoke
    COMMAND "${DUETOS_SMOKE_DRIVER}" "${CMAKE_BINARY_DIR}"
)
set_tests_properties(duetos-boot-smoke PROPERTIES
    LABELS "smoke;boot;win32"
    TIMEOUT 60
)

message(STATUS "")
message(STATUS "DuetOS configured.")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Toolchain  : ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  C compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Linker     : ${CMAKE_LINKER}")
message(STATUS "")
