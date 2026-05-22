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

# Shell-script smoke. Bakes /etc/selftest.sh into ramfs and auto-sources
# it after /etc/profile so a headless boot exercises the scripting v0
# control-flow keywords (if/while/for/$?/exit) and emits PASS/FAIL
# markers grep-able from the serial log. Lets a CI run or an AI-assisted
# debug session verify the scripting language hasn't regressed without
# typing at the prompt. See kernel/fs/ramfs.cpp for the script body.
option(DUETOS_SHELL_SELFTEST "Bake /etc/selftest.sh into ramfs and auto-source on boot" OFF)
if(DUETOS_SHELL_SELFTEST)
    add_compile_definitions(DUETOS_SHELL_SELFTEST=1)
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

# Git short hash + dirty flag baked in at configure time. Surfaced in
# the About / System Info window via DUETOS_GIT_HASH so a user can
# match a running build against a commit without booting + checking
# the kernel log. The hash is captured at configure time, not build
# time, so an in-tree edit between configure and build keeps the
# hash stable; the dirty suffix is appended when `git status` reports
# any tracked change so the user sees `1757083+` (a working tree
# diverged from the named commit) instead of mistaking it for the
# pristine commit. Falls back to "unknown" outside a git checkout.
#
# In addition to the hash we also capture: the commit subject
# (first line of the message), the author date in ISO-strict form,
# and the current branch name. These feed `live-update version`
# inside the running kernel and the post-fetch verdict on
# tools/dev/live-update.sh so an operator can match a hash against
# a human-readable "what changed" without having to consult git log
# externally. All four pieces use the same configure-time capture
# discipline as the hash.
find_package(Git QUIET)
set(_duetos_git_hash "unknown")
set(_duetos_git_subject "(unknown)")
set(_duetos_git_branch "(unknown)")
set(_duetos_git_author_date "(unknown)")
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=10 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE _duetos_git_hash_raw
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        RESULT_VARIABLE _duetos_git_rc
    )
    if(_duetos_git_rc EQUAL 0 AND NOT "${_duetos_git_hash_raw}" STREQUAL "")
        set(_duetos_git_hash "${_duetos_git_hash_raw}")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} status --porcelain
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _duetos_git_dirty
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(NOT "${_duetos_git_dirty}" STREQUAL "")
            set(_duetos_git_hash "${_duetos_git_hash}+")
        endif()
        execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%s
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _duetos_git_subject_raw
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(NOT "${_duetos_git_subject_raw}" STREQUAL "")
            # Sanitise the subject so it survives both the C string
            # literal AND the compiler command line. Commit subjects
            # routinely contain quotes / em-dashes / PR refs so this
            # is not defensive code, it's required.
            #   \  "  non-printable  break the C string literal
            #   #  is silently dropped by CMake when passed via
            #       add_compile_definitions (many compilers treat #
            #       as a comment on -D args), and a merge-commit
            #       subject like "Merge pull request #240" trips it.
            string(REPLACE "\\" "/" _duetos_git_subject_raw "${_duetos_git_subject_raw}")
            string(REPLACE "\"" "'" _duetos_git_subject_raw "${_duetos_git_subject_raw}")
            string(REPLACE "#" "" _duetos_git_subject_raw "${_duetos_git_subject_raw}")
            string(REGEX REPLACE "[^ -~]" "?" _duetos_git_subject_raw "${_duetos_git_subject_raw}")
            # Cap the subject at 120 chars so a runaway commit message
            # can't blow past the kernel's serial-line width.
            string(LENGTH "${_duetos_git_subject_raw}" _len)
            if(_len GREATER 120)
                string(SUBSTRING "${_duetos_git_subject_raw}" 0 117 _duetos_git_subject_raw)
                set(_duetos_git_subject_raw "${_duetos_git_subject_raw}...")
            endif()
            set(_duetos_git_subject "${_duetos_git_subject_raw}")
        endif()
        execute_process(
            COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _duetos_git_branch_raw
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(NOT "${_duetos_git_branch_raw}" STREQUAL "")
            string(REPLACE "\"" "'" _duetos_git_branch_raw "${_duetos_git_branch_raw}")
            string(REPLACE "#" "" _duetos_git_branch_raw "${_duetos_git_branch_raw}")
            set(_duetos_git_branch "${_duetos_git_branch_raw}")
        endif()
        execute_process(
            COMMAND ${GIT_EXECUTABLE} log -1 --pretty=format:%ad --date=iso-strict
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE _duetos_git_author_date_raw
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(NOT "${_duetos_git_author_date_raw}" STREQUAL "")
            set(_duetos_git_author_date "${_duetos_git_author_date_raw}")
        endif()
    endif()
endif()
# Build timestamp — UTC ISO-strict, captured at configure time. Pair
# with the git hash: `(hash, build_date)` together pin down which
# build artefact is running, even when the same commit was built
# twice with different flags.
string(TIMESTAMP _duetos_build_date "%Y-%m-%dT%H:%M:%SZ" UTC)
# Deliver the git/build strings via a configure_file-generated header
# (kernel/CMakeLists.txt does the configure_file) rather than `-D`
# defines. Free-form text on the compiler command line transits
# /bin/sh, so a commit subject containing `;` / backtick / `$` / `"`
# broke EVERY preset with "Unterminated quoted string". A generated
# header keeps the text off the command line entirely.
message(STATUS "  git hash             : ${_duetos_git_hash}")
message(STATUS "  git branch           : ${_duetos_git_branch}")
message(STATUS "  git subject          : ${_duetos_git_subject}")
message(STATUS "  git author date      : ${_duetos_git_author_date}")
message(STATUS "  build date           : ${_duetos_build_date}")

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

# Cross-CPU wake routing trace. When ON, every wake-side enqueue
# (RunqueuePush -> PickClusterPlacement -> RunqueuePushOn) emits a
# DEBUG-level klog line attributing the routing decision: source
# CPU, preferred CPU, picked CPU, and the "why" (last_cpu cache,
# offline-AP skip, less-loaded peer, affinity override). Catches
# the class of bug surfaced 2026-05-22 where the BSP boot task
# was routed onto a not-yet-online AP slot mid-SmpStartAps. Off
# by default — the trace lines fire on every wake (potentially
# thousands per second under load), so they belong in the
# investigation toolbox rather than the steady-state log. Turn
# on with `-DDUETOS_SCHED_ROUTING_TRACE=ON` when chasing an SMP
# routing regression; turn back off when the investigation closes.
option(DUETOS_SCHED_ROUTING_TRACE
    "Trace wake-side cross-CPU routing decisions to klog DEBUG"
    OFF)
if(DUETOS_SCHED_ROUTING_TRACE)
    add_compile_definitions(DUETOS_SCHED_ROUTING_TRACE=1)
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

# Compile-time klog floor. Below this level, the macros fold to nothing;
# the call sites are dead code that the compiler eliminates. Wired off
# the build flavor so debug builds keep Trace (deepest instrumentation
# available on demand via `loglevel t`) while release builds eliminate
# the Trace-emit code path entirely.
#
# Levels match LogLevel: Trace=0 Debug=1 Info=2 Warn=3 Error=4.
#
# Caveat: an operator on a release build cannot enable Trace at runtime
# — the call sites don't exist. The runtime knob only RAISES from this
# floor, never below it. Release-with-trace operators want a debug
# build (or the release-audit preset which forces the floor back to
# Trace via the cache variable below).
if(_duetos_is_debug)
    set(_duetos_klog_floor 0) # Trace
else()
    set(_duetos_klog_floor 1) # Debug
endif()
set(DUETOS_KLOG_COMPILE_FLOOR "${_duetos_klog_floor}" CACHE STRING
    "Compile-time klog severity floor (0=Trace 1=Debug 2=Info 3=Warn 4=Error)")
add_compile_definitions(DUETOS_KLOG_COMPILE_FLOOR=${DUETOS_KLOG_COMPILE_FLOOR})

# Default klog runtime threshold. The compile-time floor is set
# elsewhere (debug→Trace, release→Debug); this knob picks the
# BOOT-TIME runtime threshold a fresh image starts with. Levels:
# Trace=0 Debug=1 Info=2 Warn=3 Error=4 Critical=5.
#
# Debug builds default to Debug — drivers + IRQ + sched chatter
# visible by default during development. Release builds default to
# Warn — release images print only Warn/Error/Critical at boot so
# the serial log stays compact for forensic capture; operators
# dial back to Info / Debug / Trace at runtime via `loglevel`.
if(_duetos_is_debug)
    set(_duetos_klog_default 1)
else()
    set(_duetos_klog_default 3)
endif()
set(DUETOS_KLOG_DEFAULT "${_duetos_klog_default}" CACHE STRING
    "Boot-time runtime klog threshold (0=Trace 1=Debug 2=Info 3=Warn 4=Error)")
add_compile_definitions(DUETOS_KLOG_DEFAULT=${DUETOS_KLOG_DEFAULT})

# KASLR — the kernel-image randomization pass at boot. ON in both
# flavors by default, but flip-able for the rare debug session where
# reproducible RIPs across reboots beat probabilistic protection.
# (Today this is a placeholder define; the actual KASLR
# implementation is tracked in wiki/reference/Roadmap.md.)
option(DUETOS_KASLR
    "Randomize the kernel image base on boot (placeholder; ON by default)"
    ON)
if(DUETOS_KASLR)
    add_compile_definitions(DUETOS_KASLR=1)
endif()

# KASAN-equivalent diagnostics. Clang's `-fsanitize=kernel-address`
# does not support the x86_64-unknown-elf freestanding target used by
# this kernel, so the KASAN preset enables the in-tree diagnostics
# instead: heap trailer canaries, freed-payload poison, freed-page
# poison, UBSAN, lock-order audit, and full cap audit. Real shadow
# memory remains roadmap work gated on a slab allocator.
option(DUETOS_KASAN
    "Enable the in-tree KASAN-equivalent kernel memory diagnostics preset"
    OFF)
if(DUETOS_KASAN)
    add_compile_definitions(DUETOS_KASAN=1)
endif()

# Link-time optimization. Defaults ON for Release (cross-TU inlining
# of klog/cap-gate hot paths visibly speeds the steady-state kernel)
# and OFF for Debug (long link times obscure debug iteration; LTO
# also reorders code, which makes triple-fault chases harder). When
# enabled, kernel/CMakeLists.txt applies ThinLTO flags to both
# kernel link stages.
if(CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(_duetos_lto_default ON)
else()
    set(_duetos_lto_default OFF)
endif()
option(DUETOS_LTO
    "Enable link-time optimization for kernel image"
    ${_duetos_lto_default})
if(DUETOS_LTO)
    add_compile_definitions(DUETOS_LTO=1)
endif()

message(STATUS "DuetOS build flavor    : ${CMAKE_BUILD_TYPE}")
message(STATUS "  boot self-tests      : ${DUETOS_BOOT_SELFTESTS}")
message(STATUS "  KASSERT              : ${DUETOS_ASSERTS}")
message(STATUS "  lock-order audit     : ${DUETOS_LOCK_ORDER_AUDIT}")
message(STATUS "  cap-gate audit       : ${DUETOS_CAP_AUDIT}")
message(STATUS "  klog default level   : ${DUETOS_KLOG_DEFAULT}")
message(STATUS "  klog compile floor   : ${DUETOS_KLOG_COMPILE_FLOOR}")
message(STATUS "  KASLR                : ${DUETOS_KASLR}")
message(STATUS "  KASAN diagnostics    : ${DUETOS_KASAN}")
message(STATUS "  LTO                  : ${DUETOS_LTO}")

# UEFI loader (boot/uefi/) — Phase A toolchain proof. Builds a
# PE32+ EFI Application ("BOOTX64.EFI") that prints a banner and
# halts. Wired separately from the kernel because UEFI requires a
# different target triple (x86_64-unknown-windows) and a Windows-
# flavor linker (lld-link); the directory's CMakeLists drives
# clang/lld-link directly via add_custom_command rather than fight
# the kernel's freestanding-ELF toolchain file. Phase B replaces
# efi_main with a real ELF loader + multiboot2-shim handoff.
#
# Added BEFORE kernel/ so the kernel's ramfs embed-blob step can
# depend on ${DUETOS_UEFI_EFI} (cached after this subdirectory is
# processed) without a forward-reference.
add_subdirectory(boot/uefi)

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
    # 720 s wall clock. The smoke driver's inner DUETOS_TIMEOUT
    # adapts to the acceleration mode: 150 s when /dev/kvm is
    # reachable (CI runners on bare metal — kernel completes the
    # smoke in well under a minute), 600 s under TCG (dev
    # workstations / unprivileged sandboxes — the JIT can't keep
    # up with the storage stack's MMIO chatter). The outer ctest
    # TIMEOUT needs headroom over whichever path runs so the
    # signature-verification pass has time to finish after QEMU
    # exits. 720 s = 600 s inner cap + 120 s harness headroom for
    # the TCG path; KVM finishes long before either timer fires.
    # A hung kernel still trips the inner DUETOS_TIMEOUT first;
    # this only guards against the harness itself wedging.
    TIMEOUT 720
    # Exit 2 from ctest-boot-smoke.sh means a prerequisite is
    # missing (qemu / iso) — CTEST should report SKIP rather
    # than FAIL. Mirrors the duetos-uefi-smoke convention.
    SKIP_RETURN_CODE 2
)

# UEFI loader smoke test — boots the native BOOTX64.EFI under
# qemu+OVMF and verifies the Phase A banner reaches COM1. Sister
# of duetos-boot-smoke (which exercises the GRUB+Multiboot2 path);
# this one exercises the new boot/uefi/ Phase A path. The driver
# exits 2 if qemu / OVMF / BOOTX64.EFI is missing — the test is
# REQUIRED to not be wired into ctest's pass/fail when the
# prerequisites are absent on the dev host. CTEST's
# WILL_FAIL=false + SKIP_RETURN_CODE=2 lets the test report SKIP
# when the install hasn't happened, so a fresh checkout that
# hasn't run `apt-get install -y qemu-system-x86 ovmf` doesn't
# fail the whole ctest run.
set(DUETOS_UEFI_SMOKE_DRIVER "${CMAKE_SOURCE_DIR}/tools/test/uefi-smoke.sh")
add_test(NAME duetos-uefi-smoke
    COMMAND "${DUETOS_UEFI_SMOKE_DRIVER}"
)
set_tests_properties(duetos-uefi-smoke PROPERTIES
    LABELS "smoke;boot;uefi"
    # Inner timeout is 15s for the QEMU run; 60s outer gives
    # headroom for OVMF init + image-load + ESP staging.
    TIMEOUT 60
    # Exit 2 from uefi-smoke.sh means a prerequisite is missing
    # (qemu / OVMF / built EFI binary) — CTEST should report SKIP
    # rather than FAIL. Mirrors the duetos-boot-smoke convention
    # for the same situation.
    SKIP_RETURN_CODE 2
)

# Differential-boot smoke. Boots one profile (`bringup`) under a
# matrix of (engine, cpu, accel, firmware) configs and diffs the
# canonical sentinel streams pairwise. Catches config-dependent
# bugs (CPUID-gated paths, UEFI-vs-SeaBIOS memory-map deltas,
# emulator-specific instruction modelling) that a single-config
# smoke would miss. Default matrix: 3 QEMU rows + 1 Bochs row.
#
# Wall clock is the sum of the rows under TCG (~3-5 minutes per
# row on cold dev workstations). The matrix is parallelisable
# in principle but the rows share filesystem state, so the
# harness runs them sequentially — TIMEOUT scales accordingly.
set(DUETOS_DIFF_DRIVER "${CMAKE_SOURCE_DIR}/tools/test/diff-boot-smoke.sh")
add_test(NAME duetos-diff-boot-smoke
    COMMAND "${DUETOS_DIFF_DRIVER}" bringup "${CMAKE_BINARY_DIR}"
)
set_tests_properties(duetos-diff-boot-smoke PROPERTIES
    LABELS "smoke;boot;differential"
    # Generous outer timeout: 4 rows x 480s inner cap each = 32 min
    # worst case; 2400s gives headroom for the verifier passes too.
    # Real wall clock under KVM is ~30s; under TCG, 5-15 min.
    TIMEOUT 2400
    # Exit 3 from diff-boot-smoke.sh means a prerequisite is
    # missing (qemu / iso / bochs); CTEST reports SKIP. Exit 2
    # means rows-passed-but-diverged — that's a real regression,
    # NOT a skip, so it falls through to FAIL.
    SKIP_RETURN_CODE 3
)

message(STATUS "")
message(STATUS "DuetOS configured.")
message(STATUS "  Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "  Toolchain  : ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  C compiler : ${CMAKE_C_COMPILER}")
message(STATUS "  Linker     : ${CMAKE_LINKER}")
message(STATUS "")

# ----------------------------------------------------------------------------
# Optional host-side tools — duet-pkg (the federated package manager).
#
# These are HOSTED binaries (need libc, libstdc++, libcurl, libsodium,
# <filesystem>, <expected>), so they cannot share the freestanding
# `cmake/toolchains/x86_64-kernel.cmake` toolchain the kernel uses.
# Drive them via ExternalProject_Add with no toolchain inheritance, so
# `cmake --build . --target duet-pkg` from the root build dir works
# without polluting the kernel's compiler flags.
#
# OFF by default — most kernel-only flows don't need duet-pkg, and the
# ExternalProject pulls toml++ (and later libcurl + libsodium) via
# FetchContent the first time it configures. Operators wanting the
# package manager run: `cmake -DDUETOS_BUILD_TOOLS=ON ...`.
# ----------------------------------------------------------------------------
option(DUETOS_BUILD_TOOLS "Build host-side tools (duet-pkg, ...)" OFF)
if(DUETOS_BUILD_TOOLS)
    include(ExternalProject)
    ExternalProject_Add(duet-pkg-ext
        PREFIX           "${CMAKE_BINARY_DIR}/tools/duet-pkg"
        SOURCE_DIR       "${CMAKE_SOURCE_DIR}/tools/pkg"
        # Force the system compiler + no toolchain file. Pass through
        # the build type so a debug parent build gets a debug
        # duet-pkg.
        CMAKE_ARGS
            -DCMAKE_TOOLCHAIN_FILE=
            -DCMAKE_C_COMPILER=cc
            -DCMAKE_CXX_COMPILER=c++
            -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        INSTALL_COMMAND  ""
        BUILD_ALWAYS     TRUE
        TEST_COMMAND     ${CMAKE_CTEST_COMMAND} --output-on-failure
    )
endif()
