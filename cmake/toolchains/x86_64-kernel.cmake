# DuetOS freestanding x86_64 kernel toolchain.
#
# Compiles kernel TUs with clang targeting a bare-metal ELF64 image.
# No hosted libc. No exceptions. No RTTI. No SSE/MMX/x87 in kernel code —
# the FPU/SSE save area is per-thread and managed by the scheduler, not
# implicitly used for codegen.
#
# Usage: `cmake --preset x86_64-debug` (see CMakePresets.json).

set(CMAKE_SYSTEM_NAME      Generic)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Compilers — hard-pinned to clang because our inline asm and attributes
# assume clang semantics, and because we want identical codegen across
# developer machines and CI.
set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_ASM_COMPILER clang)

# Skip the compiler-works sanity probe — it tries to link a hosted
# executable, which fails for a freestanding toolchain.
set(CMAKE_C_COMPILER_WORKS   1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# We drive the link ourselves with ld.lld and a hand-written linker script.
set(CMAKE_LINKER lld)

# Target triple: plain ELF, no OS.
set(DUETOS_KERNEL_TARGET "x86_64-unknown-none-elf")

set(DUETOS_KERNEL_C_FLAGS
    "--target=${DUETOS_KERNEL_TARGET}"
    -ffreestanding
    # Stack canaries: compiler emits a per-function prologue that plants
    # a cookie from __stack_chk_guard and an epilogue that verifies it
    # before return. On mismatch, compiler-inserted code calls
    # __stack_chk_fail, which we panic from. Use -fstack-protector-strong
    # so any function with an array, address-of-local, or alloca gets
    # protected (unlike vanilla -fstack-protector which only gates on
    # char arrays > 8 bytes).
    #
    # -mstack-protector-guard=global picks __stack_chk_guard via the
    # ordinary ELF symbol path instead of the glibc TLS form (%fs:0x28),
    # which doesn't apply in freestanding mode because we don't set up
    # the TLS slot.
    -fstack-protector-strong
    -mstack-protector-guard=global
    # Control-Flow Integrity via Intel CET / IBT (Indirect Branch
    # Tracking). -fcf-protection=branch makes clang emit `endbr64`
    # at every indirect-branch target in C/C++ code. Combined with
    # CR4.CET + IA32_S_CET.ENDBR_EN (set in CetInit at boot when
    # CPUID reports support), a ret/jmp/call to a non-endbr target
    # raises #CP (vector 21), which we turn into a ring-3
    # [task-kill] or a ring-0 panic.
    #
    # endbr64 is a NOP on pre-CET CPUs, so this is safe to emit
    # unconditionally; the protection activates only when the MSR
    # is enabled at boot.
    #
    # GAP: temporarily disabled — KVM's instruction emulator on the
    # CI host kernel can't decode `f3 0f 1e fa` (endbr64) and
    # vmexits with KVM_INTERNAL_ERROR_EMULATION whenever an
    # interrupt-window or MMIO emulation fallback lands at the
    # entry of an indirectly-called function (observed at
    # MemRead, the C++ block-device callback Rust calls through
    # the Device struct). CR4.CET, IA32_S_CET writes, and
    # CetEnable now exist in tree (kernel/arch/x86_64/cet.cpp);
    # what's missing is the kernel-image compile flag below + a
    # boot-time call to CetEnable + per-task shadow-stack
    # allocation for SS. Re-enable in lockstep with a runtime
    # probe that checks whether the host KVM decoder handles
    # endbr64 (`-cpu max` exposes the feature flag but the
    # emulator support is kernel-version-gated). Flip this line
    # to `-fcf-protection=branch` AND uncomment the
    # DUETOS_KERNEL_HAS_ENDBR define just below to opt the build
    # in; CetEnable's `#if defined(DUETOS_KERNEL_HAS_ENDBR)` gate
    # will then set ENDBR_EN safely.
    -fcf-protection=none
    # When the build flag above flips to `-fcf-protection=branch`,
    # also flip this define so CetEnable knows it can set
    # ENDBR_EN without #CP'ing the next indirect call. Default off
    # to stay safe under -fcf-protection=none. (Defined-but-zero
    # is treated as "present"; an absent macro is treated as
    # "absent" by the #if defined check.)
    # add_compile_definitions(DUETOS_KERNEL_HAS_ENDBR=1)
    # Spectre-v2 / branch-target-injection mitigation. Replaces
    # every `jmp/call *%reg` with a `call __x86_indirect_thunk_<reg>`
    # that traps speculation at a lfence before the indirect
    # transfer. Attackers who can write to the branch-predictor
    # (via another process on a shared core, or via CPU-internal
    # timing channels) can't use mispredicted speculative
    # execution to steer our indirect branches toward a gadget.
    #
    # Needs us to provide the thunks (otherwise the linker fails
    # on __x86_indirect_thunk_rax etc.). Those live in
    # kernel/arch/x86_64/retpoline_thunks.S.
    #
    # Independent of CET/IBT: IBT blocks BRANCHES TO unexpected
    # targets at the victim site; retpoline blocks BRANCHES FROM
    # going to mispredicted targets at the call site. They
    # compose — IBT catches a successful injection; retpoline
    # prevents the injection from succeeding in the first place.
    -mretpoline
    # Note: -mspeculative-load-hardening was tried for Spectre-v1
    # coverage but the emitted barriers stall the kernel to a
    # crawl (boot reaches task-spawn then no more output inside
    # 60s QEMU wall-time). Clang's SLH is better tuned for
    # userland workloads; it interacts poorly with our tight
    # freestanding paths (inline asm around swapgs/iretq, the
    # timer-IRQ hot path, etc.). Deferred until we have per-site
    # __attribute__((speculation_hardening)) control to scope
    # the cost to the syscall boundary where it actually matters.
    -fno-pic
    -fno-pie
    -fno-builtin
    -fno-common
    -fno-omit-frame-pointer
    -mno-red-zone
    -mno-mmx
    -mno-sse
    -mno-sse2
    -mno-80387
    -mgeneral-regs-only
    -mcmodel=kernel
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    # --- Extended warning floor (beyond -Wall/-Wextra) ---------------
    # These are not part of -Wall/-Wextra but earn their place in a
    # freestanding kernel where the wrong cast / promotion / stack
    # shape is a fault on real hardware, not a lint nit. All of them
    # build clean today; -Werror below keeps them that way.
    #
    # -Wdouble-promotion / -Wfloat-equal: the kernel builds
    #   -mgeneral-regs-only -mno-sse, so ANY float in codegen is a
    #   latent #UD / corrupted-FPU-state bug. These two are tripwires
    #   for "someone snuck floating point into kernel code".
    # -Wvla: a runtime-sized stack array on our small fixed kernel /
    #   IRQ stacks is a stack-overflow → triple-fault waiting to fire.
    # -Wcast-qual: dropping const/volatile via a cast — volatile-drop
    #   silently breaks MMIO ordering.
    # -Wpointer-arith: arithmetic on void*/function pointers (GNU ext)
    #   is almost always an unintended size assumption.
    # -Wover-aligned: allocating an over-aligned type through an
    #   allocator that can't honour the alignment (our slab returns
    #   16-byte-aligned chunks).
    # -Wnull-dereference / -Wconditional-uninitialized: real
    #   control-flow bugs the base set misses.
    # -Wundef: `#if FOO` where FOO is a typo'd / never-defined config
    #   macro silently evaluates to 0.
    # -Wformat=2: full printf-family checking for klog format strings.
    # -Wcomma / -Wextra-semi: comma-operator misuse and stray `;`.
    # -Wmissing-declarations: a non-static global with no prior
    #   declaration is link-surface drift (should be static or in a
    #   header).
    # -Wimplicit-fallthrough: force explicit [[fallthrough]].
    # -Wthread-safety: enables clang's lock-capability analysis. Inert
    #   until headers carry GUARDED_BY/REQUIRES annotations, but on
    #   now so the enforcement lands the moment they do (see the
    #   locking discipline in CLAUDE.md / Subsystem-Isolation).
    -Wdouble-promotion
    -Wfloat-equal
    -Wvla
    -Wcast-qual
    -Wpointer-arith
    -Wover-aligned
    -Wnull-dereference
    -Wconditional-uninitialized
    -Wundef
    -Wformat=2
    -Wcomma
    -Wextra-semi
    -Wmissing-declarations
    -Wimplicit-fallthrough
    -Wthread-safety
    # Zero-warning policy (CLAUDE.md): the kernel image now matches the
    # -Werror floor that boot/uefi, tests/host, and tools/ already
    # enforce. Note: clang silently no-ops -Walloca and
    # -Wredundant-decls for this target, and -Wcast-align never fires
    # on x86_64 (unaligned access is legal) — those are deferred to the
    # aarch64 tier rather than carried as dead config here.
    -Werror
)

set(DUETOS_KERNEL_CXX_FLAGS
    ${DUETOS_KERNEL_C_FLAGS}
    # C++-only additions to the extended floor above.
    # -Wzero-as-null-pointer-constant: `0`/`NULL` used as a pointer.
    # -Wnon-virtual-dtor / -Woverloaded-virtual: polymorphism foot-guns
    #   that survive even with -fno-rtti.
    -Wzero-as-null-pointer-constant
    -Wnon-virtual-dtor
    -Woverloaded-virtual
    -fno-exceptions
    -fno-rtti
    -fno-threadsafe-statics
    -fno-use-cxa-atexit
    -std=c++23
)

set(DUETOS_KERNEL_ASM_FLAGS
    "--target=${DUETOS_KERNEL_TARGET}"
)

set(DUETOS_KERNEL_LINK_FLAGS
    "--target=${DUETOS_KERNEL_TARGET}"
    -fuse-ld=lld
    -nostdlib
    -static
    -Wl,--build-id=none
    -Wl,-z,max-page-size=0x1000
    -Wl,-z,noexecstack
)

# Expose as cached strings so per-target CMakeLists.txt files can consume them
# without re-deriving.
string(REPLACE ";" " " _kernel_c_flags   "${DUETOS_KERNEL_C_FLAGS}")
string(REPLACE ";" " " _kernel_cxx_flags "${DUETOS_KERNEL_CXX_FLAGS}")
string(REPLACE ";" " " _kernel_asm_flags "${DUETOS_KERNEL_ASM_FLAGS}")
string(REPLACE ";" " " _kernel_ld_flags  "${DUETOS_KERNEL_LINK_FLAGS}")

set(CMAKE_C_FLAGS_INIT           "${_kernel_c_flags}"    CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_INIT         "${_kernel_cxx_flags}"  CACHE STRING "" FORCE)
set(CMAKE_ASM_FLAGS_INIT         "${_kernel_asm_flags}"  CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_INIT  "${_kernel_ld_flags}"   CACHE STRING "" FORCE)

# Freestanding targets never search the host sysroot.
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
