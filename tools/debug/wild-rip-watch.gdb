# wild-rip-watch.gdb — GDB script for the boot-tail wild-RIP
# investigation (Roadmap: "Boot-tail #UD at RIP=0x101e on a fresh
# AP idle task").
#
# Usage (from tools/debug/duetos-gdb-attach.sh interactive
# session — start QEMU with the release build + GDB server, then
# run `source tools/debug/wild-rip-watch.gdb` at the gdb prompt):
#
#     # Terminal A
#     DUETOS_PRESET=x86_64-release \
#       DUETOS_GDB_SERVER=ON DUETOS_GDB_PORT=1234 \
#       tools/debug/duetos-gdb-attach.sh
#
#     # At the (gdb) prompt:
#     (gdb) source tools/debug/wild-rip-watch.gdb
#     (gdb) c
#
# The script arms five breakpoints — one per validator — and a
# catch-all on PanicWithValue. When any fires, it auto-prints
# the trap frame, the call stack with symbols, the per-CPU
# state, and the current rsp's nearby quads.  Use the printed
# rsp value to manually set a hardware watchpoint on the
# scribbled slot for a re-attach.
#
# Background:
#   Five+ in-tree validators all stay silent on the bug. The
#   panic shape is now `#PF NX_VIOLATION at rip=0xffffffffe0...fe7`
#   (i.e. INSIDE the panicking task's kstack slot — a `ret`
#   popped a scribbled return-address slot). Identifying the
#   WRITER needs hardware watchpoint coverage of the slot's
#   trampoline-RA slot (= `t->stack_base + 0x10ff8`).

set pagination off
set confirm off
set print pretty on
set print symbol-filename on

# Symbol shorthand for the validator probes we have.  GDB
# auto-completes to the namespaced name; these are the bare
# breakpoints the kernel's KBP_PROBE_V() expands to.
define probe-bp
    break duetos::debug::ProbeFire
    commands
        silent
        printf "[wild-rip-watch] probe fire id=%d rip=0x%lx\n", \
            $rdi, $rsi
        printf "[wild-rip-watch] caller chain:\n"
        bt 20
        printf "[wild-rip-watch] gprs: rax=0x%lx rbx=0x%lx rcx=0x%lx rdx=0x%lx\n", \
            $rax, $rbx, $rcx, $rdx
        printf "                    rsi=0x%lx rdi=0x%lx rbp=0x%lx rsp=0x%lx\n", \
            $rsi, $rdi, $rbp, $rsp
        printf "                    r8 =0x%lx r9 =0x%lx r10=0x%lx r11=0x%lx\n", \
            $r8, $r9, $r10, $r11
        printf "                    r12=0x%lx r13=0x%lx r14=0x%lx r15=0x%lx\n", \
            $r12, $r13, $r14, $r15
        printf "[wild-rip-watch] stack@rsp+0x00:\n"
        x/16gx $rsp
    end
end

# Catch-all on the panic banner.  When this fires, the kernel
# has already decided to halt — examine the trap frame and the
# call chain.
define panic-bp
    break duetos::core::PanicWithValue
    commands
        silent
        printf "[wild-rip-watch] PanicWithValue called\n"
        printf "  subsystem = %s\n", (char*)$rdi
        printf "  message   = %s\n", (char*)$rsi
        printf "  value     = 0x%lx\n", $rdx
        printf "[wild-rip-watch] call chain:\n"
        bt 20
        printf "[wild-rip-watch] stack@rsp+0x00:\n"
        x/16gx $rsp
    end
    break duetos::core::Panic
    commands
        silent
        printf "[wild-rip-watch] Panic called\n"
        printf "  subsystem = %s\n", (char*)$rdi
        printf "  message   = %s\n", (char*)$rsi
        printf "[wild-rip-watch] call chain:\n"
        bt 20
    end
end

# Catch the trap dispatcher's #PF kernel-side branch — fires on
# every kernel-mode page fault. The wild-RIP bug appears as
# `#PF NX_VIOLATION` at a stack-arena address.
define pf-bp
    rbreak duetos::arch::TrapDispatch
    # Auto-pretty per-frame on hit.
end

# Arm all three breakpoint groups.
probe-bp
panic-bp
# Don't auto-arm the PF breakpoint — too noisy (every IRQ exit
# touches the trap dispatcher).  Enable manually via
# `pf-bp` from the gdb prompt if needed.

printf "[wild-rip-watch] breakpoints armed: ProbeFire, PanicWithValue, Panic\n"
printf "[wild-rip-watch] run 'c' to continue; the script will dump on the next probe/panic.\n"
printf "[wild-rip-watch] for HW watchpoint on the scribbled trampoline RA slot:\n"
printf "                    (gdb) p (void*)duetos::sched::Current()->stack_base\n"
printf "                    (gdb) watch *(unsigned long*)(\\$1 + 0x10ff8)\n"
printf "                 where 0x10ff8 = slot offset of the planted trampoline\n"
printf "                 return-address slot (= aligned_top - 8).\n"
