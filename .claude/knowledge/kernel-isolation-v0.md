# Kernel isolation v0 — extable + fault domains

**Last updated:** 2026-04-23
**Type:** Decision + Pattern
**Status:** Active — primitives landed, one driver (xHCI) uses them.

## What landed

Two primitives that together give us "a fault in one part of the
kernel doesn't automatically take the whole thing down":

### 1. Generalised kernel extable — `kernel/debug/extable.{h,cpp}`

Replaces the single hardcoded `__copy_user_fault_fixup` check in
`traps.cpp` with a registry of `(rip_start, rip_end, fixup_rip,
tag)` rows. Any kernel code that wants scoped fault recovery:

```cpp
debug::KernelExtableRegister(
    reinterpret_cast<u64>(&my_faulty_func_start),
    reinterpret_cast<u64>(&my_faulty_func_end),
    reinterpret_cast<u64>(&my_fixup_landing),
    "subsys/MyFaulty");
```

The #PF / #GP trap handler consults the table before falling
through to `Panic`. A matching entry redirects `frame->rip` to
the fixup. The user-copy helpers are now just rows 0 and 1 of
this table, registered at boot via `arch::TrapsRegisterExtable()`.

**Scope:**
- Only synchronous kernel-mode traps (#PF, #GP). Async
  corruption / deadlocks / IRQ storms are out of scope.
- Fixed-size table (32 entries). Fixed capacity keeps the lookup
  bounded + allocation-free inside the trap handler.
- Re-entry guard (`g_in_lookup`) prevents an infinite loop if a
  trap somehow lands inside the extable walk itself.

### 2. Fault domains — `kernel/core/fault_domain.{h,cpp}`

A named `(init, teardown)` pair per subsystem that any caller
can invoke via `FaultDomainRestart(id)`. In v0 the restart is
manual (shell command, health scanner, future watchdog thread);
automatic restart-on-fault is a follow-up slice that wires the
extable's redirect target to call this API.

API:
```cpp
FaultDomainId id = FaultDomainRegister("drivers/usb/xhci",
                                        XhciInitWrapper,
                                        XhciShutdownWrapper);
// Later:
auto r = FaultDomainRestart(id);
if (!r) { ... r.error() is an ErrorCode ... }
```

The registry tracks:
- `restart_count` — lifetime event count
- `last_restart_ticks` — scheduler tick of the most recent
  restart (for watchdog "has this subsystem been wedged for N
  seconds?" logic)
- `alive` — false while teardown has run but init hasn't yet.
  Useful for "is this subsystem up right now?" queries.

## Teardown skeletons landed

For each subsystem registered as a fault domain we also needed
a real teardown — most drivers only had `Init()` and assumed
they'd run once at boot. This commit grows:

- `drivers::usb::xhci::XhciShutdown()` — for each live
  controller: write USBCMD.RS=0, wait for HCH=1, zero CRCR /
  DCBAAP / ERSTBA / ERDP / ERSTSZ. Resets `g_controller_count`
  + `g_init_done` so a subsequent Init starts fresh. Returns
  `BadState` if any controller doesn't halt within ~tens of ms.
- `drivers::usb::xhci::XhciRestart()` — Shutdown + Init.

Frames behind the rings are **intentionally leaked** on
shutdown — freeing them conservatively before we can prove the
controller stopped DMA'ing is the opposite of safe. Refinement
is a follow-up.

## What this doesn't solve

The inherent limit: if a driver corrupts kernel state and then
returns to the scheduler, the kernel eventually dies when that
corruption is touched. Nothing short of address-space separation
(full microkernel) catches that class of bug. This slice catches
**unexpected synchronous hardware faults** — a bad MMIO read, a
page that got unmapped between probe and use, a divide-by-zero
in a driver probe path. That's 80% of the real pain in practice.

## Boot log shape (QEMU q35)

```
[extable] register tag=mm/CopyFromUser rip=[0x... ,0x...) fixup=0x...
[extable] register tag=mm/CopyToUser   rip=[0x... ,0x...) fixup=0x...
[extable-selftest] PASS (register + hit + miss; 2 entries live)
[fault-domain] register id=0 name=selftest.synth
[fault-domain-selftest] PASS (1 domains; toy restarted 2x)
...
[xhci] NoOp roundtrip PASS
[fault-domain] register id=1 name=drivers/usb/xhci
```

## Next slices

1. **Automatic restart on fault** — the extable's fixup_rip can
   be a shared trampoline that looks up the current fault
   domain from a thread-local and calls `FaultDomainRestart`.
   The v0 manual restart is the mechanism; the auto path is one
   wiring step away.
2. **Watchdog thread** — poll `last_restart_ticks` + a per-
   domain liveness counter. A stuck subsystem gets restarted
   instead of dragging the kernel into wedged state.
3. **More teardowns** — HID parser (trivial), AML namespace
   table, NVMe, e1000, HDA. Each is ~30-60 lines of "undo what
   Init did."

## References

- `kernel/debug/extable.{h,cpp}` — registry primitive
- `kernel/core/fault_domain.{h,cpp}` — subsystem-level restart
- `kernel/arch/x86_64/traps.cpp` — trap handler consults extable
- `kernel/drivers/usb/xhci.{h,cpp}` — first subsystem with full
  Init + Shutdown + Restart lifecycle
- `kernel/util/result.h` — error type used by fault-domain return
