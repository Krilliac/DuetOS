# Example boot log

`example-boot-log-debug.txt` is a captured serial console transcript
from a clean boot of the `x86_64-debug` preset under QEMU + OVMF,
running for ~105 seconds (DUETOS_TIMEOUT=120). It exists to give
contributors and reviewers a reference for what a healthy boot looks
like end-to-end without having to spin up QEMU themselves.

## How it was captured

```bash
cmake --preset x86_64-debug && cmake --build build/x86_64-debug
DUETOS_PRESET=x86_64-debug DUETOS_TIMEOUT=120 \
    tools/qemu/run.sh > docs/example-boot-log-debug.txt 2>&1
```

The QEMU launch path is the canonical one used by CI and by every
developer running the smoke test locally. No filtering, no
post-processing — the file is the raw serial output verbatim,
including ANSI colour codes and GRUB UI sequences at the very top.

## What the log contains

| Lines (approx) | Contents |
|----------------|----------|
| 1–5 | run.sh banner + UEFI / GRUB boot menu (ANSI-coloured; renders as garbled text in plaintext editors but is harmless) |
| 6 | "[boot] DuetOS kernel reached long mode." — the first kernel-emitted line. Everything before this is firmware / loader output. |
| 7–14 | klog channel sanity probes (DEBUG / INFO / WARN / ERROR / value-form / string-form / two-value / once-info) — `[E]` and `[W]` here are deliberate, asserting the channels plumb to serial. |
| 15–~150 | Boot banner, build flavor, multiboot2 handoff, CPU feature probe, ACPI tables (RSDP / XSDT / MADT), APIC / IOAPIC, GDT / IDT, paging, frame allocator, kheap, SMP intro. |
| ~150–~250 | Subsystem self-tests (`fault-domain-selftest`, `selftest.fault-react`, `string-selftest`, `hexdump-selftest`, `process-selftest`, `fs/vfs`, `mm/zone`, soft-lockup, lockdep). Each prints its own PASS line. |
| ~250–~400 | VFS, ext4 / FAT32 / GPT probes; storage (NVMe / AHCI) probes; PCI enumeration; GPU discovery; PS/2 keyboard / mouse; e1000e bring-up. |
| ~400–~700 | Network stack: DHCP DISCOVER → ACK, ARP, ICMP, TCP/UDP self-tests; `[net-probe]`, `[dhcp]` lines (these print atomically thanks to `arch::SerialLineGuard`). |
| ~700–~1500 | Win32 subsystem bring-up, PE loader self-tests, ring-3 smoke probes (the `[hello-pe]`, `[hello-winapi]`, `[heap]`, `[advapi]`, `[perf-counter]`, `[heap-resize]`, `[calc]`, `[files]`, etc. PASS lines), windows-kill.exe execution, mini_browser.exe, the live-internet probe, the smoke PE suite. |
| ~1500–~2000 | DirectX skeleton smoke (D3D / DirectInput / D2D / DWrite). |
| ~2000–~end | The `kheartbeat` heartbeat loop. Once boot completes, the kernel emits a heartbeat sample every ~500 ms summarising heap free, frames free, ctx-switch rate, fault-domain count, etc. The log is dominated by these samples after that point — they're the visible signal that the kernel is alive and idle. |

## What "healthy" looks like

- **No `[panic]` lines** other than the literal string "panic / trap dump annotation" in the boot banner (the VA-region classifier exercises the panic-formatter on a synthetic input — no actual panic).
- **`health_issues_total` heartbeat key stays at 0** for the duration.
- **Every `[*-selftest] PASS`** line is present.
- **Every `[heap]` / `[strings]` / `[advapi]` / `[perf-counter]` / `[heap-resize]` etc. PE probe** prints its OK line.
- **`[E] core/klog : error-level sanity line`** is the only top-level `[E]` line emitted by a healthy boot. It's the klog channel sanity probe.

## What the warnings mean

The boot intentionally triggers a number of `[W]` lines on serial.
They're not bugs — they're either probe-emitted self-tests asserting
detection paths fire, or they document v0 implementation gaps. The
canonical buckets are:

1. **Probe sanity** — `[W] core/klog : warn-level sanity line` and
   similar — the klog channel-sanity self-test.
2. **Subsystem-not-up** — drivers that report "no controller
   present" or "no device discovered" on the QEMU profile in use.
3. **CPU mitigations** — `KPTI not implemented` block on a
   `RDCL_NO=0` boot (see [Roadmap](../wiki/reference/Roadmap.md)).
4. **PE loader** — `pe reject` reasons on PEs whose imports are
   intentionally unresolved.
5. **Network** — DHCP timeout / ARP retransmits when the QEMU
   `slirp` backend is slow to respond.

If you see a `[W]` line that doesn't match any of these, that's
worth a closer look.

## When to update this file

Re-capture only when:

1. A boot phase changes substantially (new init step lands, a
   self-test is added, the heartbeat cadence shifts).
2. The set of expected `[W]` / `[E]` lines changes (new probe, or a
   probe is reclassified to TRACE).
3. The file's reference value to a fresh contributor would otherwise
   drift from reality.

Avoid re-capturing on every commit — line numbers and exact
timestamps shift even between identical builds, and the log being
exactly current is less valuable than it being a reasonable
reference. Quarterly is a good cadence.
