# Troubleshooting

> **Audience:** All contributors
>
> **Execution context:** Host (build / debug) and on-target (boot panics)
>
> **Maturity:** Active — extended as new failure modes are seen

## Overview

Catalogue of failure modes seen often enough to deserve a documented
fix. For one-off failure shapes, the kernel shell's `inspect` and
`klog` commands are usually faster than grepping git history.

## Build Failures

### `clang-format mangled my .S file`

`.S` files are NOT C++. Never run `clang-format -i` on them. If your
find/xargs invocation accidentally caught a `.S` file, restore it
from git:

```bash
git checkout -- path/to/file.S
```

The canonical find pattern (kernel + drivers + subsystems +
userland) explicitly excludes `.S`. See
[Coding Standards](../tooling/Coding-Standards.md).

### `cmake --preset` fails: "no such preset"

The presets are in `CMakePresets.json` at the repo root. If the file
is missing, you're probably in a subdirectory — `cd` to the repo
root.

### `qemu-system-x86_64: command not found`

QEMU is not pre-installed. See
[Build System > Live-test Tooling](../tooling/Build-System.md#live-test-tooling--install-on-demand)
for the install line and the rules on when to install.

### "no module named X" / Rust toolchain missing

Rust subsystems are gated on `rust-toolchain.toml`. The host needs
`rustup` with the version pinned in that file. Until a Rust subsystem
actually ships, this is informational.

## Boot Failures

### `[boot] WARNING: unexpected boot magic.`

`boot.S` regression — some new code in the 32-bit boot path clobbered
`edi` or `esi`, which hold the Multiboot2 boot magic and info-struct
pointer respectively. Fix: use `ebx`, `ebp`, or `edx` for scratch in
boot.S.

### `[panic] mm/kheap: ...`

Kernel heap regression. Typical causes:

- `KFree pointer outside heap pool` — caller passed a stale or wild
  pointer; check the caller, not the allocator.
- `KFree on chunk with corrupt size` — almost always a double-free.
  `KernelHeapStatsRead()` reports `g_alloc_count` vs `g_free_count`.
- Heap self-test passes but later subsystem panics inside `KMalloc` —
  likely an SMP locking issue once that lands. Today the heap is
  single-CPU only.

### `[mm] paging self-test FAIL`

Page-table walker regression. The most likely failure modes are:

- `WalkToPte hit a 2 MiB PS page` — caller asked to map an address
  inside the boot direct map.
- `MapPage: virtual address already mapped` — bump cursor desynced
  from actual mappings.

### Workers print exactly once, then kernel goes silent

Classic EOI-after-Schedule bug in the IRQ dispatcher. The order must
be: `handler() -> LapicEoi() -> Schedule()`. See
[Scheduler > EOI-then-Schedule Ordering](../kernel/Scheduler.md#eoi-then-schedule-ordering-critical).

### "JAIL BROKEN" panic

The boot-time VFS self-test asserts that a sandbox root cannot
resolve `/etc/version`. If you see this, a path-walker change broke
the per-process root jail. See [Sandboxing](../security/Sandboxing.md).

### Live boot succeeds, but the screenshot is blank / wrong theme

Increase `DUETOS_SETTLE` (default 5s) in
`tools/qemu/screenshot-theme.sh`. The framebuffer may not be flushed
yet when the snapshot fires.

## PE / Win32 Failures

### `[ring3] pe reject name="..." reason=ImportsPresent`

Pre-stage-2 loader rejected the PE because it had imports the loader
couldn't resolve. Stage 2 closed this — if you see it now, the PE is
importing a DLL that's not in the preload set, or an export the DLL
doesn't have.

Run `inspect arm` in the kernel shell, then spawn the PE; the report
will list every imported `(dll, func)` pair.

### `[sys] denied syscall=SYS_FILE_WRITE pid=... cap=FsWrite`

The PE asked to write a file, but its `Process::caps` doesn't have
`kCapFsWrite`. Either grant the cap (for trusted binaries) or
implement the read-only fallback (for sandboxed binaries).

## Network Failures

### DHCP doesn't acquire an address

- Check the netif came up: `ifconfig` in the kernel shell.
- Check the DHCP client started: log line `[dhcp] DISCOVER sent`
  should appear within 1s of net stack init.
- For QEMU, ensure `-netdev user,model=e1000` is in the command line
  (the smoke harness sets this).

## Wiki Tooling Failures

### `tools/check-wiki-nav.sh` reports orphan pages

A page exists in `wiki/<category>/` but isn't in `_Sidebar.md`. Add
a sidebar entry under the matching `### Category` block.

### `docs/sync-wiki.sh sync` reports a stale reference

A wiki page references a kernel/userland source path that no longer
exists. Either fix the path or remove the dead reference.

## Related Pages

- [Debugging](../tooling/Debugging.md)
- [QEMU Smoke Tests](../tooling/QEMU-Smoke.md)
- [Boot Path](../kernel/Boot.md)
- [Logging and Tracing](../kernel/Logging-And-Tracing.md)
- [Roadmap](../reference/Roadmap.md)
