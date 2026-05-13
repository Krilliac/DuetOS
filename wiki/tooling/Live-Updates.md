# Live Updates

> **Audience:** Developers iterating on DuetOS with a long-running QEMU instance
>
> **Maturity:** v0 — host-side classifier; in-kernel reload not implemented

`tools/dev/live-update.sh` pulls changes from the project repo and tells
you whether the change you just fetched can keep using your current QEMU
boot, or whether you need to rebuild the kernel image and reboot.

It is **deliberately host-side**. DuetOS is from-scratch: the running
kernel has no in-kernel git client and no out-of-band channel to receive
fresh source. Every userland binary and DLL is `.incbin`-baked into the
kernel image at build time (see `duetos_embed_blob` in
[`kernel/CMakeLists.txt`](../../kernel/CMakeLists.txt)). The boundary that
matters in practice is **"did the change touch something the running
kernel ELF was built from?"** If yes, the running QEMU is stale; if no,
it is still current.

## Usage

```bash
# Dry-run: fetch, classify, print a verdict, exit. Nothing modified.
tools/dev/live-update.sh

# Apply: fast-forward the local branch onto the fetched ref. Refuses
# on a dirty work tree or when local has commits ahead of the remote.
tools/dev/live-update.sh --apply

# Show one line per changed path with its bucket.
tools/dev/live-update.sh --verbose

# Compare against a different remote/ref.
tools/dev/live-update.sh --remote upstream --ref develop

# Run the built-in classifier self-test (no git needed).
tools/dev/live-update.sh --self-test
```

## Classification

Every changed path is sorted into one of four buckets:

| Bucket | Examples | Effect on running QEMU |
|---|---|---|
| `DOCS` | `wiki/`, `docs/`, top-level `*.md`, `LICENSE` | None — re-open the wiki page if needed |
| `HOST-TOOLS` | `tools/dev/`, `tools/qemu/`, `tools/check-wiki-*.sh`, `tools/pkg/`, `tools/test/` | None — re-run the script if relevant |
| `HOST-TESTS` | `tests/host/`, `tests/fuzz/` | None — re-run `ctest --output-on-failure` |
| `KERNEL-IMAGE` | `kernel/`, `boot/`, `drivers/`, `subsystems/`, `userland/`, `CMakeLists.txt`, `CMakePresets.json`, `cmake/`, `Cargo.*`, `rust-toolchain.toml`, `tools/build/embed-blob.py`, `tools/build/gen-firmware-ramfs.py`, `tools/build/build-*.sh`, `tools/firmware/` | **Rebuild + reboot QEMU.** |

Classification is conservative: any path not explicitly recognised as
host-only is treated as `KERNEL-IMAGE`. An unnecessary rebuild costs a
few minutes; a missed rebuild costs a confusing debugging session where
your change appears to do nothing because it never reached the kernel.

`tools/build/` generators are split deliberately: scripts that **produce
generated headers consumed by the kernel build** (`embed-blob.py`,
`gen-firmware-ramfs.py`, `build-*.sh` PE-builders, the firmware
packagers under `tools/firmware/`) classify as `KERNEL-IMAGE` because
the next kernel build will pick up their new output. Pure host scripts
under `tools/dev/`, `tools/qemu/`, `tools/test/`, `tools/pkg/` classify
as `HOST-TOOLS`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Up to date, or every changed path is host-only — no rebuild needed |
| `10` | At least one `KERNEL-IMAGE` change — rebuild + reboot QEMU |
| `2` | Bad arguments |
| `3` | `git fetch` failed after retries |
| `4` | Working tree is dirty; refusing to `--apply` |
| `5` | Local and remote have diverged; `--apply` would need a manual rebase |

CI runners and shell watch-loops can use the `10` vs `0` split to
decide whether to kick a rebuild without scraping stdout.

## In-kernel companion — `live-update` shell command

The kernel ships a paired shell command. Once a kernel rebuild has
landed in a running QEMU instance, `live-update` lets the operator
hot-reload userland images **and hot-patch kernel functions**
without rebooting. Most kernel surfaces (drivers, subsystem
dispatch, baked-in DLLs) still require a full reboot — what `live-
update kernel-patch` covers is the narrow but powerful "redirect
one function to a different one" primitive, plus a bulk auto-apply
path for sets of patches registered in source.

The command is admin-gated:

```
live-update help                            usage
live-update status                          slot table + non-reloadable surfaces
live-update reload <path>                   respawn one userland image, retiring prior pid
live-update reload-all                      respawn every live slot from /tmp/<basename>
live-update restart-required [reason]       emit canonical RESTART REQUIRED line
live-update kernel-patch <target> <repl>    install one JMP-rel32 trampoline by symbol name
live-update kernel-revert <handle>          revert one named patch
live-update kernel-patches                  list every live patch
live-update kernel-auto-patch               install every entry in the registry section
live-update kernel-auto-revert              revert every live patch in one call
```

### `live-update reload <path>`

`<path>` is either a writable tmpfs slot (`/tmp/<leaf>`, capped at
512 B per the v0 tmpfs ceiling) or a read-only ramfs path
(any size; the embedded image's bytes feed the loader directly).

The implementation is a slim wrapper around the same `SpawnElfFile`
/ `SpawnPeFile` paths the existing `exec` command uses, plus an
8-slot per-name registry that tracks the pid of the most recent
spawn. When a `reload` lands a new pid for a name, the old pid is
signalled for kill via `SchedKillByPid` first so two generations
of the same image never run in parallel.

Image format is picked by header magic: `7F 45 4C 46 02` routes to
ELF64, `4D 5A` routes to PE/COFF. Anything else is rejected.

Caps and budgets are the kernel-trusted set
(`CapSetTrusted` / `kFrameBudgetTrusted` / `kTickBudgetTrusted`):
hot-reload is a developer primitive, not a sandbox.

### `live-update status`

Prints the live-app slot table (name → last_pid → reload count) and
re-states the canonical non-reloadable surfaces. Use this to confirm
which slots are bound, what their last spawn looked like, and how
many times an image has been swapped without rebooting.

### `live-update restart-required [reason]`

Emits the canonical `[live-update] RESTART REQUIRED` line both to
the serial console and through `KLOG_WARN`. Use it when an operator
discovers, mid-session, that a path they assumed was hot-reloadable
in fact requires a reboot — the host-side script (and any future
CI watcher) greps for this exact wording on the serial log to flag
a kernel-image divergence the running kernel cannot reflect.

## Kernel hot-patch — how `kernel-patch` actually works

DuetOS implements a real (single-CPU, single-pair) kernel-function
hot-patcher in [`kernel/debug/hot_patch.h`](../../kernel/debug/hot_patch.h)
and [`kernel/debug/hot_patch.cpp`](../../kernel/debug/hot_patch.cpp).
The pattern is the same one Linux's livepatch / kpatch uses, scaled
down to the kernel's actual safety guarantees.

### How a patchable target is marked

A kernel function declares itself patchable by carrying the
`KHOTPATCH_PATCHABLE` attribute:

```cpp
KHOTPATCH_PATCHABLE int CompositorDraw() { /* ... */ }
```

This expands to
`__attribute__((patchable_function_entry(5, 0), noinline))`, which
makes the compiler emit a 5-byte multi-byte NOP (`0F 1F 44 00 08` —
`nopl 8(%rax,%rax,1)`) at the function entry, before the prologue.
The function symbol points to the start of that NOP. Calling the
function executes the NOP and falls through to the body; the NOP is
the "patch area."

### How a patch is installed

`HotPatchInstall(target_va, replacement_va, &handle)`:

1. Validates both addresses are inside the embedded kernel
   symbol-table bounds.
2. Verifies the displacement fits in a signed 32-bit rel32.
3. Confirms the target's first 5 bytes are the patchability sentinel
   (refuses with `NotPatchable` otherwise).
4. Walks the caller's RBP frame chain and refuses with
   `SelfReferential` if any saved RIP is inside `[target, target+5)`
   — the obvious foot-gun of patching the code calling us.
5. Saves the 5 NOP bytes into the per-patch record (for revert).
6. Flips the containing 4 KiB page from R+X to R+W via
   `mm::SetPteFlags4K`, writes `E9 <rel32>` (JMP rel32) at the
   target, issues `mfence`, restores the page to R+X.
7. Records (id, target, replacement, original_bytes, names) in the
   live-patch table and returns a non-zero handle.

The PTE-flip primitive is exactly the one the existing software-
breakpoint subsystem uses for `0xCC` patches; the v0 SMP contract
("no other CPU is fetching from this page during the W window") is
inherited unchanged.

`HotPatchRevert(handle)` walks the same path in reverse: looks up
the record, writes the saved 5 NOP bytes back, frees the slot.

### Bulk apply via the `.duetos_hotpatch_pairs` registry

For sets of patches that ship as a unit, the source registers each
pair into a dedicated linker section:

```cpp
KHOTPATCH_REGISTER_PAIR("compositor-fast-path",
                         CompositorDraw,
                         CompositorDrawFast)
```

This emits a `HotPatchPair` struct (target, replacement, tag) into
section `.duetos_hotpatch_pairs`, which the linker bookends with
`__duetos_hotpatch_pairs_start` / `__duetos_hotpatch_pairs_end`.
`HotPatchApplyAll` walks `[start, end)` and calls
`HotPatchInstall` for every entry that isn't already live;
`HotPatchRevertAll` snapshots the live-patch table and reverts each
entry. Both functions return a small `{considered, installed,
already_patched, failed}` summary so operators can see a clean
"applied N, skipped M because already-live, M failed" verdict.

The shell wraps these as:

```
live-update kernel-auto-patch     # = HotPatchApplyAll
live-update kernel-auto-revert    # = HotPatchRevertAll
```

The kernel ships with one demo pair pre-registered (the self-test's
`HotPatchTestTargetReturns7` → `HotPatchTestReplacementReturns42`),
so `kernel-auto-patch` always has at least one entry to work with
out of the box. The full round-trip is verified at boot by
`HotPatchSelfTest` — look for `[hot-patch] PASS` on the serial log.

### Safety contract

- **Patchable attribute is mandatory.** Targets without
  `KHOTPATCH_PATCHABLE` get rejected with `NotPatchable` because
  the first 5 bytes don't match the multi-byte NOP sentinel —
  overlaying real instruction bytes would clip whatever
  instruction starts at offset 4 and crash any in-flight execution.
- **Single-CPU patch window.** The PTE flip + 5-byte write isn't
  atomic against another CPU fetching from the same page mid-flip.
  The boot self-test runs before SMP bring-up (trivially safe);
  operator-driven patches are admin-gated. The
  [Kernel Modularization](../security/Kernel-Modularization.md)
  roadmap covers turning this into a real CPU-quiesce + IPI dance.
- **Replacement signature must match.** A wrong-signature
  replacement compiles, patches, and trashes the stack at the
  first call — no runtime check can catch this.
- **No stack-walk refusal for foreign tasks.** v0 only refuses a
  self-patch (caller's RBP chain landing in the target). A v1
  enhancement would walk every `Task`'s saved RIP and refuse when
  any frame is inside `[target, target+5)`.

## What's still missing (and why)

Three families of hot-reload exist in mature kernels. DuetOS now
has two of the three:

1. **User-space process respawn** — `live-update reload[-all]`.
   ✅ Works today.
2. **Kernel function-level hot patch** — `live-update
   kernel-patch[es]` / `kernel-auto-patch` / `kernel-auto-revert`.
   ✅ Works today, with the v0 single-CPU contract documented above.
3. **Kernel module reload** (`rmmod` / `insmod`). DuetOS does not
   yet have a loadable-module ABI — every driver and subsystem
   links into the kernel ELF. This is the planned
   [Kernel Modularization](../security/Kernel-Modularization.md)
   surface; when it lands, this page gains a `MODULE` bucket and
   a matching `live-update module-reload` subcommand.

Above and below those, the iteration loop is:

- **For host-only changes (docs / dev tools / hosted tests):** the
  host script reports "hot reload applied" and you just re-open the
  page / re-run the script. No QEMU touch.
- **For userland source changes:** rebuild + reboot, then
  `kernel-auto-patch` and `reload-all` to skip further reboots
  for the same source files.
- **For kernel function changes that carry `KHOTPATCH_REGISTER_PAIR`:**
  rebuild + reboot once, then iterate via `kernel-auto-patch` /
  `kernel-auto-revert` against the running kernel.
- **Everything else (kernel core / drivers / boot / scheduler):**
  the host script reports `RESTART REQUIRED`; rebuild + reboot is
  the only path until the modularization story lands.

## See also

- [Git Workflow](Git-Workflow.md) — fetch/rebase discipline this tool follows
- [Build System](Build-System.md) — what the rebuild step on a `KERNEL-IMAGE` verdict actually does
- [QEMU Smoke Tests](QEMU-Smoke.md) — how to reboot the running instance after a verdict of `10`
- [Roadmap → System updater](../reference/Roadmap.md) — the eventual signed-A/B-slot story this tool is a developer-loop precursor to
