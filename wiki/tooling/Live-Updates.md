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
hot-reload userland images **without rebooting the kernel**. It is
the only true hot-reload primitive DuetOS has today; everything
else (kernel core, drivers, subsystems, baked-in DLLs) requires a
full reboot, which the host script's `KERNEL-IMAGE` verdict will
catch.

The command is admin-gated:

```
live-update help                          usage
live-update status                        slot table + non-reloadable surfaces
live-update reload <path>                 respawn an image, retiring prior pid
live-update restart-required [reason]     emit canonical RESTART REQUIRED line
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

## Why there is no full "hot patch the running kernel" path

In a mature OS, hot-reload spans three families. DuetOS only has one
of them today, and only at the user-mode boundary:

1. **User-space process respawn.** This is what `live-update reload`
   does — kill the prior pid, re-load the binary, queue a fresh
   ring-3 task. Works only because the source binary exists in a
   reachable VFS path (tmpfs or ramfs); the binary in the
   `.incbin`'d kernel image still requires a rebuild + reboot for
   its bytes to update.
2. **Kernel module reload** (`rmmod` / `insmod`). DuetOS does not
   yet have a loadable-module ABI — every driver and subsystem
   links into the kernel ELF. This is the planned
   [Kernel Modularization](../security/Kernel-Modularization.md)
   surface; when it lands, this page gains a fourth bucket
   (`MODULE`) and a matching `live-update module-reload` subcommand.
3. **Live patching** (kpatch-style). Requires a stable function-
   pointer table the patcher can swing under traffic. None of the
   kernel's hot paths are wrapped that way today, and the cost of
   doing so for the entire kernel is higher than the iteration
   loop justifies.

The host-side verdict therefore stays "rebuild + reboot" for
anything touching the kernel ELF, and the in-kernel `live-update`
covers the post-reboot loop where the same image needs to be
re-spawned (after a smoke test, after a crash, after a tweak that
lands via tmpfs sideload).

## See also

- [Git Workflow](Git-Workflow.md) — fetch/rebase discipline this tool follows
- [Build System](Build-System.md) — what the rebuild step on a `KERNEL-IMAGE` verdict actually does
- [QEMU Smoke Tests](QEMU-Smoke.md) — how to reboot the running instance after a verdict of `10`
- [Roadmap → System updater](../reference/Roadmap.md) — the eventual signed-A/B-slot story this tool is a developer-loop precursor to
