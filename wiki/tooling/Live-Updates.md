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

## Why there is no "hot patch the running kernel" path

In a mature OS, hot-reload usually means one of three things:

1. **Kernel module reload** (`rmmod` / `insmod`). DuetOS does not yet
   have a loadable-module ABI — every driver and subsystem links
   into the kernel ELF.
2. **User-space process restart**. The userland binaries and DLLs are
   `.incbin`'d into the kernel image, so "swap the binary on disk"
   would not be reflected by the running kernel anyway.
3. **Live patching** (kpatch-style). Requires a stable function-pointer
   table the patcher can swing under traffic. None of the kernel's
   hot paths are wrapped that way today.

Until one of those landings happens, the only true hot-reload is
"the change did not touch the kernel image, so the running image is
still right." That is exactly what this script reports.

If a future slice adds a loadable-module ABI (search the roadmap for
"System updater" and "Kernel Modularization"), this script gains a
fourth bucket (`MODULE`) that triggers an in-kernel reload via a
shell command instead of a QEMU restart. The `KERNEL-IMAGE` bucket
stays — there will always be parts of the kernel (early boot,
scheduler, paging) that no live-patch system can swap under a running
foot.

## See also

- [Git Workflow](Git-Workflow.md) — fetch/rebase discipline this tool follows
- [Build System](Build-System.md) — what the rebuild step on a `KERNEL-IMAGE` verdict actually does
- [QEMU Smoke Tests](QEMU-Smoke.md) — how to reboot the running instance after a verdict of `10`
- [Roadmap → System updater](../reference/Roadmap.md) — the eventual signed-A/B-slot story this tool is a developer-loop precursor to
