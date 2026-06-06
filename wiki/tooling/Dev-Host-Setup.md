# Dev-Host Setup — Live-Test Runtime Tooling

The dev host does not ship with `qemu-system-x86_64`, `grub-mkrescue`, `xorriso`,
`mtools`, or `ovmf`. Until these are installed, **build-clean is the only signal
available** — a "compiled cleanly, therefore it works" claim for code whose
correctness can only be proven at runtime is not acceptable.

**Install the full toolbox up front when a task legitimately requires a live-boot
smoke test** — not just `qemu-system-x86`. A diagnosis that starts as "the boot
hangs in `SmpStartAps`" turns into "I need to attach gdb to localise it" five
minutes later, and the user re-typing the install line is friction the session can
avoid by paying it once.

```bash
sudo apt-get update
# Live-boot runtime: QEMU + UEFI + ISO build chain.
sudo apt-get install -y qemu-system-x86 grub-common grub-pc-bin grub-efi-amd64-bin xorriso mtools ovmf
# PE smoke fixtures: mingw cross-toolchains (otherwise the kernel
# build emits the smoke PE blobs as _len=0 stubs and ring3-* PE
# tests can't actually load).
sudo apt-get install -y gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
# Live-debug toolbox: GDB stub attach, syscall/process tracing,
# fd/lock inspection, network capture. Install these EVERY session
# the moment a runtime-behaviour task is on the table — the GDB
# stub the DUETOS_GDB_SERVER preset publishes is useless without a
# host gdb to attach. Cheap to keep installed; expensive to
# discover missing mid-investigation.
sudo apt-get install -y gdb strace ltrace lsof tcpdump
# Binary / ELF / disassembly inspection. `objdump`/`readelf`/`nm`
# come from binutils-x86-64-linux-gnu (already a clang dep on most
# hosts but pin it). `addr2line` resolves a kernel RIP to file:line
# from the .elf. `gdbserver` lets a remote gdb attach to a
# host-side trace harness; `valgrind` doesn't run kernel code but
# is invaluable for the cross-built userland tools under tools/.
sudo apt-get install -y binutils binutils-x86-64-linux-gnu gdbserver valgrind
# Disk / FS forensics: GPT/MBR/ISO inspection during the boot-
# image plumbing (`fdisk -l`, `parted print`, `losetup`, `dumpe2fs`,
# `mtools` already covered above). `hexdump` ships with bsdmainutils
# / util-linux but we want the GNU one. `xxd` is in vim-common.
sudo apt-get install -y parted util-linux bsdmainutils vim-common
# JSON / log slicing: `jq` cuts the QEMU QMP / boot-determinism
# TSV output cleanly; `ripgrep` is faster than grep across the
# tree under load and respects `.gitignore`.
sudo apt-get install -y jq ripgrep
# Script hygiene + diagnostic automation: `shellcheck` catches
# the `grep -c file || echo 0` class of bugs that bombed
# fat32-concurrent.sh on a clean run; `yamllint` keeps GitHub
# Actions / CI configs honest. `expect` + `socat` automate
# QEMU stdio / GDB-stub interactions for the babysit-boot rig.
# `bear` produces a compile_commands.json from a build (clangd
# / ide friendly). `universal-ctags` + `silversearcher-ag`
# accelerate cross-tree navigation; `entr` watches files and
# re-runs a command on change (useful with `find kernel | entr
# -c cmake --build build/...`). `moreutils` adds `ts` for time-
# stamping piped output and `sponge` for in-place edits.
sudo apt-get install -y shellcheck yamllint expect socat bear universal-ctags silversearcher-ag entr moreutils
```

## When a task "legitimately requires" the live toolbox

Count as legitimately requiring an install:

- The commit introduces or changes an observable runtime behaviour (scheduler
  ordering, new syscall return codes, new boot-log line, new trap path, new
  sandbox-policy refusal).
- The commit claims end-to-end correctness for a path that a compile-time check
  cannot prove (address-space isolation, TLB shootdown, IRQ routing, timer drift,
  PE-image execution).
- A previous slice's runtime claim has never been verified on this host and the new
  slice depends on it.

Do **NOT** install for:

- Pure refactors with no behavioural delta.
- Docs / `CLAUDE.md` / `wiki/` changes only.
- Code that compiles but is not yet wired into any live path.

## Canonical smoke invocation

After install, `DUETOS_TIMEOUT=20 tools/qemu/run.sh` is the canonical headless smoke
invocation (see the script header for other env-var overrides). Once CI lands, the
same install line goes in the workflow file.
