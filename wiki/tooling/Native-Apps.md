# Portable Native Apps

> **Audience:** anyone adding a new DuetOS app, or migrating one
> of the in-kernel apps under `kernel/apps/` out into a separate
> ELF
>
> **Maturity:** pattern + libc + build helper land; two demo
> apps ship (`hello_native`, `nat_calc`); migration of the 57
> in-kernel apps is multi-slice future work — see "Migration
> roadmap" at the bottom

## Why this exists

Today **57 native DuetOS apps** (~20.5k LOC, see
`kernel/apps/`) are statically linked into the kernel image.
That's an architectural pile-up:

- Every app shares the kernel's address space, capability set,
  and crash domain. A bug in one app can panic the whole box.
- The kernel ABI between apps and the widget framework drifts
  every slice; the only safety net is the C++ link.
- App updates require kernel rebuilds + reboots.
- The kernel binary grows linearly with app count — every
  feature flag is paid by every install.

A daily-driver OS ships apps as **separate ELF binaries**
loaded on demand. DuetOS already has the spawn pipeline for
this (`core::SpawnElfFile`, `usershell.elf` proves it
end-to-end). What was missing was a generic build path so
adding a new portable app didn't mean writing a one-off shell
script. This page documents the path that's now in tree.

## What ships today

```
tools/build/build-native-app.sh        ← generic builder
kernel/CMakeLists.txt::duetos_native_app(<name>)  ← wraps the script
userland/libc/include/stdio.h          ← puts_str / print_int / print_hex / print_fmt
userland/libc/src/stdio.c
userland/libc/src/string.S             ← strlen rax-clobber fix
userland/native-apps/<name>/<name>.c   ← per-app source root
```

Plus two demo apps that boot every smoke run:

| App | Source | Sentinel | Demonstrates |
|-----|--------|----------|--------------|
| `hello_native` | `userland/native-apps/hello_native/hello_native.c` | `[hello-native] portable native ELF spawned` | The pipeline works; libc `print_fmt` substitutes `%d` / `%x`. |
| `nat_calc` | `userland/native-apps/nat_calc/nat_calc.c` | `[nat-calc] all eval cases passed` | Real logic in a portable app — recursive-descent arithmetic eval with operator precedence + parens. |

Both spawn at boot from `kernel/core/main.cpp` next to
`usershell.elf`. The smoke harness can grep for either sentinel
to detect a regression in the native-app pipeline.

## Adding a new portable app

```bash
# 1. Create the source tree.
mkdir -p userland/native-apps/myapp
cat > userland/native-apps/myapp/myapp.c <<'EOF'
#include "stdio.h"
#include "unistd.h"

int main(void)
{
    println("[myapp] hi from a portable native ELF");
    return 0;
}
EOF

# 2. Wire it into the kernel ramfs build.
# Edit kernel/CMakeLists.txt and add one line near the existing
# duetos_native_app() calls:
#
#     duetos_native_app(myapp)
#
# That's it for the build — the helper compiles myapp.c +
# the libc, links against userland/libc/usershell.lds, embeds
# the bytes via embed-blob.py, and exposes
# `kBinMyappBytes` in `duetos::fs::generated`.

# 3. Optional: add a Ramfs<Pascal>Bytes() / Size() accessor in
# kernel/fs/ramfs.{h,cpp} if anything in the kernel needs to
# spawn the app at boot. See RamfsHelloNativeBytes for the
# template.

# 4. Optional: spawn at boot from kernel/core/main.cpp via
# `core::SpawnElfFile`. See the hello_native + nat_calc spawn
# block right after the usershell.elf spawn.
```

## libc surface

The userland libc is intentionally tight (~10 functions today).
Every app links against it via the `duetos_native_app()` helper.

- `<unistd.h>` — `read`, `write`, `exit`, `getpid`, `STDIN_FILENO`, `STDOUT_FILENO`, `STDERR_FILENO`
- `<string.h>` — `strlen`, `strcmp`, `memcpy`, `memmove`, `memset`
- `<stdio.h>` — `puts_str`, `puts_char`, `println`, `print_int`, `print_hex`, `print_fmt`
- `<setjmp.h>` — `setjmp`, `longjmp`
- `<duet/syscall.h>` — raw `int 0x80` numbers + `errno` constants for code that wants to bypass the wrappers

`print_fmt`'s spec subset: `%s`, `%c`, `%d`, `%ld`, `%u`, `%lu`,
`%x`, `%lx`, `%p`, `%%`. No width specifiers, no precision, no
floating point. The format string + args are bounded by the
SysV varargs ABI; `-mgeneral-regs-only` is set on the build so
no float varargs work even if you ask for them.

## Migration roadmap (the 57 in-kernel apps)

Migrating each in-kernel app is two distinct chunks of work:

1. **The widget-framework half.** All 57 apps render through
   the in-kernel widget framework (`kernel/drivers/video/widget.cpp`).
   Migration needs a userland widget library (`libduet-widget` or
   similar) that talks to the kernel compositor via syscalls
   (`SYS_WIN_*`, `SYS_GDI_*` are already there for Win32 PE
   apps; the same surface works for native callers). This is
   a multi-slice piece of work — own scope.
2. **The per-app port.** Each app's logic gets lifted into a
   `userland/native-apps/<name>/` directory, depends on
   `libduet-widget` instead of the kernel widget classes, and
   gets registered via `duetos_native_app()`.

Until #1 lands, only **CLI-style apps** can move. Of the 57,
most are widget-bound; the small set of truly CLI-style ones
(or app-internal helpers like `dbg_core` / `notes_internal` /
`notes_persist` that are TU helpers, not user-facing) can move
with no widget work. The bulk of the migration waits on #1.

### Current categorisation

| Bucket | Count | Status | Notes |
|--------|-------|--------|-------|
| Widget-framework GUI apps | ~28 | Blocked on `libduet-widget` | calc, notes, files, browser, taskman, clock, gfxdemo, calendar, charmap, hexview, imageview, settings (×6 sub-pages), netstatus, devicemgr, sysmon, firewall, magnifier, screenshot, trash, notify_center, about, help, dbg, gfxdemo_modes |
| App-internal C++ helpers (not user-facing) | ~5 | Won't migrate (they go away with the app) | dbg_core, dbg_internal, dbg_render, notes_internal, notes_persist |
| Already-portable candidates | 0 | None — every visible app touches widgets | |

### Order of operations

1. **Land `libduet-widget`** — userland C++ wrapping
   `SYS_WIN_*` / `SYS_GDI_*` into a Widget API mirroring the
   kernel one. Goal: a userland widget app should be a
   one-line s/`#include "drivers/video/widget.h"`/
   `#include "duet/widget.h"`/ and a relink.
2. **Pick a canary app** to migrate (probably `about` — small,
   read-only, single window). Verify the round-trip end-to-end.
3. **Mechanical sweep** of the remaining 27 apps using the
   canary as the template.
4. **Remove `kernel/apps/`** sources once all apps are out;
   the kernel image drops by ~20.5k LOC.
5. **Wire duet-pkg** to ship native apps as packages — the
   app embeds today are temporary; once the installer is
   common, apps should be installed not embedded.

## Build path

`tools/build/build-native-app.sh <repo_root> <out_header> <name>`:

1. Compiles `userland/libc/src/{crt0,syscall,string,setjmp,stdio}.{S,c}`
   plus `userland/native-apps/<name>/<name>.c` with
   `clang --target=x86_64-unknown-none-elf -ffreestanding
   -nostdlib -fno-pic -fno-pie -mno-red-zone -fno-stack-protector
   -mgeneral-regs-only -O2 -Wall -Wextra -Wpedantic`.
2. Links via `lld` against `userland/libc/usershell.lds`
   (single PT_LOAD at 0x400000 — the v0 ELF loader's contract).
3. Runs `tools/build/embed-blob.py` to wrap the bytes into a
   `constexpr u8 array[]` C++ header in
   `${CMAKE_BINARY_DIR}/kernel/generated_<name>_native.h`.

Pascal-cased symbol convention: `<name>` → `<Name>` →
`kBin<Name>Bytes` + `kBin<Name>Bytes_len` in the
`duetos::fs::generated` namespace.

## Known limits

- Apps don't yet receive `argc` / `argv` — `main`'s signature is
  `int main(void)`. The kernel spawn path doesn't push them.
  Add when a workload depends on it.
- No userland heap. `print_fmt` and friends use stack-bound
  buffers (`char buf[24]` etc.). A `malloc` lands when something
  needs it — defer.
- No SSE / FPU registers. `-mgeneral-regs-only` is enforced
  because the kernel's userland fpu init isn't on by default.
- ELF loader is single-PT_LOAD only (the v0 contract). Multi-
  segment ELFs are rejected at spawn. The linker script
  `userland/libc/usershell.lds` collapses everything into one
  PT_LOAD.

## Related Pages

- [`Build-System`](Build-System.md)
- [`Duet-Pkg`](Duet-Pkg.md) — the eventual delivery mechanism
- [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md)
