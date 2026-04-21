# PE subsystem v0 — freestanding hello.exe end-to-end

**Type:** Observation · **Status:** Active · **Last updated:** 2026-04-21

## Context

Project pillar #1 is "run Windows PE executables natively." Before
this slice, zero PE-subsystem code existed: no loader, no NT
syscalls, no Win32 DLLs, no userland build pipeline. This entry
captures the v0 slice that brings up a real end-to-end PE path:

1. **Compile** a freestanding C source into a real x86_64 PE/COFF
   `.exe` using host `clang` + `lld-link`.
2. **Embed** the resulting bytes as a `constexpr u8[]` into the
   kernel's ramfs.
3. **Parse + map** the PE at boot via a new in-kernel PE loader.
4. **Run** the PE in ring 3, using the same process + scheduler
   plumbing the existing ELF smoke tasks use.

The PE is freestanding — no imports, no DLLs — and talks the
CustomOS **native** syscall ABI (`int 0x80`, rax = syscall #).
The Win32 subsystem (ntdll, kernel32, user32) is still future
work. This slice is the scaffolding those DLLs will sit on top of.

## The three source files

| File | Role |
|------|------|
| `userland/apps/hello_pe/hello.c` | Freestanding C — inline-asm `int 0x80` for `SYS_WRITE`, `SYS_EXIT`. Entry point `_start`. No CRT, no libc. |
| `tools/build-hello-pe.sh` | Host compile script: `clang --target=x86_64-pc-windows-msvc -ffreestanding -nostdlib …` → `lld-link /subsystem:console /entry:_start /nodefaultlib /base:0x400000 /align:4096 /filealign:4096 /dynamicbase:no`. Then calls `embed-blob.py`. |
| `tools/embed-blob.py` | Byte-blob → C++ header. Emits `constexpr unsigned char kBinHelloPeBytes[] = { ... }` + `_len`, wrapped in a namespace. |

The CMake `add_custom_command` in `kernel/CMakeLists.txt`
fires on any change to `hello.c`, the shell script, or the
embed script; its `OUTPUT` header is appended to
`CUSTOMOS_KERNEL_SHARED_SOURCES` so both kernel stages see the
dependency and the custom command runs on first configure.

The kernel include path is extended with `${CMAKE_CURRENT_BINARY_DIR}`
for both stages so `#include "generated_hello_pe.h"` resolves.

## Build-time contract (lld-link flags)

Each flag is load-bearing for the v0 loader:

| Flag | Why the loader needs it |
|------|-------------------------|
| `/subsystem:console` | Any real Subsystem value. Loader ignores it today but writes into the PE spec regardless. |
| `/entry:_start` | Skip the MSVC CRT — our `_start` is the only code. |
| `/nodefaultlib` | No `msvcrt.dll`, `libcmt.lib`, `kernel32.dll`. Keeps the Import Directory empty. |
| `/base:0x400000` | Fixed ImageBase. v0 loader does NOT apply base relocations. |
| `/align:4096` + `/filealign:4096` | SectionAlignment == FileAlignment == 0x1000 → PointerToRawData == VirtualAddress for every section. One loader code path. |
| `/dynamicbase:no` | Suppress DLL_CHARACTERISTICS_DYNAMIC_BASE so no reloc stamp is emitted. |

Running without `/align:4096` produces a PE with FileAlign=0x200
— valid Windows PE, but the v0 loader rejects it as
`FileAlignUnsup`. The future "real" loader will handle
cross-page copies.

## Loader (`kernel/core/pe_loader.{h,cpp}`)

Mirror of the ELF loader's shape so everything above it (process
creation, ring-3 entry, stack handling) stays loader-agnostic:

```cpp
PeStatus PeValidate(const u8* file, u64 file_len);
PeLoadResult PeLoad(const u8* file, u64 file_len, AddressSpace* as);
```

### What v0 handles

- **DOS stub** — `MZ` magic at offset 0; `e_lfanew` at offset 0x3C.
- **NT signature** — `PE\0\0` at `e_lfanew`.
- **FileHeader** — `Machine == IMAGE_FILE_MACHINE_AMD64 (0x8664)`, `NumberOfSections > 0`, `SizeOfOptionalHeader >= 112 + 4`.
- **OptionalHeader (PE32+)** — `Magic == 0x20B`; reads `ImageBase`, `AddressOfEntryPoint`, `SectionAlignment`, `FileAlignment`, `SizeOfImage`, `SizeOfHeaders`, `NumberOfRvaAndSizes` + data dirs.
- **Section table** — per section: maps `max(VirtualSize, SizeOfRawData)` bytes at `ImageBase + VirtualAddress`, copying `SizeOfRawData` bytes from `file[PointerToRawData..]`. Flags: `IMAGE_SCN_MEM_WRITE` → `kPageWritable`, `!IMAGE_SCN_MEM_EXECUTE` → `kPageNoExecute`. Every section is `kPageUser | kPagePresent`.
- **Headers page** — the first `SizeOfHeaders` bytes are mapped RO + NX at `ImageBase`. Loader convention — makes `__ImageBase` usable from ring 3.
- **Stack** — one writable + NX user page at `kV0StackVa = 0x7FFFE000` (same VA the ELF loader uses).

### What v0 rejects

- Non-empty **Import Directory** → `ImportsPresent`.
- Non-empty **Base Relocation Directory** → `RelocsNonEmpty`.
- Non-empty **TLS Directory** → `TlsPresent`.
- `SectionAlignment != 4096` → `SectionAlignUnsup`.
- `FileAlignment != 4096` → `FileAlignUnsup`.
- `Machine != AMD64` → `BadMachine`.

### What v0 ignores on purpose

- Exception Directory, Debug Directory, Resource Directory,
  Delay-Load Imports, Bound Imports, COM Descriptor, Load
  Config. All legal to be present; loader doesn't touch them.
- `SizeOfStackReserve` / `SizeOfStackCommit` — v0 always gives
  one 4 KiB user stack page.
- `Subsystem` — ignored. Console vs GUI is a user-mode runtime
  concern, not a kernel loader concern.

## Process + scheduler plumbing

`SpawnPeFile` in `kernel/core/ring3_smoke.cpp` is the PE twin of
`SpawnElfFile`:

1. `PeValidate` — early reject with a serial-log reason.
2. `AddressSpaceCreate(frame_budget)` — fresh PML4.
3. `PeLoad` — maps sections + stack.
4. `ProcessCreate(name, as, caps, root, r.entry_va, r.stack_va, tick_budget)`.
5. `SchedCreateUser(Ring3UserEntry, nullptr, name, proc)`.

`Ring3UserEntry` already reads `proc->user_code_va` and
`proc->user_stack_va`, so it does not know or care whether the
image was ELF or PE. The `int 0x80` IDT gate handles the
syscalls regardless.

## The canonical boot log

```
[proc] create pid=0xe name="ring3-hello-pe" caps=0x6
       code_va=0x401000 stack_va=0x7fffe000
[ring3] pe spawn name="ring3-hello-pe" pid=0xe
       entry=0x401000 image_base=0x400000 stack_top=0x7ffff000
[sched] created task id=0x16 name="ring3-hello-pe" …
[ring3] task pid=0x16 entering ring 3 rip=0x401000 rsp=0x7ffff000
[hello-pe] Hello from a PE executable!
[proc] destroy pid=0xe name="ring3-hello-pe"
```

`entry = ImageBase (0x400000) + AddressOfEntryPoint (0x1000)` —
exactly what `llvm-readobj --file-headers hello.exe` shows on
the host side. No `#GP`, no `#PF`, no `[task-kill]`.

## What's next (deliberately deferred)

1. **Real `ntdll.dll` / `kernel32.dll` stubs.** Forward
   `NtWriteFile` / `NtTerminateProcess` / etc. to the native
   `int 0x80` syscalls. That makes the PE truly Win32-like.
2. **Import resolution.** Walk the Import Directory, load
   dependent DLLs, patch the IAT. Gates `RelocsNonEmpty` path.
3. **Base relocations.** Apply `.reloc` entries so the loader
   can honour ASLR (currently we insist on fixed ImageBase).
4. **TLS callbacks.** Walk the TLS Directory, invoke each
   callback in order before the entry point. Required for most
   C/C++ programs.
5. **Standard FileAlignment (0x200).** The common case. Loader
   must copy cross-page slices for sections whose Raw bytes
   don't align to pages.
6. **Magic-sniff dispatch in `SYS_SPAWN`.** Today only ELF is
   loaded by path; PE must be called via the internal
   `SpawnPeFile`. Once SYS_SPAWN sniffs `MZ` vs `ELF`, ring-3
   can `spawn /bin/hello.exe` directly.
7. **`readpe` shell tool.** ELF already has `readelf`; a PE
   counterpart would make debugging v0 rejections easier.
8. **Host-toolchain CMake probe.** Today the build assumes
   `clang` + `lld-link` are installed. A probe + fallback to a
   pre-built blob in `third_party/` would make the build
   portable to containers without those tools.

## Related entries

- `win32-subsystem-design.md` — the long-term shape this v0
  is scaffolding toward.
- `pentest-ring3-adversarial-v0.md` — ring-3 adversarial probes
  that share the same `Ring3UserEntry` dispatch and
  `RamfsTrustedRoot` namespace used here.
