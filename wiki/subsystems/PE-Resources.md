# PE Resources (`.rsrc`)

> **Status:** REAL as of 2026-07-28 for strings and binary resources on
> both bitnesses. Icons, cursors, bitmaps and accelerators are parsed by
> nothing yet — deliberately, see [Not implemented, and
> why](#not-implemented-and-why).

The `.rsrc` walker is how a guest PE reaches its own embedded resources:
string tables, manifests, version blocks, `RCDATA` payloads, and
eventually dialog templates. It backs `kernel32!FindResource*` /
`LoadResource` / `LockResource` / `SizeofResource` / `FreeResource` /
`EnumResource*` and `user32!LoadStringW` / `LoadStringA`.

## Why there is no kernel involvement

**The parser is userland-only and needs no syscall.** The kernel PE
loader already maps the whole image into the guest's own address space
before ring-3 entry:

- `MapHeaders` (`kernel/loader/pe_loader.cpp`) copies `SizeOfHeaders`
  bytes to `ImageBase`, read-only + NX, so the DOS stub, NT headers,
  data directories and the section table are all readable from ring 3.
- `MapSection` maps every section at `ImageBase + VirtualAddress` for
  `max(VirtualSize, SizeOfRawData)` bytes, zero-filled past the raw
  tail.
- `dll_loader.cpp`'s `MapHeadersPage` does the same for preloaded DLLs,
  so `FindResourceW(GetModuleHandleW(L"comctl32.dll"), ...)` is
  structurally reachable too.

So a DLL holding an `HMODULE` can walk the tree with pointer arithmetic
on pages the guest already owns. Adding a syscall would have added
kernel attack surface to read memory the guest can read anyway.

This is the *reason* the resource parser was cheap, and it is worth
stating plainly because the opposite assumption ("resources need a
loader service") is the intuitive one.

## Where the code lives

| File | Role |
|---|---|
| `userland/libs/common/pe_resources.h` | the walker — freestanding, header-only, shared |
| `userland/libs/kernel32/kernel32_resource.c` | x86_64 Win32 translation layer |
| `userland/libs/kernel32_32/kernel32_32_resource.c` | i386 translation layer |
| `userland/libs/user32/user32.c` | x86_64 `LoadStringW` / `LoadStringA` |
| `userland/libs/user32_32/user32_32_misc.c` | i386 `LoadStringW` / `LoadStringA` |
| `tests/host/test_pe_resources.cpp` | hosted unit tests over synthetic blobs |
| `userland/apps/rsrc_pe/` | live ring-3 fixture with a real windres `.rsrc` |

**Only the walker is shared.** The thin Win32 translation layer is
duplicated per bitness on purpose: the calling convention (`__stdcall`),
the pointer width, and the `IS_INTRESOURCE` high-half test all differ,
and sharing it would put a 64-bit shape inside a `_32` DLL — the exact
mistake [`Design-Decisions.md`](../reference/Design-Decisions.md) warns
about.

`pe_unwind_bounds.h` is deliberately **not** reused: its view is PE32+
only (it rejects any optional-header magic that is not `0x20B`) and it
requires a well-formed `.pdata`, which i386 resource-only images lack.
The two headers do not include each other.

## Threat model — everything here is attacker-controlled

Every byte walked comes from a guest binary. A malformed tree must fail
closed and must never form a pointer outside the mapped image.

1. **One gate.** Every read goes through `duet_res_at`, which resolves an
   RVA to a pointer only when the whole span lies inside a mapped
   extent — computed exactly the way `MapSection` computes it,
   `max(VirtualSize, SizeOfRawData)`. An RVA inside `SizeOfImage` but in
   the hole between the header block and the first section is **not**
   mapped and is rejected; a naive `rva + size <= SizeOfImage` check
   would wave it through.
2. **Fixed depth, no recursion.** The format has exactly three levels
   (Type -> Name/ID -> Language) and the walk is three flat loops. A
   self-referential subdirectory pointer therefore cannot form a cycle,
   and a level-3 entry flagged as a subdirectory is skipped rather than
   descended.
3. **Bounded trip counts.** Entry counts are a `u16` pair, and every
   entry must clear rule 1, so a loop is bounded by the containing
   section's size regardless of what the header claims.
4. **Handles are re-validated, not trusted.** `HRSRC` is a pointer to
   the `IMAGE_RESOURCE_DATA_ENTRY` inside the module's own image, so a
   guest can fabricate one. `LoadResource` and `SizeofResource`
   re-derive the view and check alignment and containment before
   dereferencing.

### The tree bound is the section, not `DataDirectory[2].Size`

`duet_res_init` bounds the tree by the mapped extent of the section
holding the directory, not by the declared directory size. Real linkers
under-declare that `Size` often enough that trusting it rejects valid
binaries; the section extent is what the kernel actually mapped, so it
is both the honest bound and the safe one. The declared size is still
required to fit inside the section, which rejects a header claiming a
directory bigger than its own section.

### Division of labour between the two bounds checks

`duet_res_at` is the memory-safety gate. `duet_res_dir_at`'s clamp
against `dir_span` is defence-in-depth: a negative control (delete the
clamp, run `test_pe_resources`) leaves the malformed-tree cases still
caught. The clamp earns its place for two narrower reasons — it keeps
the walk semantically inside the directory rather than merely inside
some mapped section, and it proves `off + span` fits before
`dir_rva + off` is computed, so that sum cannot wrap a `u32` into an
unrelated part of the image.

## String tables — the indexing that bites

`RT_STRING` resources are bundles of **16** counted UTF-16 strings.
String `id` lives at slot `id % 16` of the resource whose integer name
is `(id / 16) + 1`. Each slot is a `u16` character count followed by
exactly that many UTF-16 code units, with **no terminator**; a count of
zero means the slot is unused, which `LoadString` reports as not-found.

Both halves of `(id / 16) + 1` are easy to get wrong, so the tests pin
them from both directions: the hosted test builds two bundles with
distinct text in every slot, and the live fixture asks for ids 15 and 16
— which live in *different* `RT_STRING` resources — so an off-by-one
returns the wrong string rather than nothing.

`LoadStringW` honours the documented `cchBufferMax == 0` form: `lpBuffer`
is treated as an `LPWSTR*` and receives a read-only pointer to the
resource itself, with the character count as the return value.

## Language selection

`FindResourceExW` tries the requested `LANGID`, then `LANG_NEUTRAL`
(0), then the first entry present. The last fallback is what a
single-language binary depends on — it stores everything under one
LANGID and expects `FindResource` to find it whatever the thread locale
is.

## Downstream consumers (since landed)

Both consumer families this section originally deferred have since
gained their sinks and landed:

- **Icons / cursors / bitmaps** (`LoadIcon`, `LoadCursor`,
  `LoadBitmap`, `LoadImage`) — REAL on both bitnesses. Off-screen
  surfaces (backlog item 12) supplied the sink: icon and bitmap
  decoders emit BGRA through `SYS_GDI_CREATE_COMPAT_BITMAP` +
  `SYS_GDI_SET_DIBITS`, and `SYS_GDI_CREATE_CURSOR_RGBA` (224) takes
  real image bits. `LoadBitmapA/W` (landed 2026-08-05) decodes
  RT_BITMAP packed DIBs via `duet_res_decode_bitmap`; the per-bpp
  DIB row unpack is shared with the icon decoder
  (`duet_res_decode_dib_row`). See
  [`Win32-Surface-Status.md`](../reference/Win32-Surface-Status.md#user32dll)
  for the per-export GAPs.
- **Accelerators** (`LoadAccelerators`, `TranslateAccelerator`) —
  REAL since 2026-07-29. The prerequisite KeyCode -> VK translation
  landed on the kernel side of the message post
  (`kernel/subsystems/win32/keycode_vk.h`), so `WM_KEYDOWN`'s
  `wParam` now carries Win32 VKs and `FVIRTKEY` entries compare
  correctly.

## Proof

- **Hosted:** `tests/host/test_pe_resources.cpp` — the three-level walk,
  named vs integer entries with the ASCII case fold, language fallback,
  the `(id/16)+1` bundling across two bundles, and eight malformed
  shapes that must fail closed. Two negative controls confirmed the
  malformed cases are not vacuous.
- **Live:** the `ring3-rsrc-pe` battery row boots `rsrc_pe.exe`, whose
  `.rsrc` is laid out by `windres` rather than by DuetOS, and reads four
  strings across three bundles plus a named and an integer `RT_RCDATA`
  through the normal IAT. Ten checks, all PASS on three consecutive
  boots.

## Measured effect

`tools/test/pe-compat-survey.py` over `C:\Windows\SysWOW64` (3121 32-bit
PEs, 341 of them `.exe`), before -> after this slice:

| export | binaries wanting it, unresolved |
|---|---|
| `user32!LoadStringW` | 282 -> 0  (82 -> 0 counting `.exe` only) |
| `kernel32!SizeofResource` | 263 -> 0 |
| `kernel32!LockResource` | 229 -> 0 |
| `kernel32!FindResourceExW` | 204 -> 0 |
| `kernel32!FindResourceW` | 128 -> 0 |
| `kernel32!FindResourceA` | 57 -> 0 |
| `kernel32!LoadStringA` | 43 -> 0 |
| `kernel32!FreeResource` | 43 -> 0 |

1128 of the 3121 32-bit PEs lost at least one unresolved import; mean
import coverage moved 46.65% -> 47.20%. Read that honestly: the survey
scores an export as present once it is *exported*, so the headline
movement is availability, not proof of correct behaviour — the
correctness claim rests on the hosted tests and the live fixture above.
Only one binary went from "some missing" to "zero missing"
(`getuname.dll`), because the long tail of 32-bit SysWOW64 binaries is
dominated by unrelated `api-ms-win-crt-*` demand.
