# PE base-relocation support v0 — walk + apply, zero-delta today

**Last updated:** 2026-04-21
**Type:** Observation
**Status:** Active

## Description

The v0 PE loader used to reject any image with a non-empty
`.reloc` directory, logged as `PeStatus::RelocsNonEmpty`. This
slice accepts such images, walks the relocation blocks, and
(when delta ≠ 0) patches each `IMAGE_REL_BASED_DIR64` entry by
`actual_base - preferred_base`. In v0 we always load at the
preferred ImageBase so the delta is zero and the inner apply
is a no-op — the walk still runs to validate the table shape.

## Context

Applies to:

- `kernel/core/pe_loader.cpp` — `ApplyRelocations` (new),
  `ParseHeaders` (relaxed), `PeLoad` (calls apply between
  section mapping and import resolution).
- `tools/build-hello-winapi.sh` — flipped from
  `/dynamicbase:no` to default `/dynamicbase` so the smoke
  harness exercises the walk on every boot.

Does **not** apply to:

- `hello.exe` (freestanding, built by `build-hello-pe.sh`)
  has no `.reloc` directory — `PeReport` logs
  `relocs: (empty)` and `ApplyRelocations` returns early.
- `windows-kill.exe` — its imports still fail to resolve at
  `MSVCP140.dll!?cout@std@@...` before reloc walking could
  affect it. The .reloc directory is reported but never
  walked in the current boot.

## Details

### What changed

1. **`ParseHeaders`** no longer returns `RelocsNonEmpty` when the
   Base Relocation directory is populated. The status enum
   keeps `RelocsNonEmpty` for a future ASLR slice that may
   reject on unsatisfiable delta constraints, but `ParseHeaders`
   no longer produces that status.

2. **New `ApplyRelocations(file, file_len, h, as, delta)`**
   walks the `.reloc` directory:
   - Each block is `{u32 PageRVA, u32 BlockSize, u16 entries[]}`.
   - Each 2-byte entry: top 4 bits = type, bottom 12 bits = offset.
   - Type 0 (`IMAGE_REL_BASED_ABSOLUTE`) — padding entry, skip.
   - Type 10 (`IMAGE_REL_BASED_DIR64`) — the only real type
     PE32+ images emit. When delta ≠ 0, load the u64 at
     `ImageBase + PageRVA + offset`, add delta, store back.
   - Any other type → log + reject (rejects half-loaded image
     cleanly by returning false from `PeLoad`).

3. **`PeLoad`** calls `ApplyRelocations` after `MapSection`
   and before `ResolveImports` with `delta = 0`. The walk
   catches a malformed `.reloc` directory before any user code
   runs; with delta = 0, no addresses change.

### Cross-page DIR64 writes

A DIR64 patch is 8 bytes at `ImageBase + PageRVA + offset`.
`offset` is 12-bit so can be up to 0xFFF. A patch starting at
offset 0xFFD would straddle the page boundary.

The apply loop handles this by doing per-byte frame lookups
rather than a single 8-byte store through one frame's direct
map. MSVC / lld-link align absolute addresses to 8 in practice
so this case rarely fires, but we handle it because the PE spec
permits it and a hostile image could craft one.

### Test fixture

`userland/apps/hello_winapi/hello.c` is the only PE in the smoke
harness that now carries a `.reloc` directory. Flipped from
`/dynamicbase:no` to default `/dynamicbase`:

Before: `relocs: (empty)` in `PeReport`; ImagerBase baked in
with no way to move the image.

After: `relocs: blocks=3 entries=0x4E dir_size=0xB4`; delta = 0
keeps the load behavior byte-identical while exercising the
validation path.

Boot log confirms the walk:

```
[pe-reloc] blocks=0x0000000000000003 applied=0x0000000000000000 delta=0x0000000000000000
```

### What's still out-of-scope

- **Actual image relocation** — requires an ASLR slice to
  compute `delta = actual_base - preferred_base` and pass a
  nonzero delta. The apply path is written + ready but has
  never been exercised with delta ≠ 0. When ASLR lands, add
  a test fixture that forces a non-preferred load (e.g., a
  second PE with the same preferred ImageBase as hello_winapi
  — second one must move).
- **Relocation types beyond DIR64** — `HIGHADJ`, `REL32` etc.
  exist in the PE spec but no PE32+ image this project would
  load uses them. Any non-DIR64 type rejects the image
  cleanly.
- **`IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` /
  `HIGH_ENTROPY_VA` honoring** — we ignore DllCharacteristics
  entirely in v0. Not a correctness gap for v0's in-tree
  PEs.

## Notes

- **Not an ASLR implementation.** This is the loader-side
  plumbing only. ASLR also needs a way to pick an actual base
  (per-process randomized VA), conflict detection when loading
  a DLL that can't fit at its preferred base, and a policy on
  high-entropy vs. low-entropy bases.
- **Regression canary:** any PE that previously parsed as `Ok`
  (no imports, no relocs, no TLS) should still parse as `Ok`
  after this slice — the only change to `ParseHeaders` is the
  reloc reject, and an Ok PE has no reloc directory to begin
  with. If hello.exe ever reports `RelocsNonEmpty`, the slice
  broke.
- **`[pe-reloc]` log line grep** catches whether the walk ran.
  On the smoke harness it should emit once per boot, with the
  block + entry counts from hello_winapi.exe.
- **See also:**
  - `pe-subsystem-v0.md` — the loader this plugs into.
  - `win32-subsystem-v0.md` — the import resolver that runs
    after reloc apply.
  - `rust-bringup-plan.md` — PE code stays C++ forever; this
    slice is a data point that confirms the lifecycle is
    reasoning-heavy rather than lifetime-heavy.
