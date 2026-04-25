# Deferred-task batch — 2026-04-25

**Last updated:** 2026-04-25
**Type:** Observation
**Status:** Active

## Description

Five small "deferred" gaps in the tree were closed in one session. Each was a real
gap that earlier slices punted on because nothing exercised it — none was a
hypothetical future need. All landed without new files, headers, or subsystems.

## Items

### 1. PE forwarder strings: ordinal form (`Dll.#N`)

`kernel/core/pe_loader.cpp::ParseForwarder` previously rejected `Dll.#N` and
returned false. Now `ParseForwarder` writes a `ParsedForwarder` struct
containing `is_ordinal`/`ordinal`/`func` and the resolver dispatches to a new
`TryResolveViaPreloadedDllsByOrdinalImpl` for the ordinal branch. Same depth
budget (`kMaxForwarderDepth = 4`) bounds chains that mix ordinal and name
forms.

### 2. Per-process forwarder chasing in GetProcAddress

`ProcessResolveDllExport` / `ProcessResolveDllExportByBase` returned 0 on
forwarder hits. Now they call the new public helper `PeResolveViaDlls`
(`pe_loader.h`) which walks the process's `dll_images` array and chases the
forwarder. `SYS_DLL_PROC_ADDRESS` therefore returns the correct VA for any
function whose export forwards into another DLL the process has loaded.

### 3. ext4 root-dir multi-block walk

`kernel/fs/ext4.cpp::WalkRootDir` previously read just the first physical
block of the first extent. It now iterates all leaf extents in the inline
extent header (up to `kInlineMaxLeafExtents = 4`) and each extent's
`len_blocks` contiguous blocks, accumulating directory entries into
`v.root_dir_entries[]` until the cap is hit or every block is parsed.
Depth>0 (intermediate index nodes) still bails — needs an extra block read
per index level and a small recursion budget. The log line now reports
`extents=N` and prints `partial` if any block read failed.

### 4. GDI: outline-on-bitmap for `Ellipse(memDC)`

`kernel/subsystems/win32/gdi_objects.cpp::DoGdiEllipse` (memDC tag) used to
fill the interior with the brush colour and skip the pen outline. New helper
`PaintEllipseOutlineOnBitmap` paints a 1-pixel ring matching the boundary of
`PaintFilledEllipseOnBitmap` (4-connected neighbour test on the same integer
ellipse equation, no sqrt). Called right after the fill.

### 5. GDI: filled-ellipse compositor primitive

`DoGdiEllipse` (window tag) used to record only the outline because the
compositor lacked a filled-ellipse prim. Added `WinGdiPrimKind::FilledEllipse`,
a `WindowClientFilledEllipse` recorder, and a dispatch case in
`drivers/video/widget.cpp` that scans the bounding box with the same integer
ellipse test (clipped against the window client rect). The window path now
records both `FilledEllipse` (interior, brush) and `Ellipse` (outline, pen),
matching the Win32 `Ellipse(hdc)` contract.

## Files touched

- `kernel/core/pe_loader.cpp` — `ParseForwarder` + ordinal-form resolver +
  public `PeResolveViaDlls` wrapper
- `kernel/core/pe_loader.h` — declares `PeResolveViaDlls`
- `kernel/core/process.cpp` — forwarder chasing in `ProcessResolveDllExport*`
- `kernel/fs/ext4.cpp` — multi-block / multi-extent root-dir walk
- `kernel/subsystems/win32/gdi_objects.cpp` — outline-on-bitmap + window-path
  filled-ellipse + outline
- `kernel/drivers/video/widget.cpp` / `.h` — `FilledEllipse` prim + recorder

## Build / verification

`cmake --build build/x86_64-debug --target duetos-kernel -j$(nproc)` clean.
No CI smoke yet on this host (qemu/grub-mkrescue not installed); all changes
guarded by existing call paths and validated by recompile.

## Patterns reusable

- **Bound forwarder recursion at the resolver, not the parser.** Adding ordinal
  support meant exposing a new branch from the same recursion point — the
  cycle bound stayed in one place.
- **Public anon-namespace re-export.** `PeResolveViaDlls` (in `duetos::core`
  outside the anon ns) calls a TU-private impl in the anon ns. Cheaper than
  moving the impl out, keeps the existing internal name stable.
- **Compositor prims pair with bitmap helpers.** When a GDI op exists on memDC
  bitmaps, the same op should exist as a recorded compositor prim — keep the
  two surfaces feature-parallel.

## Batch 2 — same session, additional gaps

### 6. RNDIS RX delivers all records per transfer

`kernel/drivers/usb/rndis.cpp::RxPollEntry` previously delivered only the
first `RNDIS_PACKET_MSG` per bulk-IN transfer. Now it walks the buffer by
each header's `msg_len`, delivers every record's data span to
`NetStackInjectRx`, and stops at the first malformed record so a runt
trailer can't desync the cursor. Ignored control-plane indications
(`RNDIS_INDICATE_STATUS_MSG`) still abort the walk for that transfer.

### 7. FAT32 LFN sequence validation

`kernel/fs/fat32.cpp::WalkDirChain` previously trusted any LFN ordinal
sequence without checking the per-fragment checksum. Now it captures the
checksum from the first fragment, requires every fragment in the sequence
to share it, and verifies the assembled checksum matches the `ComputeLfnChecksum`
of the trailing 11-byte SFN. On mismatch the walker falls back to the SFN
8.3 form — orphaned LFN runs (typical after a partial rename) no longer
clobber the displayed name with stale UTF-16 fragments.

### 8. PE by-ordinal import resolution

`kernel/core/pe_loader.cpp::ResolveImports` used to reject any IBN entry
with bit 63 set ("v0 only resolves by-name imports"). Now an ordinal
import is parsed off the IBN, a printable `#N` synthetic name is built
on the stack for log lines, and resolution dispatches to a new public
`TryResolveViaPreloadedDllsByOrdinal` wrapper. EAT-miss ordinal imports
fall through to the existing function-catch-all NO-OP stub path so PEs
with ordinal imports stop being hard-rejects.

## Files touched (batch 2)

- `kernel/drivers/usb/rndis.cpp` — multi-record RX walk
- `kernel/fs/fat32.cpp` — `ComputeLfnChecksum` + sequence check
- `kernel/core/pe_loader.cpp` — public `TryResolveViaPreloadedDllsByOrdinal`
  wrapper + ordinal-import branch in `ResolveImports`

## Batch 3 — same session

### 9. PE export name lookup: linear → binary search

`kernel/core/pe_exports.cpp::PeExportLookupName` was a linear scan with a
header note that "binary search is a one-file change when a hot loader path
demands it". With the IAT-resolver and per-process GetProcAddress now both
hitting the EAT for every import / GetProcAddress call, the loader path
counts. Upgraded to a binary search using a new `StrCmp3` 3-way compare;
the PE spec guarantees ENT is name-sorted in ASCII order. A bad name RVA
at the midpoint falls back to the original linear scan so a single
malformed slot can't mis-discard half a real DLL's exports.

## Files touched (batch 3)

- `kernel/core/pe_exports.cpp` — `StrCmp3` + binary-search rewrite of
  `PeExportLookupName`
- `kernel/core/pe_exports.h` — updated header note
