# GPT parser v0 — PMBR + primary header + entry array, CRC-validated

**Last updated:** 2026-04-21
**Type:** Observation
**Status:** Active

## Description

First on-disk layout parser in the kernel. `kernel/fs/gpt.cpp`
reads the Protective MBR, primary GPT header, and partition
entry array from any registered block device, validates the
magic + CRC32s, and caches the resulting partition list so the
next slice (FAT32 mount) can pick a partition by type GUID and
hand its sector range to a filesystem driver.

Completes **stage 4** of `.claude/knowledge/storage-and-filesystem-roadmap.md`.

## Context

Applies to:

- `kernel/fs/gpt.{h,cpp}` — the parser.
- `kernel/core/main.cpp` — `GptSelfTest` runs after `NvmeSelfTest`.
- `tools/qemu/run.sh` — now calls `make-gpt-image.py` instead of
  `dd` to prep a GPT-formatted 16 MiB scratch image.
- `tools/qemu/make-gpt-image.py` — builds a UEFI-spec GPT with
  one Linux-filesystem-type partition spanning LBA 2048..32734
  and the `"CUSTOMOS"` marker at the partition's first sector.

Does not apply to:

- Backup GPT at the last LBA. v0 reads only the primary. Disks
  with a corrupt primary fail the parse; that's intentional
  until a real workload cares about recovery.
- MBR-only disks. Non-GPT disks (including the ramtest0 block
  device) log "missing 0x55AA" and return false — not a panic,
  just a skip.
- Partition mutation. Read-only parse; no write-back CRC recompute.

## Details

### Parse sequence

1. Read LBA 0 via `drivers::storage::BlockDeviceRead`. Assert
   `0x55 0xAA` at offset 510 and at least one partition entry
   with type 0xEE (protective GPT).
2. Read LBA 1. Validate `signature == "EFI PART"`, `revision
   == 0x00010000`, `header_size` in [92, sector_size],
   `num_partition_entries == 128`, `partition_entry_size ==
   128`, `my_lba == 1`, and that `first_usable_lba` /
   `last_usable_lba` are in range. Recompute header CRC32 (IEEE)
   with the CRC field zeroed; compare.
3. Read the partition entry array (128 × 128 = 16 KiB, i.e.
   32 × 512-byte sectors) via a loop through the block layer's
   4 KiB-per-call cap. CRC32 the full array; compare against
   `partition_entries_crc32` in the header.
4. Walk entries; skip all-zero type GUIDs (unused). Cache each
   non-empty entry into the `Disk.partitions` array.

### CRC32 implementation

`Crc32` is IEEE 802.3 reflected with polynomial `0xEDB88320`,
matching Python's `zlib.crc32` and every mkfs tool. Table-driven
with a 1 KiB lazy-init `.rodata` table; 40-ish lines. If a
second subsystem wants CRC32, promote the helper out of
`(anonymous)` and share it.

### Buffers in .bss, not on the stack

Per-task kernel stacks are 16 KiB
(`kernel/sched/sched.cpp: kKernelStackBytes`), and the partition
entry array is 16 KiB on its own. A naive stack allocation of
the array + sector scratch corrupts the stack and triple-faults
into a trap storm — confirmed in-flight during bring-up. v0
keeps both buffers as `static` (`.bss`), which works because
`GptProbe` is single-threaded at boot. When a shell command
ever needs to re-probe on demand this becomes a per-call heap
allocation.

### GUID render format

`WriteGuid` emits the canonical mixed-endian form:

```
AABBCCDD-EEFF-GGHH-IIJJ-KKLLMMNNOOPP
```

Bytes 0..3 little-endian, 4..5 little-endian, 6..7 little-
endian, 8..9 big-endian, 10..15 big-endian — exactly what
`blkid` / `gdisk` print for the same partition. The partition
the scratch image seeds renders as `0fc63daf-8483-4772-8e79-
3d69d8477de4`, the Linux-filesystem-data type GUID.

### Observed boot output (QEMU q35 + `-device nvme`)

```
[fs/gpt] probing 0x2 block devices
[fs/gpt]  handle=0x0  name=ramtest0
[W] fs/gpt : LBA 0: missing 0x55AA boot signature
[fs/gpt]   -> not a GPT disk (or parse failed)
[fs/gpt]  handle=0x1  name=nvme0n1
[fs/gpt] disk handle=0x1 partitions=0x1
[fs/gpt]   part[0x0] first=0x800 last=0x7fde \
                    type=0fc63daf-8483-4772-8e79-3d69d8477de4
[fs/gpt]   -> GPT OK, disk_idx=0x0
```

## Notes

- **NvmeSelfTest was updated** from "LBA 0 must equal CUSTOMOS"
  to "LBA 0 must end in 0x55AA". LBA 0 on a GPT disk is the
  Protective MBR, so the old marker check would permanently
  fail against any GPT-formatted image. The GPT probe provides
  the full end-to-end assertion now.
- **Python for image prep.** The dev host doesn't ship
  `sfdisk` / `sgdisk`, but `python3` is stdlib-complete for
  `struct` + `zlib` + `uuid`. No extra install footprint.
- **No backup GPT in the image.** `make-gpt-image.py` skips
  writing the backup header + entries. When the parser grows a
  "primary corrupt, try backup" path, the image helper gains
  the backup write.
- **See also:**
  - `storage-and-filesystem-roadmap.md` — stage 5 (FAT32 in
    Rust) is next; this parser hands it `(block_handle,
    first_lba, last_lba)` tuples.
  - `nvme-driver-v0.md` — the driver whose LBA-0 read this
    builds on.
