# GPT (GUID Partition Table)

> **Audience:** FS authors
>
> **Execution context:** Kernel — process context, called once per disk at probe
>
> **Maturity:** v0 — primary header + entries, CRC-validated

## Overview

`kernel/fs/gpt.{h,cpp}` parses GPT partition tables on storage devices
and hands each partition to the FS backend layer for FS-type
identification.

## Validation

1. **Protective MBR**: read sector 0, expect a single partition entry
   of type `0xEE` covering the disk.
2. **Primary GPT header**: read sector 1, validate signature
   (`EFI PART`), header CRC, header size, my-LBA == 1.
3. **Partition entry array**: read the entry array starting at the
   header's `partition_entry_lba`, validate the array CRC.
4. **Walk entries**: each non-zero `partition_type_guid` entry is a
   live partition. Yield `(start_lba, end_lba, type_guid, name)` to
   the FS-detect layer.

## CRC Validation

Both the header CRC and the entry-array CRC are validated. A mismatch
on either is hard-rejected; we do **not** fall through to the backup
header at the end of the disk in v0 (that path is straightforward to
add when a real workload demands recovery from primary corruption).

## Known Limits / GAPs

- **No backup header fallback.** Primary header is the source of
  truth.
- **Installer orchestration shipped** (see
  `kernel/fs/installer.{h,cpp}` +
  `kernel/shell/shell_storage.cpp::CmdInstall`). The
  `install <handle> INSTALL` shell command lays down a 3-partition
  layout (ESP, system, crash-dump) backed by `GptInitDisk`,
  formats ESP + system with `Fat32Format`, and mounts the result.
  Crash-dump partition uses `kDuetCrashDumpTypeGuid` so the
  panic-time NVMe / AHCI dump path discovers it via
  `GptFindCrashDumpRegion` next boot. **Bootloader-bytes copy**
  (writing real `BOOTX64.EFI` + `duetos-kernel.elf` into the
  freshly-formatted ESP) is the residual — see
  [`Daily-Driver-Readiness`](../reference/Daily-Driver-Readiness.md)
  Tier 0 for the path forward.

## Related Pages

- [VFS](VFS.md)
- [Storage (NVMe + AHCI)](../drivers/Storage.md)
- [FAT32](FAT32.md)
- [ext4](ext4.md)
