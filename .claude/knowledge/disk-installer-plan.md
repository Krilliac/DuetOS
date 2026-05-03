# Disk installer plan (P2 #16) — blocked on infrastructure

## Status (2026-05-03)

**Landed:** none. Plan only.

**2026-05-03 audit:** Re-confirmed each prerequisite still
absent — `git grep -nE 'GptWrite|GptInitDisk|Fat32Format'`
returns nothing. The 2026-05-03 batch did not touch this slice.
A relevant-but-tangential adjacency: `kernel/util/cpio.{h,cpp}`
(landed today) gives a future image-generator a clean way to
build initramfs payloads, but that's an installer-payload
helper, not a precondition.

**Deferred — strictly blocking:**
- GPT write surface (`kernel/fs/gpt.cpp` is probe-only; no
  `GptWrite`, no PMBR / header / entries-array / CRC32 emit
  path).
- FAT32 mkfs / format (`kernel/fs/fat32*.cpp` writes into
  existing volumes but cannot lay down a fresh BPB / FAT
  region / root-dir cluster on a blank partition).
- Bootloader installation source (the build produces
  `boot/uefi/BOOTX64.EFI` per the boot path doc, but there's
  no in-kernel "copy the running boot image to a fresh ESP"
  step yet).

**Resume prompt:**
> Pick up the disk-installer slice. Verify the GPT-write and
> FAT32-format prerequisites against
> `.claude/knowledge/disk-installer-plan.md`. Land the
> prerequisites first (GPT write probably first, FAT32
> format second), then the installer app per the plan
> below. Do NOT skip a prerequisite — partial implementations
> brick the target disk.

## Why an installer

Today DuetOS only boots from the build-host-built
`make-gpt-image.py` image. A user with a blank NVMe drive
cannot get DuetOS onto it without a foreign OS. An installer
app — analogous to the live-USB → install-to-disk step every
mainstream OS ships — closes the loop so the project is
self-hosting after first boot.

## Design

### 1. GPT write (kernel/fs/gpt.cpp extension)

New public surface:

- `bool GptInitDisk(u32 block_handle, const PartitionSpec* parts, u32 part_count)`
  — Lays down a fresh PMBR + primary header at LBA 1 +
  entries array at LBA 2..33 + every partition entry +
  backup header at LBA(N-1) + backup entries at LBA(N-33..N-2).
  CRC32 over header / entries computed via the existing
  `Crc32` helper.
- `bool GptWritePartition(u32 block_handle, u32 part_index, const PartitionSpec*)`
  — Update one partition entry in place + recompute CRC32.

`PartitionSpec` carries: type GUID (ESP / Microsoft basic
data / Linux filesystem), unique GUID (random), start LBA,
end LBA, name (UTF-16LE).

### 2. FAT32 mkfs (new kernel/fs/fat32_format.cpp)

`bool Fat32Format(u32 block_handle, u64 first_lba, u64 sector_count, const Fat32FormatOpts& opts)`

Writes:
- BPB at relative LBA 0 (mirrors what `make-gpt-image.py`
  builds today; in fact the Python builder is the design
  reference — the kernel needs the same byte layout).
- FSInfo at relative LBA 1.
- Backup boot sector at relative LBA 6.
- Two zeroed FAT regions, sized per spec.
- Root-directory cluster (cluster 2) seeded with just a
  volume-label entry — no `.` / `..` (root has no parent).

### 3. Bootloader install

`bool InstallerCopyBoot(u32 src_volume, u32 dest_volume)`

Read `boot/uefi/BOOTX64.EFI` from the source FAT32 (the
running boot volume) via `Fat32ReadFileStream`, plant it at
`/EFI/BOOT/BOOTX64.EFI` on the destination via
`Fat32CreateAtPath` + `Fat32MkdirAtPath` for the directory
tree. The kernel ELF + symbols + initrd come along the same
way: read from the running boot volume, write to the
destination.

### 4. Installer app (new kernel/apps/installer.{h,cpp})

A windowed app that:

1. Scans block devices via the existing `BlockDevice*`
   surface, filters out the running boot disk, presents a
   target-disk picker.
2. Confirms the destructive write with a typed confirmation
   ("type ERASE to continue").
3. Calls `GptInitDisk` with two partitions: a 256 MiB ESP
   (FAT32, type GUID
   `C12A7328-F81F-11D2-BA4B-00A0C93EC93B`) and a system
   partition filling the rest (FAT32 today, native FS once
   that lands).
4. Calls `Fat32Format` against both partitions.
5. Calls `InstallerCopyBoot` to plant the EFI loader + kernel.
6. Plants a minimal `/SESSION.CFG` so first boot lands in
   the same theme the user installed from.

## Verification ladder

Before landing any of the above on real disks:

1. **Self-test against a RAM-disk block device.** Add a
   `RamBlockDevice` test fixture. Run `GptInitDisk` +
   `Fat32Format` against it, then run `GptProbe` and
   `Fat32Probe` and assert they read back the structures
   correctly. This is the crucial round-trip — if the in-
   kernel writer produces something the in-kernel reader
   can't parse, the writer is wrong.
2. **QEMU image cross-check.** Build a fresh QEMU disk
   image with the kernel installer, boot from it, run the
   installer against a second QEMU disk. Power off, swap
   the disks in the QEMU command line, boot from the new
   disk. If it comes up, the installer works end-to-end.
3. **Real hardware last.** Only after #1 and #2 pass
   green, and only on a disk the user is genuinely willing
   to lose.

## Risk notes

- **Never run installer logic from the running boot
  volume's block device.** Any partial write to LBA 0..33
  on the running disk bricks the system.
- **CRC32 mistakes silently corrupt GPT.** The header and
  entries CRC are independent; a wrong header CRC makes
  Linux + Windows + UEFI all reject the disk. Mirror the
  reference `make-gpt-image.py` byte-for-byte during
  development, then diverge only deliberately.
- **The backup GPT MUST match the primary.** A header at
  LBA 1 with no matching backup at LBA(N-1) leaves the
  disk in "primary OK, backup invalid" state — most tools
  refuse to mount it.
- **FAT32 BPB has hand-laid magic numbers.** `OEM_NAME`,
  `BS_FilSysType` (the literal 8 bytes "FAT32   "),
  `BS_BootSig`, the PMBR jump instructions — all of this
  is in `make-gpt-image.py` and must port verbatim.

## Alternative: skip the installer, ship a flasher

A radically simpler path: instead of an in-kernel
installer, ship a host-side flasher script that takes a
pre-built `duetos.img` and writes it to a target disk via
`dd`. This is the pre-Anaconda Linux model. Pro: zero
kernel-side risk. Con: it's not "an OS that can install
itself" — every install requires a working host OS.

Decision deferred until the GPT-write + FAT32-format
prerequisites are in flight; if they prove larger than
expected, fall back to the host flasher and revisit the
in-kernel installer post-1.0.
