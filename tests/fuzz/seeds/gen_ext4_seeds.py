#!/usr/bin/env python3
# DuetOS ext4 fuzz seed generator.
#
# WHAT  Emits a real, fully-valid ext4 image (via mkfs.ext4) as
#       the rich seed so fuzz_ext4 gets past the superblock magic
#       and exercises the group-descriptor / inode / extent-tree /
#       directory walkers on mutated input — the ext4 equivalent
#       of seeding fuzz_pe with the shipped windows-kill.exe.
#       Falls back to a hand-built superblock-only image when
#       mkfs.ext4 is unavailable, so the generator stays
#       self-contained on a bare dev host (that seed still covers
#       the superblock parse + group-desc read).
#
# USAGE  python3 gen_ext4_seeds.py <out_dir>

import os
import shutil
import struct
import subprocess
import sys
import tempfile

EXT4_MAGIC = 0xEF53
SB_OFFSET = 1024


def mkfs_image():
    mkfs = shutil.which("mkfs.ext4") or "/usr/sbin/mkfs.ext4"
    if not os.path.exists(mkfs):
        return None
    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
        path = tf.name
        tf.truncate(512 * 1024)  # 512 KiB — smallest mke2fs is happy with
    try:
        subprocess.run(
            [mkfs, "-q", "-F", "-b", "1024", "-O", "^has_journal", path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(path, "rb") as fh:
            data = fh.read()
        return data
    except (subprocess.CalledProcessError, OSError):
        return None
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def minimal_superblock():
    # Just enough for the Rust parse_superblock to return ok: magic
    # + non-zero blocks/inodes-per-group + sane log_block_size +
    # inode_size <= block_size. Reaches the superblock parse only;
    # the mkfs image is what reaches the deep walkers.
    img = bytearray(SB_OFFSET + 1024 + 512)
    sb = SB_OFFSET
    struct.pack_into("<I", img, sb + 0x00, 64)        # inodes_count
    struct.pack_into("<I", img, sb + 0x04, 512)       # blocks_count_lo
    struct.pack_into("<I", img, sb + 0x14, 1)         # first_data_block
    struct.pack_into("<I", img, sb + 0x18, 0)         # log_block_size -> 1024
    struct.pack_into("<I", img, sb + 0x20, 256)       # blocks_per_group
    struct.pack_into("<I", img, sb + 0x28, 32)        # inodes_per_group
    struct.pack_into("<H", img, sb + 0x38, EXT4_MAGIC)  # s_magic
    struct.pack_into("<I", img, sb + 0x4C, 1)         # rev_level
    struct.pack_into("<H", img, sb + 0x58, 128)       # inode_size
    return bytes(img)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/ext4"
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "min_sb.ext4"), "wb") as fh:
        fh.write(minimal_superblock())
    real = mkfs_image()
    if real is not None:
        with open(os.path.join(out, "mkfs.ext4"), "wb") as fh:
            fh.write(real)
    print(f"seeded {out}: {len(os.listdir(out))} files "
          f"({'mkfs+min' if real is not None else 'min only — mkfs.ext4 absent'})")


if __name__ == "__main__":
    main()
