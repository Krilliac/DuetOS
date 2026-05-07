// CRC32 (IEEE 802.3 / zlib polynomial 0xEDB88320), no_std.
//
// Used by the v2 superblock to detect corruption between mounts —
// a clean shutdown writes a CRC over the SB; a torn write at boot
// detects as Invalid and fsck rebuilds. The polynomial / table
// match `kernel/util/crc32.h` so a host-side dump tool can verify
// images cross-language.
//
// Table-driven Sarwate algorithm. The 1 KiB lookup table lives in
// .rodata (static const), so this module adds nothing to .bss.

const POLY: u32 = 0xEDB88320;

const fn build_table() -> [u32; 256]
{
    let mut t = [0u32; 256];
    let mut i: u32 = 0;
    while i < 256
    {
        let mut c = i;
        let mut k = 0;
        while k < 8
        {
            if c & 1 != 0
            {
                c = (c >> 1) ^ POLY;
            }
            else
            {
                c >>= 1;
            }
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = build_table();

/// Compute the CRC32 of `bytes`. Initial value 0xFFFFFFFF, final
/// XOR 0xFFFFFFFF (matches zlib / IEEE 802.3 / kernel/util/crc32).
pub fn crc32(bytes: &[u8]) -> u32
{
    let mut c: u32 = 0xFFFFFFFF;
    for &b in bytes
    {
        let idx = (c ^ b as u32) & 0xFF;
        c = (c >> 8) ^ TABLE[idx as usize];
    }
    c ^ 0xFFFFFFFF
}
