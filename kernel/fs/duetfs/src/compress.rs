// LZ4 compression — v7. Pure-Rust block-format compress / decompress.
//
// Two surfaces:
//   - lz4_compress(src, dst): writes the compressed bytes into dst,
//     returns the byte count. The caller sizes dst with the checked
//     `compress_bound` result. Returns 0 if dst is too small.
//   - lz4_decompress(src, dst, expected_len): writes `expected_len`
//     decompressed bytes into dst. Returns true on success, false
//     on any inconsistency (truncated input, bad header, dst short).
//
// Storage shape: a DuetFS-local u32 little-endian uncompressed-size
// prefix followed by one raw LZ4 block. This is not the standardized
// LZ4 frame container; `compress_prepend_size` and
// `decompress_size_prepended` operate on this exact local shape.

/// Single-shot work cap. Larger payloads must be chunked by the C++
/// owner instead of monopolising one kernel entry or forcing a giant
/// temporary allocation. The on-disk size prefix is only u32, so the
/// cap is also comfortably below the format ceiling.
pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

/// Compress `src` and append a 4-byte little-endian uncompressed-
/// size header. On success writes the compressed-with-header bytes
/// into `dst` and returns the byte count; on `dst` short returns
/// 0 (the caller should resize and retry).
pub fn compress_prepend_size(src: &[u8], dst: &mut [u8]) -> usize {
    if src.len() > MAX_INPUT_BYTES || dst.len() < 4 {
        return 0;
    }
    let Ok(written) = lz4_flex::block::compress_into(src, &mut dst[4..]) else {
        return 0;
    };
    let Ok(source_len) = u32::try_from(src.len()) else {
        return 0;
    };
    dst[..4].copy_from_slice(&source_len.to_le_bytes());
    written.checked_add(4).unwrap_or(0)
}

/// Decompress a `compress_prepend_size`-shaped buffer. Returns the
/// decompressed byte count or 0 on any error.
pub fn decompress_size_prepended(src: &[u8], dst: &mut [u8]) -> usize {
    let Some(prefix) = src.get(..4) else {
        return 0;
    };
    let expected = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    if expected == 0 || expected > MAX_INPUT_BYTES || expected > dst.len() {
        return 0;
    }
    match lz4_flex::block::decompress_into(&src[4..], &mut dst[..expected]) {
        Ok(written) if written == expected => written,
        _ => 0,
    }
}

/// Worst-case upper bound on the size of `compress_prepend_size`'s
/// output for an input of `n` bytes. Equal to LZ4's
/// LZ4_compressBound(n) + 4 (the size header). Callers use this to
/// size the destination buffer.
pub fn compress_bound(n: usize) -> usize {
    if n > MAX_INPUT_BYTES {
        return 0;
    }
    // lz4_flex uses `20 + input_len * 110 / 100`; add the four-byte
    // DuetFS size prefix with checked arithmetic so a hostile native-
    // width length can never panic in an overflow-checked kernel build.
    n.checked_mul(110)
        .and_then(|scaled| scaled.checked_div(100))
        .and_then(|scaled| scaled.checked_add(24))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn allocation_free_round_trip() {
        let source = b"DuetFS bounded LZ4 ingress";
        let mut compressed = vec![0u8; compress_bound(source.len())];
        let compressed_len = compress_prepend_size(source, &mut compressed);
        assert!(compressed_len >= 4);

        let mut decoded = vec![0u8; source.len()];
        let decoded_len = decompress_size_prepended(&compressed[..compressed_len], &mut decoded);
        assert_eq!(decoded_len, source.len());
        assert_eq!(&decoded, source);
    }

    #[test]
    fn hostile_size_prefix_is_rejected_before_allocation() {
        let frame = u32::MAX.to_le_bytes();
        let mut decoded = [0u8; 32];
        assert_eq!(decompress_size_prepended(&frame, &mut decoded), 0);
    }

    #[test]
    fn bound_fails_closed_above_single_shot_cap() {
        assert_ne!(compress_bound(MAX_INPUT_BYTES), 0);
        assert_eq!(compress_bound(MAX_INPUT_BYTES + 1), 0);
        assert_eq!(compress_bound(usize::MAX), 0);
    }
}
