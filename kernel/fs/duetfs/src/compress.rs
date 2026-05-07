// LZ4 compression — v7. Pure-Rust block-format compress / decompress.
//
// Two surfaces:
//   - lz4_compress(src, dst): writes the compressed bytes into dst,
//     returns the byte count. Caller sizes dst at lz4 worst-case (a
//     few percent over src.len() — we use src.len() + 256 as a
//     conservative bound for any reasonable input). Returns 0 if
//     dst is too small.
//   - lz4_decompress(src, dst, expected_len): writes `expected_len`
//     decompressed bytes into dst. Returns true on success, false
//     on any inconsistency (truncated input, bad header, dst short).
//
// Storage shape: callers prepend a u32 little-endian "uncompressed
// size" header before the compressed payload — that's the
// "size-prefixed LZ4 frame" the standard LZ4 spec describes for
// streamed inputs. The Rust crate's `compress_prepend_size` /
// `decompress_size_prepended` operate on exactly this shape.

use alloc::vec::Vec;

/// Compress `src` and append a 4-byte little-endian uncompressed-
/// size header. On success writes the compressed-with-header bytes
/// into `dst` and returns the byte count; on `dst` short returns
/// 0 (the caller should resize and retry).
pub fn compress_prepend_size(src: &[u8], dst: &mut [u8]) -> usize
{
    let compressed = lz4_flex::block::compress_prepend_size(src);
    if compressed.len() > dst.len()
    {
        return 0;
    }
    dst[..compressed.len()].copy_from_slice(&compressed);
    compressed.len()
}

/// Decompress a `compress_prepend_size`-shaped buffer. Returns the
/// decompressed byte count or 0 on any error.
pub fn decompress_size_prepended(src: &[u8], dst: &mut [u8]) -> usize
{
    match lz4_flex::block::decompress_size_prepended(src)
    {
        Ok(decoded) => {
            if decoded.len() > dst.len()
            {
                return 0;
            }
            dst[..decoded.len()].copy_from_slice(&decoded);
            decoded.len()
        }
        Err(_) => 0,
    }
}

/// Worst-case upper bound on the size of `compress_prepend_size`'s
/// output for an input of `n` bytes. Equal to LZ4's
/// LZ4_compressBound(n) + 4 (the size header). Callers use this to
/// size the destination buffer.
pub fn compress_bound(n: usize) -> usize
{
    // Use the crate's own bound + 4 for the size prefix.
    lz4_flex::block::get_maximum_output_size(n) + 4
}

/// Single-shot compress that allocates a Vec sized to the worst
/// case. Intended for diagnostics / tests; production callers use
/// `compress_prepend_size` against a reusable kernel buffer.
#[allow(dead_code)]
pub fn compress_to_vec(src: &[u8]) -> Vec<u8>
{
    lz4_flex::block::compress_prepend_size(src)
}
