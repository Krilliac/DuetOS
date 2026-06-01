#include "web/jpeg.h"

/*
 * DuetOS — baseline-JPEG decoder implementation (clean room, ITU-T
 * T.81). See web/jpeg.h for the supported surface and the GAP list.
 *
 * Everything here is integer-only. The kernel compiles with
 * -mno-sse -mno-80387, so no float/double may appear on any code
 * path. The inverse DCT is the integer AAN (Arai-Agui-Nakajima)
 * variant with fixed-point constants, and the YCbCr->RGB convert
 * uses fixed-point coefficients with rounding — both standard
 * 32-bit-integer formulations.
 */

namespace duetos::web
{

namespace
{

// ---------------------------------------------------------------------------
// Zig-zag scan order: maps the k-th coefficient in the entropy
// stream to its (row,col) position in the natural 8x8 block.
constexpr u8 kZigZag[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,  12, 19, 26, 33, 40, 48,
    41, 34, 27, 20, 13, 6,  7,  14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23,
    30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
};

// Clamp an integer to a u8 [0,255].
inline u8 Clamp8(i32 v)
{
    if (v < 0)
        return 0;
    if (v > 255)
        return 255;
    return static_cast<u8>(v);
}

// ---------------------------------------------------------------------------
// A canonical Huffman table built from a DHT segment. `bits[i]` is
// the count of codes of length (i+1) for i in [0,15]; `values` are
// the symbols in code order. We build a fast direct-lookup table
// for codes up to 9 bits plus a slow path for longer codes.
struct HuffTable
{
    bool present = false;
    // Slow path: per-length first code + value index.
    u16 maxcode[18] = {}; // maxcode[l] = largest code of length l (+1 sentinel via 0xFFFF)
    u16 mincode[18] = {};
    u16 valptr[18] = {};
    u8 values[256] = {};
    u32 count = 0;

    // Fast 9-bit lookup: for each 9-bit prefix, the symbol and the
    // real code length (0 = not a complete code here, use slow path).
    u8 fastSym[512] = {};
    u8 fastLen[512] = {};
};

// Build the canonical code tables from a DHT bits/values list.
// Returns false on a malformed (over-full) table.
bool BuildHuff(HuffTable& t, const u8 bits[16], const u8* vals, u32 nvals)
{
    t.present = true;
    t.count = nvals;
    for (u32 i = 0; i < nvals && i < 256; ++i)
        t.values[i] = vals[i];

    // Assign codes (canonical, per Annex C / F of T.81).
    u16 code = 0;
    u32 k = 0;
    u16 huffcode[256] = {};
    u8 huffsize[256] = {};
    for (u32 l = 0; l < 16; ++l)
    {
        for (u32 i = 0; i < bits[l]; ++i)
        {
            if (k >= 256)
                return false;
            huffsize[k] = static_cast<u8>(l + 1);
            ++k;
        }
    }
    if (k != nvals)
        return false;

    u32 idx = 0;
    u8 si = huffsize[0];
    while (idx < k)
    {
        while (idx < k && huffsize[idx] == si)
        {
            huffcode[idx] = code;
            ++code;
            ++idx;
        }
        // Code must not overflow the bit length.
        if (idx < k)
        {
            // shift to the next, larger length
            do
            {
                code <<= 1;
                ++si;
            } while (idx < k && huffsize[idx] != si);
        }
    }

    // Build mincode/maxcode/valptr per code length (1..16).
    u32 p = 0;
    for (u32 l = 1; l <= 16; ++l)
    {
        if (bits[l - 1] != 0)
        {
            t.valptr[l] = static_cast<u16>(p);
            t.mincode[l] = huffcode[p];
            p += bits[l - 1];
            t.maxcode[l] = huffcode[p - 1];
        }
        else
        {
            t.maxcode[l] = 0xFFFF; // no code of this length
        }
    }
    t.maxcode[17] = 0xFFFF;

    // Build the fast 9-bit lookup. For every complete code of length
    // <= 9, fill all 512-entry prefixes that begin with that code.
    for (u32 i = 0; i < 512; ++i)
        t.fastLen[i] = 0;
    p = 0;
    for (u32 l = 1; l <= 9; ++l)
    {
        for (u32 i = 0; i < bits[l - 1]; ++i)
        {
            const u16 c = huffcode[p];
            const u32 shift = 9 - l;
            const u32 lo = static_cast<u32>(c) << shift;
            const u32 hi = lo + (1u << shift);
            for (u32 e = lo; e < hi && e < 512; ++e)
            {
                t.fastSym[e] = t.values[p];
                t.fastLen[e] = static_cast<u8>(l);
            }
            ++p;
        }
    }
    // Advance p past the long codes so the slow path's valptr stays valid.
    return true;
}

} // namespace

namespace
{

// ---------------------------------------------------------------------------
// Entropy bit reader over the scan data. Reads MSB-first. Handles
// the 0xFF 0x00 byte-stuffing (a 0xFF in the entropy stream is
// followed by a 0x00 stuffing byte) and stops at any marker
// (0xFF followed by non-zero), reporting it so the MCU loop can
// react to RSTn / EOI. Past the end of input it saturates to zero
// bits, which the decoder treats as a clean truncation.
struct BitReader
{
    const u8* data = nullptr;
    u32 len = 0;
    u32 pos = 0;    // next byte to consume
    u32 bitBuf = 0; // MSB-aligned bit accumulator
    u32 bitCnt = 0; // number of valid bits in bitBuf (top)
    bool hitMarker = false;
    u8 marker = 0; // the marker byte seen (0 if none)
    bool overran = false;

    void Reset(const u8* d, u32 l, u32 p)
    {
        data = d;
        len = l;
        pos = p;
        bitBuf = 0;
        bitCnt = 0;
        hitMarker = false;
        marker = 0;
        overran = false;
    }

    // Pull the next entropy byte, honouring 0xFF stuffing and marker
    // detection. Returns the byte, or 0 with hitMarker set when a
    // marker (or end of data) is reached.
    u8 NextByte()
    {
        if (pos >= len)
        {
            overran = true;
            hitMarker = true;
            return 0;
        }
        u8 b = data[pos++];
        if (b == 0xFF)
        {
            // Skip fill bytes (0xFF 0xFF ...), then look at the next.
            u8 m = 0xFF;
            while (pos < len && (m = data[pos]) == 0xFF)
                ++pos;
            if (pos >= len)
            {
                overran = true;
                hitMarker = true;
                return 0;
            }
            if (m == 0x00)
            {
                ++pos; // consume the stuffing byte; literal 0xFF
                return 0xFF;
            }
            // A real marker — do not consume it; the MCU loop reads it.
            hitMarker = true;
            marker = m;
            return 0;
        }
        return b;
    }

    // Ensure at least `n` (<=24) bits are buffered.
    void Fill(u32 n)
    {
        while (bitCnt < n)
        {
            if (hitMarker)
            {
                // Feed zero bits past a marker / EOF.
                bitBuf |= 0u; // no-op; zeros shift in below
                bitCnt += 8;
                continue;
            }
            const u8 b = NextByte();
            bitBuf |= static_cast<u32>(b) << (24 - bitCnt);
            bitCnt += 8;
        }
    }

    // Peek the top `n` bits without consuming.
    u32 Peek(u32 n)
    {
        Fill(n);
        return (bitBuf >> (32 - n)) & ((n == 0) ? 0u : (0xFFFFFFFFu >> (32 - n)));
    }

    // Consume `n` bits.
    void Drop(u32 n)
    {
        bitBuf <<= n;
        bitCnt -= n;
    }

    // Read `n` bits as an unsigned value.
    u32 GetBits(u32 n)
    {
        if (n == 0)
            return 0;
        const u32 v = Peek(n);
        Drop(n);
        return v;
    }

    // After a marker is hit, the caller resets to byte-aligned and
    // resumes past the marker.
    void RestartAt(u32 newPos)
    {
        pos = newPos;
        bitBuf = 0;
        bitCnt = 0;
        hitMarker = false;
        marker = 0;
    }
};

// Decode one Huffman symbol. Returns 0xFFFF on a stream that runs
// out of valid codes (caller treats it as truncation).
u16 HuffDecode(BitReader& br, const HuffTable& t)
{
    const u32 look = br.Peek(9);
    const u8 fl = t.fastLen[look];
    if (fl != 0)
    {
        br.Drop(fl);
        return t.fastSym[look];
    }
    // Slow path: codes 10..16 bits.
    u32 code = look; // 9 bits so far
    u32 l = 9;
    br.Drop(9);
    while (l < 16)
    {
        code = (code << 1) | br.GetBits(1);
        ++l;
        if (t.maxcode[l] != 0xFFFF && code <= t.maxcode[l] && code >= t.mincode[l])
        {
            const u32 vi = t.valptr[l] + (code - t.mincode[l]);
            if (vi >= 256)
                return 0xFFFF;
            return t.values[vi];
        }
    }
    return 0xFFFF; // malformed
}

// Extend a value of magnitude category `s` read as `bits` per
// T.81 figure F.12 (sign-extension of a JPEG difference value).
inline i32 Extend(u32 bits, u32 s)
{
    if (s == 0)
        return 0;
    const i32 vt = 1 << (s - 1);
    if (static_cast<i32>(bits) < vt)
        return static_cast<i32>(bits) - (1 << s) + 1;
    return static_cast<i32>(bits);
}

// ---------------------------------------------------------------------------
// Integer inverse DCT (AAN-style separable, fixed-point). Input is
// the 64 dequantised coefficients in natural order; output is the
// 8x8 spatial block (before the +128 level shift) written into
// `out` (row-major, stride 8). All arithmetic is i32 with fixed
// 13-bit fractional constants — no floating point.
//
// This is the well-known "stbi" / jidctint integer IDCT: a 1-D
// pass over the columns, then a 1-D pass over the rows, with the
// standard rotation constants scaled by 4096 (12 bits).
constexpr i32 kFix_0_298631336 = 2446;
constexpr i32 kFix_0_390180644 = 3196;
constexpr i32 kFix_0_541196100 = 4433;
constexpr i32 kFix_0_765366865 = 6270;
constexpr i32 kFix_0_899976223 = 7373;
constexpr i32 kFix_1_175875602 = 9633;
constexpr i32 kFix_1_501321110 = 12299;
constexpr i32 kFix_1_847759065 = 15137;
constexpr i32 kFix_1_961570560 = 16069;
constexpr i32 kFix_2_053119869 = 16819;
constexpr i32 kFix_2_562915447 = 20995;
constexpr i32 kFix_3_072711026 = 25172;

inline i32 Descale(i32 x, i32 n)
{
    return (x + (1 << (n - 1))) >> n;
}

void IDCT8x8(const i32* coeff, u8* out, u32 stride)
{
    i32 tmp[64];

    // Column pass.
    for (u32 c = 0; c < 8; ++c)
    {
        const i32* s = coeff + c;
        // Shortcut: if all AC terms in this column are zero, the
        // output column is a constant (DC term only).
        if (s[8] == 0 && s[16] == 0 && s[24] == 0 && s[32] == 0 && s[40] == 0 && s[48] == 0 && s[56] == 0)
        {
            const i32 dc = s[0] << 2;
            for (u32 r = 0; r < 8; ++r)
                tmp[r * 8 + c] = dc;
            continue;
        }

        i32 z2 = s[16], z3 = s[48];
        i32 z1 = (z2 + z3) * kFix_0_541196100;
        i32 t2 = z1 + z3 * (-kFix_1_847759065);
        i32 t3 = z1 + z2 * kFix_0_765366865;
        i32 t0 = (s[0] + s[32]) << 13;
        i32 t1 = (s[0] - s[32]) << 13;
        const i32 x0 = t0 + t3;
        const i32 x3 = t0 - t3;
        const i32 x1 = t1 + t2;
        const i32 x2 = t1 - t2;

        i32 a0 = s[56], a1 = s[40], a2 = s[24], a3 = s[8];
        z1 = a0 + a3;
        z2 = a1 + a2;
        z3 = a0 + a2;
        i32 z4 = a1 + a3;
        i32 z5 = (z3 + z4) * kFix_1_175875602;

        a0 *= kFix_0_298631336;
        a1 *= kFix_2_053119869;
        a2 *= kFix_3_072711026;
        a3 *= kFix_1_501321110;
        z1 *= -kFix_0_899976223;
        z2 *= -kFix_2_562915447;
        z3 *= -kFix_1_961570560;
        z4 *= -kFix_0_390180644;
        z3 += z5;
        z4 += z5;
        a0 += z1 + z3;
        a1 += z2 + z4;
        a2 += z2 + z3;
        a3 += z1 + z4;

        tmp[0 * 8 + c] = Descale(x0 + a3, 11);
        tmp[7 * 8 + c] = Descale(x0 - a3, 11);
        tmp[1 * 8 + c] = Descale(x1 + a2, 11);
        tmp[6 * 8 + c] = Descale(x1 - a2, 11);
        tmp[2 * 8 + c] = Descale(x2 + a1, 11);
        tmp[5 * 8 + c] = Descale(x2 - a1, 11);
        tmp[3 * 8 + c] = Descale(x3 + a0, 11);
        tmp[4 * 8 + c] = Descale(x3 - a0, 11);
    }

    // Row pass + level shift + clamp.
    for (u32 r = 0; r < 8; ++r)
    {
        const i32* s = tmp + r * 8;
        i32 z2 = s[2], z3 = s[6];
        i32 z1 = (z2 + z3) * kFix_0_541196100;
        i32 t2 = z1 + z3 * (-kFix_1_847759065);
        i32 t3 = z1 + z2 * kFix_0_765366865;
        i32 t0 = (s[0] + s[4]) << 13;
        i32 t1 = (s[0] - s[4]) << 13;
        const i32 x0 = t0 + t3;
        const i32 x3 = t0 - t3;
        const i32 x1 = t1 + t2;
        const i32 x2 = t1 - t2;

        i32 a0 = s[7], a1 = s[5], a2 = s[3], a3 = s[1];
        z1 = a0 + a3;
        z2 = a1 + a2;
        z3 = a0 + a2;
        i32 z4 = a1 + a3;
        i32 z5 = (z3 + z4) * kFix_1_175875602;

        a0 *= kFix_0_298631336;
        a1 *= kFix_2_053119869;
        a2 *= kFix_3_072711026;
        a3 *= kFix_1_501321110;
        z1 *= -kFix_0_899976223;
        z2 *= -kFix_2_562915447;
        z3 *= -kFix_1_961570560;
        z4 *= -kFix_0_390180644;
        z3 += z5;
        z4 += z5;
        a0 += z1 + z3;
        a1 += z2 + z4;
        a2 += z2 + z3;
        a3 += z1 + z4;

        u8* o = out + r * stride;
        o[0] = Clamp8(Descale(x0 + a3, 18) + 128);
        o[7] = Clamp8(Descale(x0 - a3, 18) + 128);
        o[1] = Clamp8(Descale(x1 + a2, 18) + 128);
        o[6] = Clamp8(Descale(x1 - a2, 18) + 128);
        o[2] = Clamp8(Descale(x2 + a1, 18) + 128);
        o[5] = Clamp8(Descale(x2 - a1, 18) + 128);
        o[3] = Clamp8(Descale(x3 + a0, 18) + 128);
        o[4] = Clamp8(Descale(x3 - a0, 18) + 128);
    }
}

} // namespace

namespace
{

// Read a big-endian 16-bit value at `p` (caller bounds-checks).
inline u32 Rd16(const u8* p)
{
    return (static_cast<u32>(p[0]) << 8) | p[1];
}

// Per-component info from the SOF0 frame header.
struct Component
{
    u8 id = 0;
    u8 hSamp = 1; // horizontal sampling factor
    u8 vSamp = 1; // vertical sampling factor
    u8 quantSel = 0;
    u8 dcTable = 0;
    u8 acTable = 0;
    i32 dcPred = 0; // running DC predictor across the scan

    // Per-component plane: width/height rounded up to its block grid.
    u32 planeW = 0;
    u32 planeH = 0;
    u8* plane = nullptr; // planeW * planeH samples
};

struct Decoder
{
    const u8* data = nullptr;
    u32 len = 0;
    PngArena* arena = nullptr;

    u32 width = 0;
    u32 height = 0;
    u32 numComp = 0;
    Component comp[4];

    u16 quant[4][64] = {}; // dequant tables, natural order
    bool quantPresent[4] = {};

    HuffTable huffDC[4];
    HuffTable huffAC[4];

    u32 restartInterval = 0;

    u32 maxH = 1;
    u32 maxV = 1;
    u32 mcuW = 0;
    u32 mcuH = 0;
    u32 mcusX = 0;
    u32 mcusY = 0;
};

// Decode a single 8x8 block for component `ci` into its plane at
// pixel (bx*8, by*8). Returns false on a corrupt code.
bool DecodeBlock(Decoder& d, BitReader& br, Component& c, u32 px, u32 py)
{
    i32 coeff[64] = {};

    const HuffTable& dc = d.huffDC[c.dcTable];
    const HuffTable& ac = d.huffAC[c.acTable];
    if (!dc.present || !ac.present)
        return false;
    const u16* q = d.quant[c.quantSel];

    // DC coefficient: differential.
    const u16 s = HuffDecode(br, dc);
    if (s == 0xFFFF || s > 15)
        return false;
    const i32 diff = Extend(br.GetBits(s), s);
    c.dcPred += diff;
    coeff[0] = c.dcPred * static_cast<i32>(q[0]);

    // AC coefficients: run/length.
    u32 k = 1;
    while (k < 64)
    {
        const u16 rs = HuffDecode(br, ac);
        if (rs == 0xFFFF)
            return false;
        const u32 run = rs >> 4;
        const u32 size = rs & 0x0F;
        if (size == 0)
        {
            if (run == 15)
            {
                k += 16; // ZRL — sixteen zeros
                continue;
            }
            break; // EOB
        }
        k += run;
        if (k >= 64)
            break;
        const i32 val = Extend(br.GetBits(size), size);
        const u8 zz = kZigZag[k];
        coeff[zz] = val * static_cast<i32>(q[zz]);
        ++k;
    }

    // Inverse DCT into the component plane.
    u8* dst = c.plane + py * c.planeW + px;
    IDCT8x8(coeff, dst, c.planeW);
    return true;
}

} // namespace

namespace
{

// Parse markers up to and including SOF0/SOS, filling `d`. Returns
// the offset of the entropy-coded data (just past SOS) on success,
// or 0 on any malformed / unsupported input. Sets `unsupported` if
// the rejection is specifically a non-baseline frame.
u32 ParseHeaders(Decoder& d, bool& unsupported)
{
    unsupported = false;
    const u8* p = d.data;
    const u32 n = d.len;
    if (n < 2 || p[0] != 0xFF || p[1] != 0xD8) // SOI
        return 0;
    u32 off = 2;

    while (off + 4 <= n)
    {
        if (p[off] != 0xFF)
            return 0;
        // Skip any fill 0xFF bytes.
        while (off < n && p[off] == 0xFF)
            ++off;
        if (off >= n)
            return 0;
        const u8 m = p[off++];

        if (m == 0xD9) // EOI before SOS — malformed
            return 0;
        if (m >= 0xD0 && m <= 0xD7) // stray RSTn in header
            continue;

        if (off + 2 > n)
            return 0;
        const u32 seg = Rd16(p + off);
        if (seg < 2 || off + seg > n)
            return 0;
        const u8* body = p + off + 2;
        const u32 bodyLen = seg - 2;

        if (m == 0xC0) // SOF0 — baseline
        {
            if (bodyLen < 6)
                return 0;
            const u8 prec = body[0];
            d.height = Rd16(body + 1);
            d.width = Rd16(body + 3);
            d.numComp = body[5];
            if (prec != 8)
            {
                unsupported = true;
                return 0;
            }
            if (d.width == 0 || d.height == 0 || d.width > kJpegMaxDimension || d.height > kJpegMaxDimension)
                return 0;
            if (d.numComp != 1 && d.numComp != 3)
            {
                unsupported = true;
                return 0;
            }
            if (bodyLen < 6u + d.numComp * 3u)
                return 0;
            for (u32 i = 0; i < d.numComp; ++i)
            {
                const u8* cp = body + 6 + i * 3;
                d.comp[i].id = cp[0];
                d.comp[i].hSamp = cp[1] >> 4;
                d.comp[i].vSamp = cp[1] & 0x0F;
                d.comp[i].quantSel = cp[2];
                if (d.comp[i].hSamp < 1 || d.comp[i].hSamp > 2 || d.comp[i].vSamp < 1 || d.comp[i].vSamp > 2)
                {
                    unsupported = true;
                    return 0;
                }
                if (d.comp[i].quantSel > 3)
                    return 0;
            }
        }
        else if (m == 0xC1 || m == 0xC2 || m == 0xC3 || (m >= 0xC5 && m <= 0xCF && m != 0xC8))
        {
            // SOF1 (extended), SOF2 (progressive), SOF3 (lossless),
            // SOF5..7 (differential), SOF9..15 (arithmetic) — all
            // unsupported. 0xC4 is DHT, 0xC8 is JPGn (reserved).
            unsupported = true;
            return 0;
        }
        else if (m == 0xDB) // DQT
        {
            u32 q = 0;
            while (q < bodyLen)
            {
                const u8 pq = body[q] >> 4;   // precision: 0 = 8-bit, 1 = 16-bit
                const u8 tq = body[q] & 0x0F; // table id
                ++q;
                if (tq > 3)
                    return 0;
                const u32 need = (pq ? 128u : 64u);
                if (q + need > bodyLen)
                    return 0;
                for (u32 k = 0; k < 64; ++k)
                {
                    u16 v;
                    if (pq)
                    {
                        v = static_cast<u16>(Rd16(body + q));
                        q += 2;
                    }
                    else
                    {
                        v = body[q];
                        ++q;
                    }
                    d.quant[tq][kZigZag[k]] = v;
                }
                d.quantPresent[tq] = true;
            }
        }
        else if (m == 0xC4) // DHT
        {
            u32 q = 0;
            while (q < bodyLen)
            {
                if (q + 17 > bodyLen)
                    return 0;
                const u8 tc = body[q] >> 4;   // 0 = DC, 1 = AC
                const u8 th = body[q] & 0x0F; // table id
                ++q;
                if (tc > 1 || th > 3)
                    return 0;
                u8 bits[16];
                u32 total = 0;
                for (u32 i = 0; i < 16; ++i)
                {
                    bits[i] = body[q + i];
                    total += bits[i];
                }
                q += 16;
                if (total > 256 || q + total > bodyLen)
                    return 0;
                HuffTable& t = (tc == 0) ? d.huffDC[th] : d.huffAC[th];
                if (!BuildHuff(t, bits, body + q, total))
                    return 0;
                q += total;
            }
        }
        else if (m == 0xDD) // DRI
        {
            if (bodyLen < 2)
                return 0;
            d.restartInterval = Rd16(body);
        }
        else if (m == 0xDA) // SOS
        {
            if (bodyLen < 1)
                return 0;
            const u8 ns = body[0];
            if (ns != d.numComp || bodyLen < 1u + ns * 2u + 3u)
                return 0;
            for (u32 i = 0; i < ns; ++i)
            {
                const u8 cs = body[1 + i * 2];
                const u8 td = body[2 + i * 2] >> 4;
                const u8 ta = body[2 + i * 2] & 0x0F;
                if (td > 3 || ta > 3)
                    return 0;
                // Match scan component to a frame component by id.
                u32 ci = d.numComp;
                for (u32 j = 0; j < d.numComp; ++j)
                    if (d.comp[j].id == cs)
                        ci = j;
                if (ci == d.numComp)
                    return 0;
                d.comp[ci].dcTable = td;
                d.comp[ci].acTable = ta;
            }
            return off + 2 + bodyLen; // start of entropy data
        }
        // APPn (0xE0..0xEF), COM (0xFE), and anything else: skip body.
        off += seg;
    }
    return 0;
}

} // namespace

namespace
{

// Fixed-point YCbCr -> RGB (JFIF full-range), 16-bit fractional.
//   R = Y + 1.402   * (Cr-128)
//   G = Y - 0.34414 * (Cb-128) - 0.71414 * (Cr-128)
//   B = Y + 1.772   * (Cb-128)
inline void YCbCrToRgb(i32 y, i32 cb, i32 cr, u8* out)
{
    cb -= 128;
    cr -= 128;
    const i32 r = y + ((91881 * cr) >> 16);
    const i32 g = y - ((22554 * cb + 46802 * cr) >> 16);
    const i32 b = y + ((116130 * cb) >> 16);
    out[0] = Clamp8(r);
    out[1] = Clamp8(g);
    out[2] = Clamp8(b);
    out[3] = 255;
}

// Run the interleaved baseline scan: decode every MCU's blocks into
// the per-component planes. Returns false on a corrupt stream.
bool DecodeScan(Decoder& d, u32 scanStart)
{
    BitReader br;
    br.Reset(d.data, d.len, scanStart);

    const u32 restart = d.restartInterval;
    u32 sinceRestart = 0;

    for (u32 my = 0; my < d.mcusY; ++my)
    {
        for (u32 mx = 0; mx < d.mcusX; ++mx)
        {
            for (u32 ci = 0; ci < d.numComp; ++ci)
            {
                Component& c = d.comp[ci];
                for (u32 by = 0; by < c.vSamp; ++by)
                {
                    for (u32 bx = 0; bx < c.hSamp; ++bx)
                    {
                        const u32 px = (mx * c.hSamp + bx) * 8;
                        const u32 py = (my * c.vSamp + by) * 8;
                        if (!DecodeBlock(d, br, c, px, py))
                            return false;
                    }
                }
            }

            // Restart-interval handling. After every `restart` MCUs
            // the encoder emits an RSTn (0xFF 0xD0..0xD7) marker, the
            // entropy stream is byte-aligned, and the DC predictors
            // reset. Our bit reader stops at the marker (hitMarker)
            // with `pos` pointing at the marker-code byte; scan
            // forward from there for the next RSTn and resume past it.
            if (restart != 0)
            {
                ++sinceRestart;
                const bool lastMcu = (my == d.mcusY - 1) && (mx == d.mcusX - 1);
                if (sinceRestart == restart && !lastMcu)
                {
                    sinceRestart = 0;
                    u32 q = br.pos;
                    bool found = false;
                    while (q + 1 < d.len)
                    {
                        // br.pos may already sit on the marker code
                        // byte (no preceding 0xFF in `data[q]`), so
                        // accept either "0xFF Dn" or a bare "Dn"
                        // immediately after a 0xFF we already passed.
                        const u8 b0 = d.data[q];
                        if (b0 == 0xFF)
                        {
                            const u8 mk = d.data[q + 1];
                            if (mk >= 0xD0 && mk <= 0xD7)
                            {
                                q += 2;
                                found = true;
                                break;
                            }
                            if (mk == 0x00 || mk == 0xFF)
                            {
                                ++q; // stuffing / fill — keep scanning
                                continue;
                            }
                            return false; // other marker mid-scan: corrupt
                        }
                        if (b0 >= 0xD0 && b0 <= 0xD7)
                        {
                            q += 1; // bare RSTn we stopped on
                            found = true;
                            break;
                        }
                        ++q;
                    }
                    if (!found)
                        return false;
                    br.RestartAt(q);
                    for (u32 rci = 0; rci < d.numComp; ++rci)
                        d.comp[rci].dcPred = 0;
                }
            }
        }
    }

    // A well-formed baseline scan ends on the EOI marker, never by
    // running off the end of the buffer. If the bit reader had to
    // fabricate zero bits past the real data, the stream was
    // truncated — reject rather than return a partially-garbage
    // image. (A clean stream's trailing bits stop at FF D9.)
    if (br.overran)
        return false;
    return true;
}

// Allocate component planes (each rounded to its block grid) and the
// final RGBA buffer; returns false if the arena is exhausted.
bool AllocPlanes(Decoder& d, JpegImage* out)
{
    d.maxH = 1;
    d.maxV = 1;
    for (u32 i = 0; i < d.numComp; ++i)
    {
        if (d.comp[i].hSamp > d.maxH)
            d.maxH = d.comp[i].hSamp;
        if (d.comp[i].vSamp > d.maxV)
            d.maxV = d.comp[i].vSamp;
    }
    d.mcuW = d.maxH * 8;
    d.mcuH = d.maxV * 8;
    d.mcusX = (d.width + d.mcuW - 1) / d.mcuW;
    d.mcusY = (d.height + d.mcuH - 1) / d.mcuH;

    for (u32 i = 0; i < d.numComp; ++i)
    {
        Component& c = d.comp[i];
        if (!d.quantPresent[c.quantSel])
            return false;
        c.planeW = d.mcusX * c.hSamp * 8;
        c.planeH = d.mcusY * c.vSamp * 8;
        const u64 sz = static_cast<u64>(c.planeW) * c.planeH;
        if (sz == 0 || sz > 0xFFFFFFFFull)
            return false;
        c.plane = d.arena->Alloc(static_cast<u32>(sz));
        if (!c.plane)
            return false;
    }

    const u64 outBytes = static_cast<u64>(d.width) * d.height * 4;
    if (outBytes > 0xFFFFFFFFull)
        return false;
    out->pixels = d.arena->Alloc(static_cast<u32>(outBytes));
    if (!out->pixels)
        return false;
    out->width = d.width;
    out->height = d.height;
    return true;
}

// Compose the per-component planes into RGBA8888, upsampling chroma
// by nearest-neighbour replication (integer ratios).
void ComposeRgba(Decoder& d, JpegImage* out)
{
    if (d.numComp == 1)
    {
        const Component& c = d.comp[0];
        for (u32 y = 0; y < d.height; ++y)
        {
            const u8* row = c.plane + y * c.planeW;
            u8* o = out->pixels + y * d.width * 4;
            for (u32 x = 0; x < d.width; ++x)
            {
                const u8 g = row[x];
                o[0] = g;
                o[1] = g;
                o[2] = g;
                o[3] = 255;
                o += 4;
            }
        }
        return;
    }

    const Component& cy = d.comp[0];
    const Component& cb = d.comp[1];
    const Component& cr = d.comp[2];
    for (u32 y = 0; y < d.height; ++y)
    {
        u8* o = out->pixels + y * d.width * 4;
        const u32 ybY = (y * cy.vSamp) / d.maxV;
        const u32 ybB = (y * cb.vSamp) / d.maxV;
        const u32 ybR = (y * cr.vSamp) / d.maxV;
        const u8* rowY = cy.plane + ybY * cy.planeW;
        const u8* rowB = cb.plane + ybB * cb.planeW;
        const u8* rowR = cr.plane + ybR * cr.planeW;
        for (u32 x = 0; x < d.width; ++x)
        {
            const u32 xY = (x * cy.hSamp) / d.maxH;
            const u32 xB = (x * cb.hSamp) / d.maxH;
            const u32 xR = (x * cr.hSamp) / d.maxH;
            YCbCrToRgb(rowY[xY], rowB[xB], rowR[xR], o);
            o += 4;
        }
    }
}

} // namespace

bool JpegDecode(const u8* data, u32 len, PngArena& arena, JpegImage* out)
{
    if (!data || !out || len < 4 || len > kJpegMaxInputBytes)
        return false;

    Decoder d;
    d.data = data;
    d.len = len;
    d.arena = &arena;

    bool unsupported = false;
    const u32 scanStart = ParseHeaders(d, unsupported);
    if (scanStart == 0)
        return false; // includes the unsupported-frame rejection

    if (!AllocPlanes(d, out))
        return false;
    if (!DecodeScan(d, scanStart))
        return false;
    ComposeRgba(d, out);
    return true;
}

} // namespace duetos::web
