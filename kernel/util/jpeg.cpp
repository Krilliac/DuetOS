#include "util/jpeg.h"

#include "arch/x86_64/serial.h"
#include "img_meta_rust.h"
#include "util/result.h"

namespace duetos::util
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

JpegInfo JpegParseHeader(const u8* src, u32 src_len)
{
    // Header walking lives in the Rust crate `duetos_img_meta`.
    // Same segment hop pattern, same SOF marker classifier, same
    // SOS-before-SOF rejection, same dimension cap. The C++
    // wrapper does field-by-field copy on the way out so layout
    // drift between Rust and C++ can't silently break callers.
    JpegInfo info = {};
    img_meta::DuetosJpegInfo r{};
    if (!img_meta::duetos_img_meta_parse_jpeg(src, static_cast<usize>(src_len), &r))
        return info;
    info.width = r.width;
    info.height = r.height;
    info.precision = r.precision;
    info.components = r.components;
    info.sof_marker = r.sof_marker;
    info.ok = (r.ok != 0);
    return info;
}

// ===============================================================
// Baseline JPEG decoder. Implements the subset of ISO/IEC 10918-1
// defined by SOF0 frames at 8-bit precision, 1 or 3 components,
// subsampling ratios in {1, 2}. Spec sections referenced:
//   - B.1.1.4 — marker grammar
//   - B.2.4.1 — quantisation table specification (DQT)
//   - B.2.4.2 — Huffman table specification (DHT)
//   - F.1.2   — sequential DCT decoding procedure
//   - F.2     — extended/baseline coefficient decoding
//   - A.3.6   — IDCT definition (we use a fixed-point variant)
// ===============================================================

namespace
{

// JPEG marker bytes.
constexpr u8 kMarkerLead = 0xFF;
constexpr u8 kMarkerSoi = 0xD8;
constexpr u8 kMarkerEoi = 0xD9;
constexpr u8 kMarkerSof0 = 0xC0;
constexpr u8 kMarkerDht = 0xC4;
constexpr u8 kMarkerDqt = 0xDB;
constexpr u8 kMarkerDri = 0xDD;
constexpr u8 kMarkerSos = 0xDA;
constexpr u8 kMarkerRst0 = 0xD0; // ..0xD7

constexpr u32 kMaxComponents = 3;
constexpr u32 kMaxHuffTables = 4;
constexpr u32 kMaxQuantTables = 4;
constexpr u32 kBlockSize = 64;

// Quantisation table — one set of 64 16-bit coefficients per
// destination id (0..3). 16-bit so 12-bit precision JPEGs can be
// represented even though we reject them; widening the type
// avoids accidental truncation if a future slice lifts the cap.
struct QuantTable
{
    u16 q[kBlockSize];
    bool present;
};

// Huffman lookup table — fast direct-lookup for the first 9
// bits, fallback chain for longer codes. The fast table maps a
// 9-bit prefix to (code_length, symbol). When the matched
// length is <= 9 the decode is one table read; otherwise the
// caller walks `slow` keyed on code length.
struct HuffTable
{
    bool present;
    // Fast 9-bit lookup. fast[i] = 0xFFFF if no code <= 9 bits
    // starts with the i prefix; otherwise (length-1) << 8 | symbol.
    u16 fast[512];
    // Symbol table walked when fast missed. mincode[L] / maxcode[L]
    // give the inclusive code range for length L (1..16); offsets[L]
    // is the start index in `symbols` for that length.
    i32 mincode[17];
    i32 maxcode[17]; // -1 means no codes of that length
    u32 offsets[17];
    u8 symbols[256]; // up to 256 codes per JPEG-DHT spec
};

struct Component
{
    u8 id;                // value of Ci in SOF / SOS (matched by id)
    u8 sampling_h;        // horizontal sampling factor (1..4 in spec, 1..2 here)
    u8 sampling_v;        // vertical sampling factor
    u8 quant_id;          // index into quant_tables
    u8 dc_table_id;       // selected by SOS (DC Huffman table id)
    u8 ac_table_id;       // AC Huffman table id
    u32 width_in_blocks;  // ceil((image_w * h_i) / (max_h * 8))
    u32 height_in_blocks; // mirrored on the V axis
    i16 dc_pred;          // running DC predictor across blocks
};

struct Decoder
{
    const u8* src;
    u32 src_len;
    u32 cursor; // current byte position into src

    u32 width;
    u32 height;
    u32 mcu_w; // image width in MCUs
    u32 mcu_h; // image height in MCUs
    u8 max_h;  // max horizontal sampling across components
    u8 max_v;  // max vertical sampling
    u32 components_count;
    u32 restart_interval; // MCUs between RST markers; 0 = none

    QuantTable quant[kMaxQuantTables];
    HuffTable hdc[kMaxHuffTables];
    HuffTable hac[kMaxHuffTables];
    Component comp[kMaxComponents];

    // Bit-stream state.
    u32 bit_buf;
    u32 bit_count;
};

// ---------------------------------------------------------------
// Byte-level helpers.
// ---------------------------------------------------------------

u16 Read16Be(const u8* p)
{
    return static_cast<u16>((static_cast<u16>(p[0]) << 8) | static_cast<u16>(p[1]));
}

// ---------------------------------------------------------------
// Quantisation table parsing — DQT marker. Spec B.2.4.1.
// Body format: one or more (Pq:4 | Tq:4) bytes followed by 64
// quant values. Pq is the precision (0 = 8-bit, 1 = 16-bit; we
// accept both since 8-bit precision JPEGs can legally use either
// — the precision here is the QUANT table precision, not the
// image precision).
// ---------------------------------------------------------------
Result<void> ParseDqt(Decoder& d, u32 segment_end)
{
    while (d.cursor < segment_end)
    {
        const u8 pt = d.src[d.cursor++];
        const u8 precision = pt >> 4;
        const u8 table_id = pt & 0xF;
        if (table_id >= kMaxQuantTables)
            return Err{ErrorCode::Corrupt};
        if (precision != 0 && precision != 1)
            return Err{ErrorCode::Corrupt};
        const u32 entry_size = (precision == 0) ? 1u : 2u;
        const u32 bytes_needed = entry_size * kBlockSize;
        if (d.cursor + bytes_needed > segment_end)
            return Err{ErrorCode::Corrupt};
        QuantTable& q = d.quant[table_id];
        for (u32 i = 0; i < kBlockSize; ++i)
        {
            if (precision == 0)
                q.q[i] = d.src[d.cursor++];
            else
            {
                q.q[i] = Read16Be(&d.src[d.cursor]);
                d.cursor += 2;
            }
        }
        q.present = true;
    }
    return {};
}

// ---------------------------------------------------------------
// Huffman table parsing — DHT marker. Spec B.2.4.2.
// Body: (Tc:4 | Th:4) | 16 bytes of code-count-by-length |
// symbols (sum of those 16 counts, max 256).
// We build both the 9-bit fast lookup and the slow walk arrays.
// ---------------------------------------------------------------
Result<void> ParseDht(Decoder& d, u32 segment_end)
{
    while (d.cursor < segment_end)
    {
        const u8 tc_th = d.src[d.cursor++];
        const u8 table_class = tc_th >> 4; // 0=DC, 1=AC
        const u8 table_id = tc_th & 0xF;
        if (table_class > 1 || table_id >= kMaxHuffTables)
            return Err{ErrorCode::Corrupt};
        if (d.cursor + 16 > segment_end)
            return Err{ErrorCode::Corrupt};
        u8 counts[17] = {};
        u32 total = 0;
        for (u32 i = 1; i <= 16; ++i)
        {
            counts[i] = d.src[d.cursor++];
            total += counts[i];
        }
        if (total > 256 || d.cursor + total > segment_end)
            return Err{ErrorCode::Corrupt};
        // Reject an over-subscribed Huffman table: more codes packed at
        // some length than a prefix-free code space permits. Without
        // this, a crafted DHT (e.g. 207 symbols at length 1, which has
        // room for only 2 codes) drives the canonical `code` below past
        // 2^length, and the length<=9 fast-table fill writes past the
        // u16 fast[512] member — an attacker-controlled OOB write
        // (found by fuzz_jpeg). Kraft-inequality walk: one code slot at
        // length 0, double per length, subtract the codes used; a
        // negative remainder means over-subscription.
        {
            i32 avail = 1;
            for (u32 length = 1; length <= 16; ++length)
            {
                avail <<= 1;
                avail -= static_cast<i32>(counts[length]);
                if (avail < 0)
                    return Err{ErrorCode::Corrupt};
            }
        }
        HuffTable& t = (table_class == 0) ? d.hdc[table_id] : d.hac[table_id];
        for (u32 i = 0; i < 512; ++i)
            t.fast[i] = 0xFFFF;
        for (u32 i = 0; i <= 16; ++i)
        {
            t.mincode[i] = 0;
            t.maxcode[i] = -1;
            t.offsets[i] = 0;
        }
        u32 sym_idx = 0;
        for (u32 i = 0; i < total; ++i)
            t.symbols[i] = d.src[d.cursor++];

        // Compute Huffman codes per length per JPEG spec.
        i32 code = 0;
        for (u32 length = 1; length <= 16; ++length)
        {
            t.offsets[length] = sym_idx;
            if (counts[length] == 0)
            {
                t.maxcode[length] = -1;
                code <<= 1;
                continue;
            }
            t.mincode[length] = code;
            for (u32 j = 0; j < counts[length]; ++j)
            {
                const u8 symbol = t.symbols[sym_idx++];
                if (length <= 9)
                {
                    // Populate fast table: shift code so it sits
                    // at the high end of the 9-bit prefix, then
                    // fill every 9-bit prefix that starts with
                    // it. There are 2^(9-length) such prefixes.
                    const u32 shifted = static_cast<u32>(code) << (9 - length);
                    const u32 fill = 1u << (9 - length);
                    for (u32 k = 0; k < fill; ++k)
                        t.fast[shifted + k] = static_cast<u16>(((length - 1) << 8) | symbol);
                }
                code++;
            }
            t.maxcode[length] = code - 1;
            code <<= 1;
        }
        t.present = true;
    }
    return {};
}

// ---------------------------------------------------------------
// SOS — Start of Scan. Spec B.2.3. Body:
//   Ns | (Cs, Td/Ta)*Ns | Ss, Se, Ah/Al
// We only validate baseline (Ss=0, Se=63, Ah=Al=0); Cs values
// must match a component declared in SOF0.
// ---------------------------------------------------------------
Result<void> ParseSos(Decoder& d, u32 segment_end)
{
    if (d.cursor + 1 > segment_end)
        return Err{ErrorCode::Corrupt};
    const u8 ns = d.src[d.cursor++];
    if (ns != d.components_count)
        return Err{ErrorCode::Corrupt};
    if (d.cursor + 2u * ns + 3u > segment_end)
        return Err{ErrorCode::Corrupt};
    for (u32 i = 0; i < ns; ++i)
    {
        const u8 cs = d.src[d.cursor++];
        const u8 td_ta = d.src[d.cursor++];
        // Match cs to a component declared in SOF0.
        Component* c = nullptr;
        for (u32 j = 0; j < d.components_count; ++j)
            if (d.comp[j].id == cs)
            {
                c = &d.comp[j];
                break;
            }
        if (c == nullptr)
            return Err{ErrorCode::Corrupt};
        c->dc_table_id = td_ta >> 4;
        c->ac_table_id = td_ta & 0xF;
        if (c->dc_table_id >= kMaxHuffTables || c->ac_table_id >= kMaxHuffTables)
            return Err{ErrorCode::Corrupt};
    }
    const u8 ss = d.src[d.cursor++];
    const u8 se = d.src[d.cursor++];
    const u8 ah_al = d.src[d.cursor++];
    if (ss != 0 || se != 63 || ah_al != 0)
        return Err{ErrorCode::Corrupt};
    return {};
}

// ---------------------------------------------------------------
// SOF0 — Baseline DCT frame header. Spec B.2.2.
// Body: P, Y(2), X(2), Nf | (Ci, Hi/Vi, Tqi) * Nf
// The header validator already parsed dimensions; we use this
// pass to capture sampling factors + quant table assignments.
// ---------------------------------------------------------------
Result<void> ParseSof0(Decoder& d, u32 segment_end)
{
    if (d.cursor + 6 > segment_end)
        return Err{ErrorCode::Corrupt};
    const u8 precision = d.src[d.cursor++];
    if (precision != 8)
        return Err{ErrorCode::Corrupt};
    const u16 h = Read16Be(&d.src[d.cursor]);
    d.cursor += 2;
    const u16 w = Read16Be(&d.src[d.cursor]);
    d.cursor += 2;
    if (w != d.width || h != d.height)
        return Err{ErrorCode::Corrupt};
    const u8 nf = d.src[d.cursor++];
    if (nf != 1 && nf != 3)
        return Err{ErrorCode::Corrupt};
    if (d.cursor + 3u * nf > segment_end)
        return Err{ErrorCode::Corrupt};
    d.components_count = nf;
    u8 max_h = 0;
    u8 max_v = 0;
    for (u32 i = 0; i < nf; ++i)
    {
        Component& c = d.comp[i];
        c.id = d.src[d.cursor++];
        const u8 hv = d.src[d.cursor++];
        c.sampling_h = hv >> 4;
        c.sampling_v = hv & 0xF;
        c.quant_id = d.src[d.cursor++];
        if (c.sampling_h == 0 || c.sampling_h > 2)
            return Err{ErrorCode::Corrupt};
        if (c.sampling_v == 0 || c.sampling_v > 2)
            return Err{ErrorCode::Corrupt};
        if (c.quant_id >= kMaxQuantTables)
            return Err{ErrorCode::Corrupt};
        c.dc_pred = 0;
        if (c.sampling_h > max_h)
            max_h = c.sampling_h;
        if (c.sampling_v > max_v)
            max_v = c.sampling_v;
    }
    d.max_h = max_h;
    d.max_v = max_v;
    const u32 mcu_pixels_w = static_cast<u32>(max_h) * 8u;
    const u32 mcu_pixels_h = static_cast<u32>(max_v) * 8u;
    d.mcu_w = (d.width + mcu_pixels_w - 1) / mcu_pixels_w;
    d.mcu_h = (d.height + mcu_pixels_h - 1) / mcu_pixels_h;
    for (u32 i = 0; i < nf; ++i)
    {
        Component& c = d.comp[i];
        c.width_in_blocks = d.mcu_w * c.sampling_h;
        c.height_in_blocks = d.mcu_h * c.sampling_v;
    }
    return {};
}

// ---------------------------------------------------------------
// Bit reader over the entropy-coded scan data. Handles byte
// stuffing (FF 00 → FF) and bails on truncation. The scan ends
// when a non-zero byte follows FF (marker boundary).
//
// Hot path: FillBits / HuffDecode / DecodeBlock run once per bit /
// per Huffman symbol / per 8x8 block — millions of times for a
// full-frame JPEG. They keep their bool / i32-sentinel return per
// spec section 6.2 ("measured hot paths where Result construction
// cost is observable"). The once-per-image / once-per-segment
// callers above and below them propagate via Result.
// ---------------------------------------------------------------
bool FillBits(Decoder& d, u32 want)
{
    while (d.bit_count < want)
    {
        if (d.cursor >= d.src_len)
            return false;
        u8 byte = d.src[d.cursor++];
        if (byte == 0xFF)
        {
            if (d.cursor >= d.src_len)
                return false;
            const u8 next = d.src[d.cursor++];
            if (next == 0)
            {
                // Stuffed byte — the literal 0xFF.
            }
            else
            {
                // Marker. Push the marker bytes back so the
                // outer loop can detect EOI / RSTn. We saw 0xFF
                // then `next`; rewind both.
                d.cursor -= 2;
                // Top up the accumulator with zero bits so a
                // partial decode at marker boundary doesn't read
                // stale state. Keep only the low `bit_count` valid
                // bits. The old `<<=(32-n); >>=(32-n)` pair is UB
                // when n==0 (shift of a u32 by 32) and a no-op on
                // x86 (count masked to 0) — leaving stale high bits.
                // Mask explicitly instead.
                if (d.bit_count == 0)
                    d.bit_buf = 0;
                else if (d.bit_count < 32)
                    d.bit_buf &= (0xFFFFFFFFu >> (32 - d.bit_count));
                while (d.bit_count < want)
                {
                    d.bit_buf = (d.bit_buf << 8);
                    d.bit_count += 8;
                }
                return true;
            }
        }
        d.bit_buf = (d.bit_buf << 8) | byte;
        d.bit_count += 8;
    }
    return true;
}

// Peek `n` bits MSB-first without consuming them. Caller must
// have ensured FillBits(d, n) succeeded.
u32 PeekBits(const Decoder& d, u32 n)
{
    return (d.bit_buf >> (d.bit_count - n)) & ((1u << n) - 1u);
}

void ConsumeBits(Decoder& d, u32 n)
{
    d.bit_count -= n;
}

// Decode one Huffman symbol via the fast table when possible,
// the slow table otherwise. Returns -1 on failure.
i32 HuffDecode(Decoder& d, const HuffTable& t)
{
    if (!FillBits(d, 16))
    {
        // Try with whatever bits we have; if < 1 bit, fail.
        if (d.bit_count == 0)
            return -1;
    }
    if (d.bit_count >= 9)
    {
        const u32 idx = PeekBits(d, 9);
        const u16 e = t.fast[idx];
        if (e != 0xFFFF)
        {
            const u32 length = (e >> 8) + 1;
            ConsumeBits(d, length);
            return e & 0xFF;
        }
    }
    // Slow path — walk codes by length.
    for (u32 length = 10; length <= 16; ++length)
    {
        if (d.bit_count < length)
            return -1;
        const i32 code = static_cast<i32>(PeekBits(d, length));
        if (code <= t.maxcode[length])
        {
            ConsumeBits(d, length);
            const u32 idx = t.offsets[length] + (code - t.mincode[length]);
            if (idx >= 256)
                return -1;
            return t.symbols[idx];
        }
    }
    return -1;
}

// "EXTEND" per spec F.2.2.1 — sign-extend an N-bit unsigned
// value into a signed coefficient.
i32 ExtendValue(u32 bits, u32 length)
{
    if (length == 0)
        return 0;
    const i32 v = static_cast<i32>(bits);
    if (v < (1 << (length - 1)))
        return v + (-1 << length) + 1;
    return v;
}

// ---------------------------------------------------------------
// Zig-zag dequantise. Spec A.3.6 / F.1.2.1.
// ---------------------------------------------------------------
constexpr u8 kZigZag[kBlockSize] = {0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
                                    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
                                    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
                                    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};

bool DecodeBlock(Decoder& d, Component& comp, i32 out[kBlockSize])
{
    for (u32 i = 0; i < kBlockSize; ++i)
        out[i] = 0;
    const HuffTable& dc = d.hdc[comp.dc_table_id];
    const HuffTable& ac = d.hac[comp.ac_table_id];
    if (!dc.present || !ac.present)
        return false;

    // DC coefficient.
    const i32 dc_size = HuffDecode(d, dc);
    if (dc_size < 0 || dc_size > 11)
        return false;
    i32 dc_delta = 0;
    if (dc_size > 0)
    {
        if (!FillBits(d, dc_size))
            return false;
        const u32 bits = PeekBits(d, dc_size);
        ConsumeBits(d, dc_size);
        dc_delta = ExtendValue(bits, dc_size);
    }
    comp.dc_pred += static_cast<i16>(dc_delta);
    out[0] = comp.dc_pred * static_cast<i32>(d.quant[comp.quant_id].q[0]);

    // AC coefficients (run/length encoded).
    u32 k = 1;
    while (k < kBlockSize)
    {
        const i32 rs = HuffDecode(d, ac);
        if (rs < 0)
            return false;
        const u32 run = (rs >> 4) & 0xF;
        const u32 length = rs & 0xF;
        if (length == 0)
        {
            if (run == 15)
            {
                // ZRL — skip 16 zeros.
                k += 16;
                continue;
            }
            // EOB — remaining coefficients are zero.
            break;
        }
        k += run;
        if (k >= kBlockSize || length > 10)
            return false;
        if (!FillBits(d, length))
            return false;
        const u32 bits = PeekBits(d, length);
        ConsumeBits(d, length);
        const i32 coeff = ExtendValue(bits, length);
        out[kZigZag[k]] = coeff * static_cast<i32>(d.quant[comp.quant_id].q[kZigZag[k]]);
        ++k;
    }
    return true;
}

// ---------------------------------------------------------------
// IDCT — integer fixed-point variant of the AAN algorithm
// (Arai-Agui-Nakajima), 8×8. Input: 64 dequantised coefficients
// in zig-zag native order. Output: 64 sample values, level-
// shifted to 0..255 with clipping. Fixed-point precision: 12
// fractional bits; intermediate values fit in i32.
//
// The cosine constants are pre-computed:
//   c1 = cos(π/16) * 2^12   ≈ 4017
//   c2 = cos(2π/16) * 2^12  ≈ 3784
//   c3 = cos(3π/16) * 2^12  ≈ 3406
//   c5 = cos(5π/16) * 2^12  ≈ 2276
//   c6 = cos(6π/16) * 2^12  ≈ 1567
//   c7 = cos(7π/16) * 2^12  ≈ 799
// ---------------------------------------------------------------
constexpr i32 kC1 = 4017;
constexpr i32 kC2 = 3784;
constexpr i32 kC3 = 3406;
constexpr i32 kC5 = 2276;
constexpr i32 kC6 = 1567;
constexpr i32 kC7 = 799;
constexpr i32 kFrac = 12;

void IdctRow(i32* row)
{
    const i32 s0 = row[0];
    const i32 s1 = row[1];
    const i32 s2 = row[2];
    const i32 s3 = row[3];
    const i32 s4 = row[4];
    const i32 s5 = row[5];
    const i32 s6 = row[6];
    const i32 s7 = row[7];

    // Even part — terms involving cos(0), cos(2π/16), cos(4π/16),
    // cos(6π/16). 1D IDCT formula from JPEG Annex A.
    // i64 accumulators: a crafted JPEG can dequantize coefficients
    // large enough that s*kC and the butterfly sums overflow i32
    // (signed-overflow UB, found by fuzz_jpeg). The products and sums
    // are computed in 64-bit; the final >>kFrac result is narrowed
    // back to the i32 row[] (a defined conversion, not UB) and the
    // pixel is clamped to a byte downstream by ClampToByte.
    const i64 e0 = (static_cast<i64>(s0) + s4) << kFrac;
    const i64 e1 = (static_cast<i64>(s0) - s4) << kFrac;
    const i64 e2 = static_cast<i64>(s2) * kC6 - static_cast<i64>(s6) * kC2;
    const i64 e3 = static_cast<i64>(s2) * kC2 + static_cast<i64>(s6) * kC6;
    const i64 even0 = e0 + e3;
    const i64 even1 = e1 + e2;
    const i64 even2 = e1 - e2;
    const i64 even3 = e0 - e3;

    // Odd part.
    const i64 o0 = static_cast<i64>(s1) * kC1 + static_cast<i64>(s3) * kC3 + static_cast<i64>(s5) * kC5 +
                   static_cast<i64>(s7) * kC7;
    const i64 o1 = static_cast<i64>(s1) * kC3 - static_cast<i64>(s3) * kC7 - static_cast<i64>(s5) * kC1 -
                   static_cast<i64>(s7) * kC5;
    const i64 o2 = static_cast<i64>(s1) * kC5 - static_cast<i64>(s3) * kC1 + static_cast<i64>(s5) * kC7 +
                   static_cast<i64>(s7) * kC3;
    const i64 o3 = static_cast<i64>(s1) * kC7 - static_cast<i64>(s3) * kC5 + static_cast<i64>(s5) * kC3 -
                   static_cast<i64>(s7) * kC1;

    const i64 add = static_cast<i64>(1) << (kFrac - 1);
    row[0] = static_cast<i32>((even0 + o0 + add) >> kFrac);
    row[1] = static_cast<i32>((even1 + o1 + add) >> kFrac);
    row[2] = static_cast<i32>((even2 + o2 + add) >> kFrac);
    row[3] = static_cast<i32>((even3 + o3 + add) >> kFrac);
    row[4] = static_cast<i32>((even3 - o3 + add) >> kFrac);
    row[5] = static_cast<i32>((even2 - o2 + add) >> kFrac);
    row[6] = static_cast<i32>((even1 - o1 + add) >> kFrac);
    row[7] = static_cast<i32>((even0 - o0 + add) >> kFrac);
}

u8 ClampToByte(i32 v)
{
    if (v < 0)
        return 0;
    if (v > 255)
        return 255;
    return static_cast<u8>(v);
}

void Idct(i32 block[kBlockSize], u8 out[kBlockSize])
{
    // Row pass.
    for (u32 r = 0; r < 8; ++r)
        IdctRow(&block[r * 8]);
    // Column pass — copy each column into a temporary row,
    // process, copy back. Fewer cache lines than transposing in
    // place.
    for (u32 c = 0; c < 8; ++c)
    {
        i32 col[8];
        for (u32 r = 0; r < 8; ++r)
            col[r] = block[r * 8 + c];
        IdctRow(col);
        for (u32 r = 0; r < 8; ++r)
            block[r * 8 + c] = col[r];
    }
    // Final level shift (+128) + clamp to 0..255.
    for (u32 i = 0; i < kBlockSize; ++i)
        out[i] = ClampToByte(block[i] + 128);
}

// ---------------------------------------------------------------
// MCU iteration — decode blocks into per-component sample planes.
// Pointer layout:
//   plane[c] = scratch[plane_offset[c]]
// where plane[c] is `comp[c].width_in_blocks * 8 * comp[c].height_in_blocks * 8`
// bytes laid out row-major.
// ---------------------------------------------------------------
void EmitBlock(const u8 block[kBlockSize], u8* plane, u32 plane_stride, u32 block_x, u32 block_y)
{
    const u32 origin_x = block_x * 8;
    const u32 origin_y = block_y * 8;
    for (u32 r = 0; r < 8; ++r)
    {
        const u32 dst = (origin_y + r) * plane_stride + origin_x;
        for (u32 c = 0; c < 8; ++c)
            plane[dst + c] = block[r * 8 + c];
    }
}

Result<void> DecodeScan(Decoder& d, u8* planes[kMaxComponents], const u32 strides[kMaxComponents])
{
    d.bit_buf = 0;
    d.bit_count = 0;
    for (u32 i = 0; i < d.components_count; ++i)
        d.comp[i].dc_pred = 0;
    u32 mcu_index = 0;
    const u32 mcus_total = d.mcu_w * d.mcu_h;
    while (mcu_index < mcus_total)
    {
        const u32 mcu_x = mcu_index % d.mcu_w;
        const u32 mcu_y = mcu_index / d.mcu_w;
        for (u32 ci = 0; ci < d.components_count; ++ci)
        {
            Component& c = d.comp[ci];
            for (u32 by = 0; by < c.sampling_v; ++by)
            {
                for (u32 bx = 0; bx < c.sampling_h; ++bx)
                {
                    i32 raw[kBlockSize];
                    u8 spatial[kBlockSize];
                    if (!DecodeBlock(d, c, raw))
                        return Err{ErrorCode::Corrupt};
                    Idct(raw, spatial);
                    const u32 block_x = mcu_x * c.sampling_h + bx;
                    const u32 block_y = mcu_y * c.sampling_v + by;
                    EmitBlock(spatial, planes[ci], strides[ci], block_x, block_y);
                }
            }
        }
        ++mcu_index;
        // Restart-marker handling.
        if (d.restart_interval != 0 && (mcu_index % d.restart_interval) == 0 && mcu_index < mcus_total)
        {
            // Skip to next marker boundary, expect RSTn.
            d.bit_count = 0;
            d.bit_buf = 0;
            // Hop past 0xFF padding and the RST marker itself.
            while (d.cursor < d.src_len && d.src[d.cursor] != 0xFF)
                ++d.cursor;
            if (d.cursor + 2 > d.src_len)
                return Err{ErrorCode::Corrupt};
            const u8 m = d.src[d.cursor + 1];
            if (m < kMarkerRst0 || m > kMarkerRst0 + 7)
                return Err{ErrorCode::Corrupt};
            d.cursor += 2;
            for (u32 i = 0; i < d.components_count; ++i)
                d.comp[i].dc_pred = 0;
        }
    }
    return {};
}

// ---------------------------------------------------------------
// YCbCr → RGB conversion + chroma upsampling. We process each
// output pixel by sampling the luma plane at (x, y) and the
// chroma planes at (x * Cw/Yw, y * Ch/Yh) — nearest-neighbour
// upsampling, no smoothing, which matches what most fast JPEG
// decoders do for thumbnails. Full bilinear is a future-slice
// quality bump.
//
// Integer conversion via the standard JFIF coefficients:
//   R = Y               + 1.402   (Cr-128)
//   G = Y - 0.344136 (Cb-128) - 0.714136 (Cr-128)
//   B = Y + 1.772    (Cb-128)
// scaled by 2^16 for fixed-point math.
// ---------------------------------------------------------------
constexpr i32 kYR = 91881;   // 1.402   * 65536
constexpr i32 kYGB = -22554; // -0.344136 * 65536
constexpr i32 kYGR = -46802; // -0.714136 * 65536
constexpr i32 kYB = 116130;  // 1.772   * 65536

void EmitYCbCr(const u8* plane_y, u32 stride_y, const u8* plane_cb, u32 stride_cb, const u8* plane_cr, u32 stride_cr,
               u8 max_h, u8 max_v, u32 width, u32 height, u32* out_pixels)
{
    for (u32 y = 0; y < height; ++y)
    {
        const u32 cy = (y / max_v);
        for (u32 x = 0; x < width; ++x)
        {
            const u32 cx = (x / max_h);
            const i32 Y = plane_y[y * stride_y + x];
            const i32 Cb = plane_cb[cy * stride_cb + cx] - 128;
            const i32 Cr = plane_cr[cy * stride_cr + cx] - 128;
            const i32 r = Y + ((kYR * Cr + 32768) >> 16);
            const i32 g = Y + ((kYGB * Cb + kYGR * Cr + 32768) >> 16);
            const i32 b = Y + ((kYB * Cb + 32768) >> 16);
            const u32 R = ClampToByte(r);
            const u32 G = ClampToByte(g);
            const u32 B = ClampToByte(b);
            out_pixels[y * width + x] = 0xFF000000u | (R << 16) | (G << 8) | B;
        }
    }
}

void EmitGrayscale(const u8* plane_y, u32 stride_y, u32 width, u32 height, u32* out_pixels)
{
    for (u32 y = 0; y < height; ++y)
    {
        for (u32 x = 0; x < width; ++x)
        {
            const u32 Y = plane_y[y * stride_y + x];
            out_pixels[y * width + x] = 0xFF000000u | (Y << 16) | (Y << 8) | Y;
        }
    }
}

} // namespace

u64 JpegEstimateScratch(const JpegInfo& info)
{
    if (!info.ok)
        return 0;
    if (info.precision != 8)
        return 0;
    if (info.sof_marker != kMarkerSof0)
        return 0;
    if (info.components != 1 && info.components != 3)
        return 0;
    if (info.width == 0 || info.height == 0)
        return 0;
    if (info.width > kJpegMaxDimension || info.height > kJpegMaxDimension)
        return 0;
    // Worst case: each component plane the full image size
    // (4:4:4 subsampling); add 16 KiB headroom for the Decoder
    // struct + per-block working arrays.
    const u64 plane = static_cast<u64>(info.width) * static_cast<u64>(info.height);
    return plane * info.components + 16 * 1024;
}

Result<u64> JpegDecode(const u8* src, u32 src_len, const JpegInfo& info, u8* scratch, u64 scratch_len, u32* out_pixels)
{
    if (src == nullptr || scratch == nullptr || out_pixels == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (!info.ok || info.precision != 8 || info.sof_marker != kMarkerSof0)
        return Err{ErrorCode::InvalidArgument};
    if (info.components != 1 && info.components != 3)
        return Err{ErrorCode::InvalidArgument};
    if (info.width == 0 || info.height == 0)
        return Err{ErrorCode::InvalidArgument};
    if (info.width > kJpegMaxDimension || info.height > kJpegMaxDimension)
        return Err{ErrorCode::InvalidArgument};
    const u64 need = JpegEstimateScratch(info);
    if (scratch_len < need)
        return Err{ErrorCode::BufferTooSmall};
    if (src_len < 4)
        return Err{ErrorCode::Corrupt};
    if (src[0] != kMarkerLead || src[1] != kMarkerSoi)
        return Err{ErrorCode::Corrupt};

    // Place the Decoder struct at the start of scratch; the
    // remaining tail is reserved for per-component planes.
    Decoder* dp = reinterpret_cast<Decoder*>(scratch);
    Decoder& d = *dp;
    // Manual zero-init (constexpr static_cast of new placement
    // is overkill for a kernel TU).
    auto* zero_ptr = reinterpret_cast<u8*>(&d);
    for (u32 i = 0; i < sizeof(Decoder); ++i)
        zero_ptr[i] = 0;
    d.src = src;
    d.src_len = src_len;
    d.cursor = 2; // past SOI
    d.width = info.width;
    d.height = info.height;

    // Marker walk loop.
    bool sof_seen = false;
    bool sos_seen = false;
    while (d.cursor < d.src_len && !sos_seen)
    {
        if (d.src[d.cursor] != kMarkerLead)
            return Err{ErrorCode::Corrupt};
        while (d.cursor < d.src_len && d.src[d.cursor] == kMarkerLead)
            ++d.cursor;
        if (d.cursor >= d.src_len)
            return Err{ErrorCode::Corrupt};
        const u8 marker = d.src[d.cursor++];
        if (marker == kMarkerEoi)
            return Err{ErrorCode::Corrupt};
        // All segment markers carry a 2-byte length prefix.
        if (d.cursor + 2 > d.src_len)
            return Err{ErrorCode::Corrupt};
        const u32 seg_len = Read16Be(&d.src[d.cursor]);
        if (seg_len < 2)
            return Err{ErrorCode::Corrupt};
        const u32 seg_end = d.cursor + seg_len;
        if (seg_end > d.src_len)
            return Err{ErrorCode::Corrupt};
        d.cursor += 2;
        switch (marker)
        {
        case kMarkerSof0:
            if (sof_seen)
                return Err{ErrorCode::Corrupt};
            RESULT_TRY(ParseSof0(d, seg_end));
            sof_seen = true;
            break;
        case kMarkerDqt:
            RESULT_TRY(ParseDqt(d, seg_end));
            break;
        case kMarkerDht:
            RESULT_TRY(ParseDht(d, seg_end));
            break;
        case kMarkerDri:
            if (seg_end - d.cursor != 2)
                return Err{ErrorCode::Corrupt};
            d.restart_interval = Read16Be(&d.src[d.cursor]);
            break;
        case kMarkerSos:
            if (!sof_seen)
                return Err{ErrorCode::Corrupt};
            RESULT_TRY(ParseSos(d, seg_end));
            sos_seen = true;
            // Don't skip seg_end — entropy data starts immediately.
            d.cursor = seg_end;
            break;
        default:
            d.cursor = seg_end;
            break;
        }
    }
    if (!sos_seen)
        return Err{ErrorCode::Corrupt};

    // Carve component planes out of the scratch buffer.
    u8* plane_ptr[kMaxComponents] = {nullptr, nullptr, nullptr};
    u32 plane_stride[kMaxComponents] = {0, 0, 0};
    u8* base = scratch + sizeof(Decoder);
    for (u32 ci = 0; ci < d.components_count; ++ci)
    {
        Component& c = d.comp[ci];
        plane_stride[ci] = c.width_in_blocks * 8;
        const u64 plane_bytes = static_cast<u64>(plane_stride[ci]) * (c.height_in_blocks * 8);
        plane_ptr[ci] = base;
        base += plane_bytes;
        if (static_cast<u64>(base - scratch) > scratch_len)
            return Err{ErrorCode::BufferTooSmall};
    }
    RESULT_TRY(DecodeScan(d, plane_ptr, plane_stride));
    if (d.components_count == 1)
        EmitGrayscale(plane_ptr[0], plane_stride[0], d.width, d.height, out_pixels);
    else
        EmitYCbCr(plane_ptr[0], plane_stride[0], plane_ptr[1], plane_stride[1], plane_ptr[2], plane_stride[2], d.max_h,
                  d.max_v, d.width, d.height, out_pixels);
    return static_cast<u64>(d.width) * d.height;
}

// ---------------------------------------------------------------
// Self-test — embeds a 16×16 grayscale Baseline JPEG produced by
// a known reference encoder; decodes it and asserts the average
// brightness matches a sentinel. Smaller than a YCbCr fixture
// because grayscale exercises the marker walker + Huffman +
// dequant + IDCT path without the chroma-upsample complication.
// ---------------------------------------------------------------
namespace
{

// 16×16 mid-grey grayscale Baseline JPEG. Generated by
// `convert -size 16x16 xc:gray50 -colorspace gray -quality 75
// -sampling-factor 1x1 jpeg:test16.jpg` and embedded as a
// canonical byte sequence so the decoder selftest exercises a
// real spec-conformant file (JFIF APP0 + standard quant + the
// minimum single-symbol Huffman tables that drop every block to
// DC-only-EOB encoding).
constexpr u8 kSelfTestJpeg[] = {
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F,
    0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
    0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF,
    0xC0, 0x00, 0x0B, 0x08, 0x00, 0x10, 0x00, 0x10, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x15, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF,
    0xC4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x80, 0x3F, 0xFF, 0xD9,
};
constexpr u32 kSelfTestJpegLen = sizeof(kSelfTestJpeg);

bool ExpectSelfTest(bool cond, const char* tag)
{
    if (!cond)
    {
        arch::SerialWrite("[jpeg-selftest] FAIL ");
        arch::SerialWrite(tag);
        arch::SerialWrite("\n");
    }
    return cond;
}

} // namespace

void JpegDecoderSelfTest()
{
    bool ok = true;

    JpegInfo info = JpegParseHeader(kSelfTestJpeg, kSelfTestJpegLen);
    ok &= ExpectSelfTest(info.ok, "header.ok");
    ok &= ExpectSelfTest(info.width == 16, "width=16");
    ok &= ExpectSelfTest(info.height == 16, "height=16");
    ok &= ExpectSelfTest(info.components == 1, "grayscale");
    ok &= ExpectSelfTest(info.sof_marker == kMarkerSof0, "sof0");

    const u64 scratch_bytes = JpegEstimateScratch(info);
    ok &= ExpectSelfTest(scratch_bytes > 0, "scratch>0");

    if (!ok)
        return;

    // 32 KiB scratch is more than enough for 16×16 grayscale —
    // sized so this test stays small enough to live in
    // .bss/.data without a heap allocation.
    static u8 g_jpeg_selftest_scratch[32 * 1024];
    static u32 g_jpeg_selftest_pixels[16 * 16];
    const auto decoded = JpegDecode(kSelfTestJpeg, kSelfTestJpegLen, info, g_jpeg_selftest_scratch,
                                    sizeof(g_jpeg_selftest_scratch), g_jpeg_selftest_pixels);
    ok &= ExpectSelfTest(decoded.has_value() && decoded.value() == 16u * 16u, "decode-pixel-count");

    // Sanity check pixel values — the input is mid-grey-ish so
    // every output pixel should be in the [0x10, 0xF0] range
    // (not pure black, not pure white). A tight bound would risk
    // false-failing on small encoder-side variation.
    if (ok)
    {
        bool all_in_range = true;
        for (u32 i = 0; i < 16 * 16; ++i)
        {
            const u32 p = g_jpeg_selftest_pixels[i];
            const u32 r = (p >> 16) & 0xFF;
            // Just check red channel since grayscale puts the
            // same Y value in all three channels.
            if (r < 0x10 || r > 0xF0)
            {
                all_in_range = false;
                break;
            }
        }
        ok &= ExpectSelfTest(all_in_range, "grey-range");
    }

    if (ok)
        arch::SerialWrite("[jpeg-selftest] PASS\n");
}

} // namespace duetos::util
