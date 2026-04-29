#include "drivers/video/svg.h"

#include "arch/x86_64/serial.h"

namespace duetos::drivers::video
{

namespace
{

using arch::SerialWrite;

inline bool IsSpace(u8 c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}
inline bool IsDigit(u8 c)
{
    return c >= '0' && c <= '9';
}
inline bool IsAlpha(u8 c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline bool IsAlnum(u8 c)
{
    return IsDigit(c) || IsAlpha(c) || c == '_' || c == '-';
}

// Skip whitespace + commas (per SVG path-data convention) starting
// at *cursor; advance the cursor past the run. Bounded by `end`.
void SkipWsCommas(const u8*& c, const u8* end)
{
    while (c < end && (IsSpace(*c) || *c == ','))
        ++c;
}

// Parse a signed integer at `c`, advance `c` past it. Returns 0 if
// `c` doesn't start with a digit / sign — caller is expected to
// keep a sane state machine.
i32 ParseInt(const u8*& c, const u8* end)
{
    i32 sign = 1;
    if (c < end && *c == '-')
    {
        sign = -1;
        ++c;
    }
    else if (c < end && *c == '+')
    {
        ++c;
    }
    i32 v = 0;
    while (c < end && IsDigit(*c))
    {
        v = v * 10 + (*c - '0');
        ++c;
    }
    // Skip a fractional part (SVG allows e.g. 12.5) but truncate.
    if (c < end && *c == '.')
    {
        ++c;
        while (c < end && IsDigit(*c))
            ++c;
    }
    return v * sign;
}

// Parse a hex digit pair (00..FF).
u32 ParseHex2(const u8*& c, const u8* end)
{
    auto h = [](u8 ch) -> u32
    {
        if (ch >= '0' && ch <= '9')
            return ch - '0';
        if (ch >= 'a' && ch <= 'f')
            return 10 + ch - 'a';
        if (ch >= 'A' && ch <= 'F')
            return 10 + ch - 'A';
        return 0;
    };
    if (c + 2 > end)
        return 0;
    const u32 v = (h(c[0]) << 4) | h(c[1]);
    c += 2;
    return v;
}

// Parse #RRGGBB. Returns 0 (black) on malformed input. Three-digit
// short form #RGB is also handled (each nibble doubled).
u32 ParseHexColor(const u8* s, u32 len)
{
    if (len < 4 || s[0] != '#')
        return 0;
    if (len >= 7)
    {
        const u8* c = s + 1;
        const u32 r = ParseHex2(c, s + len);
        const u32 g = ParseHex2(c, s + len);
        const u32 b = ParseHex2(c, s + len);
        return (r << 16) | (g << 8) | b;
    }
    if (len >= 4)
    {
        // #RGB short form
        auto h = [](u8 ch) -> u32
        {
            if (ch >= '0' && ch <= '9')
                return ch - '0';
            if (ch >= 'a' && ch <= 'f')
                return 10 + ch - 'a';
            if (ch >= 'A' && ch <= 'F')
                return 10 + ch - 'A';
            return 0;
        };
        const u32 r = h(s[1]) * 0x11;
        const u32 g = h(s[2]) * 0x11;
        const u32 b = h(s[3]) * 0x11;
        return (r << 16) | (g << 8) | b;
    }
    return 0;
}

// Find an attribute value for `name` inside `[el_start, el_end)`
// (which is the bytes between the opening `<tag ` and the closing
// `>` / `/>`). Returns true and writes the value range on success.
bool FindAttr(const u8* el_start, const u8* el_end, const char* name, const u8** val_start, u32* val_len)
{
    const u32 nlen = [&]
    {
        u32 n = 0;
        while (name[n])
            ++n;
        return n;
    }();
    const u8* c = el_start;
    while (c < el_end)
    {
        // Skip until we hit alpha (start of attribute name).
        while (c < el_end && !IsAlpha(*c))
            ++c;
        const u8* name_start = c;
        while (c < el_end && IsAlnum(*c))
            ++c;
        const u32 alen = static_cast<u32>(c - name_start);
        // Skip whitespace + '=' + opening quote.
        while (c < el_end && IsSpace(*c))
            ++c;
        if (c >= el_end || *c != '=')
            continue;
        ++c;
        while (c < el_end && IsSpace(*c))
            ++c;
        if (c >= el_end || (*c != '"' && *c != '\''))
            continue;
        const u8 quote = *c++;
        const u8* val_s = c;
        while (c < el_end && *c != quote)
            ++c;
        const u32 vlen = static_cast<u32>(c - val_s);
        if (c < el_end)
            ++c;
        // Match name?
        if (alen == nlen)
        {
            bool ok = true;
            for (u32 i = 0; i < nlen; ++i)
            {
                if (name_start[i] != static_cast<u8>(name[i]))
                {
                    ok = false;
                    break;
                }
            }
            if (ok)
            {
                *val_start = val_s;
                *val_len = vlen;
                return true;
            }
        }
    }
    return false;
}

// Parse a `<path d="...">` data string into PathSegment[] entries
// stored at `image->path_segments[image->path_segment_count..]`.
// Returns the number of segments emitted.
u32 ParsePathData(const u8* d, u32 dlen, SvgImage* image)
{
    const u8* c = d;
    const u8* end = d + dlen;
    const u32 start_count = image->path_segment_count;
    i32 first_x = 0, first_y = 0;
    bool first_set = false;
    while (c < end)
    {
        SkipWsCommas(c, end);
        if (c >= end)
            break;
        const u8 cmd = *c++;
        SkipWsCommas(c, end);
        PathSegment seg{};
        switch (cmd)
        {
        case 'M':
        case 'm':
        {
            const i32 x = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 y = ParseInt(c, end);
            seg.op = PathOp::Move;
            seg.pts[0] = {x, y};
            if (!first_set)
            {
                first_x = x;
                first_y = y;
                first_set = true;
            }
            break;
        }
        case 'L':
        case 'l':
        {
            const i32 x = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 y = ParseInt(c, end);
            seg.op = PathOp::Line;
            seg.pts[0] = {x, y};
            break;
        }
        case 'C':
        case 'c':
        {
            const i32 cx1 = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 cy1 = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 cx2 = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 cy2 = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 ex = ParseInt(c, end);
            SkipWsCommas(c, end);
            const i32 ey = ParseInt(c, end);
            seg.op = PathOp::Cubic;
            seg.pts[0] = {cx1, cy1};
            seg.pts[1] = {cx2, cy2};
            seg.pts[2] = {ex, ey};
            break;
        }
        case 'Z':
        case 'z':
            seg.op = PathOp::Close;
            seg.pts[0] = {first_x, first_y};
            break;
        default:
            // Unsupported command — bail to keep state sane.
            return image->path_segment_count - start_count;
        }
        if (image->path_segment_count >= image->max_path_segments)
            return image->path_segment_count - start_count;
        image->path_segments[image->path_segment_count++] = seg;
    }
    return image->path_segment_count - start_count;
}

} // namespace

bool SvgParse(const u8* bytes, u32 size, SvgImage* image)
{
    if (bytes == nullptr || image == nullptr || size < 5)
        return false;
    if (image->shapes == nullptr || image->path_segments == nullptr)
        return false;
    image->shape_count = 0;
    image->path_segment_count = 0;
    image->viewbox_x = 0;
    image->viewbox_y = 0;
    image->viewbox_w = 100;
    image->viewbox_h = 100;

    const u8* c = bytes;
    const u8* end = bytes + size;

    while (c < end)
    {
        // Find next '<'.
        while (c < end && *c != '<')
            ++c;
        if (c >= end)
            break;
        const u8* tag_open = c;
        ++c;
        // Skip XML declarations / comments.
        if (c < end && (*c == '?' || *c == '!'))
        {
            while (c < end && *c != '>')
                ++c;
            if (c < end)
                ++c;
            continue;
        }
        // Closing tag — skip.
        if (c < end && *c == '/')
        {
            while (c < end && *c != '>')
                ++c;
            if (c < end)
                ++c;
            continue;
        }
        // Read tag name.
        const u8* tname = c;
        while (c < end && IsAlnum(*c))
            ++c;
        const u32 tname_len = static_cast<u32>(c - tname);
        // Find '>' (end of opening tag — could be self-closing />).
        const u8* attrs_end = c;
        while (attrs_end < end && *attrs_end != '>')
            ++attrs_end;
        if (attrs_end >= end)
            break;
        // attrs_end points at '>'; the attr text is [c, attrs_end).
        // Tag name match helpers.
        auto tag_is = [&](const char* name) -> bool
        {
            u32 n = 0;
            while (name[n])
                ++n;
            if (n != tname_len)
                return false;
            for (u32 i = 0; i < n; ++i)
                if (tname[i] != static_cast<u8>(name[i]))
                    return false;
            return true;
        };
        // Pull a few common attrs.
        const u8* val;
        u32 vlen;

        if (tag_is("svg"))
        {
            if (FindAttr(c, attrs_end, "viewBox", &val, &vlen))
            {
                const u8* vc = val;
                const u8* ve = val + vlen;
                image->viewbox_x = ParseInt(vc, ve);
                SkipWsCommas(vc, ve);
                image->viewbox_y = ParseInt(vc, ve);
                SkipWsCommas(vc, ve);
                image->viewbox_w = static_cast<u32>(ParseInt(vc, ve));
                SkipWsCommas(vc, ve);
                image->viewbox_h = static_cast<u32>(ParseInt(vc, ve));
            }
            else
            {
                if (FindAttr(c, attrs_end, "width", &val, &vlen))
                {
                    const u8* vc = val;
                    image->viewbox_w = static_cast<u32>(ParseInt(vc, val + vlen));
                }
                if (FindAttr(c, attrs_end, "height", &val, &vlen))
                {
                    const u8* vc = val;
                    image->viewbox_h = static_cast<u32>(ParseInt(vc, val + vlen));
                }
            }
        }
        else if (image->shape_count < image->max_shapes)
        {
            SvgShape& sh = image->shapes[image->shape_count];
            sh.stroke_rgb = 0x00000000u;
            sh.stroke_width = 1u;
            if (FindAttr(c, attrs_end, "stroke", &val, &vlen))
                sh.stroke_rgb = ParseHexColor(val, vlen);
            if (FindAttr(c, attrs_end, "stroke-width", &val, &vlen))
            {
                const u8* vc = val;
                u32 sw = static_cast<u32>(ParseInt(vc, val + vlen));
                if (sw == 0)
                    sw = 1;
                if (sw > 8)
                    sw = 8;
                sh.stroke_width = sw;
            }
            bool emit = false;
            if (tag_is("line"))
            {
                sh.kind = SvgShapeKind::Line;
                if (FindAttr(c, attrs_end, "x1", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.ax = ParseInt(vc, val + vlen);
                }
                if (FindAttr(c, attrs_end, "y1", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.ay = ParseInt(vc, val + vlen);
                }
                if (FindAttr(c, attrs_end, "x2", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.bx = ParseInt(vc, val + vlen);
                }
                if (FindAttr(c, attrs_end, "y2", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.by = ParseInt(vc, val + vlen);
                }
                emit = true;
            }
            else if (tag_is("circle"))
            {
                sh.kind = SvgShapeKind::Circle;
                if (FindAttr(c, attrs_end, "cx", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.ax = ParseInt(vc, val + vlen);
                }
                if (FindAttr(c, attrs_end, "cy", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.ay = ParseInt(vc, val + vlen);
                }
                if (FindAttr(c, attrs_end, "r", &val, &vlen))
                {
                    const u8* vc = val;
                    sh.bx = ParseInt(vc, val + vlen);
                }
                emit = true;
            }
            else if (tag_is("path"))
            {
                if (FindAttr(c, attrs_end, "d", &val, &vlen))
                {
                    sh.kind = SvgShapeKind::Path;
                    sh.path_segment_start = image->path_segment_count;
                    sh.path_segment_count = ParsePathData(val, vlen, image);
                    emit = sh.path_segment_count > 0;
                }
            }
            if (emit)
                image->shape_count++;
        }
        // Advance past this opening tag.
        c = attrs_end + 1;
        (void)tag_open;
    }
    return true;
}

void SvgRender(const SvgImage& image, i32 target_x, i32 target_y, u32 target_w, u32 target_h)
{
    if (image.viewbox_w == 0 || image.viewbox_h == 0 || target_w == 0 || target_h == 0)
        return;
    // Affine map from viewbox (vbx + vbw, vby + vbh) to target.
    // Q16.16 fixed-point multiply.
    const i64 sx_q16 = (static_cast<i64>(target_w) << 16) / image.viewbox_w;
    const i64 sy_q16 = (static_cast<i64>(target_h) << 16) / image.viewbox_h;
    auto map_x = [&](i32 x) -> i32
    { return target_x + static_cast<i32>(((static_cast<i64>(x) - image.viewbox_x) * sx_q16) >> 16); };
    auto map_y = [&](i32 y) -> i32
    { return target_y + static_cast<i32>(((static_cast<i64>(y) - image.viewbox_y) * sy_q16) >> 16); };
    auto map_r = [&](i32 r) -> u32 { return static_cast<u32>((static_cast<i64>(r) * sx_q16) >> 16); };

    for (u32 i = 0; i < image.shape_count; ++i)
    {
        const SvgShape& sh = image.shapes[i];
        switch (sh.kind)
        {
        case SvgShapeKind::Line:
            FramebufferDrawLine(map_x(sh.ax), map_y(sh.ay), map_x(sh.bx), map_y(sh.by), sh.stroke_rgb);
            break;
        case SvgShapeKind::Circle:
            FramebufferDrawCircle(map_x(sh.ax), map_y(sh.ay), map_r(sh.bx), sh.stroke_rgb);
            break;
        case SvgShapeKind::Path:
        {
            // Map every endpoint into target space via a small scratch
            // PathSegment[] (max 64 segments per shape).
            constinit static PathSegment scratch[64]{};
            const u32 n = sh.path_segment_count > 64 ? 64 : sh.path_segment_count;
            for (u32 s = 0; s < n; ++s)
            {
                PathSegment src = image.path_segments[sh.path_segment_start + s];
                src.pts[0].x = map_x(src.pts[0].x);
                src.pts[0].y = map_y(src.pts[0].y);
                if (src.op == PathOp::Cubic)
                {
                    src.pts[1].x = map_x(src.pts[1].x);
                    src.pts[1].y = map_y(src.pts[1].y);
                    src.pts[2].x = map_x(src.pts[2].x);
                    src.pts[2].y = map_y(src.pts[2].y);
                }
                scratch[s] = src;
            }
            FramebufferStrokePath(scratch, n, sh.stroke_width, sh.stroke_rgb);
            break;
        }
        }
    }
}

namespace
{
constexpr const char kSvgSelfTestSource[] = R"svg(<svg viewBox="0 0 100 100">
<line x1="0" y1="0" x2="100" y2="100" stroke="#ffffff" stroke-width="2"/>
<circle cx="50" cy="50" r="25" stroke="#00ff00" stroke-width="1"/>
<path d="M 10 90 L 90 90 C 90 50 10 50 10 90 Z" stroke="#ff8000" stroke-width="2"/>
</svg>)svg";
} // namespace

bool SvgSelfTest()
{
    SvgImage img{};
    constinit static SvgShape shapes[8]{};
    constinit static PathSegment segs[32]{};
    img.shapes = shapes;
    img.max_shapes = sizeof(shapes) / sizeof(shapes[0]);
    img.path_segments = segs;
    img.max_path_segments = sizeof(segs) / sizeof(segs[0]);

    const auto* bytes = reinterpret_cast<const u8*>(kSvgSelfTestSource);
    const u32 len = sizeof(kSvgSelfTestSource) - 1;
    if (!SvgParse(bytes, len, &img))
    {
        SerialWrite("[video/svg] selftest FAIL: parse rejected valid input\n");
        return false;
    }
    if (img.shape_count != 3)
    {
        SerialWrite("[video/svg] selftest FAIL: expected 3 shapes\n");
        return false;
    }
    if (img.viewbox_w != 100 || img.viewbox_h != 100)
    {
        SerialWrite("[video/svg] selftest FAIL: wrong viewBox\n");
        return false;
    }
    if (img.shapes[0].kind != SvgShapeKind::Line)
    {
        SerialWrite("[video/svg] selftest FAIL: shape 0 not Line\n");
        return false;
    }
    if (img.shapes[1].kind != SvgShapeKind::Circle || img.shapes[1].bx != 25)
    {
        SerialWrite("[video/svg] selftest FAIL: shape 1 not Circle r=25\n");
        return false;
    }
    if (img.shapes[2].kind != SvgShapeKind::Path || img.shapes[2].path_segment_count < 3)
    {
        SerialWrite("[video/svg] selftest FAIL: path didn't decode\n");
        return false;
    }
    SerialWrite("[video/svg] selftest ok (3 shapes: line/circle/path with cubic)\n");
    return true;
}

} // namespace duetos::drivers::video
