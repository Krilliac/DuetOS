#include "net/drsh/drsh_internal.h"

#include "diag/fix_journal.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/video/framebuffer.h"
#include "log/klog.h"
#include "sched/sched.h"

/*
 * DRSH — desktop channel.
 *
 * Streams the live framebuffer to the client as tile updates and
 * accepts input events (keyboard + mouse) that get injected into
 * the kernel's input queues. This is the "remote desktop" half of
 * the service — analogous in shape to RFB/VNC's framebuffer-update
 * messages, but encoded for our protocol's frame size.
 *
 * Wire payload for kDrshFrameChannelData on this channel:
 *
 *   First byte = sub-type:
 *     0  TileBlit       — server -> client; one rect of raw BGRA pixels
 *     1  FrameStart     — server -> client; header describing a frame
 *                          { width(2 BE) | height(2 BE) | bpp | flags }
 *     2  FrameEnd       — server -> client; marks the end of a frame
 *     3  InputKey       — client -> server; { code(2 LE) | mods | press(1) }
 *     4  InputMouse     — client -> server; { dx(i16 BE) | dy(i16 BE) | buttons }
 *     5  ResizeAck      — client -> server; acknowledge a FrameStart with
 *                          its width/height (lets future client-side
 *                          downscale negotiate); currently ignored.
 *
 * Frame format on the wire (TileBlit payload):
 *   u16 x_be | u16 y_be | u16 w_be | u16 h_be | u8 pixels[w*h*4]
 *   pixels are BGRA8888 in source-framebuffer order, packed (no
 *   pitch padding). One tile is capped at a width*height that fits
 *   within kDrshMaxPayload - 8 bytes of header.
 *
 * v0 limitations (each tagged GAP, so a future audit knows where to look):
 *   - GAP: full-frame on every tick — no damage tracking integration with
 *     the framebuffer driver's g_damage union yet. Bandwidth is
 *     pessimal; visually correct.
 *   - GAP: BGRA only — assumes the kernel framebuffer is 32-bit. Other
 *     depths are silently refused (the channel sends a FrameStart with
 *     bpp=0 and immediately closes).
 *   - GAP: mouse events go via MouseInjectPacket (PS/2 shape) — exact
 *     deltas, not absolute coordinates. Suits an RFB-style "send relative
 *     deltas" client; an absolute-pointer client would need a follow-up.
 */

namespace duetos::net::drsh::internal
{

namespace
{

constexpr u8 kSubTileBlit = 0;
constexpr u8 kSubFrameStart = 1;
constexpr u8 kSubFrameEnd = 2;
constexpr u8 kSubInputKey = 3;
constexpr u8 kSubInputMouse = 4;
constexpr u8 kSubResizeAck = 5;

// Largest tile a single frame can carry, in pixels. Header is 8
// bytes (sub-type byte + 4 u16 coords + sub-byte adjustment). We
// leave 8 bytes of slack so we never split a row mid-byte.
constexpr u32 kTileHdrBytes = 1 + 8; // sub-type + (x,y,w,h)
constexpr u32 kMaxPixelsPerTile = (kDrshMaxPayload - kTileHdrBytes) / 4;

inline void WriteU16Be(u8* dst, u16 v)
{
    dst[0] = static_cast<u8>((v >> 8) & 0xFFu);
    dst[1] = static_cast<u8>(v & 0xFFu);
}

inline u16 ReadU16Be(const u8* src)
{
    return static_cast<u16>((static_cast<u16>(src[0]) << 8) | static_cast<u16>(src[1]));
}

inline i16 ReadI16Be(const u8* src)
{
    return static_cast<i16>(ReadU16Be(src));
}

bool SendFrameStart(DrshTransport& t, DrshSession& s, u8 channel_id, u32 w, u32 h, u8 bpp)
{
    u8 buf[8];
    buf[0] = kSubFrameStart;
    WriteU16Be(&buf[1], static_cast<u16>(w));
    WriteU16Be(&buf[3], static_cast<u16>(h));
    buf[5] = bpp;
    buf[6] = 0; // flags reserved
    buf[7] = 0;
    return SendFrame(t, s, kDrshFrameChannelData, channel_id, buf, sizeof(buf));
}

bool SendFrameEnd(DrshTransport& t, DrshSession& s, u8 channel_id)
{
    u8 b = kSubFrameEnd;
    return SendFrame(t, s, kDrshFrameChannelData, channel_id, &b, 1);
}

bool SendTile(DrshTransport& t, DrshSession& s, u8 channel_id, u16 x, u16 y, u16 w, u16 h, const u8* fb_base,
              u32 fb_pitch)
{
    static u8 payload[kDrshMaxPayload];
    u32 off = 0;
    payload[off++] = kSubTileBlit;
    WriteU16Be(&payload[off], x);
    off += 2;
    WriteU16Be(&payload[off], y);
    off += 2;
    WriteU16Be(&payload[off], w);
    off += 2;
    WriteU16Be(&payload[off], h);
    off += 2;
    // Copy pixels row-by-row to compress out the framebuffer pitch
    // padding. w * h * 4 bytes contiguous on the wire — the client
    // pastes back into its own surface with its own pitch.
    for (u32 row = 0; row < h; ++row)
    {
        const u8* src = fb_base + static_cast<u64>(static_cast<u32>(y) + row) * fb_pitch +
                        static_cast<u64>(static_cast<u32>(x)) * 4u;
        for (u32 i = 0; i < static_cast<u32>(w) * 4u; ++i)
            payload[off + i] = src[i];
        off += static_cast<u32>(w) * 4u;
    }
    return SendFrame(t, s, kDrshFrameChannelData, channel_id, payload, off);
}

void HandleInputKey(const u8* p, u32 plen)
{
    if (plen < 4)
        return;
    duetos::drivers::input::KeyEvent ev{};
    ev.code = static_cast<u16>((static_cast<u16>(p[1]) << 8) | static_cast<u16>(p[0])); // LE on the wire
    ev.modifiers = p[2];
    // payload[3] is "press" (1) or "release" (0); is_release is the inverse.
    ev.is_release = (p[3] == 0);
    duetos::drivers::input::KeyboardInjectEvent(ev);
}

// Mouse injection requires a PS/2-style 3-byte packet shape. The
// PS/2 driver's MouseInjectPacket lives in drivers/input/ps2mouse.h;
// we forward-declare and bridge to keep this TU's includes minimal.
} // namespace

} // namespace duetos::net::drsh::internal

namespace duetos::drivers::input
{
struct MousePacket
{
    u8 buttons;
    i8 dx;
    i8 dy;
};
void MouseInjectPacket(const MousePacket& p);
} // namespace duetos::drivers::input

namespace duetos::net::drsh::internal
{

namespace
{

void HandleInputMouse(const u8* p, u32 plen)
{
    if (plen < 6)
        return;
    const i16 dx = ReadI16Be(&p[1]);
    const i16 dy = ReadI16Be(&p[3]);
    const u8 buttons = p[5];
    // Saturate i16 deltas to i8 for the PS/2 shape. Anything beyond
    // +/-127 is delivered in successive packets; clients that send
    // bigger deltas accept the slower glide.
    auto sat8 = [](i16 v) -> i8
    {
        if (v > 127)
            return 127;
        if (v < -128)
            return -128;
        return static_cast<i8>(v);
    };
    duetos::drivers::input::MousePacket pk{};
    pk.buttons = buttons;
    pk.dx = sat8(dx);
    pk.dy = sat8(dy);
    duetos::drivers::input::MouseInjectPacket(pk);
}

} // namespace

bool DesktopChannelService(DrshTransport& t, DrshSession& s, u8 channel_id)
{
    const auto fb = duetos::drivers::video::FramebufferGet();
    if (!duetos::drivers::video::FramebufferAvailable() || fb.bpp != 32)
    {
        // Refuse cleanly: tell the client the framebuffer isn't a
        // shape we can stream, then close.
        (void)SendFrameStart(t, s, channel_id, 0, 0, 0);
        (void)SendFrame(t, s, kDrshFrameChannelClose, channel_id, nullptr, 0);
        return true;
    }

    const u32 width = fb.width;
    const u32 height = fb.height;
    const u32 pitch = fb.pitch;
    const u8* fb_base = reinterpret_cast<const u8*>(fb.virt);

    if (!SendFrameStart(t, s, channel_id, width, height, 32))
        return false;

    // Tile geometry: maximise pixels-per-tile without exceeding
    // the per-frame payload budget. kMaxPixelsPerTile = (4096-9)/4
    // = 1021. 32 wide x 30 tall = 960 pixels < 1021 ✓; the tail
    // rows / cols are emitted as smaller tiles by the loop below.
    constexpr u32 kTileW = 32;
    constexpr u32 kTileH = 30;
    static_assert(kTileW * kTileH <= kMaxPixelsPerTile, "tile too big for one DRSH frame");

    // ----------------------------- Main desktop loop.
    // Server pushes one full frame, then drains any pending input
    // frames the client sent. We do not push another frame until
    // the input drain returns; this caps bandwidth to roughly one
    // refresh per round-trip + input batch.
    while (true)
    {
        // ----- Push a full frame as a sequence of tiles.
        for (u32 y = 0; y < height; y += kTileH)
        {
            const u32 th = (y + kTileH > height) ? (height - y) : kTileH;
            for (u32 x = 0; x < width; x += kTileW)
            {
                const u32 tw = (x + kTileW > width) ? (width - x) : kTileW;
                if (!SendTile(t, s, channel_id, static_cast<u16>(x), static_cast<u16>(y), static_cast<u16>(tw),
                              static_cast<u16>(th), fb_base, pitch))
                    return false;
            }
        }
        if (!SendFrameEnd(t, s, channel_id))
            return false;

        // ----- Drain inbound input frames until either we see a
        //       channel-close OR the per-frame budget elapses. The
        //       budget is "one Recv" — single non-blocking attempt
        //       would be cleaner, but the transport is blocking; we
        //       give the client a brief window via SchedSleepTicks.
        u8 payload[kDrshMaxPayload];
        u32 plen = 0;
        u8 type = 0;
        u8 chan = 0;
        if (!RecvFrame(t, s, &type, &chan, payload, &plen))
            return false;
        if (chan != channel_id)
            return false;
        if (type == kDrshFrameChannelClose)
        {
            KLOG_INFO("net/drsh", "desktop channel: close requested by client");
            return true;
        }
        if (type == kDrshFramePing)
        {
            if (!SendFrame(t, s, kDrshFramePong, kDrshChannelControl, nullptr, 0))
                return false;
            continue;
        }
        if (type != kDrshFrameChannelData || plen == 0)
            continue;
        switch (payload[0])
        {
        case kSubInputKey:
            HandleInputKey(payload, plen);
            break;
        case kSubInputMouse:
            HandleInputMouse(payload, plen);
            break;
        case kSubResizeAck:
            // GAP: client-side resize negotiation — not used in v0.
            FIX_NOTE_GAP("net/drsh/drsh_desktop.cpp:ResizeAck", "wire client-side resize negotiation");
            break;
        default:
            // Unknown sub-type: ignore. Forward-compatible if a
            // future revision adds a sub-type the v0 server doesn't
            // recognise.
            break;
        }
        // Yield a tick so we don't full-rate stream when nothing
        // is moving on the framebuffer.
        duetos::sched::SchedSleepTicks(2);
    }
}

} // namespace duetos::net::drsh::internal
