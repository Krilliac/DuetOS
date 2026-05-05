#include "drivers/video/cursor.h"

#include "drivers/video/framebuffer.h"

namespace duetos::drivers::video
{

namespace
{

// Shaped-mask arrow sprite. 12 columns x 20 rows; '#' = opaque
// white, '.' = opaque black (outline), ' ' = transparent (the
// background pixel shows through). Classic NW-pointing arrow
// silhouette — the shape every Windows / X11 / macOS cursor
// converges on.
constexpr u32 kCursorWidth = 12;
constexpr u32 kCursorHeight = 20;

// Pixel kinds. Packed 2 bits per pixel would save space but the
// full byte-per-pixel form survives easy editing — 240 bytes of
// .rodata isn't worth compressing.
enum : u8
{
    kPxTransparent = 0,
    kPxOutline = 1, // drawn as black
    kPxFill = 2,    // drawn as white
};

// clang-format off
constinit const u8 kArrowMask[kCursorHeight][kCursorWidth] = {
    {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, // row 0  #
    {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, //        ##
    {1, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}, //        #.#
    {1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0}, //        #..#
    {1, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, // widest
    {1, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1}, // elbow — tail starts
    {1, 2, 2, 2, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 2, 1, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 2, 1, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {1, 1, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0},
    {1, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// I-beam: vertical bar with serifs top + bottom. Hot spot is
// the middle column (col 5/6); the centre rows define a thin
// fill flanked by outline.
constinit const u8 kIBeamMask[kCursorHeight][kCursorWidth] = {
    {0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0}, // row 0  serif top
    {0, 0, 0, 0, 1, 2, 2, 2, 1, 0, 0, 0}, //        ###
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0}, //         #
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 2, 1, 0, 0, 0}, //        ###
    {0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0}, //        serif bot
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Pointing hand: outlined index finger + thumb stub. Hot spot
// at the fingertip (col 4 row 0). 12×20 is tight for a hand —
// this is a stylised glyph, not a photographic copy.
constinit const u8 kHandMask[kCursorHeight][kCursorWidth] = {
    {0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0}, // row 0   ##
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0}, //         #.#
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 1, 1, 0, 0, 0}, //         #.### (knuckles)
    {0, 0, 0, 0, 1, 2, 2, 2, 2, 1, 0, 0}, //         #....#
    {0, 1, 1, 0, 1, 2, 2, 2, 2, 2, 1, 0}, //        ## #.....#
    {1, 2, 2, 1, 1, 2, 2, 2, 2, 2, 1, 0}, //        #..##.....#
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, //        #.........#
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0},
    {0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, //         #........#
    {0, 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0}, //         #.......#
    {0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Vertical resize: ↕ arrow with arrowheads top + bottom and a
// thin shaft. Used over top / bottom window borders.
constinit const u8 kResizeNSMask[kCursorHeight][kCursorWidth] = {
    {0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0}, // row 0    ##
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0}, //         #..#
    {0, 0, 0, 1, 2, 2, 2, 2, 1, 0, 0, 0}, //        #....#
    {0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 0}, //       #......#
    {0, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 1, 1, 1, 1, 2, 2, 1, 1, 1, 1, 0},
    {0, 0, 1, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {0, 0, 0, 1, 2, 2, 2, 2, 1, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Horizontal resize: ↔ arrow. Used over left / right borders.
constinit const u8 kResizeEWMask[kCursorHeight][kCursorWidth] = {
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0},
    {0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0},
    {1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1},
    {1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1},
    {0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0},
    {0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Diagonal NESW resize: ⤢, top-right ↔ bottom-left arrow.
constinit const u8 kResizeNESWMask[kCursorHeight][kCursorWidth] = {
    {0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0}, // top-right arrowhead
    {0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 0},
    {0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 0},
    {0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 1, 0},
    {0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 1, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0},
    {0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0},
    {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0}, // bottom-left arrowhead
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Diagonal NWSE resize: ⤡, top-left ↔ bottom-right arrow.
constinit const u8 kResizeNWSEMask[kCursorHeight][kCursorWidth] = {
    {1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0}, // top-left arrowhead
    {1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0, 0},
    {1, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 2, 2, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 1, 2, 1, 0, 0},
    {0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0}, // bottom-right arrowhead
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Hourglass / "wait" shape. Two stacked triangles.
constinit const u8 kWaitMask[kCursorHeight][kCursorWidth] = {
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0}, // row 0 — top bar
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, //        full sand
    {0, 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {0, 0, 1, 2, 2, 2, 2, 2, 1, 0, 0, 0}, //        narrowing
    {0, 0, 0, 1, 2, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0}, //        waist
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 1, 2, 1, 0, 0, 0, 0, 0}, //        widening
    {0, 0, 0, 1, 2, 2, 2, 1, 0, 0, 0, 0},
    {0, 0, 1, 2, 2, 2, 2, 2, 1, 0, 0, 0},
    {0, 1, 2, 2, 2, 2, 2, 2, 2, 1, 0, 0},
    {1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 0}, //        full sand
    {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0}, //        bottom bar
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

// Active mask is dispatched on every Save / Restore / Draw. The
// pointer is updated by CursorSetShape; the table picks one of
// the four sprites declared above.
constinit const u8 (*g_active_mask)[kCursorWidth] = kArrowMask;
constinit CursorShape g_active_shape = CursorShape::Arrow;

// Custom cursor cache. Each slot holds a 12×20 mask buffer
// plus an "in use" flag and per-slot hotspot coords. Slot
// ids are 256+slot_idx so the public API can't collide with
// the CursorShape enum values (0..7).
constinit u8 g_custom_masks[kCustomCursorMax][kCursorHeight][kCursorWidth] = {};
constinit u8 g_custom_x_hot[kCustomCursorMax] = {};
constinit u8 g_custom_y_hot[kCustomCursorMax] = {};
constinit bool g_custom_in_use[kCustomCursorMax] = {};
constinit u32 g_active_custom_id = 0; // 0 = none; ≥ kCustomCursorIdBase = active

// Active hotspot — the (x_hot, y_hot) the sprite is currently
// translated by. The cursor's reported position
// (CursorPosition) is the click point; the sprite is painted
// at (g_x - hot_x, g_y - hot_y). Built-in shapes default to
// (0, 0); custom sprites set theirs from the registered
// values.
constinit u8 g_active_x_hot = 0;
constinit u8 g_active_y_hot = 0;
// Wait stack — refcounted. CursorPushWait increments + sets
// shape to Wait; CursorPopWait decrements and restores the
// pre-push shape on the last balance.
constinit u32 g_wait_depth = 0;
constinit CursorShape g_pre_wait_shape = CursorShape::Arrow;
// clang-format on

// Default colours match the v0 hardcoded behaviour (black
// outline, white fill). Theme switches update these via
// `CursorSetColours`.
constinit u32 g_colour_outline = 0x00000000;
constinit u32 g_colour_fill = 0x00FFFFFF;

constinit u32 g_x = 0;
constinit u32 g_y = 0;
constinit u32 g_desktop_rgb = 0;
constinit bool g_ready = false;

// Per-pixel save/restore buffer. The cursor can land on top of any
// pixels (desktop fill today, widgets tomorrow), so "erase by
// painting the desktop colour" stops working the moment something
// non-desktop is under the cursor. Keeping 12x20 = 240 u32s in
// .bss costs nothing and makes the cursor work correctly over any
// future painted content.
constinit u32 g_backing[kCursorHeight][kCursorWidth] = {};
constinit bool g_backing_valid = false;

// Clamp a signed addition of `delta` to `value` into [0, max).
// Required because mouse dx / dy can be much larger than the
// screen (rapid flick) or negative past the origin (cursor at
// x=0, move left).
u32 ClampMove(u32 value, i32 delta, u32 max)
{
    const i64 sum = static_cast<i64>(value) + delta;
    if (sum < 0)
    {
        return 0;
    }
    if (static_cast<u64>(sum) >= max)
    {
        return (max == 0) ? 0 : max - 1;
    }
    return static_cast<u32>(sum);
}

u32 FramebufferReadPixel(u32 x, u32 y)
{
    const auto info = FramebufferGet();
    if (info.virt == nullptr || x >= info.width || y >= info.height)
    {
        return g_desktop_rgb;
    }
    const auto* row = reinterpret_cast<const volatile u32*>(reinterpret_cast<const u8*>(info.virt) +
                                                            static_cast<u64>(y) * info.pitch);
    return row[x];
}

// Save every pixel the cursor sprite covers so a later RestoreAt
// can put them back exactly — even if a widget painted under the
// cursor between move events. Only samples pixels the mask will
// actually overwrite; fully-transparent pixels are skipped.
void SaveAt(u32 x, u32 y)
{
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            if (g_active_mask[yi][xi] == kPxTransparent)
            {
                continue;
            }
            g_backing[yi][xi] = FramebufferReadPixel(x + xi, y + yi);
        }
    }
    g_backing_valid = true;
}

void RestoreAt(u32 x, u32 y)
{
    if (!g_backing_valid)
    {
        return;
    }
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            if (g_active_mask[yi][xi] == kPxTransparent)
            {
                continue;
            }
            FramebufferPutPixel(x + xi, y + yi, g_backing[yi][xi]);
        }
    }
}

void DrawAt(u32 x, u32 y)
{
    for (u32 yi = 0; yi < kCursorHeight; ++yi)
    {
        for (u32 xi = 0; xi < kCursorWidth; ++xi)
        {
            const u8 kind = g_active_mask[yi][xi];
            if (kind == kPxTransparent)
            {
                continue;
            }
            const u32 rgb = (kind == kPxOutline) ? g_colour_outline : g_colour_fill;
            FramebufferPutPixel(x + xi, y + yi, rgb);
        }
    }
}

} // namespace

void CursorInit(u32 desktop_rgb)
{
    if (!FramebufferAvailable())
    {
        return;
    }
    const auto info = FramebufferGet();

    // Remember desktop colour for any later "restore under cursor"
    // that falls back to a flat fill (widget-less regions). Do NOT
    // clear the framebuffer here — callers may already have painted
    // desktop chrome + widgets before invoking this, and we must
    // render on top rather than wipe.
    g_desktop_rgb = desktop_rgb;

    // Centre the cursor. Guard against a framebuffer smaller than
    // the cursor sprite — clamp the starting position so the draw
    // still fits, even if only one row/column is visible.
    const u32 cx = (info.width > kCursorWidth) ? (info.width - kCursorWidth) / 2 : 0;
    const u32 cy = (info.height > kCursorHeight) ? (info.height - kCursorHeight) / 2 : 0;
    g_x = cx;
    g_y = cy;

    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
    g_ready = true;
}

void CursorMove(i32 dx, i32 dy)
{
    if (!g_ready)
    {
        return;
    }
    const auto info = FramebufferGet();
    const u32 x_max = (info.width > kCursorWidth) ? info.width - kCursorWidth : 1;
    const u32 y_max = (info.height > kCursorHeight) ? info.height - kCursorHeight : 1;

    const u32 new_x = ClampMove(g_x, dx, x_max);
    const u32 new_y = ClampMove(g_y, dy, y_max);
    if (new_x == g_x && new_y == g_y)
    {
        return;
    }
    RestoreAt(g_x, g_y);
    g_x = new_x;
    g_y = new_y;
    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
}

void CursorPosition(u32* x_out, u32* y_out)
{
    // Click point = sprite-top-left + active hotspot. Built-in
    // shapes have a (0, 0) hotspot so this collapses to
    // (g_x, g_y); custom sprites with non-zero hotspots
    // expose the visually meaningful position.
    if (x_out != nullptr)
    {
        *x_out = g_x + g_active_x_hot;
    }
    if (y_out != nullptr)
    {
        *y_out = g_y + g_active_y_hot;
    }
}

void CursorHide()
{
    if (!g_ready)
    {
        return;
    }
    RestoreAt(g_x, g_y);
    g_ready = false;
    // Leave backing_valid true — it's just stale, but the next
    // SaveAt from CursorShow replaces it before it's read.
}

void CursorShow()
{
    if (g_ready)
    {
        return; // already visible
    }
    if (!FramebufferAvailable())
    {
        return;
    }
    SaveAt(g_x, g_y);
    DrawAt(g_x, g_y);
    g_ready = true;
}

void CursorSetDesktopBackground(u32 rgb)
{
    g_desktop_rgb = rgb;
}

void CursorSetColours(u32 outline_rgb, u32 fill_rgb)
{
    g_colour_outline = outline_rgb;
    g_colour_fill = fill_rgb;
    // Repaint with the new colours if the cursor is currently
    // visible. Otherwise we'd wait for the next motion event,
    // which can be many seconds when the user is mid-task.
    if (g_ready)
    {
        DrawAt(g_x, g_y);
    }
}

namespace
{

const u8 (*MaskFor(CursorShape s))[kCursorWidth]
{
    switch (s)
    {
    case CursorShape::IBeam:
        return kIBeamMask;
    case CursorShape::Hand:
        return kHandMask;
    case CursorShape::Wait:
        return kWaitMask;
    case CursorShape::ResizeNS:
        return kResizeNSMask;
    case CursorShape::ResizeEW:
        return kResizeEWMask;
    case CursorShape::ResizeNESW:
        return kResizeNESWMask;
    case CursorShape::ResizeNWSE:
        return kResizeNWSEMask;
    case CursorShape::Arrow:
    default:
        return kArrowMask;
    }
}

} // namespace

void CursorSetShape(CursorShape s)
{
    // The change-gate is special-cased: when a custom cursor
    // is active, the comparison against g_active_shape is
    // meaningless (we always set Arrow as a sentinel). So
    // skip the gate when transitioning OUT of a custom id.
    if (s == g_active_shape && g_active_custom_id == 0)
    {
        return;
    }
    if (g_ready)
    {
        RestoreAt(g_x, g_y);
    }
    g_active_shape = s;
    g_active_mask = MaskFor(s);
    g_active_custom_id = 0;
    // Built-in shapes default to a (0, 0) hotspot — sprite
    // top-left = click point. The Arrow's tip is at (0, 0)
    // so this matches reality; IBeam / Hand are visually
    // off-centre but pre-hotspot v0 already accepted that
    // — landing precision wins is a follow-up that picks
    // a hotspot per built-in shape.
    g_active_x_hot = 0;
    g_active_y_hot = 0;
    if (g_ready)
    {
        SaveAt(g_x, g_y);
        DrawAt(g_x, g_y);
    }
}

CursorShape CursorGetShape()
{
    return g_active_shape;
}

void CursorPushWait()
{
    if (g_wait_depth == 0)
    {
        g_pre_wait_shape = g_active_shape;
        CursorSetShape(CursorShape::Wait);
    }
    ++g_wait_depth;
}

void CursorPopWait()
{
    if (g_wait_depth == 0)
    {
        return; // unbalanced — silently ignore
    }
    --g_wait_depth;
    if (g_wait_depth == 0)
    {
        CursorSetShape(g_pre_wait_shape);
    }
}

u32 CursorRegisterCustom(const u8* mask_240, u8 x_hot, u8 y_hot)
{
    if (mask_240 == nullptr)
        return 0;
    if (x_hot >= kCursorWidth || y_hot >= kCursorHeight)
        return 0;
    for (u32 i = 0; i < kCustomCursorMax; ++i)
    {
        if (g_custom_in_use[i])
            continue;
        for (u32 y = 0; y < kCursorHeight; ++y)
        {
            for (u32 x = 0; x < kCursorWidth; ++x)
            {
                const u8 v = mask_240[y * kCursorWidth + x];
                // Clamp out-of-range values to transparent so a
                // malformed PE upload can't paint garbage.
                g_custom_masks[i][y][x] = (v <= 2) ? v : 0;
            }
        }
        g_custom_x_hot[i] = x_hot;
        g_custom_y_hot[i] = y_hot;
        g_custom_in_use[i] = true;
        return kCustomCursorIdBase + i;
    }
    return 0; // table full
}

void CursorSetShapeCustom(u32 custom_id)
{
    if (custom_id < kCustomCursorIdBase || custom_id >= kCustomCursorIdBase + kCustomCursorMax)
    {
        // Not a custom id — fall back to Arrow.
        CursorSetShape(CursorShape::Arrow);
        return;
    }
    const u32 idx = custom_id - kCustomCursorIdBase;
    if (!g_custom_in_use[idx])
    {
        CursorSetShape(CursorShape::Arrow);
        return;
    }
    if (g_active_custom_id == custom_id)
        return; // change-gate
    if (g_ready)
    {
        RestoreAt(g_x, g_y);
    }
    g_active_mask = g_custom_masks[idx];
    g_active_shape = CursorShape::Arrow; // sentinel — MaskFor isn't consulted
    g_active_custom_id = custom_id;
    g_active_x_hot = g_custom_x_hot[idx];
    g_active_y_hot = g_custom_y_hot[idx];
    if (g_ready)
    {
        SaveAt(g_x, g_y);
        DrawAt(g_x, g_y);
    }
}

} // namespace duetos::drivers::video
