#include "input/ps2_encode.h"
#include <unordered_map>
// WIN32_LEAN_AND_MEAN is already defined project-wide via CMake compile
// definitions (target_compile_definitions in tests/CMakeLists.txt).
// Do NOT re-define it here — duplicate definition would trigger C4005 /WX.
#include <windows.h>

namespace duetos::vmm
{

// ---------------------------------------------------------------------------
// Scan code set 1 tables.
//
// The DuetOS kernel ps2kbd driver explicitly forces scan code set 1 on the
// keyboard device during ControllerInit() (step 8: sends 0xF0 then 0x01).
// Set-1 protocol:
//   make  (non-extended): single byte, e.g. 0x1E for 'A'.
//   break (non-extended): single byte, 0x80 | make_byte, e.g. 0x9E for 'A'.
//   make  (extended):     0xE0 followed by make_byte.
//   break (extended):     0xE0 followed by (0x80 | make_byte).
//
// Scancodes cross-referenced against ps2kbd.cpp constants and the
// kKeymapLowerUS table (indexed by scancode: 'a'=0x1E confirms index).
// ---------------------------------------------------------------------------

// Helper type alias to keep pair construction readable.
using VkSc = std::pair<uint32_t, uint8_t>;

// Non-extended VK -> set-1 make byte.
static const std::unordered_map<uint32_t, uint8_t>& BaseTable()
{
    // Use explicit uint8_t casts on every value to satisfy MSVC /W4:
    // brace-init of std::pair<uint32_t,uint8_t> from int literals triggers
    // C4244 (int->uint8_t narrowing) inside <utility> under /WX.
    static const std::unordered_map<uint32_t, uint8_t> m = {
        // Letters (scancodes from kKeymapLowerUS, index = set-1 scancode).
        VkSc{'A', uint8_t{0x1E}}, VkSc{'B', uint8_t{0x30}},
        VkSc{'C', uint8_t{0x2E}}, VkSc{'D', uint8_t{0x20}},
        VkSc{'E', uint8_t{0x12}}, VkSc{'F', uint8_t{0x21}},
        VkSc{'G', uint8_t{0x22}}, VkSc{'H', uint8_t{0x23}},
        VkSc{'I', uint8_t{0x17}}, VkSc{'J', uint8_t{0x24}},
        VkSc{'K', uint8_t{0x25}}, VkSc{'L', uint8_t{0x26}},
        VkSc{'M', uint8_t{0x32}}, VkSc{'N', uint8_t{0x31}},
        VkSc{'O', uint8_t{0x18}}, VkSc{'P', uint8_t{0x19}},
        VkSc{'Q', uint8_t{0x10}}, VkSc{'R', uint8_t{0x13}},
        VkSc{'S', uint8_t{0x1F}}, VkSc{'T', uint8_t{0x14}},
        VkSc{'U', uint8_t{0x16}}, VkSc{'V', uint8_t{0x2F}},
        VkSc{'W', uint8_t{0x11}}, VkSc{'X', uint8_t{0x2D}},
        VkSc{'Y', uint8_t{0x15}}, VkSc{'Z', uint8_t{0x2C}},
        // Number row.
        VkSc{'1', uint8_t{0x02}}, VkSc{'2', uint8_t{0x03}},
        VkSc{'3', uint8_t{0x04}}, VkSc{'4', uint8_t{0x05}},
        VkSc{'5', uint8_t{0x06}}, VkSc{'6', uint8_t{0x07}},
        VkSc{'7', uint8_t{0x08}}, VkSc{'8', uint8_t{0x09}},
        VkSc{'9', uint8_t{0x0A}}, VkSc{'0', uint8_t{0x0B}},
        // Common control keys (non-extended variants).
        VkSc{VK_RETURN,   uint8_t{0x1C}},
        VkSc{VK_ESCAPE,   uint8_t{0x01}},
        VkSc{VK_BACK,     uint8_t{0x0E}},
        VkSc{VK_TAB,      uint8_t{0x0F}},
        VkSc{VK_SPACE,    uint8_t{0x39}},
        VkSc{VK_LSHIFT,   uint8_t{0x2A}},
        VkSc{VK_RSHIFT,   uint8_t{0x36}},
        VkSc{VK_SHIFT,    uint8_t{0x2A}}, // generic Shift -> left scancode
        VkSc{VK_LCONTROL, uint8_t{0x1D}},
        VkSc{VK_CONTROL,  uint8_t{0x1D}}, // generic Ctrl -> left scancode
        VkSc{VK_MENU,     uint8_t{0x38}}, // generic Alt -> left scancode
        VkSc{VK_LMENU,    uint8_t{0x38}},
        // F-keys (kScanF1=0x3B..kScanF10=0x44, F11=0x57, F12=0x58 per ps2kbd.cpp).
        VkSc{VK_F1,  uint8_t{0x3B}}, VkSc{VK_F2,  uint8_t{0x3C}},
        VkSc{VK_F3,  uint8_t{0x3D}}, VkSc{VK_F4,  uint8_t{0x3E}},
        VkSc{VK_F5,  uint8_t{0x3F}}, VkSc{VK_F6,  uint8_t{0x40}},
        VkSc{VK_F7,  uint8_t{0x41}}, VkSc{VK_F8,  uint8_t{0x42}},
        VkSc{VK_F9,  uint8_t{0x43}}, VkSc{VK_F10, uint8_t{0x44}},
        VkSc{VK_F11, uint8_t{0x57}}, VkSc{VK_F12, uint8_t{0x58}},
        // Caps Lock.
        VkSc{VK_CAPITAL, uint8_t{0x3A}},
    };
    return m;
}

// Extended VK -> set-1 make byte (each prefixed with 0xE0 on the wire).
// Sourced from ps2kbd.cpp kScanExt* constants.
static const std::unordered_map<uint32_t, uint8_t>& ExtTable()
{
    static const std::unordered_map<uint32_t, uint8_t> m = {
        VkSc{VK_RIGHT,    uint8_t{0x4D}}, // kScanExtArrowRight
        VkSc{VK_LEFT,     uint8_t{0x4B}}, // kScanExtArrowLeft
        VkSc{VK_UP,       uint8_t{0x48}}, // kScanExtArrowUp
        VkSc{VK_DOWN,     uint8_t{0x50}}, // kScanExtArrowDown
        VkSc{VK_HOME,     uint8_t{0x47}}, // kScanExtHome
        VkSc{VK_END,      uint8_t{0x4F}}, // kScanExtEnd
        VkSc{VK_PRIOR,    uint8_t{0x49}}, // kScanExtPageUp
        VkSc{VK_NEXT,     uint8_t{0x51}}, // kScanExtPageDown
        VkSc{VK_INSERT,   uint8_t{0x52}}, // kScanExtInsert
        VkSc{VK_DELETE,   uint8_t{0x53}}, // kScanExtDelete
        VkSc{VK_RCONTROL, uint8_t{0x1D}}, // kScanExtRCtrl
        VkSc{VK_RMENU,    uint8_t{0x38}}, // kScanExtRAlt
    };
    return m;
}

std::vector<uint8_t> VkToSet1(uint32_t vk, bool down, bool extended)
{
    const auto& tbl = extended ? ExtTable() : BaseTable();
    auto it = tbl.find(vk);
    if (it == tbl.end())
    {
        return {};
    }

    std::vector<uint8_t> out;
    if (extended)
    {
        out.push_back(uint8_t{0xE0});
    }
    // Set-1: make = scancode byte, break = 0x80 | scancode byte.
    out.push_back(down ? it->second : static_cast<uint8_t>(0x80u | it->second));
    return out;
}

// ---------------------------------------------------------------------------
// PS/2 mouse packet builder — standard 3-byte protocol.
//
// The DuetOS ps2mouse driver uses ONLY the 3-byte protocol. The driver
// header explicitly states: "Standard 3-byte protocol only. Wheel /
// 5-button extensions need a device-specific sample-rate handshake."
// No IntelliMouse knock (200/100/80) is performed; 4-byte packets are
// never read. The `intelliMouse` parameter is accepted for call-site
// symmetry but is currently ignored — always 3-byte output.
//
// Packet layout (mirrors ps2mouse.h struct MousePacket comments):
//   byte0: [Y_OV|X_OV|Y_SGN|X_SGN|1|MB|RB|LB]
//   byte1: X delta (uint8_t, sign indicated by X_SGN in byte0).
//   byte2: Y delta (uint8_t, sign indicated by Y_SGN in byte0).
//          PS/2 Y-positive = mouse moved UP; screen-space dy-positive = DOWN,
//          so we negate dy before encoding.
// ---------------------------------------------------------------------------

static int8_t ClampDelta(int v)
{
    if (v < -127) return int8_t{-127};
    if (v >  127) return int8_t{127};
    return static_cast<int8_t>(v);
}

std::vector<uint8_t> MousePacket(int dx, int dy, uint32_t buttons,
                                 int wheel, bool /*intelliMouse*/)
{
    // Negate dy: screen-space down (+) -> PS/2 up (-).
    int8_t x = ClampDelta(dx);
    int8_t y = ClampDelta(-dy);

    uint8_t b0 = uint8_t{0x08}; // always-1 bit (packet re-sync marker)
    if (buttons & 0x1u) b0 = static_cast<uint8_t>(b0 | 0x01u); // left
    if (buttons & 0x2u) b0 = static_cast<uint8_t>(b0 | 0x02u); // right
    if (buttons & 0x4u) b0 = static_cast<uint8_t>(b0 | 0x04u); // middle
    if (x < 0) b0 = static_cast<uint8_t>(b0 | 0x10u);          // X_SGN
    if (y < 0) b0 = static_cast<uint8_t>(b0 | 0x20u);          // Y_SGN

    // wheel is intentionally unused: driver is 3-byte only.
    (void)wheel;

    return {b0, static_cast<uint8_t>(x), static_cast<uint8_t>(y)};
}

} // namespace duetos::vmm
