#pragma once
#include <cstdint>
#include <vector>

namespace duetos::vmm
{
// Win32 virtual-key (+ extended flag) -> scan-set-1 byte sequence.
// Set 1 break codes are (0x80 | make_byte); extended keys are
// prefixed with 0xE0. Returns empty for keys with no PS/2 mapping.
// NOTE: The DuetOS kernel ps2kbd driver explicitly forces scan code
// set 1 (sends 0xF0, 0x01 during init), so the encoder targets set 1.
std::vector<uint8_t> VkToSet1(uint32_t vk, bool down, bool extended);

// Build one PS/2 mouse movement packet (standard 3-byte format).
// The DuetOS ps2mouse driver uses the 3-byte protocol only — no
// IntelliMouse/wheel extension (no sample-rate knock sequence).
// dx/dy are screen-space deltas (positive = right / down).
// buttons: bit0=L bit1=R bit2=M.
// wheel is ignored (kept in signature for call-site symmetry; always
// produces a 3-byte packet regardless).
std::vector<uint8_t> MousePacket(int dx, int dy, uint32_t buttons,
                                 int wheel, bool intelliMouse);
} // namespace duetos::vmm
