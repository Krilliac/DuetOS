#!/usr/bin/env python3
# DuetOS VESA E-EDID base-block fuzz seed generator.
#
# WHAT  Emits 128-byte VESA E-EDID base blocks with the canonical
#       8-byte header, valid manufacturer-ID encoding, sensible
#       version/revision, and a valid 1-byte checksum so the
#       parser walks every byte of the block instead of bailing
#       at byte 0 or 127. One "happy path" seed (1080p DTD +
#       monitor name + range limits) and one "edge" seed (every
#       descriptor slot is a Dummy 0x10 descriptor — exercises
#       the descriptor-kind dispatcher's fall-through arm).
#
# WHY   The 8-byte EDID header (00 FF FF FF FF FF FF 00) is hard
#       for random mutation to hit, and even then the checksum
#       gate eliminates 255 of every 256 inputs at the byte-127
#       step. A seed that clears both gates puts the fuzzer
#       inside the descriptor walkers and the DTD pixel-clock /
#       refresh-rate math from cycle 1.
#
# USAGE  python3 gen_edid_seeds.py <out_dir>

import os
import sys


def fix_checksum(b: bytearray) -> bytearray:
    assert len(b) == 128
    s = sum(b[:127]) & 0xFF
    b[127] = (256 - s) & 0xFF
    return b


def mfg_id(a: str, b: str, c: str) -> bytes:
    def v(ch: str) -> int:
        return (ord(ch) - ord('A') + 1) & 0x1F
    word = (v(a) << 10) | (v(b) << 5) | v(c)
    return bytes([(word >> 8) & 0xFF, word & 0xFF])


def build_1080p_dtd() -> bytes:
    # Pixel clock 148.5 MHz -> 14850 (units of 10 kHz).
    pixel_clock = 14850
    h_active, h_blanking = 1920, 280
    v_active, v_blanking = 1080, 45
    h_sync_offset, h_sync_pulse = 88, 44
    v_sync_offset, v_sync_pulse = 4, 5
    h_image_mm, v_image_mm = 530, 300
    d = bytearray(18)
    d[0] = pixel_clock & 0xFF
    d[1] = (pixel_clock >> 8) & 0xFF
    d[2] = h_active & 0xFF
    d[3] = h_blanking & 0xFF
    d[4] = ((h_active >> 4) & 0xF0) | ((h_blanking >> 8) & 0x0F)
    d[5] = v_active & 0xFF
    d[6] = v_blanking & 0xFF
    d[7] = ((v_active >> 4) & 0xF0) | ((v_blanking >> 8) & 0x0F)
    d[8] = h_sync_offset & 0xFF
    d[9] = h_sync_pulse & 0xFF
    d[10] = (((v_sync_offset & 0x0F) << 4) | (v_sync_pulse & 0x0F))
    d[11] = (((h_sync_offset >> 8) & 0x03) << 6) | (((h_sync_pulse >> 8) & 0x03) << 4) \
            | (((v_sync_offset >> 4) & 0x03) << 2) | ((v_sync_pulse >> 4) & 0x03)
    d[12] = h_image_mm & 0xFF
    d[13] = v_image_mm & 0xFF
    d[14] = ((h_image_mm >> 4) & 0xF0) | ((v_image_mm >> 8) & 0x0F)
    # Borders zero.
    d[15] = 0
    d[16] = 0
    # Flags byte: bit 7 interlace=0, bits 4-3 sync_type=3 (digital
    # separate), bits 2-1 vsync polarity=1 (+), bit 1 hsync
    # polarity=1 (+).
    d[17] = (3 << 3) | (1 << 2) | (1 << 1)
    return bytes(d)


def monitor_descriptor(kind: int, text: bytes) -> bytes:
    # Monitor descriptor: bytes 0-1 = 0x0000 (signals non-DTD),
    # byte 2 = reserved 0, byte 3 = kind, byte 4 = 0, bytes 5-17 =
    # payload (13 bytes). String descriptors pad with 0x0A then 0x20.
    payload = bytearray(13)
    n = min(len(text), 13)
    payload[:n] = text[:n]
    if n < 13:
        payload[n] = 0x0A  # LF terminator
        for i in range(n + 1, 13):
            payload[i] = 0x20
    return bytes([0x00, 0x00, 0x00, kind, 0x00]) + bytes(payload)


def build_block(descriptor_slots: list) -> bytearray:
    b = bytearray(128)
    # Header.
    b[0:8] = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
    # Manufacturer ID "DEL".
    b[8:10] = mfg_id('D', 'E', 'L')
    # Product code (LE).
    b[10:12] = (0xABCD).to_bytes(2, 'little')
    # Serial number (LE).
    b[12:16] = (0xDEADBEEF).to_bytes(4, 'little')
    # Week + Year (1990 + 34 = 2024).
    b[16] = 10
    b[17] = 34
    # EDID 1.4.
    b[18] = 1
    b[19] = 4
    # Video input (digital, 8 bpc, HDMI-a).
    b[20] = 0x80 | (1 << 4) | 2  # bit7 digital, bits6:4 bpc=001=6→use 010=8bpc; bits3:0 iface=2
    # Screen size (cm).
    b[21] = 53
    b[22] = 30
    # Gamma (raw byte; e.g. 2.2 -> 120).
    b[23] = 120
    # Features.
    b[24] = (1 << 7) | (1 << 6) | (1 << 5) | (1 << 2)  # standby/suspend/active_off + sRGB
    # Chromaticity / colour bits (10 bytes zero is fine for v0).
    # Established timings (3 bytes).
    b[35] = 0
    b[36] = 0
    b[37] = 0
    # Standard timings (8 × 2-byte slots — 0x01 0x01 marks "unused").
    for i in range(8):
        b[38 + 2 * i] = 0x01
        b[38 + 2 * i + 1] = 0x01
    # Four descriptor slots @ 54..125.
    for i, desc in enumerate(descriptor_slots[:4]):
        assert len(desc) == 18
        b[54 + i * 18:54 + (i + 1) * 18] = desc
    # Pad unused descriptor slots with Dummy descriptors.
    for i in range(len(descriptor_slots), 4):
        dummy = monitor_descriptor(0x10, b"")
        b[54 + i * 18:54 + (i + 1) * 18] = dummy
    # Extension count.
    b[126] = 0
    # Checksum.
    return fix_checksum(b)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/edid"
    os.makedirs(out, exist_ok=True)

    # Happy path: 1080p DTD as descriptor 1, monitor name as
    # descriptor 2, range limits as descriptor 3, ASCII string as
    # descriptor 4.
    happy = build_block([
        build_1080p_dtd(),
        monitor_descriptor(0xFC, b"DUETOS-FUZZ"),  # MonitorName
        monitor_descriptor(0xFD,
                           bytes([50, 75, 30, 83, 14]) + b"\x00\x0a" + b"\x20" * 6),
        monitor_descriptor(0xFE, b"ASCII-SEED"),
    ])
    open(os.path.join(out, "happy_1080p.bin"), "wb").write(happy)

    # Edge: every descriptor slot is a Dummy 0x10 — exercises the
    # descriptor-kind fall-through arm.
    edge = build_block([
        monitor_descriptor(0x10, b""),
        monitor_descriptor(0x10, b""),
        monitor_descriptor(0x10, b""),
        monitor_descriptor(0x10, b""),
    ])
    open(os.path.join(out, "edge_all_dummy.bin"), "wb").write(edge)

    # Header-only stub: valid header + checksum but every other byte
    # zero. Exercises the version=0/revision=0 path the parser must
    # tolerate.
    stub = bytearray(128)
    stub[0:8] = bytes([0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00])
    fix_checksum(stub)
    open(os.path.join(out, "header_only.bin"), "wb").write(bytes(stub))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
