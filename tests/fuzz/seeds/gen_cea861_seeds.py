#!/usr/bin/env python3
# DuetOS CEA-861 EDID-extension-block fuzz seed generator.
#
# WHAT  Emits 128-byte CEA-861 extension blocks past the byte-0
#       tag gate (0x02 required) and byte-127 checksum gate, so
#       fuzz_cea861 immediately exercises the Data Block
#       Collection walker and the trailing DTD list. One "happy
#       path" seed with a realistic Audio + Video + HDMI-VSDB +
#       Speaker Allocation + Extended-Colorimetry block sequence;
#       one "DTDs only" seed (DBC empty, three DTDs in the
#       trailing area) — exercises the dtd_start_offset == 4 path.
#
# WHY   Random mutation can hit byte 0 = 0x02 in 1/256 inputs but
#       producing a coherent DBC walk where each block's
#       length-prefix advances exactly past its payload is much
#       lower probability. The 18-byte DTD slots also need byte
#       layout the EDID parser can decode. Seeded coverage gets
#       both walkers exercised on cycle 1.
#
# USAGE  python3 gen_cea861_seeds.py <out_dir>

import os
import sys


def fix_checksum(b: bytearray) -> bytearray:
    assert len(b) == 128
    s = sum(b[:127]) & 0xFF
    b[127] = (256 - s) & 0xFF
    return b


def dbc_tag_byte(tag: int, length: int) -> int:
    # Data Block Collection header byte: top 3 bits = tag, bottom 5
    # bits = payload length (in bytes, excluding the header byte).
    return ((tag & 0x07) << 5) | (length & 0x1F)


def audio_block(sads: list) -> bytes:
    # Tag 1 (Audio). Each SAD is 3 bytes. payload length = 3 * N.
    pay = b""
    for fmt, channels, srate_flags, byte2 in sads:
        pay += bytes([
            ((fmt & 0x0F) << 3) | ((channels - 1) & 0x07),
            srate_flags & 0x7F,
            byte2 & 0xFF,
        ])
    return bytes([dbc_tag_byte(1, len(pay))]) + pay


def video_block(svds: list) -> bytes:
    # Tag 2 (Video). Each SVD is 1 byte: top bit = native, bottom 7 = VIC.
    pay = bytes([(0x80 if native else 0x00) | (vic & 0x7F) for vic, native in svds])
    return bytes([dbc_tag_byte(2, len(pay))]) + pay


def hdmi_vsdb() -> bytes:
    # Tag 3 (Vendor-Specific). OUI 0x000C03 (HDMI) little-endian.
    # Followed by source physical address (2 bytes) + flags + ...
    # Minimal payload: OUI(3) + SPA(2) + flags(1) + max-TMDS(1)
    # + latency-flags(1) + audio_latency(1) + video_latency(1) = 10 bytes.
    pay = bytes([0x03, 0x0C, 0x00,             # OUI
                 0x10, 0x00,                   # SPA 1.0.0.0
                 0x00,                          # support flags (no dual-link, no DC)
                 0x1E,                          # max TMDS 150 MHz (30 * 5)
                 0xC0,                          # latency present (lat_lip + i_lat_lip)
                 25, 50])                       # audio/video latency
    return bytes([dbc_tag_byte(3, len(pay))]) + pay


def speaker_allocation() -> bytes:
    # Tag 4. Payload = 3 bytes: layout byte (FL/FR + LFE + FC) + 2 reserved.
    pay = bytes([0x07, 0x00, 0x00])
    return bytes([dbc_tag_byte(4, len(pay))]) + pay


def extended_colorimetry() -> bytes:
    # Tag 7 (Extended), extended-tag 5 (Colorimetry). 4 bytes total
    # in the payload: ext-tag + supported_lo + supported_hi + metadata.
    inner = bytes([0x05,                       # ext tag 5 = Colorimetry
                   0x03,                       # xvYCC601 + xvYCC709
                   0x00,
                   0x00])
    return bytes([dbc_tag_byte(7, len(inner))]) + inner


def edid_dtd_1080p() -> bytes:
    # Same as the EDID seed's 1080p DTD; CEA-861 DTDs share layout.
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
    d[17] = (3 << 3) | (1 << 2) | (1 << 1)
    return bytes(d)


def build_block(dbc: bytes, dtds: list) -> bytearray:
    b = bytearray(128)
    b[0] = 0x02        # tag
    b[1] = 0x03        # revision
    # dtd_start_offset: byte 2. Set to where the DTDs begin, or 0
    # if no DTDs. The DBC fills bytes 4..(dtd_start - 1).
    if dtds:
        b[2] = 4 + len(dbc)
    else:
        b[2] = 0
    # Global flags byte 3: bit 7 underscan + bit 6 audio + bit 5/4 YCbCr,
    # bottom nibble = native DTD count.
    b[3] = (1 << 7) | (1 << 6) | (1 << 5) | (1 << 4) | (len(dtds) & 0x0F)
    # DBC.
    b[4:4 + len(dbc)] = dbc
    # DTDs.
    for i, dtd in enumerate(dtds):
        off = b[2] + i * 18
        if off + 18 > 127:
            break
        b[off:off + 18] = dtd
    return fix_checksum(b)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/cea861"
    os.makedirs(out, exist_ok=True)

    # Happy path: full DBC + one DTD.
    sads = [
        (1, 2, 0x07, 0x07),  # LPCM, 2ch, 32/44.1/48 kHz, 16/20/24 bpc
        (7, 6, 0x0F, 0x80),  # DTS, 6ch, 4 sample rates, max bitrate
    ]
    svds = [
        (16, True),   # VIC 16 = 1080p60, native
        (4, False),   # VIC 4 = 720p60
        (3, False),   # VIC 3 = 480p
    ]
    dbc = (audio_block(sads)
           + video_block(svds)
           + hdmi_vsdb()
           + speaker_allocation()
           + extended_colorimetry())
    happy = build_block(dbc, [edid_dtd_1080p()])
    open(os.path.join(out, "happy_full_dbc.bin"), "wb").write(happy)

    # DTDs only: empty DBC, three DTDs in the trailing area.
    dtds_only = build_block(b"", [edid_dtd_1080p(), edid_dtd_1080p(), edid_dtd_1080p()])
    open(os.path.join(out, "edge_dtds_only.bin"), "wb").write(dtds_only)

    # Minimal: valid tag + checksum, no DBC, no DTDs. Exercises the
    # parser's empty-block path.
    minimal = bytearray(128)
    minimal[0] = 0x02
    minimal[1] = 0x03
    fix_checksum(minimal)
    open(os.path.join(out, "minimal.bin"), "wb").write(bytes(minimal))

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
