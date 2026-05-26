#!/usr/bin/env python3
# DuetOS USB HID report-descriptor fuzz seed generator.
#
# WHAT  Emits real HID report descriptors covering the three
#       device classifications the v0 parser distinguishes:
#         - boot keyboard (USB HID 1.11 Appendix B.1)
#         - boot mouse    (Appendix B.2)
#         - high-DPI mouse with 16-bit X/Y + wheel + AC Pan +
#           Report ID prefix (matches the layout the
#           HidExtractMouseLayout high-DPI follow-on parses)
#
# WHY   HID descriptors are short-item TLV streams where the
#       byte-0 item prefix encodes (type, tag, size) packed into
#       4+4+2 bits. Random mutation rarely produces a coherent
#       Collection -> Input -> EndCollection chain. Seeds let
#       the fuzzer exercise the collection-depth tracking,
#       Report Size/Count multiplication, and signed/unsigned
#       logical-min/max parsing from cycle 1.
#
# USAGE  python3 gen_usbhid_seeds.py <out_dir>

import os
import sys


def boot_keyboard() -> bytes:
    # USB HID 1.11 Appendix B.1 — canonical boot keyboard.
    return bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop)
        0x09, 0x06,        # Usage (Keyboard)
        0xA1, 0x01,        # Collection (Application)
        0x05, 0x07,        #   Usage Page (Key Codes)
        0x19, 0xE0,        #   Usage Minimum (224)
        0x29, 0xE7,        #   Usage Maximum (231)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x75, 0x01,        #   Report Size (1)
        0x95, 0x08,        #   Report Count (8)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x08,        #   Report Size (8)
        0x81, 0x01,        #   Input (Constant)  reserved byte
        0x95, 0x05,        #   Report Count (5)
        0x75, 0x01,        #   Report Size (1)
        0x05, 0x08,        #   Usage Page (LEDs)
        0x19, 0x01,        #   Usage Minimum (1)
        0x29, 0x05,        #   Usage Maximum (5)
        0x91, 0x02,        #   Output (Data, Variable, Absolute) — LEDs
        0x95, 0x01,        #   Report Count (1)
        0x75, 0x03,        #   Report Size (3)
        0x91, 0x01,        #   Output (Constant)
        0x95, 0x06,        #   Report Count (6)
        0x75, 0x08,        #   Report Size (8)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x65,        #   Logical Maximum (101)
        0x05, 0x07,        #   Usage Page (Key Codes)
        0x19, 0x00,        #   Usage Minimum (0)
        0x29, 0x65,        #   Usage Maximum (101)
        0x81, 0x00,        #   Input (Data, Array)
        0xC0,              # End Collection
    ])


def boot_mouse() -> bytes:
    # USB HID 1.11 Appendix B.2 — canonical boot mouse.
    return bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop)
        0x09, 0x02,        # Usage (Mouse)
        0xA1, 0x01,        # Collection (Application)
        0x09, 0x01,        #   Usage (Pointer)
        0xA1, 0x00,        #   Collection (Physical)
        0x05, 0x09,        #     Usage Page (Buttons)
        0x19, 0x01,        #     Usage Minimum (1)
        0x29, 0x03,        #     Usage Maximum (3)
        0x15, 0x00,        #     Logical Minimum (0)
        0x25, 0x01,        #     Logical Maximum (1)
        0x95, 0x03,        #     Report Count (3)
        0x75, 0x01,        #     Report Size (1)
        0x81, 0x02,        #     Input (Data, Variable, Absolute)
        0x95, 0x01,        #     Report Count (1)
        0x75, 0x05,        #     Report Size (5)
        0x81, 0x01,        #     Input (Constant) — padding
        0x05, 0x01,        #     Usage Page (Generic Desktop)
        0x09, 0x30,        #     Usage (X)
        0x09, 0x31,        #     Usage (Y)
        0x15, 0x81,        #     Logical Minimum (-127)
        0x25, 0x7F,        #     Logical Maximum (127)
        0x75, 0x08,        #     Report Size (8)
        0x95, 0x02,        #     Report Count (2)
        0x81, 0x06,        #     Input (Data, Variable, Relative)
        0xC0,              #   End Collection
        0xC0,              # End Collection
    ])


def high_dpi_mouse() -> bytes:
    # High-DPI mouse with Report ID, 16-bit X/Y, wheel, AC Pan.
    return bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop)
        0x09, 0x02,        # Usage (Mouse)
        0xA1, 0x01,        # Collection (Application)
        0x85, 0x01,        #   Report ID 1
        0x09, 0x01,        #   Usage (Pointer)
        0xA1, 0x00,        #   Collection (Physical)
        0x05, 0x09,        #     Usage Page (Buttons)
        0x19, 0x01, 0x29, 0x05,
        0x15, 0x00, 0x25, 0x01,
        0x95, 0x05, 0x75, 0x01,
        0x81, 0x02,        #     Input (Data, Var, Abs)
        0x95, 0x01, 0x75, 0x03,
        0x81, 0x01,        #     Input (Const) padding
        0x05, 0x01,        #     Usage Page (Generic Desktop)
        0x09, 0x30, 0x09, 0x31,  # Usage X, Usage Y
        0x16, 0x00, 0x80,  #     Logical Minimum (-32768)
        0x26, 0xFF, 0x7F,  #     Logical Maximum (32767)
        0x75, 0x10, 0x95, 0x02,  # 16 bits, 2 fields
        0x81, 0x06,        #     Input (Data, Var, Rel)
        0x09, 0x38,        #     Usage (Wheel)
        0x15, 0x81, 0x25, 0x7F,
        0x75, 0x08, 0x95, 0x01,
        0x81, 0x06,        #     Input (Data, Var, Rel)
        0x05, 0x0C,        #     Usage Page (Consumer)
        0x0A, 0x38, 0x02,  #     Usage (AC Pan)
        0x75, 0x08, 0x95, 0x01,
        0x81, 0x06,        #     Input (Data, Var, Rel)
        0xC0,              #   End Collection
        0xC0,              # End Collection
    ])


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "corpus/usbhid"
    os.makedirs(out, exist_ok=True)

    open(os.path.join(out, "boot_keyboard.bin"), "wb").write(boot_keyboard())
    open(os.path.join(out, "boot_mouse.bin"), "wb").write(boot_mouse())
    open(os.path.join(out, "high_dpi_mouse.bin"), "wb").write(high_dpi_mouse())

    print(f"seeded {out}: {len(os.listdir(out))} files")


if __name__ == "__main__":
    main()
