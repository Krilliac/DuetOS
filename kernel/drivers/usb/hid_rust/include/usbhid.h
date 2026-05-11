#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Keep in lockstep with duetos::drivers::usb::hid::DeviceKind.
    enum
    {
        DUETOS_USBHID_KIND_UNKNOWN = 0,
        DUETOS_USBHID_KIND_KEYBOARD = 1,
        DUETOS_USBHID_KIND_MOUSE = 2,
        DUETOS_USBHID_KIND_POINTER = 3,
        DUETOS_USBHID_KIND_KEYPAD = 4,
        DUETOS_USBHID_KIND_JOYSTICK = 5,
        DUETOS_USBHID_KIND_GAMEPAD = 6,
        DUETOS_USBHID_KIND_CONSUMER = 7,
        DUETOS_USBHID_KIND_DIGITIZER = 8,
        DUETOS_USBHID_KIND_OTHER = 9,
    };

    typedef struct DuetosUsbHidReportSummary
    {
        bool parse_ok;
        uint32_t bytes_consumed;
        uint8_t primary_kind;
        uint16_t top_usage_page;
        uint16_t top_usage;
        uint32_t collection_depth_max;
        uint32_t input_bits_total;
        uint32_t output_bits_total;
        uint32_t feature_bits_total;
        uint32_t button_field_count;
        uint32_t report_id_count;
    } DuetosUsbHidReportSummary;

    typedef struct DuetosUsbHidMouseField
    {
        bool present;
        bool is_signed;
        uint8_t bit_size;
        uint32_t bit_offset;
    } DuetosUsbHidMouseField;

    typedef struct DuetosUsbHidMouseLayout
    {
        bool valid;
        uint8_t report_id;
        uint32_t report_size_bits;
        DuetosUsbHidMouseField buttons;
        DuetosUsbHidMouseField x;
        DuetosUsbHidMouseField y;
        DuetosUsbHidMouseField wheel;
        DuetosUsbHidMouseField h_tilt;
    } DuetosUsbHidMouseLayout;

    bool duetos_usbhid_parse_descriptor(const uint8_t* buf, uint32_t len, DuetosUsbHidReportSummary* out);
    bool duetos_usbhid_extract_mouse_layout(const uint8_t* buf, uint32_t len, DuetosUsbHidMouseLayout* out);

#ifdef __cplusplus
}
#endif
