#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        DUETOS_USBCLASS_FLAG_MSC_BULK_ONLY = 1u << 0,
        DUETOS_USBCLASS_FLAG_HUB = 1u << 1,
        DUETOS_USBCLASS_FLAG_UVC_CONTROL = 1u << 2,
        DUETOS_USBCLASS_FLAG_UVC_STREAMING = 1u << 3,
        DUETOS_USBCLASS_FLAG_BLUETOOTH = 1u << 4,
    };

    typedef struct DuetosUsbClassEndpointSet
    {
        uint8_t bulk_in;
        uint8_t bulk_out;
        uint8_t interrupt_in;
        uint8_t interrupt_out;
        uint8_t iso_in;
        uint8_t iso_out;
    } DuetosUsbClassEndpointSet;

    typedef struct DuetosUsbClassSummary
    {
        bool parse_ok;
        uint32_t bytes_consumed;
        uint8_t config_value;
        uint8_t interface_count;
        uint8_t endpoint_count;
        uint32_t flags;
        DuetosUsbClassEndpointSet msc;
        DuetosUsbClassEndpointSet hub;
        DuetosUsbClassEndpointSet uvc_control;
        DuetosUsbClassEndpointSet uvc_streaming;
        DuetosUsbClassEndpointSet bluetooth;
    } DuetosUsbClassSummary;

    bool duetos_usbclass_parse_config(const uint8_t* buf, uint32_t len, DuetosUsbClassSummary* out);

#ifdef __cplusplus
}
#endif
