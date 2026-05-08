#pragma once

#include "util/types.h"

namespace duetos::drivers::usb
{

inline constexpr u32 kUsbClassFlagMscBulkOnly = 1u << 0;
inline constexpr u32 kUsbClassFlagHub = 1u << 1;
inline constexpr u32 kUsbClassFlagUvcControl = 1u << 2;
inline constexpr u32 kUsbClassFlagUvcStreaming = 1u << 3;
inline constexpr u32 kUsbClassFlagBluetooth = 1u << 4;

struct UsbClassEndpointSet
{
    u8 bulk_in;
    u8 bulk_out;
    u8 interrupt_in;
    u8 interrupt_out;
    u8 iso_in;
    u8 iso_out;
};

struct UsbClassConfigSummary
{
    bool parse_ok;
    u32 bytes_consumed;
    u8 config_value;
    u8 interface_count;
    u8 endpoint_count;
    u32 flags;
    UsbClassEndpointSet msc;
    UsbClassEndpointSet hub;
    UsbClassEndpointSet uvc_control;
    UsbClassEndpointSet uvc_streaming;
    UsbClassEndpointSet bluetooth;
};

bool UsbClassParseConfigDescriptor(const u8* buf, u32 len, UsbClassConfigSummary* out);
void UsbClassDescriptorSelfTest();

} // namespace duetos::drivers::usb
