#pragma once

#include "../../core/types.h"

/*
 * 16550-compatible UART for early kernel output. This is the only output
 * path available before the real console/log subsystem is initialized,
 * and the single path used by QEMU's `-serial stdio` for boot diagnostics.
 *
 * Context: kernel. Thread-unsafe by design — used only during boot,
 * before SMP is online.
 */

namespace customos::arch
{

/// COM1 I/O base port on standard PC hardware.
inline constexpr u16 kCom1Port = 0x3F8;

/// Initialize COM1 to 115200 baud, 8N1, FIFO enabled, interrupts disabled.
/// Safe to call before any other subsystem.
void SerialInit();

/// Write a single byte to COM1 (polling — blocks until THR is empty).
void SerialWriteByte(u8 byte);

/// Write a NUL-terminated string to COM1.
void SerialWrite(const char* str);

} // namespace customos::arch
