#pragma once

/*
 * DuetOS — kernel reboot.
 *
 * Try the firmware-defined ACPI reset register first (FADT
 * RESET_REG / RESET_VALUE, wired via `acpi::AcpiReset()`), fall
 * back to chipset-specific I/O (port 0xCF9 on PC-AT), then the
 * 8042 keyboard-controller reset line, and triple-fault as a
 * guaranteed-last-resort. Each step logs at Warn so the serial
 * log makes it clear which path actually reset the machine.
 *
 * NEVER returns. Safe to call from any context, though by the
 * time this runs any outstanding DMA / device state should have
 * been quiesced — this is a hard reset, not a clean shutdown.
 *
 * Context: kernel. The only consumer today is intended to be a
 * diagnostic / emergency-reset path; a proper shutdown sequence
 * (stop tasks → flush caches → sync filesystems → ACPI S5) comes
 * when AML support lands.
 */

namespace duetos::core
{

[[noreturn]] void KernelReboot();

} // namespace duetos::core
