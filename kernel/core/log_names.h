#pragma once

#include "types.h"

namespace duetos::core
{

// Symbolic names for opaque numeric values that show up in logs.
// Each function returns a static const char* — never null, never
// owned by the caller, safe to print from any context (including
// IRQ / panic). For numbers outside the known range, the
// returned string is "?" so callers don't have to special-case
// missing entries.

const char* SyscallName(u64 num);
const char* LinuxSyscallName(u64 nr);
const char* WifiSecurityName(u64 sec);
const char* FwSourcePolicyName(u64 policy);

// PCI vendor ID -> short vendor string. Used by the PCI
// enumerator log and any driver that wants to print a
// human-tag next to a 16-bit vendor id. Returns "?" for
// unknown ids so callers don't have to special-case missing
// entries.
const char* PciVendorName(u64 vid);

// PE/COFF machine field -> ABI name (x86-64, x86, ARM64, ARM,
// ItaniumIA64, EBC). The PE loader prints raw `IMAGE_FILE_HEADER
// .Machine` hex; this turns it into the symbolic ABI name.
const char* PeMachineName(u64 machine);

// IDT vector -> short label. Covers the architectural
// exceptions (0..31) and a few well-known vectors DuetOS
// programs (LAPIC timer 0x20, syscall 0x80, spurious 0xff).
// Returns "external-irq" for everything in 0x21..0x7f.
const char* IdtVectorName(u64 vec);

// Bit-field writer for ProcessCreate's caps= line. Walks the
// set bits and writes "FsRead|FsWrite|..." to COM1, or
// "<none>" if no bits are set. Lives next to the other
// log helpers because the caller (process.cpp [proc] create)
// is itself a serial-emitting log site.
void SerialWriteCapBits(u64 bits);

} // namespace duetos::core
