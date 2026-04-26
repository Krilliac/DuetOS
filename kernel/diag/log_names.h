#pragma once

#include "util/types.h"

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

// POSIX/Linux signal number -> short name (SIGTERM, SIGKILL,
// SIGSEGV, ...). Covers signals 1..31 plus the SIGRTMIN range.
// Returns "?" for everything outside the known set. Used by
// the Linux subsystem's kill / tgkill / sigaction logs.
const char* LinuxSignalName(u64 sig);

// Linux errno (positive number — the absolute value of a
// negative-return) -> short name (EAGAIN / EINVAL / ENOENT
// / ...). Used by syscall failure logs so a `-22` return
// becomes `(-22 EINVAL)` in the trace. Pass a positive value
// (negate the kernel return first).
const char* LinuxErrnoName(u64 errno_val);

// NTSTATUS (32-bit Windows return code) -> short name. Covers
// STATUS_SUCCESS, STATUS_INVALID_PARAMETER, STATUS_NO_MEMORY,
// STATUS_ACCESS_VIOLATION, etc. Returns "?" for codes outside
// the curated subset the Win32 subsystem actually emits.
const char* NtStatusName(u64 status);

// Win32 file/object access mask (DESIRED_ACCESS) -> bitwise
// flag list rendered to COM1 directly. Recognises GENERIC_*,
// FILE_GENERIC_*, STANDARD_RIGHTS_*, and the per-object basic
// rights (FILE_READ_DATA / FILE_WRITE_DATA / SYNCHRONIZE / ...).
void SerialWriteWin32AccessMask(u64 mask);

// POSIX open() flags decoded as `[O_RDONLY|O_RDWR|O_CREAT|...]`
// to COM1. Recognises the access-mode pair (low 2 bits) plus
// the standard creation/status flags.
void SerialWriteOpenFlags(u64 flags);

// POSIX-style mmap() prot bits (PROT_READ / WRITE / EXEC /
// NONE) decoded as `[R|W|X]` or `[NONE]`.
void SerialWriteMmapProt(u64 prot);

// POSIX-style mmap() flags (MAP_SHARED / MAP_PRIVATE / MAP_FIXED
// / MAP_ANONYMOUS / MAP_STACK / MAP_NORESERVE / MAP_GROWSDOWN
// / ...) decoded as `[SHARED|FIXED|ANONYMOUS|...]`.
void SerialWriteMmapFlags(u64 flags);

// Inode / file mode bits (S_IFREG / S_IFDIR / S_IFCHR / etc.
// for the type, and rwxrwxrwx + sticky/setuid/setgid for the
// permissions) decoded as `[REG rwxr-xr-x]` or `[DIR drwxr-xr-x]`.
void SerialWriteInodeMode(u64 mode);

// FAT directory-entry attribute byte (RO/H/S/V/D/A/LFN) decoded
// as `[A|R|H|S|D|V]` or "[LFN]" for the long-name escape value.
void SerialWriteFatAttr(u64 attr);

} // namespace duetos::core
