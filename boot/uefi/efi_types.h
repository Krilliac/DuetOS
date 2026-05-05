#pragma once

/*
 * DuetOS — minimal UEFI ABI types, Phase A.
 *
 * Hand-rolled. We do NOT depend on EDK2 or gnu-efi headers — the
 * project is freestanding and the type surface a v0 loader needs is
 * small enough that vendoring the relevant slice keeps the build
 * tree closed (no system include path, no third-party header rot).
 *
 * Scope of this header:
 *   - Primitive UEFI types (EFI_STATUS, EFI_HANDLE, EFI_GUID,
 *     CHAR16, etc.) per the UEFI 2.10 spec, §2.3.
 *   - The EFI System Table + Boot Services + Runtime Services
 *     structures, with ONLY the fields a Phase A loader uses.
 *     Padding fields are typed as `void*` placeholders so the
 *     struct layout matches the spec without each field's full
 *     prototype clogging this header.
 *   - The Simple Text Output protocol (`ConOut`), which is all
 *     Phase A needs to print a banner.
 *
 * UEFI calling convention is Microsoft x64 (RCX/RDX/R8/R9, no red
 * zone). The build invocation pins `-target x86_64-unknown-windows`
 * so plain function pointers in this header inherit the right ABI
 * automatically — no explicit `__attribute__((ms_abi))`.
 *
 * Phase B (full kernel handoff) will append: Loaded Image protocol,
 * Simple File System / File protocol, Graphics Output Protocol,
 * GetMemoryMap / ExitBootServices / AllocatePages from Boot
 * Services. None of those are wired here; the placeholder slots
 * are flagged `void*` with a comment so the reader knows the spec
 * shape is preserved.
 */

namespace duetos::boot::uefi
{

// ---------------------------------------------------------------
// Primitives. UEFI uses fixed-width types throughout; we mirror
// them in our own namespace rather than including <stdint.h> so
// the loader stays self-contained.
// ---------------------------------------------------------------

using UINT8 = unsigned char;
using UINT16 = unsigned short;
using UINT32 = unsigned int;
using UINT64 = unsigned long long;
using INT8 = signed char;
using INT16 = signed short;
using INT32 = signed int;
using INT64 = signed long long;

using BOOLEAN = UINT8;
using UINTN = UINT64; // x86_64 native word
using INTN = INT64;
using CHAR8 = char;
using CHAR16 = char16_t; // UCS-2 — UEFI strings are UCS-2 (binary-compatible with u16)

using EFI_HANDLE = void*;
using EFI_EVENT = void*;
using EFI_STATUS = UINTN;

// ---------------------------------------------------------------
// EFI_STATUS values. The high bit set marks an error; otherwise
// it's a warning or success. We use only EFI_SUCCESS in Phase A.
// ---------------------------------------------------------------

inline constexpr EFI_STATUS EFI_SUCCESS = 0;
inline constexpr EFI_STATUS EFI_LOAD_ERROR = 0x8000000000000001ULL;
inline constexpr EFI_STATUS EFI_INVALID_PARAMETER = 0x8000000000000002ULL;
inline constexpr EFI_STATUS EFI_UNSUPPORTED = 0x8000000000000003ULL;

// ---------------------------------------------------------------
// EFI_GUID — identifies every UEFI protocol. The UEFI spec
// publishes these as little-endian DCE/UUID-style. Phase A uses
// none, but the type is needed for Phase B's
// `BootServices->LocateProtocol`.
// ---------------------------------------------------------------

struct EFI_GUID
{
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    UINT8 Data4[8];
};

// ---------------------------------------------------------------
// EFI_TABLE_HEADER — every UEFI table starts with this.
// Signature + revision + size let the firmware validate the table
// before handing the pointer to a loader.
// ---------------------------------------------------------------

struct EFI_TABLE_HEADER
{
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
};

// ---------------------------------------------------------------
// EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL — `ConOut` and `StdErr` on the
// System Table point to this. We only call `OutputString` in
// Phase A; the rest are `void*` placeholders so the offsets match.
// ---------------------------------------------------------------

struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

using EFI_TEXT_RESET = EFI_STATUS (*)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* self, BOOLEAN extended);
using EFI_TEXT_STRING = EFI_STATUS (*)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* self, CHAR16* str);

struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL
{
    EFI_TEXT_RESET Reset;
    EFI_TEXT_STRING OutputString;
    void* TestString;        // EFI_TEXT_TEST_STRING
    void* QueryMode;         // EFI_TEXT_QUERY_MODE
    void* SetMode;           // EFI_TEXT_SET_MODE
    void* SetAttribute;      // EFI_TEXT_SET_ATTRIBUTE
    void* ClearScreen;       // EFI_TEXT_CLEAR_SCREEN
    void* SetCursorPosition; // EFI_TEXT_SET_CURSOR_POSITION
    void* EnableCursor;      // EFI_TEXT_ENABLE_CURSOR
    void* Mode;              // EFI_SIMPLE_TEXT_OUTPUT_MODE*
};

// ---------------------------------------------------------------
// EFI_BOOT_SERVICES — populated by the firmware before it hands
// control to a loader. Phase A uses `Stall` to pace the banner
// and `Exit` would be how a real loader terminates; everything
// else is `void*` placeholders preserving the spec layout so
// Phase B can fill in the prototypes incrementally.
// ---------------------------------------------------------------

using EFI_STALL = EFI_STATUS (*)(UINTN microseconds);

struct EFI_BOOT_SERVICES
{
    EFI_TABLE_HEADER Hdr;

    // Task priority services
    void* RaiseTPL;
    void* RestoreTPL;

    // Memory services
    void* AllocatePages;
    void* FreePages;
    void* GetMemoryMap;
    void* AllocatePool;
    void* FreePool;

    // Event & timer services
    void* CreateEvent;
    void* SetTimer;
    void* WaitForEvent;
    void* SignalEvent;
    void* CloseEvent;
    void* CheckEvent;

    // Protocol handler services
    void* InstallProtocolInterface;
    void* ReinstallProtocolInterface;
    void* UninstallProtocolInterface;
    void* HandleProtocol;
    void* Reserved;
    void* RegisterProtocolNotify;
    void* LocateHandle;
    void* LocateDevicePath;
    void* InstallConfigurationTable;

    // Image services
    void* LoadImage;
    void* StartImage;
    void* Exit;
    void* UnloadImage;
    void* ExitBootServices;

    // Misc services
    void* GetNextMonotonicCount;
    EFI_STALL Stall;
    void* SetWatchdogTimer;

    // (DriverSupport / OpenProtocol / Connect / etc. continue
    // beyond here — Phase B fills them in when the loader needs
    // them. The struct is open-ended in the spec, so leaving the
    // tail off does not affect offsets used in Phase A.)
};

// ---------------------------------------------------------------
// EFI_SYSTEM_TABLE — top-level handoff from firmware to loader.
// Pointer is in RDX on entry; firmware passes our image handle
// in RCX.
// ---------------------------------------------------------------

struct EFI_SYSTEM_TABLE
{
    EFI_TABLE_HEADER Hdr;
    CHAR16* FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void* ConIn; // EFI_SIMPLE_TEXT_INPUT_PROTOCOL*
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL* StdErr;
    void* RuntimeServices;
    EFI_BOOT_SERVICES* BootServices;
    UINTN NumberOfTableEntries;
    void* ConfigurationTable;
};

} // namespace duetos::boot::uefi
