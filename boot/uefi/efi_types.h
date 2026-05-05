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
// EFI_MEMORY_TYPE — passed to AllocatePool / AllocatePages so
// the firmware classifies the allocation. EfiLoaderData is the
// right pool for transient loader buffers (we own them until
// ExitBootServices, after which the firmware reclaims any
// EfiLoaderCode/EfiLoaderData not preserved by the OS).
// ---------------------------------------------------------------

enum EFI_MEMORY_TYPE : UINT32
{
    EfiReservedMemoryType = 0,
    EfiLoaderCode = 1,
    EfiLoaderData = 2,
    EfiBootServicesCode = 3,
    EfiBootServicesData = 4,
    EfiRuntimeServicesCode = 5,
    EfiRuntimeServicesData = 6,
    EfiConventionalMemory = 7,
    EfiUnusableMemory = 8,
    EfiACPIReclaimMemory = 9,
    EfiACPIMemoryNVS = 10,
    EfiMemoryMappedIO = 11,
    EfiMemoryMappedIOPortSpace = 12,
    EfiPalCode = 13,
    EfiPersistentMemory = 14,
};

// ---------------------------------------------------------------
// EFI_BOOT_SERVICES — populated by the firmware before it hands
// control to a loader. Phase A used only `Stall`; Phase B.1 adds
// types for `AllocatePool` / `FreePool` / `HandleProtocol`. The
// remaining fields stay `void*` placeholders preserving the spec
// layout so Phase B.2+ can fill in prototypes incrementally.
// ---------------------------------------------------------------

using EFI_STALL = EFI_STATUS (*)(UINTN microseconds);
using EFI_ALLOCATE_POOL = EFI_STATUS (*)(EFI_MEMORY_TYPE pool_type, UINTN size, void** out_buffer);
using EFI_FREE_POOL = EFI_STATUS (*)(void* buffer);
using EFI_HANDLE_PROTOCOL = EFI_STATUS (*)(EFI_HANDLE handle, EFI_GUID* protocol, void** out_interface);

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
    EFI_ALLOCATE_POOL AllocatePool;
    EFI_FREE_POOL FreePool;

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
    EFI_HANDLE_PROTOCOL HandleProtocol;
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
    // beyond here — Phase B.2+ fills them in when the loader
    // needs them. The struct is open-ended in the spec, so
    // leaving the tail off does not affect offsets used by
    // Phase A / B.1.)
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

// ---------------------------------------------------------------
// Phase B.1 — protocol surface for locating + reading the kernel
// ELF on the boot device.
//
// Path the loader walks:
//   image_handle -+ HandleProtocol(EFI_LOADED_IMAGE_PROTOCOL_GUID)
//                 |     -> EFI_LOADED_IMAGE_PROTOCOL { DeviceHandle }
//                 v
//   DeviceHandle -+ HandleProtocol(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID)
//                 |     -> EFI_SIMPLE_FILE_SYSTEM_PROTOCOL { OpenVolume }
//                 v
//   OpenVolume() ->  root EFI_FILE_PROTOCOL { Open, Read, Close }
//                 v
//   root.Open(L"\\duetos-kernel.elf", READ)
//                 v
//   kernel EFI_FILE_PROTOCOL — Read into a buffer.
// ---------------------------------------------------------------

inline constexpr EFI_GUID kEfiLoadedImageProtocolGuid = {
    0x5B1B31A1, 0x9562, 0x11D2, {0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};

inline constexpr EFI_GUID kEfiSimpleFileSystemProtocolGuid = {
    0x964E5B22, 0x6459, 0x11D2, {0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B}};

// EFI_LOADED_IMAGE_PROTOCOL — describes the running loader image.
// We only need `DeviceHandle` (the EFI_HANDLE of the volume the
// loader was loaded from); the rest are placeholders preserving
// offsets per UEFI 2.10 §9.1.
struct EFI_LOADED_IMAGE_PROTOCOL
{
    UINT32 Revision;
    EFI_HANDLE ParentHandle;
    EFI_SYSTEM_TABLE* SystemTable;
    EFI_HANDLE DeviceHandle; // <-- this is what we walk to FS protocol
    void* FilePath;          // EFI_DEVICE_PATH_PROTOCOL*
    void* Reserved;
    UINT32 LoadOptionsSize;
    void* LoadOptions;
    void* ImageBase;
    UINT64 ImageSize;
    EFI_MEMORY_TYPE ImageCodeType;
    EFI_MEMORY_TYPE ImageDataType;
    void* Unload; // EFI_IMAGE_UNLOAD
};

// File-mode flags for EFI_FILE_PROTOCOL.Open. We open RO.
inline constexpr UINT64 kEfiFileModeRead = 0x0000000000000001ULL;

struct EFI_FILE_PROTOCOL;

using EFI_FILE_OPEN = EFI_STATUS (*)(EFI_FILE_PROTOCOL* self, EFI_FILE_PROTOCOL** new_handle, CHAR16* file_name,
                                     UINT64 open_mode, UINT64 attributes);
using EFI_FILE_CLOSE = EFI_STATUS (*)(EFI_FILE_PROTOCOL* self);
using EFI_FILE_READ = EFI_STATUS (*)(EFI_FILE_PROTOCOL* self, UINTN* buffer_size, void* buffer);

struct EFI_FILE_PROTOCOL
{
    UINT64 Revision;
    EFI_FILE_OPEN Open;
    EFI_FILE_CLOSE Close;
    void* Delete; // EFI_FILE_DELETE
    EFI_FILE_READ Read;
    void* Write;       // EFI_FILE_WRITE
    void* GetPosition; // EFI_FILE_GET_POSITION
    void* SetPosition; // EFI_FILE_SET_POSITION
    void* GetInfo;     // EFI_FILE_GET_INFO
    void* SetInfo;     // EFI_FILE_SET_INFO
    void* Flush;       // EFI_FILE_FLUSH
    // Revision >= 0x00020000 adds OpenEx/ReadEx/WriteEx/FlushEx;
    // we don't need them for Phase B.1.
};

struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

using EFI_SIMPLE_FS_OPEN_VOLUME = EFI_STATUS (*)(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* self, EFI_FILE_PROTOCOL** out_root);

struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
{
    UINT64 Revision;
    EFI_SIMPLE_FS_OPEN_VOLUME OpenVolume;
};

} // namespace duetos::boot::uefi
