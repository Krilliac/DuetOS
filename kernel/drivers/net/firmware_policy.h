#pragma once

#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — firmware-source policy matrix for wireless bring-up.
 *
 * Modern Wi-Fi NICs and Intel GPUs often require device-side
 * microcode before the host driver can do useful work. Some blobs are
 * redistributable but closed, some old Wi-Fi targets have genuinely
 * open firmware, and some research projects patch proprietary images
 * rather than replacing them. This file gives driver code one small,
 * deterministic place to classify those sources before a future
 * firmware package manager or loader tries to stage bytes into DMA.
 *
 * Policy intent:
 *   - Prefer source-available firmware where it exists (ath9k_htc,
 *     OpenFWWF-class Broadcom b43).
 *   - Allow out-of-tree redistributable vendor blobs as a pragmatic
 *     runtime dependency for current Intel / Realtek / GPU hardware.
 *   - Never commit closed or no-modification blobs to the DuetOS tree.
 *   - Treat patching frameworks as research references, not as
 *     production firmware inputs, unless the user explicitly supplies
 *     the vendor base image and accepts that trust boundary.
 *
 * Threading: all lookup functions return pointers to immutable .rodata;
 * no allocation, no global mutation, safe in probe/init paths.
 */

namespace duetos::drivers::net
{

enum class FirmwareFamily : u8
{
    IntelIwlwifi = 0,
    IntelGpuUc = 1,
    AtherosAth9kHtc = 2,
    BroadcomB43OpenFwwf = 3,
    BroadcomBrcmFullMac = 4,
    RealtekRtl88xx = 5,
};

enum class FirmwareSourceKind : u8
{
    OpenSource = 0,
    RedistributableBinary = 1,
    ExtractedVendorBinary = 2,
    PatchFramework = 3,
};

enum class FirmwareDisposition : u8
{
    Preferred = 0,      // source-available or otherwise best target for DuetOS bring-up
    RuntimePackage = 1, // acceptable only as a separately supplied runtime package
    ResearchOnly = 2,   // reverse-engineering reference; not a production input
    Reject = 3,         // do not load by policy
};

struct FirmwareSourceFacts
{
    FirmwareFamily family;
    FirmwareSourceKind kind;
    FirmwareDisposition disposition;

    const char* short_name;
    const char* hardware;
    const char* upstream;
    const char* license_note;

    bool source_available;
    bool modification_allowed;
    bool may_ship_in_tree;
};

const char* FirmwareFamilyName(FirmwareFamily family);
const char* FirmwareSourceKindName(FirmwareSourceKind kind);
const char* FirmwareDispositionName(FirmwareDisposition disposition);

const FirmwareSourceFacts* FirmwarePolicyFind(FirmwareFamily family);
const FirmwareSourceFacts* FirmwarePolicyFindByName(const char* short_name);

bool FirmwarePolicyCanBundle(const FirmwareSourceFacts& facts);
bool FirmwarePolicyCanLoadRuntime(const FirmwareSourceFacts& facts);

void FirmwarePolicySelfTest();

} // namespace duetos::drivers::net
