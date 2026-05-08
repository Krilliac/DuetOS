#pragma once

#include "drivers/net/iwlwifi_fw.h"
#include "util/result.h"
#include "util/types.h"

/*
 * DuetOS — iwlwifi .ucode TLV image builder.
 *
 * This builds the same outer file format as Intel's iwlwifi-*.ucode
 * blobs: 88-byte TLV header followed by `(type, length, payload, pad)`
 * records. The payload bytes are caller-supplied instruction/data
 * sections; this code never derives, copies, or embeds Intel firmware.
 *
 * Important hardware boundary: retail Intel Wi-Fi devices require
 * Intel-signed operational firmware. A DuetOS-built custom image is
 * useful for parser/upload tests, clean-room tooling, and any future
 * lab target that accepts unsigned firmware, but it is not expected to
 * boot on signed retail iwlwifi silicon.
 *
 * Threading: pure builder. No heap, no global state.
 */

namespace duetos::drivers::net
{

struct IwlFirmwareBuildSection
{
    IwlTlvType type;
    const u8* data;
    u32 size;
};

struct IwlFirmwareBuildRequest
{
    const char* human_readable;
    u32 ver_packed;
    u32 build;

    // Optional metadata TLVs. A zero value means omit that TLV except
    // for `num_of_cpu`, where 0 also means omit (normal blobs use >=1).
    u32 flags;
    u32 num_of_cpu;
    u32 fw_version;

    const IwlFirmwareBuildSection* sections;
    u32 section_count;
};

struct IwlFirmwareBuildResult
{
    u32 bytes_written;
    u32 tlv_records;
};

::duetos::core::Result<IwlFirmwareBuildResult> IwlFirmwareBuild(const IwlFirmwareBuildRequest& req, u8* out,
                                                                u32 out_cap);

void IwlFirmwareBuilderSelfTest();

} // namespace duetos::drivers::net
