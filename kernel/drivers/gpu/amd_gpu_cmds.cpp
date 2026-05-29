/*
 * DuetOS — AMD GFX9+ PM4 command encoders. See amd_gpu_cmds.h.
 *
 * Proven at COMPILE time by the static_asserts below, against values
 * derived from the amdgpu soc15d.h macro expressions.
 */

#include "drivers/gpu/amd_gpu_cmds.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::drivers::gpu::amd
{

static_assert(kPacket3Type == 0xC0000000u, "PM4 type-3 tag");
static_assert(EncodePacket3(kPacket3Nop, 0) == 0xC0001000u, "PACKET3(NOP,0)");
static_assert(EncodePacket3(kPacket3WriteData, 3) == 0xC0033700u, "PACKET3(WRITE_DATA,3)");
static_assert(kWriteDataControlMemMe == 0x00100500u, "WRITE_DATA control (DST_SEL=mem|WR_CONFIRM|ENGINE=ME)");
constexpr WriteDataPacket kWdTest = EncodeWriteData(0x800000ull, 0xCAFEF00Du);
static_assert(kWdTest.dw[0] == 0xC0033700u, "write_data header");
static_assert(kWdTest.dw[1] == 0x00100500u, "write_data control");
static_assert(kWdTest.dw[2] == 0x00800000u, "write_data addr lo");
static_assert(kWdTest.dw[3] == 0x00000000u, "write_data addr hi");
static_assert(kWdTest.dw[4] == 0xCAFEF00Du, "write_data value");

void AmdGpuCmdsSelfTest()
{
    const WriteDataPacket wd = EncodeWriteData(0x800000ull, 0xCAFEF00Du);
    const bool ok = EncodePacket3(kPacket3Nop, 0) == 0xC0001000u && wd.dw[0] == 0xC0033700u &&
                    wd.dw[1] == 0x00100500u && wd.dw[4] == 0xCAFEF00Du;
    if (ok)
    {
        arch::SerialWrite("[gpu/amd/cmds] selftest PASS (PM4 PACKET3 + WRITE_DATA compile-verified)\n");
        return;
    }
    KBP_PROBE_V(::duetos::debug::ProbeId::kBootSelftestFail, 0x4143u /* 'AC' */);
    arch::SerialWrite("[gpu/amd/cmds] selftest FAIL (PM4 encoders)\n");
}

} // namespace duetos::drivers::gpu::amd
