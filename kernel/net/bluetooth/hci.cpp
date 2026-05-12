#include "net/bluetooth/hci.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "net/hci_rust/include/hci_rust.h"

namespace duetos::net::bluetooth
{

namespace
{

void WriteLeU16(u8* dst, u16 v)
{
    dst[0] = u8(v & 0xFF);
    dst[1] = u8((v >> 8) & 0xFF);
}

u16 ReadLeU16(const u8* src)
{
    return u16(u16(src[0]) | (u16(src[1]) << 8));
}

void Eq(u64 actual, u64 expected, const char* what)
{
    if (actual == expected)
        return;
    arch::SerialWrite("[bt-hci] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite(" actual=");
    arch::SerialWriteHex(actual);
    arch::SerialWrite(" expected=");
    arch::SerialWriteHex(expected);
    arch::SerialWrite("\n");
    core::PanicWithValue("net/bluetooth/hci", "HCI self-test mismatch", actual);
}

} // namespace

u32 HciBuildCmd(u8* out, u32 out_size, u8 ogf, u16 ocf)
{
    return HciBuildCmdWithParams(out, out_size, ogf, ocf, nullptr, 0);
}

u32 HciBuildCmdWithParams(u8* out, u32 out_size, u8 ogf, u16 ocf, const u8* params, u8 params_len)
{
    if (out == nullptr)
        return 0;
    const u32 total = kHciCmdHeaderBytes + params_len;
    if (out_size < total)
        return 0;
    if (params_len > kHciCmdMaxParamLen)
        return 0;
    if (params_len > 0 && params == nullptr)
        return 0;
    const u16 op = HciOpcode(ogf, ocf);
    WriteLeU16(out, op);
    out[2] = params_len;
    for (u32 i = 0; i < params_len; ++i)
        out[kHciCmdHeaderBytes + i] = params[i];
    return total;
}

u32 HciBuildCmdReset(u8* out, u32 out_size)
{
    return HciBuildCmd(out, out_size, kOgfHostController, kOcfReset);
}

u32 HciBuildCmdLeSetScanParameters(u8* out, u32 out_size, u8 le_scan_type, u16 interval, u16 window, u8 own_addr_type,
                                   u8 filter_policy)
{
    // §7.8.10 parameter layout (7 bytes):
    //   [0]    LE_Scan_Type (0=passive, 1=active)
    //   [1..2] LE_Scan_Interval LE u16 (0x0004..0x4000, units of 0.625 ms)
    //   [3..4] LE_Scan_Window LE u16 (must be <= interval)
    //   [5]    Own_Address_Type (0=public, 1=random, 2/3=resolvable)
    //   [6]    Scanning_Filter_Policy (0=all, 1=whitelist-only)
    if (window > interval)
        return 0;
    u8 p[7];
    p[0] = le_scan_type;
    WriteLeU16(p + 1, interval);
    WriteLeU16(p + 3, window);
    p[5] = own_addr_type;
    p[6] = filter_policy;
    return HciBuildCmdWithParams(out, out_size, kOgfLeController, kOcfLeSetScanParameters, p, sizeof(p));
}

u32 HciBuildCmdLeSetScanEnable(u8* out, u32 out_size, u8 enable, u8 filter_duplicates)
{
    // §7.8.11 parameter layout (2 bytes):
    //   [0] LE_Scan_Enable (0=off, 1=on)
    //   [1] Filter_Duplicates (0=off, 1=on)
    u8 p[2];
    p[0] = enable;
    p[1] = filter_duplicates;
    return HciBuildCmdWithParams(out, out_size, kOgfLeController, kOcfLeSetScanEnable, p, sizeof(p));
}

bool HciParseEventHeader(const u8* buf, u32 len, HciEventHeader* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    if (buf == nullptr || len < kHciEvtHeaderBytes)
        return false;
    out->event_code = buf[0];
    out->parameter_total_length = buf[1];
    if (kHciEvtHeaderBytes + out->parameter_total_length > len)
        return false;
    out->parameters = (out->parameter_total_length > 0) ? (buf + kHciEvtHeaderBytes) : nullptr;
    out->parameters_size = out->parameter_total_length;
    return true;
}

bool HciParseCommandComplete(const u8* buf, u32 len, HciCommandComplete* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    HciEventHeader hdr;
    if (!HciParseEventHeader(buf, len, &hdr))
        return false;
    if (hdr.event_code != kEvtCommandComplete)
        return false;
    // Command_Complete parameter layout (Vol 4 Part E §7.7.14):
    //   [0]    Num_HCI_Command_Packets
    //   [1..2] Command_Opcode (LE u16)
    //   [3..N] Return parameters (per-command, may be empty)
    if (hdr.parameter_total_length < 3)
        return false;
    out->num_hci_command_packets = hdr.parameters[0];
    out->command_opcode = ReadLeU16(hdr.parameters + 1);
    out->return_parameters = (hdr.parameter_total_length > 3) ? (hdr.parameters + 3) : nullptr;
    out->return_parameters_size = hdr.parameter_total_length - 3;
    return true;
}

bool HciParseCommandStatus(const u8* buf, u32 len, HciCommandStatus* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    HciEventHeader hdr;
    if (!HciParseEventHeader(buf, len, &hdr))
        return false;
    if (hdr.event_code != kEvtCommandStatus)
        return false;
    // Command_Status parameter layout (§7.7.15):
    //   [0]    Status
    //   [1]    Num_HCI_Command_Packets
    //   [2..3] Command_Opcode (LE u16)
    if (hdr.parameter_total_length != 4)
        return false;
    out->status = hdr.parameters[0];
    out->num_hci_command_packets = hdr.parameters[1];
    out->command_opcode = ReadLeU16(hdr.parameters + 2);
    return true;
}

bool HciParseReadLocalVersion(const u8* buf, u32 len, HciReadLocalVersion* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    if (buf == nullptr)
        return false;
    ::duetos::net::hci_rust::DuetosHciReadLocalVersion r{};
    if (!::duetos::net::hci_rust::duetos_hci_parse_read_local_version(buf, len, &r) || r.ok == 0)
        return false;
    out->status = r.status;
    out->hci_version = r.hci_version;
    out->hci_revision = r.hci_revision;
    out->lmp_version = r.lmp_version;
    out->manufacturer_name = r.manufacturer_name;
    out->lmp_subversion = r.lmp_subversion;
    return true;
}

bool HciParseReadBdAddr(const u8* buf, u32 len, HciReadBdAddr* out)
{
    if (out == nullptr)
        return false;
    *out = {};
    if (buf == nullptr)
        return false;
    ::duetos::net::hci_rust::DuetosHciReadBdAddr r{};
    if (!::duetos::net::hci_rust::duetos_hci_parse_read_bd_addr(buf, len, &r) || r.ok == 0)
        return false;
    out->status = r.status;
    for (u32 i = 0; i < 6; ++i)
        out->bd_addr[i] = r.bd_addr[i];
    return true;
}

void HciEventLog(const HciEventHeader& evt)
{
    arch::SerialWrite("[bt-hci] event=");
    arch::SerialWriteHex(evt.event_code);
    arch::SerialWrite(" plen=");
    arch::SerialWriteHex(evt.parameter_total_length);
    arch::SerialWrite("\n");
}

void HciSelfTest()
{
    // ---- Opcode pack / unpack round-trip. -----------------------
    {
        const u16 op = HciOpcode(kOgfLeController, kOcfLeSetScanEnable);
        Eq(op, 0x200Cu, "opcode(LE, set_scan_enable) == 0x200C");
        Eq(HciOpcodeOgf(op), kOgfLeController, "ogf round-trip");
        Eq(HciOpcodeOcf(op), kOcfLeSetScanEnable, "ocf round-trip");
    }

    // ---- HCI_Reset (3-byte command, no params). ----------------
    {
        u8 buf[16] = {};
        const u32 n = HciBuildCmdReset(buf, sizeof(buf));
        Eq(n, 3, "Reset built bytes");
        Eq(ReadLeU16(buf), HciOpcode(kOgfHostController, kOcfReset), "Reset opcode");
        Eq(buf[2], 0, "Reset param-len 0");
    }

    // ---- HCI_LE_Set_Scan_Parameters. ---------------------------
    {
        u8 buf[16] = {};
        const u32 n = HciBuildCmdLeSetScanParameters(buf, sizeof(buf), kLeScanTypeActive,
                                                     /*interval=*/0x60u,
                                                     /*window=*/0x30u, kLeOwnAddrTypePublic, kLeFilterPolicyAll);
        Eq(n, 3 + 7, "LE_SetScanParams bytes");
        Eq(buf[2], 7, "LE_SetScanParams param-len");
        Eq(buf[3], kLeScanTypeActive, "LE_SetScanParams scan_type");
        Eq(ReadLeU16(buf + 4), 0x60u, "LE_SetScanParams interval");
        Eq(ReadLeU16(buf + 6), 0x30u, "LE_SetScanParams window");
        Eq(buf[8], kLeOwnAddrTypePublic, "LE_SetScanParams own_addr");
        Eq(buf[9], kLeFilterPolicyAll, "LE_SetScanParams filter_policy");
    }

    // window > interval is rejected.
    {
        u8 buf[16] = {};
        const u32 n = HciBuildCmdLeSetScanParameters(buf, sizeof(buf), kLeScanTypeActive, 0x10u, 0x20u, 0, 0);
        Eq(n, 0, "LE_SetScanParams window>interval rejected");
    }

    // ---- HCI_LE_Set_Scan_Enable. -------------------------------
    {
        u8 buf[16] = {};
        const u32 n = HciBuildCmdLeSetScanEnable(buf, sizeof(buf), /*enable=*/1, /*filter_duplicates=*/1);
        Eq(n, 3 + 2, "LE_SetScanEnable bytes");
        Eq(buf[3], 1, "LE_SetScanEnable enable");
        Eq(buf[4], 1, "LE_SetScanEnable filter_duplicates");
    }

    // ---- Event header parser. ----------------------------------
    {
        // Synthetic Disconnection_Complete event: 0x05, plen=4, status, conn_handle (LE16), reason.
        const u8 evt[] = {kEvtDisconnectionComplete, 0x04, 0x00, 0x40, 0x00, 0x13};
        HciEventHeader h;
        Eq(u64(HciParseEventHeader(evt, sizeof(evt), &h)), 1, "parse evt header ok");
        Eq(h.event_code, kEvtDisconnectionComplete, "evt code");
        Eq(h.parameter_total_length, 4, "evt plen");
        Eq(h.parameters[0], 0x00, "evt params[0]");
        Eq(h.parameters[3], 0x13, "evt params[3]");
    }

    // Truncated event must be rejected.
    {
        const u8 short_evt[] = {kEvtCommandComplete};
        HciEventHeader h;
        Eq(u64(HciParseEventHeader(short_evt, sizeof(short_evt), &h)), 0, "short evt rejected");
    }

    // Declared param length > available bytes must be rejected.
    {
        const u8 lying[] = {kEvtCommandComplete, 0x10, 0x01};
        HciEventHeader h;
        Eq(u64(HciParseEventHeader(lying, sizeof(lying), &h)), 0, "lying plen rejected");
    }

    // ---- Command_Complete parser + Read_BD_ADDR decode. --------
    {
        const u16 op = HciOpcode(kOgfInformational, kOcfReadBdAddr);
        u8 evt[2 + 3 + 7] = {};
        evt[0] = kEvtCommandComplete;
        evt[1] = 3 + 7; // plen
        evt[2] = 1;     // num_hci_command_packets
        WriteLeU16(evt + 3, op);
        evt[5] = 0x00; // status = success
        // BD_ADDR = 11:22:33:44:55:66 — wire is LE so byte 0 = 0x66
        evt[6] = 0x66;
        evt[7] = 0x55;
        evt[8] = 0x44;
        evt[9] = 0x33;
        evt[10] = 0x22;
        evt[11] = 0x11;

        HciCommandComplete cc;
        Eq(u64(HciParseCommandComplete(evt, sizeof(evt), &cc)), 1, "parse Command_Complete ok");
        Eq(cc.num_hci_command_packets, 1, "Command_Complete num_pkts");
        Eq(cc.command_opcode, op, "Command_Complete opcode");
        Eq(cc.return_parameters_size, 7, "Command_Complete rparams size");

        HciReadBdAddr addr;
        Eq(u64(HciParseReadBdAddr(cc.return_parameters, cc.return_parameters_size, &addr)), 1,
           "parse BD_ADDR rparams ok");
        Eq(addr.status, 0, "BD_ADDR status");
        Eq(addr.bd_addr[0], 0x66, "BD_ADDR[0] LE");
        Eq(addr.bd_addr[5], 0x11, "BD_ADDR[5] LE");
    }

    // ---- Read_Local_Version_Information decode. ----------------
    {
        // Status=0, HCI=0x0C (5.3), HCI_Rev=0x1234, LMP=0x0C, Mfr=0x000F (Broadcom),
        // LMP_Sub=0x6116.
        const u8 rp[9] = {0x00, 0x0C, 0x34, 0x12, 0x0C, 0x0F, 0x00, 0x16, 0x61};
        HciReadLocalVersion v;
        Eq(u64(HciParseReadLocalVersion(rp, sizeof(rp), &v)), 1, "parse local version ok");
        Eq(v.status, 0, "local version status");
        Eq(v.hci_version, 0x0C, "hci_version");
        Eq(v.hci_revision, 0x1234, "hci_revision");
        Eq(v.lmp_version, 0x0C, "lmp_version");
        Eq(v.manufacturer_name, 0x000F, "manufacturer");
        Eq(v.lmp_subversion, 0x6116, "lmp_subversion");
    }

    // ---- Command_Status parser. --------------------------------
    {
        const u16 op = HciOpcode(kOgfLinkControl, kOcfDisconnect);
        u8 evt[6] = {};
        evt[0] = kEvtCommandStatus;
        evt[1] = 0x04;
        evt[2] = 0x00; // status = success
        evt[3] = 0x01; // num_pkts
        WriteLeU16(evt + 4, op);
        HciCommandStatus cs;
        Eq(u64(HciParseCommandStatus(evt, sizeof(evt), &cs)), 1, "parse Command_Status ok");
        Eq(cs.status, 0, "Command_Status status");
        Eq(cs.command_opcode, op, "Command_Status opcode");
    }

    // ---- Build buffer-overflow rejection. ----------------------
    {
        u8 tiny[2] = {};
        Eq(HciBuildCmdReset(tiny, sizeof(tiny)), 0, "Reset rejects 2-byte buf");
    }

    arch::SerialWrite("[bt-hci] selftest pass\n");
}

} // namespace duetos::net::bluetooth
