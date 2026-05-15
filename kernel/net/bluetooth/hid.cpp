#include "net/bluetooth/hid.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "drivers/input/hid_keyboard.h"
#include "log/klog.h"
#include "sync/spinlock.h"

namespace duetos::net::bluetooth
{

namespace
{

u16 ReadLeU16(const u8* p)
{
    return u16(u16(p[0]) | (u16(p[1]) << 8));
}

void CopyBytes(u8* dst, const u8* src, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        dst[i] = src[i];
}

// Normalise a HID Input report payload (after ATT/HIDP framing has
// been stripped) into the 8-byte boot keyboard report. Accepts the
// bare 8-byte boot report, or a 9-byte report whose leading byte is
// a Report ID prefix (HOGP report maps commonly carry one). Any
// other length is a non-boot report map this v0 does not decode
// (GAP: report-descriptor parsing is out of scope).
bool NormaliseBootReport(const u8* value, u32 value_len, u8 out[8])
{
    if (value == nullptr)
        return false;
    if (value_len == 8)
    {
        CopyBytes(out, value, 8);
        return true;
    }
    if (value_len == 9)
    {
        CopyBytes(out, value + 1, 8); // strip Report ID prefix
        return true;
    }
    return false;
}

} // namespace

bool BtHidParseAclHeader(const u8* p, u32 len, BtHidAclHeader* out, const u8** payload, u32* payload_len)
{
    if (p == nullptr || out == nullptr || payload == nullptr || payload_len == nullptr)
        return false;
    *out = {};
    *payload = nullptr;
    *payload_len = 0;
    if (len < 4)
        return false;
    const u16 hf = ReadLeU16(p);
    out->handle = u16(hf & 0x0FFF);
    out->pb = u8((hf >> 12) & 0x3);
    out->bc = u8((hf >> 14) & 0x3);
    out->data_len = ReadLeU16(p + 2);
    if (u32(4) + out->data_len > len)
        return false;
    *payload = (out->data_len > 0) ? (p + 4) : nullptr;
    *payload_len = out->data_len;
    return true;
}

bool BtHidParseL2cap(const u8* pdu, u32 len, u16* cid, const u8** sdu, u32* sdu_len)
{
    if (pdu == nullptr || cid == nullptr || sdu == nullptr || sdu_len == nullptr)
        return false;
    *cid = 0;
    *sdu = nullptr;
    *sdu_len = 0;
    if (len < 4)
        return false;
    const u16 plen = ReadLeU16(pdu);
    *cid = ReadLeU16(pdu + 2);
    if (u32(4) + plen > len)
        return false;
    *sdu = (plen > 0) ? (pdu + 4) : nullptr;
    *sdu_len = plen;
    return true;
}

bool BtHidExtractBootReport(BtHidKind kind, u16 att_match_handle, const u8* sdu, u32 sdu_len, u8 out_report[8])
{
    if (sdu == nullptr || out_report == nullptr || sdu_len == 0)
        return false;

    if (kind == BtHidKind::LeHogp)
    {
        // ATT PDU: [0]=opcode, [1..2]=attr handle LE, [3..]=value.
        const u8 op = sdu[0];
        if (op != kAttHandleValueNotification && op != kAttHandleValueIndication)
            return false;
        if (sdu_len < 3)
            return false;
        const u16 attr = ReadLeU16(sdu + 1);
        if (att_match_handle != 0 && attr != att_match_handle)
            return false;
        // GAP: an Indication should be answered with a Handle Value
        // Confirmation (0x1E). Keyboards use notifications; v0 does
        // not emit the confirmation, so an indication-only keyboard
        // would stop after one report. Notification path is exact.
        return NormaliseBootReport(sdu + 3, sdu_len - 3, out_report);
    }

    if (kind == BtHidKind::Classic)
    {
        // HIDP: [0]=header. DATA/Input only.
        if (sdu[0] != kHidpHdrDataInput)
            return false;
        return NormaliseBootReport(sdu + 1, sdu_len - 1, out_report);
    }

    return false;
}

namespace
{

struct BtHidConnection
{
    bool live;
    BtHidKind kind;
    u16 acl_handle;
    u16 att_report_handle; // LeHogp: 0 = accept any
    u16 interrupt_cid;     // Classic
    u8 prev[8];            // last boot report, for press/release diffing

    // Per-connection L2CAP reassembly. Boot keyboard reports never
    // fragment in practice (≤ ~10 bytes, ATT_MTU ≥ 23) but a
    // correct host must follow the PB flag regardless.
    u8 reasm[kBtHidReasmMax];
    u32 reasm_len;

    u64 reports_seen;
};

struct BtHidState
{
    BtHidConnection conns[kBtHidMaxConnections];
    bool init_done;
};

constinit BtHidState g_state{};
constinit duetos::sync::SpinLock g_hid_lock{};

// Self-test capture seam. When armed, EmitReport diffs into this
// buffer instead of calling KeyboardInjectEvent, so the boot
// self-test can prove the whole ACL→KeyEvent chain without leaking
// phantom keystrokes into the live shell input queue. Off in
// production; only BtHidSelfTest toggles it, single-threaded, at
// boot.
constinit bool g_capture_active = false;
constinit duetos::drivers::input::KeyEvent g_capture_buf[duetos::drivers::input::kHidKbMaxEventsPerDiff * 4] = {};
constinit u32 g_capture_count = 0;

BtHidConnection* FindByHandleLocked(u16 acl_handle)
{
    for (u32 i = 0; i < kBtHidMaxConnections; ++i)
    {
        if (g_state.conns[i].live && g_state.conns[i].acl_handle == acl_handle)
            return &g_state.conns[i];
    }
    return nullptr;
}

BtHidConnection* AllocSlotLocked()
{
    for (u32 i = 0; i < kBtHidMaxConnections; ++i)
    {
        if (!g_state.conns[i].live)
            return &g_state.conns[i];
    }
    return nullptr;
}

// Diff this connection's previous report against `report` and
// surface the KeyEvents. Production path injects into the kernel
// input queue (same as USB HID); the self-test capture path records
// them for assertion. Caller holds g_hid_lock.
void EmitReportLocked(BtHidConnection& c, const u8 report[8])
{
    if (g_capture_active)
    {
        duetos::drivers::input::KeyEvent evs[duetos::drivers::input::kHidKbMaxEventsPerDiff];
        const u32 n = duetos::drivers::input::HidKeyboardDiffEvents(c.prev, report, evs,
                                                                    duetos::drivers::input::kHidKbMaxEventsPerDiff);
        for (u32 i = 0; i < n; ++i)
        {
            const u32 cap = sizeof(g_capture_buf) / sizeof(g_capture_buf[0]);
            if (g_capture_count < cap)
                g_capture_buf[g_capture_count++] = evs[i];
        }
    }
    else
    {
        duetos::drivers::input::HidKeyboardDiffAndInject(c.prev, report);
    }
    CopyBytes(c.prev, report, 8);
    ++c.reports_seen;
}

// Route one fully-reassembled L2CAP PDU for a connection. Caller
// holds g_hid_lock.
void DispatchL2capLocked(BtHidConnection& c, const u8* pdu, u32 pdu_len)
{
    u16 cid = 0;
    const u8* sdu = nullptr;
    u32 sdu_len = 0;
    if (!BtHidParseL2cap(pdu, pdu_len, &cid, &sdu, &sdu_len))
        return;

    bool match = false;
    if (c.kind == BtHidKind::LeHogp)
        match = (cid == kL2capCidAtt);
    else if (c.kind == BtHidKind::Classic)
        match = (cid == c.interrupt_cid);
    if (!match)
        return;

    u8 report[8];
    if (BtHidExtractBootReport(c.kind, c.att_report_handle, sdu, sdu_len, report))
        EmitReportLocked(c, report);
}

} // namespace

void BtHidInit()
{
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    if (g_state.init_done)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return;
    }
    for (u32 i = 0; i < kBtHidMaxConnections; ++i)
        g_state.conns[i] = {};
    g_state.init_done = true;
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
    KLOG_INFO("net/bluetooth/hid", "online");
}

::duetos::core::Result<void> BtHidRegisterLeKeyboard(u16 acl_handle, u16 att_report_handle)
{
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    if (FindByHandleLocked(acl_handle) != nullptr)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    }
    BtHidConnection* c = AllocSlotLocked();
    if (c == nullptr)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *c = {};
    c->live = true;
    c->kind = BtHidKind::LeHogp;
    c->acl_handle = acl_handle;
    c->att_report_handle = att_report_handle;
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
    return {};
}

::duetos::core::Result<void> BtHidRegisterClassicKeyboard(u16 acl_handle, u16 interrupt_cid)
{
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    if (FindByHandleLocked(acl_handle) != nullptr)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return ::duetos::core::Err{::duetos::core::ErrorCode::AlreadyExists};
    }
    BtHidConnection* c = AllocSlotLocked();
    if (c == nullptr)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return ::duetos::core::Err{::duetos::core::ErrorCode::OutOfMemory};
    }
    *c = {};
    c->live = true;
    c->kind = BtHidKind::Classic;
    c->acl_handle = acl_handle;
    c->interrupt_cid = interrupt_cid;
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
    return {};
}

void BtHidUnregister(u16 acl_handle)
{
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    BtHidConnection* c = FindByHandleLocked(acl_handle);
    if (c != nullptr)
        *c = {};
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
}

void BtHidDeliverAcl(const u8* acl_pkt, u32 len)
{
    BtHidAclHeader hdr;
    const u8* frag = nullptr;
    u32 frag_len = 0;
    if (!BtHidParseAclHeader(acl_pkt, len, &hdr, &frag, &frag_len))
        return;
    if (frag == nullptr || frag_len == 0)
        return;

    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    BtHidConnection* c = FindByHandleLocked(hdr.handle);
    if (c == nullptr)
    {
        duetos::sync::SpinLockRelease(g_hid_lock, flags);
        return; // unknown connection — not a registered keyboard
    }

    if (hdr.pb == kAclPbContinuation)
    {
        // Append to the in-progress PDU.
        if (c->reasm_len + frag_len <= kBtHidReasmMax)
        {
            CopyBytes(c->reasm + c->reasm_len, frag, frag_len);
            c->reasm_len += frag_len;
        }
        else
        {
            c->reasm_len = 0; // overflow — drop the partial PDU
        }
    }
    else
    {
        // Start of a new L2CAP PDU.
        c->reasm_len = 0;
        if (frag_len <= kBtHidReasmMax)
        {
            CopyBytes(c->reasm, frag, frag_len);
            c->reasm_len = frag_len;
        }
    }

    // Dispatch once the full L2CAP PDU (4-byte header + declared
    // payload) has arrived.
    if (c->reasm_len >= 4)
    {
        const u32 want = u32(4) + ReadLeU16(c->reasm);
        if (c->reasm_len >= want)
        {
            DispatchL2capLocked(*c, c->reasm, want);
            c->reasm_len = 0;
        }
    }
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
}

u32 BtHidConnectionCount()
{
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    u32 n = 0;
    for (u32 i = 0; i < kBtHidMaxConnections; ++i)
    {
        if (g_state.conns[i].live)
            ++n;
    }
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
    return n;
}

BtHidConnectionInfo BtHidConnectionAt(u32 index)
{
    BtHidConnectionInfo info{};
    auto flags = duetos::sync::SpinLockAcquire(g_hid_lock);
    if (index < kBtHidMaxConnections)
    {
        const BtHidConnection& c = g_state.conns[index];
        info.live = c.live;
        info.kind = c.kind;
        info.acl_handle = c.acl_handle;
        info.match_id = (c.kind == BtHidKind::Classic) ? c.interrupt_cid : c.att_report_handle;
        info.reports_seen = c.reports_seen;
    }
    duetos::sync::SpinLockRelease(g_hid_lock, flags);
    return info;
}

namespace
{

void Expect(bool cond, const char* what)
{
    if (cond)
        return;
    arch::SerialWrite("[bt-hid] MISMATCH ");
    arch::SerialWrite(what);
    arch::SerialWrite("\n");
    core::Panic("net/bluetooth/hid", "BT HID self-test mismatch");
}

void WriteLe16(u8* d, u16 v)
{
    d[0] = u8(v & 0xFF);
    d[1] = u8((v >> 8) & 0xFF);
}

// Build one HCI ACL packet wrapping an L2CAP B-frame around `sdu`.
// Returns total length written into `out`.
u32 BuildAcl(u8* out, u16 acl_handle, u8 pb, u16 cid, const u8* sdu, u32 sdu_len)
{
    const u16 hf = u16((acl_handle & 0x0FFF) | (u16(pb & 0x3) << 12));
    const u16 l2cap_total = u16(4 + sdu_len);
    WriteLe16(out, hf);
    WriteLe16(out + 2, l2cap_total);
    WriteLe16(out + 4, u16(sdu_len)); // L2CAP payload length
    WriteLe16(out + 6, cid);          // L2CAP CID
    for (u32 i = 0; i < sdu_len; ++i)
        out[8 + i] = sdu[i];
    return 8 + sdu_len;
}

} // namespace

void BtHidSelfTest()
{
    BtHidInit();

    // ---- Pure ACL header parse. --------------------------------
    {
        // handle=0x0040, pb=2 (start), data_len=15 (4 header + 15
        // payload = 19 bytes total).
        const u8 pkt[] = {0x40, 0x20, 0x0F, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        BtHidAclHeader h;
        const u8* pl = nullptr;
        u32 pll = 0;
        Expect(BtHidParseAclHeader(pkt, sizeof(pkt), &h, &pl, &pll), "acl header parse ok");
        Expect(h.handle == 0x0040, "acl handle");
        Expect(h.pb == 2, "acl pb=start");
        Expect(h.data_len == 15 && pll == 15, "acl data_len");
        // Short buffer + lying length rejected.
        Expect(!BtHidParseAclHeader(pkt, 3, &h, &pl, &pll), "short acl rejected");
        const u8 lying[] = {0x40, 0x20, 0x40, 0x00, 0x01};
        Expect(!BtHidParseAclHeader(lying, sizeof(lying), &h, &pl, &pll), "lying acl len rejected");
    }

    // ---- Pure L2CAP + ATT extraction. --------------------------
    {
        const u8 press_a[8] = {0, 0, 0x04, 0, 0, 0, 0, 0};
        u8 att[3 + 8];
        att[0] = kAttHandleValueNotification;
        WriteLe16(att + 1, 0x002A);
        for (u32 i = 0; i < 8; ++i)
            att[3 + i] = press_a[i];
        u8 l2[4 + sizeof(att)];
        WriteLe16(l2, sizeof(att));
        WriteLe16(l2 + 2, kL2capCidAtt);
        for (u32 i = 0; i < sizeof(att); ++i)
            l2[4 + i] = att[i];

        u16 cid = 0;
        const u8* sdu = nullptr;
        u32 sl = 0;
        Expect(BtHidParseL2cap(l2, sizeof(l2), &cid, &sdu, &sl), "l2cap parse ok");
        Expect(cid == kL2capCidAtt, "l2cap cid=ATT");
        Expect(sl == sizeof(att), "l2cap sdu len");

        u8 rep[8];
        Expect(BtHidExtractBootReport(BtHidKind::LeHogp, 0x002A, sdu, sl, rep), "att extract ok");
        Expect(rep[2] == 0x04, "att report usage 'a'");
        Expect(!BtHidExtractBootReport(BtHidKind::LeHogp, 0x0099, sdu, sl, rep), "att handle mismatch rejected");
        att[0] = 0x0B; // ATT Read Response — not a notification
        Expect(!BtHidExtractBootReport(BtHidKind::LeHogp, 0x002A, att, sizeof(att), rep), "non-notification rejected");
    }

    // ---- End-to-end: BLE HOGP press / release with capture. ----
    g_capture_active = true;
    {
        Expect(BtHidRegisterLeKeyboard(0x0040, 0x002A).has_value(), "register LE kbd");
        Expect(!BtHidRegisterLeKeyboard(0x0040, 0x002A).has_value(), "dup register rejected");
        Expect(BtHidConnectionCount() == 1, "one connection after register");

        auto deliver = [](u16 handle, const u8 boot[8])
        {
            u8 att[3 + 8];
            att[0] = kAttHandleValueNotification;
            WriteLe16(att + 1, 0x002A);
            for (u32 i = 0; i < 8; ++i)
                att[3 + i] = boot[i];
            u8 pkt[64];
            const u32 n = BuildAcl(pkt, handle, 2 /*start*/, kL2capCidAtt, att, sizeof(att));
            g_capture_count = 0;
            BtHidDeliverAcl(pkt, n);
        };

        const u8 press_a[8] = {0, 0, 0x04, 0, 0, 0, 0, 0};
        deliver(0x0040, press_a);
        Expect(g_capture_count == 1, "press 'a' -> 1 event");
        Expect(g_capture_buf[0].code == u16('a') && !g_capture_buf[0].is_release, "press 'a' decoded");

        const u8 release[8] = {0, 0, 0, 0, 0, 0, 0, 0};
        deliver(0x0040, release);
        Expect(g_capture_count == 1, "release 'a' -> 1 event");
        Expect(g_capture_buf[0].code == u16('a') && g_capture_buf[0].is_release, "release 'a' decoded");

        // Report-ID-prefixed 9-byte value: press 'b' (usage 0x05).
        {
            const u8 ridrep[9] = {0x01, 0, 0, 0x05, 0, 0, 0, 0, 0};
            u8 att[3 + 9];
            att[0] = kAttHandleValueNotification;
            WriteLe16(att + 1, 0x002A);
            for (u32 i = 0; i < 9; ++i)
                att[3 + i] = ridrep[i];
            u8 pkt[64];
            const u32 n = BuildAcl(pkt, 0x0040, 2, kL2capCidAtt, att, sizeof(att));
            g_capture_count = 0;
            BtHidDeliverAcl(pkt, n);
            Expect(g_capture_count == 1 && g_capture_buf[0].code == u16('b'), "report-id strip -> 'b'");
        }
    }

    // ---- Fragmented L2CAP reassembly (START + CONT). -----------
    {
        Expect(BtHidRegisterLeKeyboard(0x0041, 0x002A).has_value(), "register LE kbd #2");
        const u8 press_c[8] = {0, 0, 0x06, 0, 0, 0, 0, 0};
        u8 att[3 + 8];
        att[0] = kAttHandleValueNotification;
        WriteLe16(att + 1, 0x002A);
        for (u32 i = 0; i < 8; ++i)
            att[3 + i] = press_c[i];
        // Full L2CAP frame = 4 + 11 = 15 bytes. Split at byte 6.
        u8 l2[4 + sizeof(att)];
        WriteLe16(l2, sizeof(att));
        WriteLe16(l2 + 2, kL2capCidAtt);
        for (u32 i = 0; i < sizeof(att); ++i)
            l2[4 + i] = att[i];
        const u32 total = sizeof(l2);
        const u32 split = 6;

        u8 f1[16];
        WriteLe16(f1, u16(0x0041 | (2u << 12))); // pb=start
        WriteLe16(f1 + 2, u16(split));
        for (u32 i = 0; i < split; ++i)
            f1[4 + i] = l2[i];
        u8 f2[16];
        WriteLe16(f2, u16(0x0041 | (u16(kAclPbContinuation) << 12)));
        WriteLe16(f2 + 2, u16(total - split));
        for (u32 i = 0; i < total - split; ++i)
            f2[4 + i] = l2[split + i];

        g_capture_count = 0;
        BtHidDeliverAcl(f1, 4 + split);
        Expect(g_capture_count == 0, "partial PDU not yet dispatched");
        BtHidDeliverAcl(f2, 4 + (total - split));
        Expect(g_capture_count == 1 && g_capture_buf[0].code == u16('c'), "reassembled -> press 'c'");
    }

    // ---- Classic HIDP DATA/Input. ------------------------------
    {
        Expect(BtHidRegisterClassicKeyboard(0x0050, 0x0045).has_value(), "register classic kbd");
        u8 sdu[1 + 8];
        sdu[0] = kHidpHdrDataInput;
        const u8 press_d[8] = {0, 0, 0x07, 0, 0, 0, 0, 0};
        for (u32 i = 0; i < 8; ++i)
            sdu[1 + i] = press_d[i];
        u8 pkt[64];
        const u32 n = BuildAcl(pkt, 0x0050, 2, 0x0045, sdu, sizeof(sdu));
        g_capture_count = 0;
        BtHidDeliverAcl(pkt, n);
        Expect(g_capture_count == 1 && g_capture_buf[0].code == u16('d'), "HIDP -> press 'd'");
        // Wrong HIDP header (not DATA/Input) is ignored.
        sdu[0] = 0xA2;
        const u32 n2 = BuildAcl(pkt, 0x0050, 2, 0x0045, sdu, sizeof(sdu));
        g_capture_count = 0;
        BtHidDeliverAcl(pkt, n2);
        Expect(g_capture_count == 0, "non-DATA/Input HIDP ignored");
    }

    // ---- Teardown: leave the table pristine for production. ----
    BtHidUnregister(0x0040);
    BtHidUnregister(0x0041);
    BtHidUnregister(0x0050);
    BtHidUnregister(0x0040); // idempotent
    Expect(BtHidConnectionCount() == 0, "table empty after teardown");
    g_capture_active = false;
    g_capture_count = 0;

    arch::SerialWrite("[bt-hid] selftest pass\n");
}

} // namespace duetos::net::bluetooth
