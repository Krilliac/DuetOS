#include "net/wireless/wnetif.h"

#include "net/stack.h"
#include "net/wireless/gcmp.h"

namespace duetos::net::wireless
{

namespace
{

using ::duetos::core::Err;
using ::duetos::core::ErrorCode;
using ::duetos::core::Result;

constexpr u32 kWNetifMaxCtx = 4;
constinit WNetifCtx g_ctx[kWNetifMaxCtx] = {};

void Copy(u8* d, const u8* s, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        d[i] = s[i];
}

bool Equal(const u8* a, const u8* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

// SNAP header for an IP/ARP MSDU: AA AA 03 00 00 00 then EtherType.
constexpr u8 kSnapPrefix[6] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00};

// Build the 24-byte 3-address 802.11 data header. `from_ds` true
// → AP→STA (FromDS); false → STA→AP (ToDS).
void BuildHeader(u8* h, bool from_ds, const u8 sta[6], const u8 ap[6], const u8 eth_dst[6], const u8 eth_src[6])
{
    u16 fc = 0x0008; // type=Data, subtype=0
    fc |= 0x4000;    // Protected
    fc |= from_ds ? 0x0200 : 0x0100;
    h[0] = static_cast<u8>(fc & 0xFF);
    h[1] = static_cast<u8>(fc >> 8);
    h[2] = 0;
    h[3] = 0; // Duration
    if (from_ds)
    {
        Copy(h + 4, sta, 6);      // A1 = DA  (STA)
        Copy(h + 10, ap, 6);      // A2 = BSSID/TA (AP)
        Copy(h + 16, eth_src, 6); // A3 = SA
    }
    else
    {
        Copy(h + 4, ap, 6);       // A1 = BSSID (AP)
        Copy(h + 10, sta, 6);     // A2 = TA (STA)
        Copy(h + 16, eth_dst, 6); // A3 = DA
    }
    h[22] = 0;
    h[23] = 0; // SeqCtrl
}

} // namespace

Result<void> WNetifEncap(const u8 tk[16], const u8 sta_mac[6], const u8 ap_mac[6], bool from_ds, u64 pn, const u8* eth,
                         u32 eth_len, u8* out, u32 out_cap, u32* out_len)
{
    if (eth == nullptr || out == nullptr || out_len == nullptr || eth_len < kWNetifEthHdr)
        return Err{ErrorCode::InvalidArgument};

    const u8* eth_dst = eth;
    const u8* eth_src = eth + 6;
    const u8* ethertype = eth + 12;
    const u8* l3 = eth + kWNetifEthHdr;
    const u32 l3_len = eth_len - kWNetifEthHdr;

    u8 hdr[kWNetif80211Hdr];
    BuildHeader(hdr, from_ds, sta_mac, ap_mac, eth_dst, eth_src);

    // MSDU = LLC/SNAP (6) + EtherType (2) + L3.
    u8 msdu[kWNetifMaxFrame];
    const u32 msdu_len = kWNetifSnapBytes + l3_len;
    if (msdu_len > sizeof(msdu))
        return Err{ErrorCode::Overflow};
    Copy(msdu, kSnapPrefix, 6);
    msdu[6] = ethertype[0];
    msdu[7] = ethertype[1];
    Copy(msdu + kWNetifSnapBytes, l3, l3_len);

    if (out_cap < kWNetif80211Hdr)
        return Err{ErrorCode::BufferTooSmall};
    Copy(out, hdr, kWNetif80211Hdr);

    const u8* ta = hdr + 10; // A2
    u32 body_len = 0;
    RESULT_TRY(GcmpProtect(tk, ta, pn, hdr, kWNetif80211Hdr, msdu, msdu_len, out + kWNetif80211Hdr,
                           out_cap - kWNetif80211Hdr, &body_len));
    *out_len = kWNetif80211Hdr + body_len;
    return Result<void>{};
}

Result<void> WNetifDecap(const u8 tk[16], const u8 sta_mac[6], const u8 ap_mac[6], bool from_ds, const u8* in,
                         u32 in_len, u64* out_pn, u8* eth_out, u32 eth_cap, u32* eth_len)
{
    if (in == nullptr || out_pn == nullptr || eth_out == nullptr || eth_len == nullptr)
        return Err{ErrorCode::InvalidArgument};
    if (in_len < kWNetif80211Hdr + kGcmpOverheadBytes)
        return Err{ErrorCode::Corrupt};

    const u8* hdr = in;
    const u8* ta = hdr + 10; // A2

    // Validate the header addresses for the expected direction so a
    // misrouted / spoofed frame is rejected before the AEAD step.
    // STA→AP (ToDS): A1=AP(BSSID), A2=STA(TA). AP→STA (FromDS):
    // A1=STA(DA), A2=AP(TA).
    const u8* expect_a1 = from_ds ? sta_mac : ap_mac;
    const u8* expect_a2 = from_ds ? ap_mac : sta_mac;
    if (!Equal(hdr + 4, expect_a1, 6) || !Equal(hdr + 10, expect_a2, 6))
        return Err{ErrorCode::Corrupt};

    u8 msdu[kWNetifMaxFrame];
    u32 msdu_len = 0;
    RESULT_TRY(GcmpUnprotect(tk, ta, hdr, kWNetif80211Hdr, in + kWNetif80211Hdr, in_len - kWNetif80211Hdr, out_pn, msdu,
                             sizeof(msdu), &msdu_len));

    if (msdu_len < kWNetifSnapBytes || !Equal(msdu, kSnapPrefix, 6))
        return Err{ErrorCode::Corrupt};

    const u32 l3_len = msdu_len - kWNetifSnapBytes;
    if (eth_cap < kWNetifEthHdr + l3_len)
        return Err{ErrorCode::BufferTooSmall};

    // Recover 802.3 addresses from the 802.11 header per direction.
    if (from_ds)
    {
        Copy(eth_out, hdr + 4, 6);      // DA = A1 (STA)
        Copy(eth_out + 6, hdr + 16, 6); // SA = A3
    }
    else
    {
        Copy(eth_out, hdr + 16, 6);     // DA = A3
        Copy(eth_out + 6, hdr + 10, 6); // SA = A2 (STA)
    }
    eth_out[12] = msdu[6];
    eth_out[13] = msdu[7];
    Copy(eth_out + kWNetifEthHdr, msdu + kWNetifSnapBytes, l3_len);
    *eth_len = kWNetifEthHdr + l3_len;
    return Result<void>{};
}

namespace
{

bool WNetifTxTrampoline(u32 iface_index, const void* frame, u64 len)
{
    WNetifCtx* ctx = WNetifByIface(iface_index);
    if (ctx == nullptr || ctx->wdev == nullptr || ctx->wdev->ops.SendDataFrame == nullptr)
        return false;
    auto r = ctx->wdev->ops.SendDataFrame(ctx->wdev, static_cast<const u8*>(frame), static_cast<u32>(len));
    return r.has_value();
}

} // namespace

WNetifCtx* WNetifByIface(u32 iface_index)
{
    for (u32 i = 0; i < kWNetifMaxCtx; ++i)
        if (g_ctx[i].in_use && g_ctx[i].iface_index == iface_index)
            return &g_ctx[i];
    return nullptr;
}

WNetifCtx* WNetifBind(WirelessDevice* wdev, u32 iface_index, const u8 sta_mac[6], const u8 ap_mac[6], const u8 tk[16])
{
    if (wdev == nullptr || sta_mac == nullptr || ap_mac == nullptr || tk == nullptr)
        return nullptr;
    WNetifCtx* ctx = WNetifByIface(iface_index);
    if (ctx == nullptr)
    {
        for (u32 i = 0; i < kWNetifMaxCtx; ++i)
        {
            if (!g_ctx[i].in_use)
            {
                ctx = &g_ctx[i];
                break;
            }
        }
    }
    if (ctx == nullptr)
        return nullptr;

    *ctx = WNetifCtx{};
    ctx->in_use = true;
    ctx->iface_index = iface_index;
    ctx->wdev = wdev;
    Copy(ctx->tk, tk, 16);
    Copy(ctx->sta_mac, sta_mac, 6);
    Copy(ctx->ap_mac, ap_mac, 6);

    MacAddress mac{};
    Copy(mac.octets, sta_mac, 6);
    Ipv4Address ip{{0, 0, 0, 0}};
    if (!NetStackBindInterface(iface_index, mac, ip, &WNetifTxTrampoline))
    {
        ctx->in_use = false;
        return nullptr;
    }
    return ctx;
}

Result<void> WNetifInjectDecrypted(WNetifCtx* ctx, const u8* frame, u32 len)
{
    if (ctx == nullptr || frame == nullptr)
        return Err{ErrorCode::InvalidArgument};

    u8 eth[kWNetifMaxFrame];
    u32 eth_len = 0;
    u64 pn = 0;
    auto dr =
        WNetifDecap(ctx->tk, ctx->sta_mac, ctx->ap_mac, /*from_ds=*/true, frame, len, &pn, eth, sizeof(eth), &eth_len);
    if (!dr.has_value())
    {
        ++ctx->rx_auth_fail;
        return dr;
    }
    if (pn <= ctx->rx_pn_seen)
    {
        ++ctx->rx_replays;
        return Err{ErrorCode::Corrupt};
    }
    ctx->rx_pn_seen = pn;
    ++ctx->rx_frames;
    NetStackInjectRx(ctx->iface_index, eth, eth_len);
    return Result<void>{};
}

} // namespace duetos::net::wireless
