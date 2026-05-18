#include "net/wireless/test/wireless_dataplane_test.h"

#include "arch/x86_64/serial.h"
#include "core/panic.h"
#include "net/stack.h"
#include "net/wireless/test/loopback_driver.h"
#include "net/wireless/wnetif.h"

namespace duetos::net::wireless::test
{

namespace
{

constexpr u32 kIface = 2; // 0 = e1000, 1 = stack self-test, 2 = us

bool IpEq(const duetos::net::Ipv4Address& a, const u8 b[4])
{
    for (u32 i = 0; i < 4; ++i)
        if (a.octets[i] != b[i])
            return false;
    return true;
}

} // namespace

void WirelessDataPlaneSelfTest()
{
    arch::SerialWrite("[wifi-data] starting GCMP data-plane self-test\n");

    static LoopbackDriver drv = {};
    const u8 ap_mac[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01};
    const u8 sta_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x01};

    auto rr = LoopbackDriverRegister(&drv, "DuetOS-ISP", "ISPpassword123", ap_mac, sta_mac, /*channel=*/6);
    KASSERT(rr.has_value(), "net/wireless/data", "loopback register failed");

    auto dr = LoopbackDriverDrive(&drv, "ISPpassword123");
    KASSERT(dr.has_value(), "net/wireless/data", "association/handshake failed (good PSK)");
    KASSERT(drv.wdev->op_state == WirelessOpState::Connected, "net/wireless/data", "did not reach Connected");
    KASSERT(drv.sta_pairwise_key_len == 16, "net/wireless/data", "pairwise TK not 16 bytes");

    const u8 gw_ip[4] = {10, 7, 0, 1};
    const u8 lease_ip[4] = {10, 7, 0, 55};
    auto br = LoopbackDriverBindNetif(&drv, kIface, gw_ip, lease_ip);
    KASSERT(br.has_value(), "net/wireless/data", "netif bind failed");
    KASSERT(duetos::net::InterfaceIsBound(kIface), "net/wireless/data", "iface not bound after WNetifBind");

    // DHCP over the encrypted link.
    const bool started = duetos::net::DhcpStart(kIface);
    KASSERT(started, "net/wireless/data", "DhcpStart refused (single g_dhcp still in flight on iface 0?)");
    for (u32 round = 0; round < 16 && !duetos::net::DhcpLeaseRead().valid; ++round)
        LoopbackDriverPump(&drv);

    const auto lease = duetos::net::DhcpLeaseRead();
    KASSERT(lease.valid, "net/wireless/data", "no DHCP lease after pumping the encrypted link");
    KASSERT(IpEq(lease.ip, lease_ip), "net/wireless/data", "leased IP is not the gateway's pool address");
    KASSERT(IpEq(duetos::net::InterfaceIp(kIface), lease_ip), "net/wireless/data", "iface IP not rebound to lease");

    // ICMP: ping the gateway. ARP for gw_ip was auto-seeded by the
    // stack from the inbound DHCP IPv4 frames.
    duetos::net::NetPingArm(0xBEEF, 1);
    const bool sent = duetos::net::NetIcmpSendEcho(kIface, duetos::net::Ipv4Address{{10, 7, 0, 1}}, 0xBEEF, 1);
    KASSERT(sent, "net/wireless/data", "echo TX failed (no ARP entry for gateway?)");
    for (u32 round = 0; round < 8 && !duetos::net::NetPingRead().replied; ++round)
        LoopbackDriverPump(&drv);
    KASSERT(duetos::net::NetPingRead().replied, "net/wireless/data", "no ICMP echo reply over the encrypted link");

    // The link must actually be encrypted: the last STA→AP frame's
    // GCMP KeyId byte has ExtIV set, the protected body differs
    // from the cleartext 802.3 frame, and it decrypts back intact.
    KASSERT(drv.last_tx_wire_len >= kWNetif80211Hdr + 8 + 16, "net/wireless/data", "captured TX frame too short");
    KASSERT((drv.last_tx_wire[kWNetif80211Hdr + 3] & 0x20) != 0, "net/wireless/data", "GCMP ExtIV bit not set");
    {
        bool differs = false;
        const u32 body_off = kWNetif80211Hdr + 8;
        for (u32 i = 0; i + body_off < drv.last_tx_wire_len && i < drv.last_tx_plain_len; ++i)
            if (drv.last_tx_wire[body_off + i] != drv.last_tx_plain[i])
                differs = true;
        KASSERT(differs, "net/wireless/data", "on-wire body equals cleartext — not encrypted");
    }
    {
        static u8 back[kWNetifMaxFrame];
        u32 back_len = 0;
        u64 pn = 0;
        auto ur = WNetifDecap(drv.sta_pairwise_key, sta_mac, ap_mac, /*from_ds=*/false, drv.last_tx_wire,
                              drv.last_tx_wire_len, &pn, back, sizeof(back), &back_len);
        KASSERT(ur.has_value(), "net/wireless/data", "captured frame failed to decrypt");
        KASSERT(back_len == drv.last_tx_plain_len, "net/wireless/data", "decrypted length mismatch");
        for (u32 i = 0; i < back_len; ++i)
            KASSERT(back[i] == drv.last_tx_plain[i], "net/wireless/data", "decrypted bytes mismatch");
    }

    arch::SerialWrite("[wifi-data] PASS — DHCP lease + gateway ping over GCMP-encrypted Wi-Fi link\n");
}

} // namespace duetos::net::wireless::test
