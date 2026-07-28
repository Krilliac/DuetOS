#include "debug/gdb_packet.h"

namespace duetos::vmm::gdb
{

namespace
{

// Consumes hex digits from `s` starting at `i` and returns how many
// were consumed (0 = no digit there, i.e. malformed). `v` saturates
// instead of wrapping: a client is free to send 32 f's and the caller
// clamps the result anyway, but a silent wrap would turn a huge
// length into a small plausible one.
size_t ScanHex(const std::string& s, size_t i, uint64_t& v)
{
    const size_t start = i;
    v = 0;
    while (i < s.size() && IsHex(s[i]))
    {
        if (v > (UINT64_MAX >> 4))
        {
            v = UINT64_MAX;
        }
        else
        {
            v = (v << 4) | Unhex(s[i]);
        }
        ++i;
    }
    return i - start;
}

} // namespace

bool IsHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

uint8_t Unhex(char c)
{
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

bool ParseRegBlock(const std::string& hex, uint64_t out[kRegBlockRegs])
{
    if (hex.size() < kRegBlockHexLen) return false;
    for (size_t i = 0; i < kRegBlockHexLen; ++i)
    {
        if (!IsHex(hex[i])) return false;
    }
    for (size_t r = 0; r < kRegBlockRegs; ++r)
    {
        uint64_t x = 0;
        for (size_t b = 0; b < 8; ++b)
        {
            const size_t  off = r * 16 + b * 2;
            const uint8_t byte =
                static_cast<uint8_t>((Unhex(hex[off]) << 4) |
                                     Unhex(hex[off + 1]));
            x |= static_cast<uint64_t>(byte) << (8 * b);
        }
        out[r] = x;
    }
    return true;
}

bool ParseMemSpec(const std::string& pkt, uint64_t& addr, uint64_t& len,
                  size_t* dataOff)
{
    if (dataOff) *dataOff = 0;
    size_t       i  = 1; // skip the 'm'/'M'
    const size_t na = ScanHex(pkt, i, addr);
    if (na == 0) return false;
    i += na;
    if (i >= pkt.size() || pkt[i] != ',') return false;
    ++i;
    const size_t nl = ScanHex(pkt, i, len);
    if (nl == 0) return false;
    i += nl;
    if (len > kMaxMemBytes) len = kMaxMemBytes;
    if (dataOff && i < pkt.size() && pkt[i] == ':') *dataOff = i + 1;
    return true;
}

bool ParseBpSpec(const std::string& pkt, uint64_t& addr)
{
    // "<Z|z>0,<addr>[,<kind>]" — [0] type, [1] kind, [2] ',', [3..]
    // address. Anything shorter has no address field at all.
    if (pkt.size() < 4 || pkt[2] != ',') return false;
    return ScanHex(pkt, 3, addr) != 0;
}

} // namespace duetos::vmm::gdb
