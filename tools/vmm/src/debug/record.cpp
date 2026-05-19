#include "debug/record.h"

#include <cstring>

namespace duetos::vmm
{

namespace
{
// On-disk record: fixed 17-byte little-endian frame.
//   u64 seq | u8 kind | u64 a
constexpr size_t kFrame = 8 + 1 + 8;
constexpr char kMagic[8] = {'D', 'U', 'E', 'T', 'R', 'E', 'C', '1'};
} // namespace

EventLog::~EventLog()
{
    if (m_fp)
    {
        std::fclose(m_fp);
    }
}

bool EventLog::OpenRecord(const std::string& path)
{
    m_fp = std::fopen(path.c_str(), "wb");
    if (!m_fp)
    {
        return false;
    }
    std::fwrite(kMagic, 1, sizeof(kMagic), m_fp);
    m_mode = RecMode::Record;
    return true;
}

bool EventLog::OpenReplay(const std::string& path)
{
    m_fp = std::fopen(path.c_str(), "rb");
    if (!m_fp)
    {
        return false;
    }
    char hdr[8] = {};
    if (std::fread(hdr, 1, sizeof(hdr), m_fp) != sizeof(hdr) ||
        std::memcmp(hdr, kMagic, sizeof(kMagic)) != 0)
    {
        std::fclose(m_fp);
        m_fp = nullptr;
        return false;
    }
    m_mode = RecMode::Replay;
    m_haveNext = ReadNext();
    return true;
}

void EventLog::Put(uint64_t seq, EvKind kind, uint64_t a)
{
    if (m_mode != RecMode::Record)
    {
        return;
    }
    uint8_t buf[kFrame];
    std::memcpy(buf, &seq, 8);
    buf[8] = static_cast<uint8_t>(kind);
    std::memcpy(buf + 9, &a, 8);
    std::fwrite(buf, 1, kFrame, m_fp);
    std::fflush(m_fp);
}

bool EventLog::ReadNext()
{
    uint8_t buf[kFrame];
    if (std::fread(buf, 1, kFrame, m_fp) != kFrame)
    {
        return false;
    }
    std::memcpy(&m_next.seq, buf, 8);
    m_next.kind = static_cast<EvKind>(buf[8]);
    std::memcpy(&m_next.a, buf + 9, 8);
    return true;
}

bool EventLog::Peek(Event& out) const
{
    if (m_mode != RecMode::Replay || !m_haveNext)
    {
        return false;
    }
    out = m_next;
    return true;
}

void EventLog::Pop()
{
    if (m_mode == RecMode::Replay)
    {
        m_haveNext = ReadNext();
    }
}

} // namespace duetos::vmm
