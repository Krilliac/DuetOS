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
    if (std::fwrite(kMagic, 1, sizeof(kMagic), m_fp) != sizeof(kMagic))
    {
        std::fclose(m_fp);
        m_fp = nullptr;
        return false;
    }
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
    if (std::fwrite(buf, 1, kFrame, m_fp) != kFrame && !m_writeFailed)
    {
        // One-shot: a full disk would otherwise emit this per event.
        m_writeFailed = true;
        std::fprintf(stderr,
                     "[vmm] record: short write — the log is truncated "
                     "and will not replay faithfully\n");
        std::fflush(stderr);
    }
    std::fflush(m_fp);
}

bool EventLog::ReadNext()
{
    uint8_t buf[kFrame];
    if (std::fread(buf, 1, kFrame, m_fp) != kFrame)
    {
        return false; // clean EOF, or a truncated trailing frame
    }

    Event ev;
    std::memcpy(&ev.seq, buf, 8);
    std::memcpy(&ev.a, buf + 9, 8);

    // A replay log is an untrusted file. Reject a kind PumpReplay has no
    // arm for, rather than letting it fall through the dispatch switch:
    // silently skipping an event makes the replay diverge from the
    // recording while still reporting success, which defeats the whole
    // point of the feature.
    const uint8_t kind = buf[8];
    if (kind != static_cast<uint8_t>(EvKind::SerialRx) &&
        kind != static_cast<uint8_t>(EvKind::RaiseLine) &&
        kind != static_cast<uint8_t>(EvKind::Pit2Expire))
    {
        return false;
    }
    ev.kind = static_cast<EvKind>(kind);

    // Deliberately NOT validated: that seq is non-decreasing. Put() is
    // called from four threads (vCPU via HandleIoPort, stdin, the PIT
    // timer, and the window thread through Ps2I8042's raise callback),
    // it takes no lock, and the seq it stamps comes from a plain
    // non-atomic ExitTrace::m_seq. So a producer can read seq=10, get
    // descheduled, and land its frame after another thread's seq=15 —
    // a correct recording legitimately contains out-of-order frames.
    // Rejecting them here would silently truncate the rest of a valid
    // replay. PumpReplay already copes: its `ev.seq <= m_trace.total()`
    // gate simply fires a late frame at the next opportunity.
    m_next = ev;
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
