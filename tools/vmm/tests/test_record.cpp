// Parser tests for the record/replay log (src/debug/record.cpp).
//
// A replay log is untrusted input: it is read back from disk and its
// events are injected into the guest. Before the hardening, ReadNext
// cast any byte to EvKind and never checked seq ordering, so a corrupt
// log replayed a DIFFERENT execution than the one it was recorded from
// while still reporting success — which defeats the point of the
// determinism feature.
#include "test_main.h"

#include "debug/record.h"

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using duetos::vmm::EventLog;
using duetos::vmm::Event;
using duetos::vmm::EvKind;

namespace
{

// Unique temp path per case; removed on scope exit.
struct TempFile
{
    std::filesystem::path path;

    explicit TempFile(const char* stem)
    {
        path = std::filesystem::temp_directory_path() /
               (std::string("duetos-vmm-") + stem + ".rec");
        std::filesystem::remove(path);
    }
    ~TempFile() { std::error_code ec; std::filesystem::remove(path, ec); }

    std::string str() const { return path.string(); }
};

constexpr char kMagic[8] = {'D', 'U', 'E', 'T', 'R', 'E', 'C', '1'};

void AppendFrame(std::vector<uint8_t>& v, uint64_t seq, uint8_t kind,
                 uint64_t a)
{
    const size_t off = v.size();
    v.resize(off + 17);
    std::memcpy(&v[off], &seq, 8);
    v[off + 8] = kind;
    std::memcpy(&v[off + 9], &a, 8);
}

void WriteRaw(const std::string& path, const std::vector<uint8_t>& bytes)
{
    std::FILE* f = std::fopen(path.c_str(), "wb");
    CHECK(f != nullptr);
    if (!bytes.empty())
    {
        std::fwrite(bytes.data(), 1, bytes.size(), f);
    }
    std::fclose(f);
}

// Drain every event a replay log will hand out, in order.
std::vector<Event> DrainReplay(const std::string& path, bool& opened)
{
    EventLog log;
    opened = log.OpenReplay(path);
    std::vector<Event> out;
    if (!opened)
    {
        return out;
    }
    Event ev;
    while (log.Peek(ev))
    {
        out.push_back(ev);
        log.Pop();
    }
    return out;
}

} // namespace

TEST(record_replay_round_trip_preserves_events)
{
    TempFile tf("roundtrip");
    {
        EventLog rec;
        CHECK(rec.OpenRecord(tf.str()));
        rec.Put(1, EvKind::SerialRx, 'A');
        rec.Put(5, EvKind::RaiseLine, 4);
        rec.Put(9, EvKind::Pit2Expire, 0);
        CHECK(!rec.writeFailed());
    }

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened);
    CHECK_EQ(evs.size(), size_t(3));
    CHECK_EQ(evs[0].seq, uint64_t(1));
    CHECK(evs[0].kind == EvKind::SerialRx);
    CHECK_EQ(evs[0].a, uint64_t('A'));
    CHECK_EQ(evs[1].seq, uint64_t(5));
    CHECK(evs[1].kind == EvKind::RaiseLine);
    CHECK_EQ(evs[1].a, uint64_t(4));
    CHECK_EQ(evs[2].seq, uint64_t(9));
    CHECK(evs[2].kind == EvKind::Pit2Expire);
}

TEST(record_replay_rejects_bad_magic)
{
    TempFile tf("badmagic");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    b[3] = 'X';
    AppendFrame(b, 1, 1, 'A');
    WriteRaw(tf.str(), b);

    EventLog log;
    CHECK(!log.OpenReplay(tf.str()));
}

// A frame whose kind byte is not one of the three PumpReplay can apply
// must end the replay, not be skipped silently.
TEST(record_replay_stops_at_unknown_kind)
{
    TempFile tf("badkind");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    AppendFrame(b, 1, 1, 'A');  // SerialRx — good
    AppendFrame(b, 2, 99, 0);   // not a legal EvKind
    AppendFrame(b, 3, 2, 4);    // would be good, but is past the bad one
    WriteRaw(tf.str(), b);

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened);
    CHECK_EQ(evs.size(), size_t(1));
    CHECK_EQ(evs[0].seq, uint64_t(1));
}

TEST(record_replay_rejects_zero_kind_in_first_frame)
{
    TempFile tf("zerokind");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    AppendFrame(b, 1, 0, 0); // 0 is not a legal EvKind
    WriteRaw(tf.str(), b);

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened); // the magic is fine, so the file opens...
    CHECK_EQ(evs.size(), size_t(0)); // ...but yields nothing
}

// Out-of-order seq must be TOLERATED, not rejected. EventLog::Put takes
// no lock and is called from four threads (vCPU, stdin, PIT timer, and
// the window thread via Ps2I8042's raise callback), stamping a seq read
// from a plain non-atomic ExitTrace::m_seq. A producer can therefore
// read seq=10, get descheduled, and land its frame after another
// thread's seq=15 — so a CORRECT recording legitimately contains
// backwards frames. Dropping the replay there would silently truncate a
// valid session, which is the exact divergence this feature exists to
// prevent. (Making seq truly monotonic means locking the producer; that
// is a separate change to the record path, not to this parser.)
TEST(record_replay_tolerates_backwards_seq)
{
    TempFile tf("backseq");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    AppendFrame(b, 10, 1, 'A');
    AppendFrame(b, 5, 1, 'B'); // legitimately possible: see above
    WriteRaw(tf.str(), b);

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened);
    CHECK_EQ(evs.size(), size_t(2));
    CHECK_EQ(evs[0].seq, uint64_t(10));
    CHECK_EQ(evs[1].seq, uint64_t(5));
}

// Equal seq is legal — several inputs can land at the same exit.
TEST(record_replay_allows_repeated_seq)
{
    TempFile tf("sameseq");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    AppendFrame(b, 7, 1, 'A');
    AppendFrame(b, 7, 1, 'B');
    WriteRaw(tf.str(), b);

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened);
    CHECK_EQ(evs.size(), size_t(2));
}

TEST(record_replay_stops_at_truncated_trailing_frame)
{
    TempFile tf("trunc");
    std::vector<uint8_t> b(kMagic, kMagic + 8);
    AppendFrame(b, 1, 1, 'A');
    b.resize(b.size() + 5); // a partial 17-byte frame
    WriteRaw(tf.str(), b);

    bool opened = false;
    auto evs = DrainReplay(tf.str(), opened);
    CHECK(opened);
    CHECK_EQ(evs.size(), size_t(1));
}

TEST(record_replay_rejects_missing_file)
{
    EventLog log;
    CHECK(!log.OpenReplay("duetos-vmm-nonexistent-replay-file.rec"));
}
