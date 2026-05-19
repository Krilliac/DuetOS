// Record / replay of the guest's host-origin non-deterministic
// inputs, keyed by the monotonic vmexit sequence number (the only
// execution anchor the VMM fully controls).
//
// Recorded: serial RX bytes, IOAPIC line raises (IRQ4/IRQ0), and
// the exit-seq at which PIT channel-2 OUT2 first reads expired
// (the LAPIC-calibration reference). On replay these are fed back
// at the same exit-seq, so the I/O-port / MMIO / exception exit
// stream reproduces.
//
// DETERMINISM BOUNDARY: WHP's xApic emulation owns the LAPIC timer
// internally — its firing is neither observable nor schedulable by
// us — so replay is reproducible at *exit-sequence* granularity,
// not cycle-exact. That is enough to re-hit a serial-driven or
// IRQ-ordering bug; it is not a cycle-accurate time machine.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace duetos::vmm
{

enum class RecMode
{
    Off,
    Record,
    Replay
};

enum class EvKind : uint8_t
{
    SerialRx   = 1, // a = byte
    RaiseLine  = 2, // a = irq
    Pit2Expire = 3  // (no payload)
};

struct Event
{
    uint64_t seq = 0;
    EvKind   kind = EvKind::SerialRx;
    uint64_t a = 0;
};

// Append-only binary log. One Recorder OR one Player per run.
class EventLog
{
public:
    ~EventLog();

    bool OpenRecord(const std::string& path);
    bool OpenReplay(const std::string& path);
    RecMode mode() const { return m_mode; }

    // Record: append an event at the current exit seq.
    void Put(uint64_t seq, EvKind kind, uint64_t a);

    // Replay: true if another event remains; peeks its seq.
    bool Peek(Event& out) const;
    // Replay: consume the peeked event (call after Peek + apply).
    void Pop();

private:
    RecMode m_mode = RecMode::Off;
    FILE*   m_fp = nullptr;
    Event   m_next;          // replay lookahead
    bool    m_haveNext = false;
    bool    ReadNext();
};

} // namespace duetos::vmm
