#pragma once

#include "util/types.h"

/*
 * DuetOS — Wireless diagnostic event ring.
 *
 * A small, bounded ring buffer that every wireless-stack TU logs
 * to. The point is bring-up debuggability on real hardware:
 * because QEMU emulates no Wi-Fi NIC, every code path under
 * `kernel/net/wireless/` and `kernel/drivers/net/{iwlwifi,
 * rtl88xx, bcm43xx}*` ships untested on the dev host. When the
 * first user installs DuetOS on a laptop with an Intel AX200 (or
 * any other supported chip) and Wi-Fi doesn't come up, the only
 * artifact they can ship back is the serial / panic log.
 *
 * Therefore: every state transition, every register write, every
 * timeout, every key-derivation result is recorded as an event
 * in this ring. The ring is dumped as part of any panic dump and
 * via the shell command `wifi diag`.
 *
 * Threading:
 *   - `Record` is callable from any kernel context. The
 *     internal lock is an irq-save spinlock so it is safe from
 *     interrupt-handler bottom halves.
 *   - The ring discards the oldest event when full (no caller
 *     ever blocks on a full ring).
 *
 * Capacity is fixed at 512 events × 96 bytes = 48 KiB; that
 * fits comfortably in the kernel BSS. Events older than
 * `kRingCapacity` slots are silently overwritten.
 */

namespace duetos::net::wireless::diag
{

enum class Layer : u8
{
    Driver = 0,   // per-vendor driver (iwlwifi/rtl88xx/bcm43xx)
    FwUpload = 1, // microcode upload state machine
    Rings = 2,    // TX/RX ring setup + doorbell
    Mlme = 3,     // 802.11 MLME (scan/auth/assoc/disassoc)
    Eapol = 4,    // EAPOL 4-way handshake
    KeyMgmt = 5,  // key install / rekey
    Tx = 6,       // outbound frame path
    Rx = 7,       // inbound frame path
    Wdev = 8,     // WirelessDevice / cfg80211-equivalent surface
    Diag = 9,     // diagnostic-layer meta events
};

inline constexpr u32 kRingCapacity = 512;
inline constexpr u32 kTagMaxLen = 23;    // tag string bound
inline constexpr u32 kDetailMaxLen = 31; // detail string bound

struct Event
{
    u64 timestamp_ticks; // tick at which event was recorded
    u32 sequence;        // monotonic sequence number across reboot
    u8 cpu;              // CPU index that recorded the event
    Layer layer;
    u8 reserved0;
    u8 reserved1;
    char tag[kTagMaxLen + 1];       // short event name (e.g. "scan-start")
    char detail[kDetailMaxLen + 1]; // optional human-readable detail
    u64 v0;
    u64 v1;
    u64 v2;
    u32 status; // ErrorCode encoded; 0 = Ok
};

/// Record an event into the ring. `tag` is required and must be a
/// nul-terminated string of length ≤ `kTagMaxLen`. `detail` may be
/// null. `v0/v1/v2` are arbitrary numeric arguments for the
/// formatter — typically (register-offset, value, expected) or
/// (state-from, state-to, trigger).
void Record(Layer layer, const char* tag, u64 v0 = 0, u64 v1 = 0, u64 v2 = 0, u32 status = 0,
            const char* detail = nullptr);

/// Convenience overloads that pre-fill `status` from a Result.
void RecordOk(Layer layer, const char* tag, u64 v0 = 0, u64 v1 = 0, u64 v2 = 0, const char* detail = nullptr);
void RecordErr(Layer layer, const char* tag, u32 status_code, u64 v0 = 0, u64 v1 = 0, u64 v2 = 0,
               const char* detail = nullptr);

/// Number of events currently in the ring (≤ `kRingCapacity`).
u32 EventCount();

/// Read an event by index where 0 is oldest. Returns false if
/// out-of-range or `out` is null.
bool EventAt(u32 index, Event* out);

/// Total events recorded since boot (including those that were
/// overwritten because the ring filled). Useful for detecting
/// "did I lose events?" cases.
u64 TotalRecorded();

/// Total events dropped to ring overrun (subtract from total to
/// get currently-retained).
u64 TotalDropped();

/// Dump the last `max_events` events (or fewer if the ring isn't
/// full) to the kernel serial log in a fixed-width tabular form.
/// Called automatically from the panic handler and from the
/// shell command `wifi diag`. Pass 0 to dump all retained events.
void Dump(u32 max_events);

/// One-line layer name for log formatting.
const char* LayerName(Layer l);

/// Clear the ring. Used by the shell command `wifi diag clear`.
void Clear();

/// Initialize the diag layer. Idempotent. Safe to call before
/// scheduler bring-up (uses simple irq-save locking).
void Init();

} // namespace duetos::net::wireless::diag
