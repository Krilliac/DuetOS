#pragma once

#include "../../core/types.h"

/*
 * PS/2 mouse driver — v0.
 *
 * Second end-to-end IRQ-driven input device. Sits on the 8042
 * auxiliary (port 2) channel, routed through the IOAPIC on the GSI
 * mapped from ISA IRQ 12. Speaks the classic 3-byte "standard mouse"
 * packet format — no wheel, no 5-button extension (those need a
 * Microsoft IntelliMouse handshake the keyboard path avoids by
 * design).
 *
 * Relationship to the keyboard driver: both devices share the same
 * 8042 controller, and Ps2KeyboardInit() explicitly DISABLED port 2
 * during its init sequence (`kCmdDisablePort2`). Ps2MouseInit()
 * re-enables it, programs the mouse, then routes IRQ 12. The two
 * drivers MUST run in order (keyboard first, mouse second) — the
 * mouse driver assumes the controller is already self-tested and
 * the keyboard is working.
 *
 * Packet layout (3 bytes, LSB first):
 *
 *   byte 0: | Y_OV | X_OV | Y_SGN | X_SGN | 1 | MB | RB | LB |
 *   byte 1: X movement (-256..+255, sign-extended from X_SGN)
 *   byte 2: Y movement (-256..+255, sign-extended from Y_SGN, POSITIVE
 *           means mouse moved DOWN in screen space — we invert this
 *           so higher-level code sees the conventional "up = -")
 *
 * The "always 1" bit in byte 0 is a re-sync marker: if a byte with
 * bit 3 clear arrives when we expected byte 0 of a packet, the IRQ
 * stream got out of phase (typical cause: a spurious IRQ during
 * init, or a hot-plugged PS/2 mouse). The driver resets its packet
 * cursor and drops the byte.
 *
 * API shape:
 *   - `Ps2MouseReadPacket()`: blocks until a complete packet is
 *     available, returns it. One packet per call; caller can poll
 *     from task context as fast as it wants.
 *   - `Ps2MouseTryReadPacket()`: non-blocking variant; returns
 *     false if no packet is pending. For the compositor main loop
 *     once it exists — the shell would poll between frame blits.
 *
 * Scope limits that will be fixed in later commits:
 *   - Standard 3-byte protocol only. Wheel / 5-button extensions
 *     need a device-specific sample-rate handshake (200/100/80)
 *     and a 4th byte in each packet.
 *   - No sample-rate override — we accept whatever the firmware
 *     default is (typically 100 Hz). Fine for early compositor
 *     work; games that need 1000 Hz polling come later.
 *   - No USB HID. Real hardware routes most mice via USB today;
 *     xHCI + HID class land in their own tracks.
 *   - Absolute-coordinate mice (tablets, QEMU USB-tablet) look
 *     like standard relative mice on the PS/2 stream — they
 *     report relative deltas. The USB-tablet absolute path lands
 *     with USB HID.
 *
 * Context: kernel. Init runs once, after Ps2KeyboardInit.
 */

namespace duetos::drivers::input
{

constexpr u8 kMouseButtonLeft = 1U << 0;
constexpr u8 kMouseButtonRight = 1U << 1;
constexpr u8 kMouseButtonMiddle = 1U << 2;

struct MousePacket
{
    i32 dx;     // pixels, positive = right
    i32 dy;     // pixels, positive = down (screen-space convention)
    u8 buttons; // bitmask of kMouseButton*
    u8 _pad[3];
};

/// Enable the 8042 aux channel, reset + configure the mouse, route
/// ISA IRQ 12 to the dispatcher, unmask. Safe to call exactly once.
/// Soft-fails with a warning log if no PS/2 mouse responds — common
/// on modern laptops that only expose USB input. Callers should not
/// assume packets will arrive.
void Ps2MouseInit();

/// Block the calling task until a full 3-byte packet has been
/// assembled from the IRQ stream, then return it decoded. Never
/// blocks if a packet is already queued.
MousePacket Ps2MouseReadPacket();

/// Non-blocking variant. Returns true + writes `out` if a packet
/// was ready; returns false otherwise. For consumers that want to
/// drain buffered packets without parking the task.
bool Ps2MouseTryReadPacket(MousePacket* out);

/// Lifetime counters for diagnostics / tests.
struct Ps2MouseStats
{
    u64 irqs_seen;       // total IRQ 12 deliveries
    u64 packets_decoded; // full 3-byte packets assembled
    u64 bytes_dropped;   // bytes lost to desync or overflow
};
Ps2MouseStats Ps2MouseStatsRead();

/// External packet injection — analogous to `KeyboardInjectEvent`.
/// Lets the xHCI HID mouse polling task push packets into the
/// same ring `Ps2MouseReadPacket` consumes. Thread-safe under
/// the same Cli-bracketed discipline the IRQ path uses.
void MouseInjectPacket(const MousePacket& p);

} // namespace duetos::drivers::input
