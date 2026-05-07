#pragma once

#include "drivers/audio/hda_jack.h"
#include "util/types.h"

/*
 * DuetOS — HDA jack inventory, v0.
 *
 * Companion to `hda_jack.{h,cpp}`. The decoder is a pure
 * function; this module is the kernel-owned table the codec
 * walker populates as it visits each pin widget.
 *
 * Why it exists: once the HDA controller is brought up and
 * `WalkCodec` enumerates each codec's widgets, the operator
 * needs a single, stable surface that names every physical
 * jack on the chassis. The audio server uses it to pick "the
 * speaker pin" or "the headphone pin" when the operator says
 * "play here"; the Settings panel's audio routing tab will
 * read it; the boot log surfaces it for triage.
 *
 * v0 scope:
 *   - Bounded inventory (`kHdaJackInventoryCap` slots).
 *   - One record per pin-complex widget the walker encounters.
 *   - Spinlock-guarded so the inventory can be read from any
 *     kernel context (shell command, audio server, GUI thread)
 *     while the walker is running.
 *   - Companion accessor for the audio server to ask "what's
 *     the first speaker pin?" / "what's the first headphone
 *     pin?" without re-deriving the answer.
 *
 * Out of scope:
 *   - Hot-plug. Real headphone-jack insertion fires an
 *     unsolicited HDA event; `WalkCodec` only runs once at
 *     bring-up. Tracking presence over time is a separate
 *     slice that needs the unsolicited-response path live.
 *   - Per-codec widget topology (DAC -> mixer -> pin chain).
 *     The inventory is a *flat* list of physical jacks; the
 *     audio server's path-selection lives elsewhere.
 *
 * Threading: every public function takes the inventory
 * spinlock. Safe to call from any kernel context.
 */

namespace duetos::drivers::audio::hda
{

inline constexpr u32 kHdaJackInventoryCap = 32;

struct HdaJackRecord
{
    bool live;
    u8 codec_slot;
    u8 pin_node;
    HdaPinConfigDefault config;
    bool jack_present_known; // true once GET_PIN_SENSE has been polled
    bool jack_present;       // bit-31 of last GET_PIN_SENSE response
};

/// Reset the inventory. Idempotent.
void HdaJackInventoryReset();

/// Record a pin widget seen during codec walk. The walker passes
/// the raw 32-bit config-default dword; the inventory decodes it
/// once and stores the result. Returns true on success, false if
/// the table is full.
bool HdaJackInventoryRecord(u8 codec_slot, u8 pin_node, u32 config_default_raw);

/// Update the cached presence state for a previously-recorded pin
/// widget. Looks up by (codec_slot, pin_node). No-op if not found.
void HdaJackInventoryStampPresence(u8 codec_slot, u8 pin_node, u32 pin_sense_response);

/// Number of live records.
u32 HdaJackInventoryCount();

/// Read a record by index in [0, HdaJackInventoryCount()). Returns
/// false on out-of-range. The returned record is a copy (the
/// internal table holds the source of truth).
bool HdaJackInventoryRead(u32 index, HdaJackRecord* out);

/// Convenience: find the first pin whose decoded default-device
/// matches `target` (typically Speaker or HpOut). Returns false
/// if no match is recorded. On success, `*codec_slot_out` and
/// `*pin_node_out` are filled.
bool HdaJackInventoryFindByDevice(HdaDefaultDevice target, u8* codec_slot_out, u8* pin_node_out);

/// Boot self-test. Wipes the table, records 4 synthetic pin
/// records (rear green line-out / internal speaker / front pink
/// mic / no-conn), asserts count + accessors + the
/// FindByDevice helper. Logs `[hda-inventory] selftest pass/fail`.
void HdaJackInventorySelfTest();

} // namespace duetos::drivers::audio::hda
