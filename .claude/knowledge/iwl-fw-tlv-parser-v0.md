# iwlwifi TLV firmware parser v0

**Last updated:** 2026-05-01
**Type:** Observation + Decision
**Status:** Active — parser only; microcode upload + MLME still deferred

## Description

First piece of real per-vendor firmware logic on DuetOS. The
`kernel/loader/firmware_loader.{h,cpp}` scaffold (VFS-backed
`/lib/firmware/duetos/open/...` then `/lib/firmware/<vendor>/...`)
already returned bytes when a blob was present, but no driver
actually parsed them — the iwlwifi bring-up just dropped the blob
and continued in `firmware_pending` state. This slice closes the
parser half of the v0 wireless story:

- `kernel/drivers/net/iwlwifi_fw.{h,cpp}` — TLV walker for the
  iwlwifi microcode envelope. Validates the zero/magic preamble,
  walks every TLV record, categorises section types (INST / DATA /
  INIT / INIT_DATA / SEC_RT / SecureSecRt), captures the FLAGS /
  NUM_OF_CPU / FW_VERSION / PHY_SKU / HW_TYPE dwords, counts unknown
  records, and bails on any record whose declared length would
  overflow the blob.
- `kernel/drivers/net/iwlwifi.cpp::IwlwifiBringUp` — when
  `FwLoad` returns a blob, the BringUp path now calls
  `IwlFirmwareParse`. A structurally valid blob lifts the NIC out
  of `firmware_pending` and logs a 1-line summary
  (`[iwl-fw] name="..." ver=... build=... tlvs=N inst=... data=... sec_rt=...`).
  A malformed blob marks the NIC `Incompatible` rather than `Ready`
  so the GUI flyout / `netscan` can flag the mismatch honestly.
- `IwlFirmwareSelfTest()` — boot-time self-test wired into
  `kernel/core/main.cpp` immediately after `FwLoaderInit`. Builds a
  synthetic 7-record TLV blob in a 384-byte static buffer and
  asserts every recognised field round-trips, plus three negative
  cases (bad magic → Corrupt, truncated header → InvalidArgument,
  TLV length overflow → Corrupt). Gated by `DUETOS_BOOT_SELFTEST`
  so release builds skip it.

## Why this slice and not the next one

The iwlwifi feature gap (P0 #4 in
`feature-gaps-end-user-v0.md`) sits behind two long blockers:

1. A firmware loader subsystem (existed as a scaffold; needed a
   real per-vendor parser to actually move the needle).
2. A full 802.11 MLME state machine (still deferred).

Even with no firmware blob installed, the parser is testable end-to-end
via the synthetic-blob self-test, and shipping it now means the
moment a blob lands at `/lib/firmware/intel-iwlwifi/iwlwifi-...ucode`
the driver gets a structured view instead of an opaque byte buffer.
That's the prerequisite a microcode-upload slice will need before
the hardware will associate.

Concretely, the format spec is stable Intel ABI:

```
+0     u32 zero       (must be 0)
+4     u32 magic      (0x0A4C5749 = "IWL\n" LE)
+8     u8  name[64]   (NUL-terminated ASCII, sanitized to printable)
+72    u32 ver        (packed major/minor/api/serial)
+76    u32 build
+80    u8  ignore[8]
+88    {                          // TLV stream
         u32 type;
         u32 length;
         u8  payload[length];
         u8  pad[ (-length) & 3 ];   // dword alignment
       }*
```

The TLV identifier numbers are forever-stable (Intel's
`iwl_ucode_tlv_type` enum is shipped in every Linux iwlwifi blob),
so an enum-class mapping in the header costs ~50 lines of header
once and rots roughly never.

## Scope

### Covered

- TLV envelope validation (zero + magic).
- 64-byte name copy with control-character sanitisation.
- Versioning fields (`ver_packed`, `build`).
- Section TLV capture: INST(1), DATA(2), INIT(3), INIT_DATA(4),
  SEC_RT(19), SecureSecRt(24).
- Scalar TLV capture: FLAGS(18), NUM_OF_CPU(27), FW_VERSION(36),
  PHY_SKU(23), HW_TYPE(58).
- SEC_RT count (modern firmware ships multiple back-to-back; we
  pin the first payload + count the rest so a future upload pass
  can re-walk).
- Unknown-record bookkeeping (`unknown_records` is informational —
  never fatal).
- Length-overflow bounds check (the v0 trust boundary). A length
  that would push `payload_off + length` past `blob_size` is
  Corrupt + return.
- Boot self-test: 7 positive records + 3 negative cases.
- Driver wiring: parse-on-load in `IwlwifiBringUp`, with
  `wireless_fw_state = Incompatible` when a blob loads but parses
  badly.

### Deliberately not in scope

- Section-header (`iwl_ucode_section`) parsing inside SEC_RT
  payloads. Each SEC_RT record has its own internal layout
  (offset + length + bytes); the runtime-microcode upload slice
  needs that, not the envelope parser.
- PNVM / IML / debug-region payloads.
- Signature verification. The parser sets
  `parsed.valid = true` on any structurally clean blob — the
  `verified` bit on the `FwBlob` is still false because no
  vendor-signature check has landed.
- Firmware upload to the chip (the slice that drives
  `CSR_RESET`, `CSR_GP_CNTRL.MAC_INIT`, secure-boot handshake,
  copies INST + DATA + SEC_RT into `FW_LOAD_BUFFER`, and waits
  for ALIVE notification). Each silicon family from 1000 through
  Be has different register addresses; chip-ID classification
  already lives in `iwlwifi.cpp::ChipIdShortString`.
- 802.11 MLME (scan / association / EAPOL / key install).

## Integration points

- `kernel/drivers/net/iwlwifi.cpp` — `IwlwifiBringUp` now calls
  `IwlFirmwareParse` when `FwLoad` returns a blob. On parse
  success the NIC clears `firmware_pending` + sets
  `wireless_fw_state = Ready`. On parse failure it stays
  `firmware_pending` + sets `wireless_fw_state = Incompatible`.
- `kernel/core/main.cpp` — `IwlFirmwareSelfTest()` runs after
  `FwLoaderInit()` so the parser is exercised before any NIC
  comes through `NetInit`. New include of
  `drivers/net/iwlwifi_fw.h`.
- `kernel/CMakeLists.txt` — no change. The kernel uses
  `GLOB_RECURSE` over `kernel/**/*.cpp`, so the new TU is picked
  up automatically.

## Observable

Boot log on a host with no firmware installed (the common case
today):

```
[boot] Bringing up firmware loader (scaffold).
[fw-loader] online — backend=VFS (/lib/firmware), policy=OpenThenVendor
[iwl-fw] selftest pass
[boot] Detecting NICs.
... (no /lib/firmware blob → FwLoad returns NotFound, no [iwl-fw] log) ...
```

Boot log on a host where someone has installed a real iwlwifi
ucode (e.g. by mounting `/lib/firmware/intel-iwlwifi/` from a
ramfs at boot and dropping `iwlwifi-cc-a0-46.ucode` into it):

```
[fw-loader] hit /lib/firmware/intel-iwlwifi/iwlwifi-cc-a0-46.ucode
[iwl-fw] name="iwlwifi-cc-a0-46" ver=0x47104 build=0x0 tlvs=0x39 unknown=0x4 inst=0x0 data=0x0 init=0x0 init_data=0x0 sec_rt=0xC
[iwlwifi] online ... status=fw-pending
```

(The `status=fw-pending` line is misleading once parse succeeds —
follow-up: branch to `status=ready` when `wireless_fw_state == Ready`.)

`netscan` then reports:

```
WIRELESS: 1 driver shell online (firmware parsed; microcode upload pending)
```

Boot log if a malformed blob lands (e.g. truncated download):

```
[fw-loader] hit /lib/firmware/intel-iwlwifi/iwlwifi-broken.ucode
[iwlwifi] firmware blob found but TLV parse failed — marking Incompatible
```

## Edge cases / what to remember

- **Header zero word IS load-bearing.** It's the discriminator
  against iwlwifi's older v1/v2 blob formats. Every real TLV
  blob has bytes [0..4) all-zero; v1/v2 blobs put a length there
  instead.
- **TLV length is dword-aligned.** A record with declared length
  5 takes `8 + ((5+3) & ~3) = 16` bytes total. The parser pads
  by `(len + 3) & ~3` and walks past — never reads the pad
  bytes.
- **Length overflow is the trust boundary.** A length of e.g.
  0xFFFFFFF0 must be caught — `payload_off + length > blob_size`
  bails Corrupt before any byte of the bogus payload is read.
  Self-test exercises this case.
- **Unknown records are not fatal.** New iwlwifi blobs add new
  TLV types regularly (the `iwl_ucode_tlv_type` enum has grown
  from ~30 to >70 entries since 2014). The parser increments
  `unknown_records` and continues.
- **`human_readable` is sanitized.** The 64-byte name field can
  legally contain anything; v0 collapses any byte outside
  `[0x20, 0x7F)` to `?` so a mangled blob can't slip control
  characters into the serial log.
- **Parser is pure / no allocation.** Pointers in
  `IwlFirmwareParsed` reference back into the original blob.
  The caller (driver) must keep the blob alive — the firmware
  loader's `FwBlob` does, since it points into a ramfs node.
- **Self-test runs in debug only.** `DUETOS_BOOT_SELFTESTS=1` in
  the debug preset; the release preset skips it via the
  `DUETOS_BOOT_SELFTEST` macro.

## Source attribution

The TLV format (record types, header layout, padding rules) is
documented Intel firmware ABI; the same byte-for-byte format is
parsed by:

- Linux `drivers/net/wireless/intel/iwlwifi/iwl-drv.c` (GPL-2.0)
- OpenIntelWireless/itlwm `IntelFirmware.cpp` (BSD-3-Clause; a
  port to macOS).

The DuetOS implementation is clean-room: only the public format
(record numbers, byte layout) is carried over. No code lifted
from either source.

## See also

- `feature-gaps-end-user-v0.md` — P0 #4 Wi-Fi entry; this slice
  advances the firmware-loader half of that blocker.
- `wireless-drivers-v0.md` — chip-ID-only iwlwifi/rtl88xx/bcm43xx
  shells the parser plugs into.
- `firmware-loader.h` — VFS-backed lookup that produces the blob
  this parser consumes.
- `kernel/drivers/net/iwlwifi.cpp::ChipIdShortString` — silicon
  family table the upload slice will need to match against the
  parsed `human_readable` name when picking which sections to
  load.
