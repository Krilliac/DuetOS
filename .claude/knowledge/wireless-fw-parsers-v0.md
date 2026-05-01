# Wireless firmware parsers v0 — rtl88xx + bcm43xx + iwlwifi (consolidated)

**Last updated:** 2026-05-01
**Type:** Observation + Decision
**Status:** Active — parsers only; microcode upload + MLME still deferred

## Description

Closes the parser half of the firmware-loader blocker for every
wireless silicon family DuetOS recognises. Each vendor uses a
different on-disk format; this slice lands a clean-room parser
for each, plus parse-on-load wiring in the corresponding
`*BringUp` path and a boot self-test driven from synthetic
blobs.

| Family | TU | Format | Self-test |
|--------|----|--------|-----------|
| Intel iwlwifi | `kernel/drivers/net/iwlwifi_fw.{h,cpp}` (landed earlier) | TLV envelope: 88-byte header (zero/magic/name/ver/build/ignore) + record stream `(u32 type, u32 length, u8 payload[length], u8 pad)` dword-aligned | 7-record + 3 negative cases |
| Realtek rtl88xx / rtw88 / rtw89 | `kernel/drivers/net/rtl88xx_fw.{h,cpp}` | Fixed 32-byte header: `__le16 sig + u8 cat + u8 fn + __le16 ver + u8 sub + u8 subsub + u8[4] date + __le16 ramcodesize + __le16 reserved + __le32 svnindex + __le32 reserved[3]` then raw payload | rtlwifi positive + rtw89 sig + bad-sig + truncated cases |
| Broadcom bcm43xx | `kernel/drivers/net/bcm43xx_fw.{h,cpp}` | b43 record stream: each record `u8 type ('u'/'p'/'i') + u8 ver + be16 reserved + be32 size + payload[size]` back-to-back | 3-record + bad-type + truncated + length-overflow cases |

All three follow the same shape: `Parse(blob, size, &out) →
Result<void>`, output struct holds views back into the original
blob (no copying), `Log()` writes a 1-line serial summary,
`SelfTest()` runs at boot when `DUETOS_BOOT_SELFTESTS=1`.

## Scope

### Covered

**Realtek (`rtl88xx_fw.{h,cpp}`):**
- Signature classification across three driver generations
  (`rtlwifi` for 8192/8723/8821/8812/8814, `rtw88` for 8822be,
  `rtw89` for 8852ae and Wi-Fi 6E).
- Header field extraction: signature, category, function,
  version, sub/subsub, build date (mm/dd/hh/mm), ramcodesize,
  svn index.
- Payload pointer + size view.
- Tolerant size-mismatch flag — the `ramcodesize` field is
  documented as bytes in rtlwifi v1 but kbytes in some later
  blobs. The parser accepts either if the blob's remainder
  matches within 4 KiB; otherwise sets `size_mismatch=true`
  but still returns Ok (a future upload pass can decide what
  to do).
- Boot self-test: positive case (rtlwifi sig 0x8821), positive
  case (rtw89 sig 0x8852), bad-signature → Corrupt,
  truncated-header → InvalidArgument.
- Wiring: `Rtl88xxBringUp` parses on FwLoad hit; sets
  `wireless_fw_state = Ready` on parse success or
  `Incompatible` on parse failure.

**Broadcom (`bcm43xx_fw.{h,cpp}`):**
- b43 record-stream walker. Each record is 8 bytes of
  big-endian header + payload bytes. Recognised record types:
  `kB43FwTypeUcode = 0x75 ('u')`, `kB43FwTypePcm = 0x70 ('p')`,
  `kB43FwTypeIv = 0x69 ('i')`.
- Bounded record table at `kBcmMaxRecords = 8` — vendor blobs
  ship 1..4 records in practice; excess records bump
  `dropped_records` so the count is never silently lost.
- Convenience pointers: `parsed.ucode / parsed.pcm / parsed.iv`
  point at the first record of each type.
- Truncation handling: a bad length / unknown type mid-stream
  flags `truncated=true` and stops walking, but the records
  walked so far are still surfaced as long as at least one
  parsed clean.
- Boot self-test: 3-record positive case + bad-first-byte +
  short-header + length-overflow.
- Wiring: `Bcm43xxBringUp` parses on FwLoad hit; same
  Ready/Incompatible split as the Realtek path.

### Deliberately not in scope

- **brcmfmac format** for newer Broadcom silicon. The brcmfmac
  driver uses a different binary layout (CLM blob + signed
  firmware header); v0 only covers the legacy b43 record stream.
  When a brcmfmac blob lands, a dedicated parser will be
  needed.
- **Realtek per-section payload structure.** Each rtlwifi blob
  carries a microcode block whose internal layout (basic / WoWLAN
  / BT-coex / dynamic-mech) varies by silicon. v0 records the
  payload pointer + size; section walking is for the upload
  slice.
- **iwlwifi SEC_RT inner section headers** — see
  `iwl-fw-tlv-parser-v0.md` for that gap.
- **Signature verification.** Every parser sets `parsed.valid =
  true` on a structurally clean blob; no vendor signature
  checks are run.
- **Microcode upload to the chip.** Per-vendor reset / load
  sequence is the next slice and lives in the same TUs (or a
  parallel `*_upload.cpp`).

## Integration points

- `kernel/drivers/net/iwlwifi.cpp::IwlwifiBringUp` parses TLV
  envelopes (landed earlier).
- `kernel/drivers/net/rtl88xx.cpp::Rtl88xxBringUp` now parses
  the rtlwifi/rtw88/rtw89 header on FwLoad hit.
- `kernel/drivers/net/bcm43xx.cpp::Bcm43xxBringUp` now parses
  the b43 record stream on FwLoad hit.
- `kernel/core/main.cpp` runs all three self-tests after
  `FwLoaderInit()` and before `NetInit()`. New includes:
  `drivers/net/{iwlwifi,rtl88xx,bcm43xx}_fw.h`.

## Observable

Boot log on a host with no firmware installed:

```
[fw-loader] online — backend=VFS (/lib/firmware), policy=OpenThenVendor
[iwl-fw] selftest pass
[rtl-fw] selftest pass
[bcm-fw] selftest pass
[80211] beacon selftest pass
```

Boot log when a real Realtek blob is installed at
`/lib/firmware/realtek-rtl88xx/rtlwifi/rtl8821aefw.bin`:

```
[fw-loader] hit /lib/firmware/realtek-rtl88xx/rtlwifi/rtl8821aefw.bin
[rtl-fw] gen=rtlwifi sig=0x8821 ver=0x00031 sub=0x07.0x00 payload=0x6840
[rtl88xx] online ... status=fw-pending
```

Boot log when a Broadcom b43 blob is installed:

```
[fw-loader] hit /lib/firmware/broadcom-bcm43xx/brcm/brcmfmac4356-pcie.bin
[bcm-fw] records=0x3 [ucode ver=0x1 size=0x4000] [pcm ver=0x1 size=0x800] [iv ver=0x1 size=0x100]
[bcm43xx] online ... status=fw-pending
```

A malformed Realtek blob (wrong signature) logs:

```
[rtl88xx] firmware blob found but header parse failed — marking Incompatible
```

## Edge cases / what to remember

- **Realtek signature space is dense and overlapping.** Some
  Linux blobs use 0x88B0 for both rtl8822be and certain rtl8821ce
  variants. v0 classifies by signature exactly; an exact match
  drives generation, anything else returns Corrupt. New silicon
  → add the constant.
- **b43 stops walking on the first unrecognised type.** A blob
  whose first byte is `'u'` but with a corrupted second record
  produces 1 record + `truncated=true`. Treat truncated blobs
  as Incompatible at the upload layer until partial-blob upload
  is proven safe.
- **Realtek `ramcode_size` units are family-specific.** Field is
  `u16`; reading 0x6840 (~26 KB) on rtl8821ae is the byte count;
  reading 0x06 (= 6 KB scaled) on rtw88 is the kbyte count. The
  parser tries both and reports `size_mismatch=true` if neither
  agrees within tolerance — but still returns Ok.
- **All three parsers are pure, no allocation.** Output structs
  carry pointers into the original `FwBlob.data`; the caller
  must keep the blob alive. The firmware loader's VFS-backed
  ramfs node guarantees that.
- **Self-tests run with `DUETOS_BOOT_SELFTESTS=1`.** Release
  builds skip them via the macro guard.

## Source attribution

- iwlwifi format: documented Intel firmware ABI; same byte
  layout parsed by Linux `iwl-drv.c` and OpenIntelWireless
  `IntelFirmware.cpp`.
- Realtek format: rtlwifi/rtw88/rtw89 header layout from
  Linux `drivers/net/wireless/realtek/`. Signature constants
  in `rtl_phycfg.h`.
- Broadcom b43 format: `drivers/net/wireless/broadcom/b43/main.c`
  (`B43_FW_TYPE_*` constants + `b43_fw_header` layout).

All three implementations are clean-room — only the public byte
layouts and identifier numbers are carried over. No code lifted.

## See also

- `iwl-fw-tlv-parser-v0.md` — sibling iwlwifi entry for the TLV
  parser landed earlier.
- `feature-gaps-end-user-v0.md` — P0 #4 Wi-Fi entry; this slice
  closes the parser tier across all three vendors.
- `wireless-drivers-v0.md` — chip-ID-only iwlwifi/rtl88xx/bcm43xx
  shells the parsers plug into.
- `firmware-loader.h` — VFS-backed lookup that produces blobs.
