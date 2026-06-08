# Audio

> **Audience:** Driver authors
>
> **Execution context:** Kernel — IRQ + softirq for buffer completions
>
> **Maturity:** Driver shells; minimal output backend

## Overview

`kernel/drivers/audio/` houses the audio drivers. Today this is
primarily Intel HDA (High Definition Audio) shell with stubs for the
core mixer + audio-server surface that the Win32 `winmm` /
`xaudio2` DLLs will eventually marshal through.

## Intel HDA driver

PCI discovery + classification lives in `kernel/drivers/audio/audio.{h,cpp}`;
HDA-specific bring-up + codec walking + stream programming lives in
`kernel/drivers/audio/hda.{h,cpp}` (split out of `audio.cpp` once the
HDA code grew past the bloat threshold). The shell calls
`hda::BringUp(controller)` for the first HDA controller it finds.

The HDA driver:

- Programs CORB / RIRB rings against a single 4 KiB DMA-coherent
  page (CORB at offset 0, RIRB at offset 1 KiB).
- Walks every codec slot reported by `STATESTS` and records
  per-codec DAC / ADC / pin counts, amp-widget counts, and
  connection-list totals.
- Reads ISS / OSS from `GCAP` so the stream-arming helper knows
  the SD index range.
- Provides `hda::IssueVerbAndPoll(...)` so future codec
  configuration code (`SET_PIN_WIDGET_CONTROL`,
  `SET_AMP_GAIN_MUTE`) doesn't re-marshal CORB writes.
- Provides `hda::StreamArm(controller, dir, fmt, bdl_phys,
  buffer_bytes, lvi)` to program a free SD slot's BDL pointer,
  CBL, LVI, FORMAT, and stream tag. `RUN` is **not** set —
  flipping it requires real BDL entries pointing at audio buffer
  pages, which lands in the audio-server slice.
- Provides `hda::FindFirstOutputPath()` as the v0 routing
  heuristic: prefer Speaker, then Headphone Out, then Line Out
  from the jack inventory, and pair the selected pin with the
  first DAC node walked on that codec. This is intentionally a
  bootstrap selector, not a full codec-topology solver.

`winmm!waveOutWrite` now routes the WAVEHDR's PCM through the
`SYS_AUDIO_WRITE` (210) syscall into the in-kernel audio backend,
which bounded-copies it into the DMA ring and flips RUN. The
backend's `Init` keeps the stream armed + active even when codec
routing is unavailable (`codec_routed=false`), so the controller
DMA byte path (`hda::StreamPosition` / SD_LPIB) is exercised and
verified by the boot self-test; the QEMU smoke adds
`-device intel-hda -device hda-output`. The codec walk + audible
routing now work end to end on QEMU (DAC → line-out pin, LPIB
advancing) via the Immediate-Command-Interface fallback — see the
codec-walk note below.

## Audio Routing

Slice 2 of the ToaruOS clean-room port landed the in-kernel
backend layer.

```
[ Producer ]                       winmm / xaudio2 / native apps (future)
        |
[ Audio backend ]                  kernel/subsystems/audio/audio_backend.{h,cpp}
        |   (Init / Start / Stop / WritePcmS16Stereo / WriteSine)
        |
[ HDA driver ]                     kernel/drivers/audio/hda/
        |   (StreamArm / StreamFillBdl / StreamRun / ConfigureOutputPath)
        |
[ Audio codec ]
```

DuetOS's compositor and toolkit are in-kernel rather than userland
(see [Subsystem Isolation](../kernel/Subsystem-Isolation.md)), so
the "audio server" in this stack is also an in-kernel subsystem
(`kernel/subsystems/audio/`) rather than a separate IPC-isolated
process. Producers reach it through an in-kernel API today; a
future slice exposes `SYS_AUDIO_*` syscalls for ring-3 PE thunks
(`winmm!waveOutWrite`, `xaudio2!IXAudio2SourceVoice::SubmitSourceBuffer`).

The backend's v0 format is fixed at S16LE / 48 kHz / stereo —
HDA's consumer default. Producers convert to that shape before
calling `WritePcmS16Stereo`; a follow-up slice adds format /
sample-rate conversion when a producer demands a different format.

### Software master gain (F-030)

The backend applies a software **master volume** (`AudioSetMasterVolume`
/ `AudioGetMasterVolume`, 0..100%, default 100 = identity) plus a
**mute** flag (`AudioSetMuted` / `AudioIsMuted`) as a per-sample scale
inside the `WritePcm*` producer paths (`ApplyMasterGain`:
`sample * pct / 100`, saturating; mute forces the applied gain to 0
while the stored level is retained so un-mute restores it). It is the
single software output volume — both the taskbar volume flyout and the
Settings ▸ Sound panel drive the same backend state. The level + mute
persist across reboot via `SESSION.CFG` (`sound.volume` / `sound.muted`,
round-tripped by `kernel/core/session_restore.cpp`). A boot self-test
(`[audio-selftest] gain PASS`) verifies the unity / half / mute /
level-kept math deterministically (runs even with no HDA controller).
**GAP:** the gain is applied at *write* time — the HDA DMA reads the
ring directly with no kernel hook, so a level change affects samples
written after it (correct for streaming producers like waveOutWrite).
A future HDA codec amp-gain path would move the control downstream;
the audible result is unverified (DuetOS audio is QEMU-smoke-only).

## Known Limits / GAPs

- **No producers yet.** Slice 2 ships the backend layer but no
  caller. `winmm!waveOutWrite` and `xaudio2` thunks still return
  success without producing sound — wiring needs new
  `SYS_AUDIO_*` syscalls (separate slice). A native in-kernel
  beep producer (e.g. error tone on policy violation) is the
  most likely first consumer.
- **HDA codec walk — FIXED (was: 0 function groups on QEMU).**
  Root cause: QEMU's intel-hda runs the CORB DMA engine exactly
  once (CORBRP freezes at 1 while CORBWP advances and CORBCTL.RUN
  stays set), so every verb after the first timed out and the
  walker read `SubordinateNodeCount == 0`. Fix: `DispatchVerb`
  now falls back from CORB/RIRB to the **Immediate Command
  Interface** (ICOI/ICII/ICS) on a timeout and latches a sticky
  `use_ici` — the real-hardware-valid path equivalent to Linux's
  `single_cmd`; the fixed `pause` bound was also replaced with a
  20 ms monotonic deadline. A second bug (the codec self-test
  reset the shared jack inventory after the real walk filled it)
  was fixed by snapshotting/restoring the inventory in
  `HdaJackInventorySelfTest`. The walk now finds the function
  group, DAC and line-out pin; `ConfigureOutputPath` succeeds and
  the boot self-test confirms `DMA LPIB advanced (routed, audible
  path)`.
- **No mixer.** Single producer / single stream in v0. Multiple
  concurrent producers would race on the ring; that's the next
  audio slice's first job.
- **No IRQ-driven refill.** BDL entries have IOC = 0; the HDA
  DMA loops the ring forever. A producer that wants longer
  playback than the ring fits (~85 ms at the v0 format) needs
  the IRQ + per-buffer refill path that's a future slice.
- **No microphone / capture path.** v0 is output-only.
- **No format conversion / sample-rate conversion.** Producers
  must submit S16LE / 48 kHz / stereo.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Win32 DLLs](../subsystems/Win32-DLLs.md) — `winmm` is part of the
  Win32 surface
- [PCIe Enumeration](PCIe-Enumeration.md)
