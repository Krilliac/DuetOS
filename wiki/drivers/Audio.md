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

`winmm!waveOutWrite` still returns success with a `// STUB:`
marker because no audio server consumes the armed stream.

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

## Known Limits / GAPs

- **No producers yet.** Slice 2 ships the backend layer but no
  caller. `winmm!waveOutWrite` and `xaudio2` thunks still return
  success without producing sound — wiring needs new
  `SYS_AUDIO_*` syscalls (separate slice). A native in-kernel
  beep producer (e.g. error tone on policy violation) is the
  most likely first consumer.
- **HDA codec walker stops at 0 function groups on QEMU
  virtual codecs.** Both `-device hda-output` and `-device
  hda-duplex` advertise codecs that the DuetOS walker reads as
  having zero function groups, so `FindFirstOutputPath` returns
  no path and the backend logs `[audio-backend]
  FindFirstOutputPath returned no path ...` and skips
  initialisation. This is a pre-existing limitation of the
  walker, surfaced by slice 2's diagnostic logging — fix tracked
  outside this slice. The StreamArm path and codec verb framing
  *do* succeed; the walker is the only thing blocking output on
  emulator.
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
