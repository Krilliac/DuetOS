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

`winmm!waveOutWrite` still returns success with a `// STUB:`
marker because no audio server consumes the armed stream.

## Audio Routing (planned)

```
[ App ]                            winmm / xaudio2
        |
[ Audio server (process) ]         subsystems/audio/ (planned)
        |
[ Mixer / format conversion ]      kernel/subsystems/audio/ (planned)
        |
[ HDA driver ]                     kernel/drivers/audio/hda/
        |
[ Audio codec ]
```

The plan is for the audio server to be one of the first IPC-isolated
processes — it holds the HDA hardware capability, every other process
sends mix submissions over a port. See
[IPC](../kernel/IPC.md).

## Known Limits / GAPs

- **No live audio output.** HDA driver is a shell; mixer / format
  conversion / sample-rate conversion are not implemented.
- **No microphone / capture path.**
- **`winmm` and `xaudio2`** at the userland DLL level satisfy probes
  but do not produce sound.

## Related Pages

- [Driver Overview](Driver-Overview.md)
- [Win32 DLLs](../subsystems/Win32-DLLs.md) — `winmm` is part of the
  Win32 surface
- [PCIe Enumeration](PCIe-Enumeration.md)
