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

## Intel HDA Shell

`kernel/drivers/audio/hda/`.

- PCI probe + MMIO register map.
- CORB / RIRB ring setup is in progress.
- No live audio output yet — `winmm!waveOutWrite` returns success
  with `// STUB:` markers in the userland DLL.

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
