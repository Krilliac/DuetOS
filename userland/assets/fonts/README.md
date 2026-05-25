# DuetOS chrome assets — fonts

## `duet-chrome.ttf`

**Liberation Sans Regular**, copied verbatim from the Debian `fonts-liberation` package (Red Hat, Google).

Liberation Sans is a metric-compatible drop-in for Arial / Helvetica
— the universally-readable modern sans-serif. Renders cleanly at
chrome sizes (16–32 px) on the 4× supersample rasterizer in
`kernel/drivers/video/ttf_raster.cpp`, and reads well across every
Duet-family theme (slate / light / blue / violet / green / classic).

- **Source**: `/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf`
- **Size**: 411 KiB
- **License**: SIL Open Font License 1.1 (see `LICENSE-Liberation.txt`)
- **Coverage**: full ASCII + Latin-1 + extensive Latin extended; cmap
  format 4 covers everything chrome paint needs

The font is embedded into the kernel image at build time via
`tools/build/embed-blob.py` (see `kernel/CMakeLists.txt`). At boot
the bytes are handed to `TtfLoad` and the resulting `TtfFont` is
registered via `TtfChromeFontSet`. The 5 Duet-family themes opt in
to TTF via their `Theme::FontKind` field; the bitmap fallback in
`FramebufferDrawStringScaled` stays available for the non-TTF
themes (Classic / Slate10 / Amber / DuetClassic / HighContrast).

## `duet-chrome-bold.ttf`

**Liberation Sans Bold**, the paired bold weight from the same
`fonts-liberation` package. Added in Pass C for the four-tier
typography hierarchy (Display / Title / Body / Caption); used
whenever `ChromeTextWeight::Bold` is requested — Display + Title
roles always, Body + Caption opt-in for emphasis.

- **Source**: `/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf`
- **Size**: 405 KiB
- **License**: SIL Open Font License 1.1 (see `LICENSE-Liberation.txt`)
- **Coverage**: identical to Regular — full ASCII + Latin-1 + Latin
  extended via cmap format 4

Embedded the same way as the Regular variant — `embed-blob.py`
produces `generated_chrome_font_bold.h` at build time with
`kBinChromeFontBoldBytes` in `duetos::drivers::video::generated`;
boot hands the bytes to `TtfLoad` and registers the resulting
`TtfFont` via `TtfChromeBoldSet`. Non-TTF themes still fall back to
the bitmap path (which double-paints at `(x+1, y)` for a
synthesized bold).

## License compliance

The OFL's redistribution clauses are satisfied by:

1. The font file ships unmodified.
2. The full license text ships alongside the font in
   `LICENSE-Liberation.txt`.
3. The font is not bundled into a product whose **name** includes
   "Liberation" — DuetOS uses it as a chrome asset, not as a
   re-branded font product.
