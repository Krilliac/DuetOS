# BrowserGame — Gloomwood ARPG Design System

A design system for **BrowserGame**, a browser-based, server-authoritative 2.5D
action-RPG in the lineage of Diablo II/III, WarCraft III and RuneScape — dark,
gritty, torch-lit, with RNG-tier loot and a touch of gore. This system codifies
the game's visual language so designers and agents can produce **coherent,
theme-matching** UI, HUD, items, FX and environment art — to replace or
supplement the game's current placeholder assets.

> The brand has no formal name yet (the project is "in development"). This system
> uses **Gloomwood** — the game's first wilderness area — as a working wordmark.
> Swap it for the real title once chosen.

## Sources (read these for deeper fidelity)
Everything here was derived from the live codebase, not guessed:
- **GitHub — [Krilliac/BrowserGame](https://github.com/Krilliac/BrowserGame)** (branch `main`). The
  authoritative source. Read its `CLAUDE.md`, `wiki/`, `src/shared/items.ts`,
  `src/shared/theme.ts`, `src/shared/areas.ts`, and the `src/client/*` HUD modules
  to extend this system accurately. Sibling repos referenced by the project:
  [SparkEngine](https://github.com/Krilliac/SparkEngine) (engineering doctrine) and
  [DuetOS](https://github.com/Krilliac/DuetOS) (security posture) — influence only, no shared art.
- Verbatim source extracts are vendored under **`reference/*.txt`** (rarity, theme,
  areas, equipment, item-icons, belt, atmosphere, inventory-panel) — these are the
  exact rules this system mirrors. Asset license tables are in `reference/*CREDITS.md`.

The game is **TypeScript end-to-end** with a **PixiJS** WebGL world renderer and a
**Canvas2D HUD overlay**; all content (areas, items, monsters, themes, loot) is
data-driven from a **SQLite** DB. Entities currently render as **procedural
shapes** — sprite atlases are a deferred, open decision, which is exactly the gap
this system helps fill.

---

## CONTENT FUNDAMENTALS — voice & copy

The game's writing is **terse, grim, and evocative** — gothic high-fantasy with a
dry, plainspoken core. It never winks at the player.

- **Tone:** ominous and weighty, but economical. Place names and lore carry the
  dread; UI copy stays functional. *"The dead do not stay buried."* / *"Abandon
  hope."* (Abyssal Throne) sit next to *"Tap an item to equip · sell at the
  Merchant to clear space · Esc to close."*
- **Person:** instructional UI addresses the player as **you** ("Your bag is
  empty.", "You found Doomscar, the Last Verdict."). Lore is third-person.
- **Casing:** **Title Case** for proper nouns — areas (*Rotfen Marsh*, *The
  Forgotten Catacombs*), bosses (*Maggath*, *Athraxis, the Unmade God*), unique
  items. **UPPERCASE** display tracking for titles/headers/banners. Sentence case
  for body, hints and tooltips.
- **Item naming = the affix grammar.** Items read as composed names, not
  "Rare Sword": prefixes + base + suffixes — *"Savage Keen Iron Sword of the
  Boar."* Rarity is conveyed by **color, never a word**. Affix tiers escalate in
  menace: power → *Jagged → Savage → Cruel → Merciless*; hp → *of the Fox → Boar →
  Bear → Colossus*. (See `reference/shared-items.ts.txt`.)
- **Numbers are flavor-light.** Stat lines are compact and honest: `+14 power`,
  `+5% crit`, `+1 projectile`, debuffs as `−30 hp`. No invented stats, no padding.
- **Place-naming pattern:** evocative noun + grim modifier — *Gloomwood,
  Emberdeep Mines, Frostpeak Pass, The Sundered Wastes, The Voidmarch*. Towns are
  warmer, plainer (*Aldermere, Duskhaven, Vhal'reth*).
- **No emoji** in game copy. Unicode **arrows/sigils** mark portals and directions
  (`→ ↓ ⌖ ↑`) — keep that, it's part of the voice.

---

## VISUAL FOUNDATIONS

The whole system is **dark-first** (`color-scheme: dark`). Light is precious —
torches, hearths, glowing loot and spell FX punch out of near-black surroundings.

- **Palette.** One brand metal — **warm gold `#c9a24b`** — on **obsidian
  `#0e0f13`**, with **parchment `#e7d9b0`** text. Resources are the blood-red /
  cold-blue duo (`#d23b3b` / `#3b6fd2`). Everything else is the **loot-rarity
  ladder** (the emotional core) and **per-biome accent** moods. All values are
  lifted hex-exact from the codebase — see `tokens/colors.css`.
- **Loot rarity (memorize this):** common `#c9c9c9` · magic `#6ea8ff` · rare
  `#ffd24a` · epic `#c06bff` · legendary `#ff7a1a` · corrupted `#ff2d6f` · unique
  `#bfa05a`. Rarity drives item-name color, slot frame, ground-drop glow and
  tooltip border. Note this game's mapping (magic = blue, rare = yellow) — follow it.
- **Type.** Engraved **Cinzel** caps (tracked, uppercase) for titles, item names
  and panel headers; **system-ui** for HUD/body (matches the shipped renderer);
  **Spectral** italic for lore/flavor; **mono** for tabular stats. See
  `tokens/typography.css`. ⚠ Cinzel & Spectral are Google-Fonts substitutes — no
  brand font files were supplied (see Caveats).
- **Backgrounds.** No flat fills and **no bluish-purple gradients**. The world is a
  tinted radial ground (biome `groundBase` + speckle), framed by an **edge
  vignette** that hazes toward the area's `fogColor`, plus a creeping **crimson
  corruption pall** (`#3a0810`) and a day/night wash on outdoor areas. Indoor
  crypts/dungeons stay perpetually dusk-dark.
- **Surfaces / cards.** HUD windows are **translucent obsidian** (`rgba(8,9,13,.94)`)
  with a **2px gold frame**, a faint top sheen, and a heavy drop shadow — sharp
  corners (radius 7–8px), never soft web cards. Slots are **recessed** (inner
  shadow) with rarity-colored frames.
- **Borders & shadows.** Gold hairlines (`rgba(201,162,75,.25)` on slots, solid
  `#c9a24b` on frames). Depth = dark drop shadow + **inner shadow** on recesses;
  emphasis = **outer glow** in gold or the rarity color. No colored left-border
  accent cards.
- **Glow is meaning.** Legendary/corrupted/unique items, ready abilities, lit
  torches and spell projectiles all emit a colored glow. Use the `--glow-*` tokens;
  reserve glow for things that matter.
- **Motion.** Weighty and terse — `--ease-out` / `--ease-in-out`, 90ms press →
  160ms hover → 320ms panel open. Slow `1100ms` pulses only for legendary/corruption
  ambiance. No bouncy/elastic easing. **Hover:** lift + brighten; **press:**
  `translateY(1px) scale(.985)` (forged buttons feel like they depress).
- **Transparency & blur** are used sparingly: panels get a 2px backdrop blur over
  the busy world; chat/topbar chips sit on `rgba(0,0,0,.4–.55)` washes for
  legibility. Text over terrain always carries `--shadow-text`.
- **Imagery vibe.** Pixel art, nearest-neighbor (`image-rendering: pixelated`),
  cool desaturated dungeons vs. warm hearth-lit towns; per-area color grading
  (saturation/brightness/contrast) is part of the mood (see `tokens` + `areas`).
- **Layout.** Fixed full-viewport, responsive (laptop **and** phone). HUD anchors:
  orbs bottom corners, action bar bottom-center, topbar top-left, minimap
  top-right, chat bottom-left, XP strip along the bottom edge.

---

## ICONOGRAPHY

The game's icon language is **pixel art**, not a stroke-icon font. **Every asset in
this system is original** — procedurally generated in the Gloomwood palette (the
generator pipeline is documented in `HANDOFF.md`). It carries **no third-party
license**: the project owns it outright. All the prior placeholder packs (Kenney,
CraftPix, 32rogues, Mana Seed, Szadi) have been **fully replaced**.

- **Item icons** — original **faceted gems** (nine families), **carved-stone runes**
  (Diablo-style: *El, Dol, Nef, Ort, Ral, Sol, Thul, Tir, Vex, Zod*) and **crafting
  materials** (ember-ore, frost-core, rune-shard) in **`assets/icons/`** — the
  canonical loot icons. The game also resolves item ids to a generated sheet
  keyword/slot-based (`tools/assetgen/icons` → `items_gen.png`; see
  `reference/client-item-icons.ts.txt`).
- **UI chrome** — original **obsidian + gold nine-slice** chrome (`gw_*`): panels,
  inset slots, 3-slice blood/mana bars, forged buttons in `assets/ui/`. Build HP/MP
  as bars from the 3-slice parts or as in-renderer orbs.
- **FX / projectiles** — original **spell strips** (fireball, firebomb, ice lance,
  arcane bolt, water bolt, magic orb/sparks, rock, splash), an **arrows** sheet and
  a 4×4 **explosion** sheet in `assets/fx/` (16px frames; see `HANDOFF.md` for the
  frame layout per file).
- **Loot drops** — original coins/currency, gem & crafting specimen sheets, potion
  and trinket items in `assets/items/`.
- **Environment decor** — original graves, bones, dead/living trees, crystals, fungi,
  horror-plants, ruins, rocks, stalagmites, pots, barrels, braziers/candles in
  `assets/decor/` (+ `assets/decor/anim/` flicker frames). **Terrain** as original
  16px biome tilesheets in `assets/terrain/`.
- **Mobs** — original top-down roster (hero + skeleton, zombie, wraith, cultist,
  demon, hellhound, bat, spider, slime) in `assets/mobs/`.
- **No emoji.** Unicode **arrows/sigils** are used for portals/directions only.
- **Substitute icon font:** none is required. If a vector glyph is unavoidable in a
  marketing/web context, match Lucide (thin, no-fill) and **flag the substitution**.

⚠ **The art is programmatic, not hand-painted.** It is coherent, theme-matched and
fully license-free — a production-ready placeholder layer and art-direction
reference. For final polish, an artist can repaint over it, or you can extend the
generators (see `HANDOFF.md` → *Asset generator pipeline*).

---

## INDEX / manifest

**Root**
- `styles.css` — the single entry point consumers link (`@import`s the tokens).
- `tokens/` — `fonts.css`, `colors.css`, `typography.css`, `spacing.css`.
- `README.md` — this guide. `SKILL.md` — Agent-Skills wrapper for Claude Code.
- `reference/` — verbatim source extracts (`*.ts.txt`) + asset license credits.

**Assets** (`assets/`) — **all original, zero third-party license**
- `icons/` — original gem / rune / material loot icons (canonical).
- `items/` — original coins, gems, item & crafting specimen sheets, potion/trinkets.
- `fx/` — original spell/projectile strips + 4×4 explosion sheet.
- `decor/` (+ `anim/`) — original environment props. `terrain/` — original 16px biome tilesheets.
- `ui/` — original `gw_*` obsidian/gold panels, bars, buttons (9-slice).
- `mobs/` — original top-down mob + hero sprites.
- `HANDOFF.md` (root) — the Claude-Code wiring + engine-improvement guide.

**Foundations** (`guidelines/cards/`) — specimen cards shown in the Design System tab
(Colors, Type, Spacing, Brand).

**Components** (`components/`) — React primitives (`window.BrowserGameARPGDesignSystem_aa965c`):
- `core/` — **Button**, **Panel**, **IconSlot**
- `loot/` — **RarityName**, **Badge**, **ItemTooltip** (the loot inspection card)
- `hud/` — **OrbGauge**, **ResourceBar**, **AbilitySlot**, **Nameplate**

**UI kits** (`ui_kits/`)
- `gloomwood-hud/` — the interactive in-game HUD (orbs, hotbar, belt, minimap,
  chat, Inventory & Merchant windows). Open `index.html`.

**Templates** (`templates/`)
- `game-hud/` — a HUD-screen scaffold (`GameHud.dc.html`) consuming projects can copy.

---

## CAVEATS & how to make this perfect

- **Fonts are substitutes.** Cinzel (display) and Spectral (lore) are Google-Fonts
  stand-ins; the live game uses `system-ui`. **If you have a licensed display face
  (e.g. an Exocet-style title font), send the `.woff2`** and I'll wire real
  `@font-face` rules. `JetBrains Mono` is referenced for stats and will fall back
  until uploaded.
- **No logo / wordmark exists.** I used **"Gloomwood"** as a placeholder lockup.
  **What's the real game name?** I'll build the proper wordmark + favicon.
- **All art is now original.** Every prior third-party pack (Kenney, CraftPix,
  32rogues, Mana Seed, Szadi) has been replaced with procedurally-generated art in
  the Gloomwood palette — icons, FX, decor, terrain, UI chrome **and** a new mob
  roster. It is stylized/programmatic rather than hand-painted, but coherent and
  fully license-free. See **`HANDOFF.md`** for how it's wired and how to extend or
  repaint it.
- **The art is a starting layer, not a final shipped atlas.** Tell me which
  mobs/biomes/items to prioritize and I'll deepen those (more variants, animation
  frames, higher fidelity).

**👉 Your move:** confirm the game name, send any real fonts/logo, and tell me which
surface to deepen next — a fuller **character/skill screen**, a **vendor/gamble**
flow, **loot-drop & damage-number FX**, or **boss-fight HUD**. I'll iterate until
it's pixel-perfect.
