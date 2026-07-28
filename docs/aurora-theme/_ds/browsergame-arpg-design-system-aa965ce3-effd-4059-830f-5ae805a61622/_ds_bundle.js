/* @ds-bundle: {"format":3,"namespace":"BrowserGameARPGDesignSystem_aa965c","components":[{"name":"Button","sourcePath":"components/core/Button.jsx"},{"name":"IconSlot","sourcePath":"components/core/IconSlot.jsx"},{"name":"Panel","sourcePath":"components/core/Panel.jsx"},{"name":"AbilitySlot","sourcePath":"components/hud/AbilitySlot.jsx"},{"name":"Nameplate","sourcePath":"components/hud/Nameplate.jsx"},{"name":"OrbGauge","sourcePath":"components/hud/OrbGauge.jsx"},{"name":"ResourceBar","sourcePath":"components/hud/ResourceBar.jsx"},{"name":"Badge","sourcePath":"components/loot/Badge.jsx"},{"name":"ItemTooltip","sourcePath":"components/loot/ItemTooltip.jsx"},{"name":"RARITY_COLOR","sourcePath":"components/loot/RarityName.jsx"},{"name":"RarityName","sourcePath":"components/loot/RarityName.jsx"}],"sourceHashes":{"components/core/Button.jsx":"0cc79a0d2c67","components/core/IconSlot.jsx":"5a46e0b360d2","components/core/Panel.jsx":"0349f7db022c","components/hud/AbilitySlot.jsx":"7d273aa7e7aa","components/hud/Nameplate.jsx":"503e427e5336","components/hud/OrbGauge.jsx":"376e83a78b87","components/hud/ResourceBar.jsx":"1c4339f195f9","components/loot/Badge.jsx":"b0eea6e87feb","components/loot/ItemTooltip.jsx":"0a69b00616a2","components/loot/RarityName.jsx":"8296b8533de3","tools/assetgen/anim.js":"0c3cc41d1a76","tools/assetgen/build.js":"4b6e1e57220c","tools/assetgen/core.js":"6d8eb93e8f22","tools/assetgen/decor.js":"6f70da3d413f","tools/assetgen/fx.js":"f17b351362d0","tools/assetgen/icons.js":"a1c12578803b","tools/assetgen/mobs.js":"5c26c0f0b925","tools/assetgen/rig.js":"3d148dab4b4b","tools/assetgen/terrain.js":"46065b0f8760","tools/assetgen/ui.js":"e223c15d771c","ui_kits/gloomwood-hud/Hud.jsx":"eda098c0e1c1","ui_kits/gloomwood-hud/InventoryView.jsx":"ede72a536c3d","ui_kits/gloomwood-hud/MerchantView.jsx":"732ab5568d8a","ui_kits/gloomwood-hud/Scene.jsx":"472ed07ad883"},"inlinedExternals":[],"unexposedExports":[]} */

(() => {

const __ds_ns = (window.BrowserGameARPGDesignSystem_aa965c = window.BrowserGameARPGDesignSystem_aa965c || {});

const __ds_scope = {};

(__ds_ns.__errors = __ds_ns.__errors || []);

// components/core/Button.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Button — the forged action control. Stone-dark fill, gold frame, engraved
 * uppercase label. Used for menus, confirms, vendor actions and dialog choices.
 * Mirrors the game's gold-on-obsidian chrome (Kenney brown button lineage).
 */
function Button({
  children,
  variant = 'primary',
  size = 'md',
  block = false,
  disabled = false,
  iconLeft = null,
  style = {},
  ...rest
}) {
  const sizes = {
    sm: {
      padding: '6px 12px',
      fontSize: 'var(--text-2xs)',
      minHeight: 28
    },
    md: {
      padding: '9px 18px',
      fontSize: 'var(--text-xs)',
      minHeight: 38
    },
    lg: {
      padding: '13px 26px',
      fontSize: 'var(--text-sm)',
      minHeight: 48
    }
  };
  const variants = {
    primary: {
      background: 'linear-gradient(180deg, var(--gold-400), var(--gold-600))',
      color: 'var(--text-on-gold)',
      border: '1px solid var(--gold-300)',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.35), 0 2px 0 #000, var(--glow-gold)',
      textShadow: '0 1px 0 rgba(255,255,255,0.3)'
    },
    secondary: {
      background: 'linear-gradient(180deg, var(--ink-700), var(--ink-850))',
      color: 'var(--gold-300)',
      border: '1px solid var(--gold-600)',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06), 0 2px 0 #000',
      textShadow: 'var(--shadow-text)'
    },
    ghost: {
      background: 'transparent',
      color: 'var(--text-muted)',
      border: '1px solid transparent',
      boxShadow: 'none',
      textShadow: 'none'
    },
    danger: {
      background: 'linear-gradient(180deg, #b33, var(--hp-deep))',
      color: '#ffe2e2',
      border: '1px solid var(--danger)',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.18), 0 2px 0 #000, var(--glow-hp)',
      textShadow: '0 1px 1px rgba(0,0,0,0.6)'
    }
  };
  return /*#__PURE__*/React.createElement("button", _extends({
    disabled: disabled,
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      justifyContent: 'center',
      gap: 8,
      width: block ? '100%' : 'auto',
      fontFamily: 'var(--font-display)',
      fontWeight: 'var(--weight-semibold)',
      letterSpacing: 'var(--tracking-heading)',
      textTransform: 'uppercase',
      borderRadius: 'var(--radius-sm)',
      cursor: disabled ? 'not-allowed' : 'pointer',
      opacity: disabled ? 0.45 : 1,
      transition: 'transform var(--dur-fast) var(--ease-out), filter var(--dur-base)',
      userSelect: 'none',
      ...sizes[size],
      ...variants[variant],
      ...style
    },
    onMouseDown: e => !disabled && (e.currentTarget.style.transform = 'translateY(1px) scale(0.985)'),
    onMouseUp: e => e.currentTarget.style.transform = '',
    onMouseLeave: e => e.currentTarget.style.transform = ''
  }, rest), iconLeft, children);
}
Object.assign(__ds_scope, { Button });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Button.jsx", error: String((e && e.message) || e) }); }

// components/core/IconSlot.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const RARITY_COLOR = {
  common: 'var(--rarity-common)',
  magic: 'var(--rarity-magic)',
  rare: 'var(--rarity-rare)',
  epic: 'var(--rarity-epic)',
  legendary: 'var(--rarity-legendary)',
  corrupted: 'var(--rarity-corrupted)',
  unique: 'var(--rarity-unique)'
};
const RARITY_GLOW = {
  magic: 'var(--glow-magic)',
  rare: 'var(--glow-rare)',
  epic: 'var(--glow-epic)',
  legendary: 'var(--glow-legendary)',
  corrupted: 'var(--glow-corrupted)',
  unique: 'var(--glow-unique)'
};

/**
 * IconSlot — a single inventory / hotbar / belt cell. Recessed obsidian square
 * with an inner shadow, a rarity-colored frame + glow when it holds gear, and
 * optional stack count (bottom-right) and hotkey (top-left). The atomic cell the
 * inventory grid, vault, belt and ability bar are all built from.
 */
function IconSlot({
  src = null,
  alt = '',
  children = null,
  rarity = null,
  size = 52,
  count = null,
  hotkey = null,
  empty = false,
  selected = false,
  onClick,
  style = {},
  ...rest
}) {
  const frame = rarity ? RARITY_COLOR[rarity] : 'var(--border-accent-soft)';
  const glow = rarity ? RARITY_GLOW[rarity] : 'none';
  return /*#__PURE__*/React.createElement("div", _extends({
    onClick: onClick,
    style: {
      position: 'relative',
      width: size,
      height: size,
      flex: 'none',
      background: empty ? 'rgba(0,0,0,0.35)' : 'var(--surface-slot)',
      border: `${rarity ? 2 : 1}px solid ${selected ? 'var(--gold-300)' : frame}`,
      borderRadius: 'var(--radius-slot)',
      boxShadow: `var(--shadow-slot-inset)${glow !== 'none' ? ', ' + glow : ''}${selected ? ', var(--glow-gold-strong)' : ''}`,
      cursor: onClick ? 'pointer' : 'default',
      display: 'grid',
      placeItems: 'center',
      overflow: 'hidden',
      ...style
    }
  }, rest), src ? /*#__PURE__*/React.createElement("img", {
    src: src,
    alt: alt,
    style: {
      width: '74%',
      height: '74%',
      objectFit: 'contain',
      imageRendering: 'pixelated',
      filter: 'drop-shadow(0 2px 3px rgba(0,0,0,0.7))'
    }
  }) : children, hotkey != null && /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      top: 3,
      left: 4,
      fontFamily: 'var(--font-body)',
      fontWeight: 700,
      fontSize: 'var(--text-2xs)',
      color: 'var(--gold-500)',
      textShadow: 'var(--shadow-text)',
      lineHeight: 1
    }
  }, hotkey), count != null && /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      bottom: 2,
      right: 4,
      fontFamily: 'var(--font-body)',
      fontWeight: 700,
      fontSize: 'var(--text-xs)',
      color: 'var(--gold-300)',
      textShadow: 'var(--shadow-text)',
      lineHeight: 1
    }
  }, count));
}
Object.assign(__ds_scope, { IconSlot });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/IconSlot.jsx", error: String((e && e.message) || e) }); }

// components/core/Panel.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Panel — the canonical HUD window: translucent obsidian fill, a 2px gold frame,
 * an engraved title bar and optional ✕ close. Every dialog, vendor screen and
 * inventory window is built on it. Matches inventory-panel.ts exactly
 * (rgba(8,9,13,0.94) fill, #c9a24b stroke, parchment header).
 */
function Panel({
  title,
  subtitle,
  onClose,
  footer,
  children,
  width = 'auto',
  style = {},
  ...rest
}) {
  return /*#__PURE__*/React.createElement("div", _extends({
    style: {
      position: 'relative',
      width,
      background: 'var(--surface-panel)',
      border: 'var(--border-frame) solid var(--border-accent)',
      borderRadius: 'var(--radius-md)',
      boxShadow: 'var(--shadow-panel)',
      backdropFilter: 'blur(2px)',
      color: 'var(--text-body)',
      fontFamily: 'var(--font-body)',
      overflow: 'hidden',
      ...style
    }
  }, rest), (title || onClose) && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: '12px 14px 10px',
      borderBottom: '1px solid var(--border-accent-soft)',
      background: 'linear-gradient(180deg, rgba(201,162,75,0.08), transparent)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1,
      minWidth: 0
    }
  }, title && /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: 'var(--font-display)',
      fontWeight: 'var(--weight-semibold)',
      fontSize: 'var(--text-md)',
      letterSpacing: 'var(--tracking-heading)',
      textTransform: 'uppercase',
      color: 'var(--text-display)',
      textShadow: 'var(--shadow-text)'
    }
  }, title), subtitle && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 'var(--text-xs)',
      color: 'var(--text-muted)',
      marginTop: 2
    }
  }, subtitle)), onClose && /*#__PURE__*/React.createElement("button", {
    onClick: onClose,
    "aria-label": "Close",
    style: {
      flex: 'none',
      width: 22,
      height: 22,
      display: 'grid',
      placeItems: 'center',
      background: 'transparent',
      border: '1px solid var(--border-accent-soft)',
      borderRadius: 'var(--radius-sm)',
      color: 'var(--text-muted)',
      cursor: 'pointer',
      fontSize: 13,
      lineHeight: 1
    }
  }, "\u2715")), /*#__PURE__*/React.createElement("div", {
    style: {
      padding: 14
    }
  }, children), footer && /*#__PURE__*/React.createElement("div", {
    style: {
      padding: '9px 14px',
      borderTop: '1px solid var(--border-accent-soft)',
      fontSize: 'var(--text-xs)',
      color: 'var(--text-faint)'
    }
  }, footer));
}
Object.assign(__ds_scope, { Panel });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/core/Panel.jsx", error: String((e && e.message) || e) }); }

// components/hud/AbilitySlot.jsx
try { (() => {
/**
 * AbilitySlot — a spell/skill button on the action hotbar. Recessed gold-framed
 * cell with the ability icon, a hotkey caption, an optional radial cooldown sweep
 * (conic overlay + seconds remaining), and a dim "out of mana" state. Built to
 * match the renderer's 52px hotbar slots.
 */
function AbilitySlot({
  src = null,
  children = null,
  hotkey = '1',
  size = 52,
  cooldown = 0,
  // 0..1 fraction remaining
  cooldownText = null,
  ready = true,
  disabled = false,
  onClick,
  style = {}
}) {
  const onCd = cooldown > 0;
  return /*#__PURE__*/React.createElement("div", {
    onClick: onClick,
    style: {
      position: 'relative',
      width: size,
      height: size,
      flex: 'none',
      background: 'var(--surface-slot)',
      border: '2px solid var(--gold-500)',
      borderRadius: 'var(--radius-slot)',
      boxShadow: ready && !onCd ? 'var(--shadow-slot-inset), var(--glow-gold)' : 'var(--shadow-slot-inset)',
      cursor: onClick ? 'pointer' : 'default',
      display: 'grid',
      placeItems: 'center',
      overflow: 'hidden',
      opacity: disabled ? 0.5 : 1
    }
  }, src ? /*#__PURE__*/React.createElement("img", {
    src: src,
    alt: "",
    style: {
      width: '72%',
      height: '72%',
      objectFit: 'contain',
      imageRendering: 'pixelated',
      filter: onCd ? 'grayscale(0.6) brightness(0.6)' : 'drop-shadow(0 2px 3px rgba(0,0,0,0.7))'
    }
  }) : children, onCd && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      background: `conic-gradient(rgba(0,0,0,0.7) ${cooldown * 360}deg, transparent 0)`,
      pointerEvents: 'none'
    }
  }), onCd && cooldownText && /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      inset: 0,
      display: 'grid',
      placeItems: 'center',
      fontFamily: 'var(--font-mono)',
      fontWeight: 700,
      fontSize: size * 0.3,
      color: 'var(--text-heading)',
      textShadow: '0 1px 3px #000'
    }
  }, cooldownText), /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      top: 2,
      left: 4,
      fontFamily: 'var(--font-body)',
      fontWeight: 700,
      fontSize: 'var(--text-2xs)',
      color: 'var(--gold-500)',
      textShadow: 'var(--shadow-text)',
      lineHeight: 1
    }
  }, hotkey));
}
Object.assign(__ds_scope, { AbilitySlot });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/hud/AbilitySlot.jsx", error: String((e && e.message) || e) }); }

// components/hud/OrbGauge.jsx
try { (() => {
/**
 * OrbGauge — the iconic ARPG liquid globe for health (left) and mana (right).
 * A glass sphere with a rising liquid fill, inner glow, a glossy sheen and a
 * gold rim, with the current/max value centered. Colors come straight from the
 * belt flask palette (hp #d23b3b, mana #3b6fd2).
 */
function OrbGauge({
  type = 'health',
  value = 70,
  max = 100,
  size = 128,
  showValue = true,
  style = {}
}) {
  const pct = Math.max(0, Math.min(1, max ? value / max : 0));
  const fillTop = `var(--${type === 'mana' ? 'mana-glow' : 'hp-glow'})`;
  const fillMid = `var(--${type === 'mana' ? 'mana' : 'hp'})`;
  const fillDeep = `var(--${type === 'mana' ? 'mana-deep' : 'hp-deep'})`;
  const glow = type === 'mana' ? 'var(--glow-mana)' : 'var(--glow-hp)';
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative',
      width: size,
      height: size,
      borderRadius: '50%',
      background: 'radial-gradient(circle at 50% 60%, #15161d, #05060a 80%)',
      border: '2px solid var(--gold-600)',
      boxShadow: `inset 0 4px 12px rgba(0,0,0,0.8), 0 0 0 1px #000, ${glow}`,
      overflow: 'hidden',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: 0,
      right: 0,
      bottom: 0,
      height: `${pct * 100}%`,
      background: `linear-gradient(180deg, ${fillTop}, ${fillMid} 38%, ${fillDeep})`,
      boxShadow: `inset 0 6px 14px rgba(255,255,255,0.25)`,
      transition: 'height var(--dur-slow) var(--ease-out)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: -2,
      left: 0,
      right: 0,
      height: 4,
      background: fillTop,
      opacity: 0.8,
      filter: 'blur(1px)'
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      borderRadius: '50%',
      background: 'radial-gradient(60% 45% at 38% 26%, rgba(255,255,255,0.35), transparent 60%)',
      pointerEvents: 'none'
    }
  }), showValue && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      display: 'grid',
      placeItems: 'center',
      fontFamily: 'var(--font-mono)',
      fontVariantNumeric: 'tabular-nums',
      fontWeight: 700,
      fontSize: size * 0.16,
      color: 'var(--text-heading)',
      textShadow: '0 1px 3px #000, 0 0 6px rgba(0,0,0,0.9)'
    }
  }, Math.round(value)));
}
Object.assign(__ds_scope, { OrbGauge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/hud/OrbGauge.jsx", error: String((e && e.message) || e) }); }

// components/hud/ResourceBar.jsx
try { (() => {
/**
 * ResourceBar — a horizontal gold-framed gauge for health, mana, experience or a
 * boss/cast bar. Recessed track, colored fill, optional label and value readout.
 * The flat alternative to OrbGauge (and the Kenney bar lineage); good for nameplates,
 * party frames and the XP strip.
 */
const KIND = {
  health: {
    fill: 'linear-gradient(180deg, var(--hp-glow), var(--hp) 55%, var(--hp-deep))'
  },
  mana: {
    fill: 'linear-gradient(180deg, var(--mana-glow), var(--mana) 55%, var(--mana-deep))'
  },
  xp: {
    fill: 'linear-gradient(180deg, var(--gold-300), var(--gold-500) 55%, var(--gold-700))'
  },
  essence: {
    fill: 'linear-gradient(180deg, #b6f0a0, var(--essence) 55%, #1e4a1a)'
  }
};
function ResourceBar({
  kind = 'health',
  value = 70,
  max = 100,
  label = null,
  showValue = false,
  height = 16,
  style = {}
}) {
  const pct = Math.max(0, Math.min(1, max ? value / max : 0));
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: '100%',
      ...style
    }
  }, (label || showValue) && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      justifyContent: 'space-between',
      marginBottom: 3,
      fontSize: 'var(--text-2xs)',
      letterSpacing: 'var(--tracking-label)',
      textTransform: 'uppercase',
      color: 'var(--text-label)'
    }
  }, /*#__PURE__*/React.createElement("span", null, label), showValue && /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      color: 'var(--text-stat)'
    }
  }, Math.round(value), " / ", max)), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative',
      height,
      background: 'rgba(0,0,0,0.55)',
      border: '1px solid var(--gold-700)',
      borderRadius: 'var(--radius-sm)',
      boxShadow: 'inset 0 2px 5px rgba(0,0,0,0.7)',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      width: `${pct * 100}%`,
      background: KIND[kind].fill,
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.3)',
      transition: 'width var(--dur-base) var(--ease-out)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 0,
      left: 0,
      right: 0,
      height: '45%',
      background: 'linear-gradient(180deg, rgba(255,255,255,0.18), transparent)',
      pointerEvents: 'none'
    }
  })));
}
Object.assign(__ds_scope, { ResourceBar });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/hud/ResourceBar.jsx", error: String((e && e.message) || e) }); }

// components/hud/Nameplate.jsx
try { (() => {
const TIER = {
  normal: {
    color: 'var(--rarity-common)',
    label: null,
    width: 96,
    h: 5
  },
  elite: {
    color: 'var(--rarity-magic)',
    label: 'Elite',
    width: 120,
    h: 6
  },
  champion: {
    color: 'var(--rarity-rare)',
    label: 'Champion',
    width: 132,
    h: 7
  },
  boss: {
    color: 'var(--rarity-corrupted)',
    label: 'Boss',
    width: 200,
    h: 9
  }
};

/**
 * Nameplate — the floating name + health bar above a monster. The tier drives the
 * name color, the bar size and an optional rank label: normal (white), elite
 * (blue), champion (gold), boss (corrupted red, with a wider bar). Reproduces the
 * overworld monster banner; pin it above the sprite in the world layer.
 */
function Nameplate({
  name = 'Rot Ghoul',
  tier = 'normal',
  level = null,
  hp = 80,
  maxHp = 100,
  style = {}
}) {
  const t = TIER[tier];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      width: t.width,
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: 3,
      textAlign: 'center',
      ...style
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'baseline',
      gap: 5,
      lineHeight: 1
    }
  }, level != null && /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: 'var(--text-2xs)',
      color: 'var(--text-faint)'
    }
  }, "L", level), /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-display)',
      fontWeight: 'var(--weight-semibold)',
      fontSize: tier === 'boss' ? 'var(--text-base)' : 'var(--text-xs)',
      letterSpacing: '0.04em',
      textTransform: 'uppercase',
      color: t.color,
      textShadow: 'var(--shadow-text)'
    }
  }, name), t.label && /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-body)',
      fontWeight: 600,
      fontSize: 'var(--text-2xs)',
      letterSpacing: '0.1em',
      textTransform: 'uppercase',
      color: t.color,
      opacity: 0.85
    }
  }, t.label)), /*#__PURE__*/React.createElement("div", {
    style: {
      width: '100%'
    }
  }, /*#__PURE__*/React.createElement(__ds_scope.ResourceBar, {
    kind: "health",
    value: hp,
    max: maxHp,
    height: t.h
  })));
}
Object.assign(__ds_scope, { Nameplate });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/hud/Nameplate.jsx", error: String((e && e.message) || e) }); }

// components/loot/Badge.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
/**
 * Badge — a small engraved pill for rarity tags, status states, area labels and
 * counts. Three tones: solid (filled accent), outline (gold hairline), and
 * rarity (tinted to a loot tier). Kept compact and uppercase to read as game
 * chrome, not web UI.
 */
const TONE = {
  gold: {
    bg: 'var(--gold-600)',
    bd: 'var(--gold-400)',
    fg: 'var(--text-on-gold)'
  },
  neutral: {
    bg: 'var(--ink-700)',
    bd: 'var(--border-subtle)',
    fg: 'var(--text-muted)'
  },
  danger: {
    bg: 'var(--hp-deep)',
    bd: 'var(--danger)',
    fg: '#ffe2e2'
  },
  ok: {
    bg: '#1e3d20',
    bd: 'var(--ok)',
    fg: 'var(--ok)'
  }
};
const RARITY_COLOR = {
  common: 'var(--rarity-common)',
  magic: 'var(--rarity-magic)',
  rare: 'var(--rarity-rare)',
  epic: 'var(--rarity-epic)',
  legendary: 'var(--rarity-legendary)',
  corrupted: 'var(--rarity-corrupted)',
  unique: 'var(--rarity-unique)'
};
function Badge({
  children,
  tone = 'neutral',
  rarity = null,
  outline = false,
  style = {},
  ...rest
}) {
  let colors;
  if (rarity) {
    const c = RARITY_COLOR[rarity];
    colors = {
      bg: `color-mix(in srgb, ${c} 16%, transparent)`,
      bd: c,
      fg: c
    };
  } else {
    const t = TONE[tone];
    colors = outline ? {
      bg: 'transparent',
      bd: t.bd,
      fg: t.bd
    } : t;
  }
  return /*#__PURE__*/React.createElement("span", _extends({
    style: {
      display: 'inline-flex',
      alignItems: 'center',
      gap: 5,
      padding: '3px 8px',
      fontFamily: 'var(--font-body)',
      fontWeight: 'var(--weight-semibold)',
      fontSize: 'var(--text-2xs)',
      letterSpacing: 'var(--tracking-label)',
      textTransform: 'uppercase',
      lineHeight: 1,
      borderRadius: 'var(--radius-sm)',
      background: colors.bg,
      border: `1px solid ${colors.bd}`,
      color: colors.fg,
      whiteSpace: 'nowrap',
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { Badge });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/loot/Badge.jsx", error: String((e && e.message) || e) }); }

// components/loot/RarityName.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const RARITY_COLOR = {
  common: 'var(--rarity-common)',
  magic: 'var(--rarity-magic)',
  rare: 'var(--rarity-rare)',
  epic: 'var(--rarity-epic)',
  legendary: 'var(--rarity-legendary)',
  corrupted: 'var(--rarity-corrupted)',
  unique: 'var(--rarity-unique)'
};
const RARITY_TSHADOW = {
  legendary: 'var(--glow-legendary)',
  corrupted: 'var(--glow-corrupted)',
  unique: 'var(--glow-unique)',
  epic: 'var(--glow-epic)'
};

/**
 * RarityName — an item title painted in its loot-tier color. The single source
 * of the rarity→color rule for any inline item reference (chat drop lines, loot
 * toasts, bag rows). Higher tiers gain a soft glow. Mirrors RARITY[r].color.
 */
function RarityName({
  children,
  rarity = 'common',
  size = 'base',
  glow = true,
  style = {},
  ...rest
}) {
  const fontSize = {
    sm: 'var(--text-sm)',
    base: 'var(--text-base)',
    lg: 'var(--text-lg)'
  }[size];
  return /*#__PURE__*/React.createElement("span", _extends({
    style: {
      fontFamily: 'var(--font-display)',
      fontWeight: 'var(--weight-bold)',
      letterSpacing: '0.02em',
      fontSize,
      color: RARITY_COLOR[rarity],
      textShadow: glow && RARITY_TSHADOW[rarity] ? RARITY_TSHADOW[rarity] : 'var(--shadow-text)',
      ...style
    }
  }, rest), children);
}
Object.assign(__ds_scope, { RARITY_COLOR, RarityName });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/loot/RarityName.jsx", error: String((e && e.message) || e) }); }

// components/loot/ItemTooltip.jsx
try { (() => {
function _extends() { return _extends = Object.assign ? Object.assign.bind() : function (n) { for (var e = 1; e < arguments.length; e++) { var t = arguments[e]; for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]); } return n; }, _extends.apply(null, arguments); }
const RARITY_GLOW = {
  magic: 'var(--glow-magic)',
  rare: 'var(--glow-rare)',
  epic: 'var(--glow-epic)',
  legendary: 'var(--glow-legendary)',
  corrupted: 'var(--glow-corrupted)',
  unique: 'var(--glow-unique)'
};

/**
 * ItemTooltip — the loot inspection card. The most important surface in an ARPG:
 * a rarity-colored, centered title (the affix-composed name), the item type, base
 * stats, rolled affix lines (buffs in steel-blue, debuffs in blood-red), gem
 * sockets, an italic flavor line, and a value/level footer. Structure follows
 * src/shared/items.ts (instanceTitle, affixLabel, sockets, gearSellValue).
 */
function ItemTooltip({
  name,
  rarity = 'common',
  itemType = '',
  baseStats = [],
  affixes = [],
  sockets = [],
  flavor = '',
  requiredLevel = null,
  levelMet = true,
  value = null,
  width = 248,
  style = {},
  ...rest
}) {
  const color = __ds_scope.RARITY_COLOR[rarity];
  const glow = RARITY_GLOW[rarity];
  return /*#__PURE__*/React.createElement("div", _extends({
    style: {
      width,
      background: 'var(--surface-panel)',
      border: `1px solid ${color}`,
      borderTop: `3px solid ${color}`,
      borderRadius: 'var(--radius-sm)',
      boxShadow: `var(--shadow-float)${glow ? ', ' + glow : ''}`,
      padding: '12px 14px 11px',
      fontFamily: 'var(--font-body)',
      textAlign: 'center',
      ...style
    }
  }, rest), /*#__PURE__*/React.createElement("div", {
    style: {
      fontFamily: 'var(--font-display)',
      fontWeight: 'var(--weight-bold)',
      fontSize: 'var(--text-base)',
      lineHeight: 1.2,
      letterSpacing: '0.02em',
      color,
      textShadow: glow || 'var(--shadow-text)',
      textWrap: 'balance'
    }
  }, name), itemType && /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 'var(--text-xs)',
      color: 'var(--text-muted)',
      marginTop: 3
    }
  }, itemType), baseStats.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 9,
      paddingTop: 9,
      borderTop: '1px solid var(--border-accent-soft)',
      display: 'flex',
      flexDirection: 'column',
      gap: 3
    }
  }, baseStats.map((s, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      fontFamily: 'var(--font-mono)',
      fontVariantNumeric: 'tabular-nums',
      fontSize: 'var(--text-sm)',
      color: 'var(--gold-300)'
    }
  }, s.label, " ", /*#__PURE__*/React.createElement("strong", {
    style: {
      color: 'var(--text-heading)'
    }
  }, s.value)))), affixes.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 9,
      display: 'flex',
      flexDirection: 'column',
      gap: 2
    }
  }, affixes.map((a, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      fontFamily: 'var(--font-mono)',
      fontSize: 'var(--text-sm)',
      color: a.debuff ? 'var(--danger)' : 'var(--rarity-magic)'
    }
  }, a.text))), sockets.length > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      display: 'flex',
      gap: 5,
      justifyContent: 'center'
    }
  }, sockets.map((gem, i) => /*#__PURE__*/React.createElement("span", {
    key: i,
    style: {
      width: 22,
      height: 22,
      borderRadius: '50%',
      display: 'grid',
      placeItems: 'center',
      background: gem ? 'transparent' : 'rgba(0,0,0,0.55)',
      border: '1px solid var(--ink-500)',
      boxShadow: 'inset 0 0 5px rgba(0,0,0,0.8)'
    }
  }, gem && /*#__PURE__*/React.createElement("img", {
    src: gem,
    alt: "",
    style: {
      width: 18,
      height: 18,
      imageRendering: 'pixelated'
    }
  })))), flavor && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      fontFamily: 'var(--font-lore)',
      fontStyle: 'italic',
      fontSize: 'var(--text-xs)',
      lineHeight: 1.5,
      color: 'var(--gold-400)',
      textWrap: 'pretty'
    }
  }, "\u201C", flavor, "\u201D"), (requiredLevel != null || value != null) && /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 10,
      paddingTop: 8,
      borderTop: '1px solid var(--border-accent-soft)',
      display: 'flex',
      justifyContent: 'space-between',
      fontSize: 'var(--text-xs)'
    }
  }, requiredLevel != null ? /*#__PURE__*/React.createElement("span", {
    style: {
      color: levelMet ? 'var(--text-faint)' : 'var(--danger)'
    }
  }, "Requires Level ", requiredLevel) : /*#__PURE__*/React.createElement("span", null), value != null && /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--coin)'
    }
  }, value, "g")));
}
Object.assign(__ds_scope, { ItemTooltip });
})(); } catch (e) { __ds_ns.__errors.push({ path: "components/loot/ItemTooltip.jsx", error: String((e && e.message) || e) }); }

// tools/assetgen/anim.js
try { (() => {
/** Mob animation strips — 4-frame idle / walk / attack loops (256×64) built from the mob draws. */
const C = require('./core');
const {
  MOBS
} = require('./mobs');
const {
  RIGGED
} = require('./rig');
const S = 64,
  N = 4,
  TAU = Math.PI * 2;

// Flyers / stationary mobs hover or pulse instead of striding.
const HOVER = new Set(['bat', 'slime', 'giant-worm']);
const PARAMS = {
  idle: i => {
    const t = i / N;
    return {
      bob: -Math.sin(t * TAU) * 1.2,
      sy: 1 + Math.sin(t * TAU) * 0.03,
      sx: 1 - Math.sin(t * TAU) * 0.02
    };
  },
  walk: i => {
    const t = i / N;
    return {
      bob: -Math.abs(Math.sin(t * TAU)) * 2.2,
      rot: Math.sin(t * TAU) * 0.05
    };
  },
  hover: i => {
    const t = i / N;
    return {
      bob: -Math.sin(t * TAU) * 2.2,
      sx: 1 + Math.sin(t * TAU) * 0.02
    };
  },
  attack: i => [{
    rot: -0.1,
    bob: 1
  }, {
    rot: -0.04
  }, {
    rot: 0.17,
    sx: 1.06,
    sy: 1.06,
    bob: -2
  }, {
    rot: 0.04
  }][i],
  pulse: i => [{
    sx: 0.96,
    sy: 0.96
  }, {
    sx: 1,
    sy: 1
  }, {
    sx: 1.12,
    sy: 1.12,
    bob: -2
  }, {
    sx: 1.02,
    sy: 1.02
  }][i]
};

/** Render one mob to a 64² sprite, matching the static mobs.js output (ss3 + grain8). */
function sprite(name) {
  const c = C.makeIcon(S, S, 3, MOBS[name]);
  C.grain(c, 8);
  return c;
}
function frame(g, img, fx, p) {
  g.save();
  const ax = S / 2,
    ay = S * 0.9;
  g.translate(fx + ax, (p.bob || 0) + ay);
  g.rotate(p.rot || 0);
  g.scale(p.sx || 1, p.sy || 1);
  g.translate(-ax, -ay);
  g.imageSmoothingEnabled = true;
  g.quality = 'best';
  g.drawImage(img, 0, 0, S, S);
  g.restore();
}
function jobs() {
  const out = [];
  for (const name of Object.keys(MOBS)) {
    if (RIGGED.includes(name)) continue; // rig.js owns these (true per-limb cycles)
    const states = {
      idle: PARAMS.idle,
      walk: HOVER.has(name) ? PARAMS.hover : PARAMS.walk,
      attack: HOVER.has(name) ? PARAMS.pulse : PARAMS.attack
    };
    for (const [state, pf] of Object.entries(states)) {
      out.push({
        path: `mobs/${name}_${state}.png`,
        w: S * N,
        h: S,
        ss: 1,
        draw: g => {
          const spr = sprite(name);
          for (let i = 0; i < N; i++) frame(g, spr, i * S, pf(i));
        }
      });
    }
  }
  return out;
}
module.exports = {
  jobs
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/anim.js", error: String((e && e.message) || e) }); }

// tools/assetgen/build.js
try { (() => {
/**
 * Gloomwood asset generator — orchestrator.
 *
 *   node build.js               # build everything
 *   node build.js icons mobs    # build only named groups
 *   OUT=../../public/assets node build.js   # override output root
 *
 * Output root defaults to ../../public/assets (the game's Vite web root) so files land
 * at the paths the renderer expects. Override with the OUT env var.
 */
const fs = require('fs');
const path = require('path');
const {
  grain
} = require('./core');
const GROUPS = {
  icons: require('./icons'),
  fx: require('./fx'),
  terrain: require('./terrain'),
  ui: require('./ui'),
  decor: require('./decor'),
  mobs: require('./mobs'),
  anim: require('./anim'),
  rig: require('./rig')
};
const OUT = process.env.OUT || path.resolve(__dirname, '../../public/assets');
const C = require('./core');
function render(job) {
  const c = C.makeIcon(job.w, job.h, job.ss || 1, job.draw);
  if (job.grain) grain(c, job.grain);
  const dest = path.join(OUT, job.path);
  fs.mkdirSync(path.dirname(dest), {
    recursive: true
  });
  fs.writeFileSync(dest, c.toBuffer('image/png'));
  return dest;
}
function main() {
  const want = process.argv.slice(2);
  const groups = want.length ? want : Object.keys(GROUPS);
  let n = 0;
  for (const g of groups) {
    const mod = GROUPS[g];
    if (!mod) {
      console.error(`unknown group: ${g} (have: ${Object.keys(GROUPS).join(', ')})`);
      continue;
    }
    for (const job of mod.jobs()) {
      render(job);
      n++;
    }
    console.log(`✓ ${g}`);
  }
  console.log(`\nGenerated ${n} files → ${OUT}`);
}
main();
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/build.js", error: String((e && e.message) || e) }); }

// tools/assetgen/core.js
try { (() => {
/**
 * Gloomwood ARPG — procedural art generator: shared core.
 *
 * Pure Canvas2D (node-canvas) drawing helpers + the locked Gloomwood palette. Every
 * generator module (icons/fx/decor/terrain/ui/mobs) builds on these. Output is
 * deterministic given a seed, so re-running produces byte-stable art.
 *
 *   npm i canvas      # one native dependency
 *   node build.js     # regenerates the whole set
 */
const {
  createCanvas
} = require('canvas');

/** Locked palette — mirror of tokens/colors.css (the values the renderer uses). */
const P = {
  ink950: '#08090d',
  ink900: '#0e0f13',
  ink800: '#16171d',
  ink700: '#1f2128',
  ink600: '#2a2d36',
  ink500: '#3a3e4a',
  ink400: '#4d5260',
  gold: '#c9a24b',
  goldHi: '#e7d9b0',
  goldDk: '#6b5226',
  cork: '#caa46a',
  bone: '#d7dbe3',
  boneHi: '#e8eef7',
  ash: '#9aa3b2',
  hp: '#d23b3b',
  hpHi: '#f08a8a',
  hpDeep: '#6e1414',
  mana: '#3b6fd2',
  manaHi: '#7fa3ec',
  manaDeep: '#14306a',
  coin: '#ffcf5c',
  fxFire: '#ff8a3a',
  fxFrost: '#7fc4ff',
  fxArcane: '#b07ae8',
  fxPoison: '#aef07a',
  fxHoly: '#ffe9a8',
  fxBlood: '#ff2d6f',
  // bone / stone families used by decor + mobs
  boneL: '#dcd4bd',
  boneM: '#a39a82',
  boneD: '#615b48',
  stoneL: '#5a5f6e',
  stoneM: '#3a3e4a',
  stoneD: '#1b1d24'
};
function hx(h) {
  h = h.replace('#', '');
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}
function rgb(a) {
  return `rgb(${a[0] | 0},${a[1] | 0},${a[2] | 0})`;
}
function mix(c1, c2, t) {
  const a = hx(c1),
    b = hx(c2);
  return rgb([a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t]);
}
function mix3(d, m, l, t) {
  return t < 0.5 ? mix(d, m, t * 2) : mix(m, l, (t - 0.5) * 2);
}

/** Seeded RNG — mulberry32. */
function mulberry32(a) {
  return function () {
    a |= 0;
    a = a + 0x6d2b79f5 | 0;
    let t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

/** Render `fn(ctx,w,h)` at `ss`× then downscale to W×H for clean antialiased edges. */
function makeIcon(W, H, ss, fn) {
  const big = createCanvas(W * ss, H * ss);
  const g = big.getContext('2d');
  g.scale(ss, ss);
  fn(g, W, H);
  const out = createCanvas(W, H);
  const o = out.getContext('2d');
  o.imageSmoothingEnabled = true;
  o.quality = 'best';
  o.drawImage(big, 0, 0, W, H);
  return out;
}

/** Additive radial glow. */
function glow(g, x, y, r, col, a, additive) {
  const rad = g.createRadialGradient(x, y, 0, x, y, r);
  rad.addColorStop(0, col);
  rad.addColorStop(1, 'rgba(0,0,0,0)');
  g.save();
  g.globalAlpha = a;
  if (additive) g.globalCompositeOperation = 'lighter';
  g.fillStyle = rad;
  g.beginPath();
  g.arc(x, y, r, 0, 7);
  g.fill();
  g.restore();
}

/** Per-pixel grain (skips transparent pixels). */
function grain(canvas, amt) {
  const g = canvas.getContext('2d');
  const w = canvas.width,
    h = canvas.height;
  const d = g.getImageData(0, 0, w, h);
  const p = d.data;
  for (let i = 0; i < p.length; i += 4) {
    if (p[i + 3] < 8) continue;
    const n = (Math.random() - 0.5) * amt;
    p[i] += n;
    p[i + 1] += n;
    p[i + 2] += n;
  }
  g.putImageData(d, 0, 0);
}

/** Soft foot-shadow ellipse (decor + mobs are foot-anchored). */
function shadow(g, w, h, rx) {
  rx = rx || 0.32;
  const cy = h * 0.9;
  const rad = g.createRadialGradient(w / 2, cy, 0, w / 2, cy, w * rx);
  rad.addColorStop(0, 'rgba(0,0,0,0.5)');
  rad.addColorStop(1, 'rgba(0,0,0,0)');
  g.fillStyle = rad;
  g.save();
  g.translate(w / 2, cy);
  g.scale(1, 0.3);
  g.beginPath();
  g.arc(0, 0, w * rx, 0, 7);
  g.fill();
  g.restore();
}
function lg(g, x0, y0, x1, y1, a, b, c) {
  const grd = g.createLinearGradient(x0, y0, x1, y1);
  grd.addColorStop(0, a);
  grd.addColorStop(c ? 0.55 : 1, b);
  if (c) grd.addColorStop(1, c);
  return grd;
}
function poly(g, pts) {
  g.beginPath();
  pts.forEach((p, i) => i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]));
  g.closePath();
}
function rr(g, x, y, w, h, r) {
  g.beginPath();
  g.moveTo(x + r, y);
  g.arcTo(x + w, y, x + w, y + h, r);
  g.arcTo(x + w, y + h, x, y + h, r);
  g.arcTo(x, y + h, x, y, r);
  g.arcTo(x, y, x + w, y, r);
  g.closePath();
}
function limb(g, x1, y1, x2, y2, wd, col) {
  g.strokeStyle = col;
  g.lineWidth = wd;
  g.lineCap = 'round';
  g.beginPath();
  g.moveTo(x1, y1);
  g.lineTo(x2, y2);
  g.stroke();
}
function eyes(g, cx, cy, dx, r, col) {
  glow(g, cx - dx, cy, r * 3, col, 0.7);
  glow(g, cx + dx, cy, r * 3, col, 0.7);
  g.fillStyle = col;
  g.beginPath();
  g.arc(cx - dx, cy, r, 0, 7);
  g.arc(cx + dx, cy, r, 0, 7);
  g.fill();
}
module.exports = {
  createCanvas,
  P,
  hx,
  rgb,
  mix,
  mix3,
  mulberry32,
  makeIcon,
  glow,
  grain,
  shadow,
  lg,
  poly,
  rr,
  limb,
  eyes
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/core.js", error: String((e && e.message) || e) }); }

// tools/assetgen/decor.js
try { (() => {
/** Environment decor + animated props. Native pixel dims (foot-anchored, baked soft shadow). */
const C = require('./core');
const STONE = ['#5a5f6e', '#3a3e4a', '#1b1d24'];
const BONE = ['#dcd4bd', '#a39a82', '#615b48'];

// canonical content-box dimensions (px) — keep these so decor-sprites.ts scales stay valid
const DIMS = {
  'barrel': [29, 41],
  'crate': [12, 18],
  'skull-pile': [71, 51],
  'bones-1': [26, 22],
  'bones-2': [25, 22],
  'bones-3': [32, 29],
  'bones-4': [48, 48],
  'bones-5': [30, 64],
  'bones-6': [43, 39],
  'grave-1': [16, 18],
  'grave-2': [15, 18],
  'grave-3': [16, 21],
  'grave-4': [15, 16],
  'grave-5': [16, 17],
  'grave-6': [16, 28],
  'ruin-1': [80, 95],
  'ruin-2': [55, 54],
  'ruin-3': [29, 22],
  'rock-1': [57, 56],
  'rock-2': [45, 44],
  'rock-3': [34, 33],
  'rock-4': [26, 27],
  'stalagmite-1': [41, 74],
  'stalagmite-2': [27, 54],
  'stalagmite-3': [21, 39],
  'dead-tree-1': [63, 89],
  'dead-tree-2': [59, 69],
  'dead-tree-3': [46, 45],
  'dead-tree-4': [84, 39],
  'tree-1': [59, 74],
  'tree-2': [49, 63],
  'tree-3': [32, 41],
  'crystal-1': [46, 50],
  'crystal-2': [39, 36],
  'crystal-3': [27, 25],
  'crystal-4': [44, 46],
  'mushroom-1': [44, 60],
  'mushroom-2': [35, 45],
  'mushroom-3': [56, 79],
  'mushroom-4': [52, 57],
  'mushroom-5': [33, 42],
  'thorn-plant-1': [110, 80],
  'thorn-plant-2': [94, 53],
  'thorn-plant-3': [58, 46],
  'horror-plant-1': [51, 56],
  'horror-plant-2': [98, 93],
  'horror-plant-3': [109, 127],
  'horror-plant-4': [45, 62],
  'horror-plant-5': [74, 69],
  'horror-plant-6': [69, 58],
  'pot-amber': [18, 22],
  'pot-green': [18, 22],
  'pot-red': [18, 22],
  'pot-white': [18, 22]
};
function longbone(g, x1, y1, x2, y2, wd) {
  const ang = Math.atan2(y2 - y1, x2 - x1);
  g.save();
  g.translate(x1, y1);
  g.rotate(ang);
  const L = Math.hypot(x2 - x1, y2 - y1);
  g.lineCap = 'round';
  g.strokeStyle = BONE[0];
  g.lineWidth = wd;
  g.beginPath();
  g.moveTo(0, 0);
  g.lineTo(L, 0);
  g.stroke();
  g.fillStyle = BONE[0];
  for (const kx of [0, L]) {
    g.beginPath();
    g.arc(kx, -wd * 0.35, wd * 0.5, 0, 7);
    g.arc(kx, wd * 0.35, wd * 0.5, 0, 7);
    g.fill();
  }
  g.restore();
}
function skull(g, cx, cy, R) {
  g.fillStyle = BONE[0];
  g.beginPath();
  g.arc(cx, cy, R, Math.PI, 0);
  g.lineTo(cx + R * 0.7, cy + R * 0.7);
  g.quadraticCurveTo(cx, cy + R, cx - R * 0.7, cy + R * 0.7);
  g.closePath();
  g.fill();
  g.fillStyle = '#1b1d24';
  g.beginPath();
  g.ellipse(cx - R * 0.38, cy - R * 0.05, R * 0.26, R * 0.3, 0, 0, 7);
  g.ellipse(cx + R * 0.38, cy - R * 0.05, R * 0.26, R * 0.3, 0, 0, 7);
  g.fill();
  g.beginPath();
  g.moveTo(cx, cy + R * 0.15);
  g.lineTo(cx - R * 0.12, cy + R * 0.45);
  g.lineTo(cx + R * 0.12, cy + R * 0.45);
  g.closePath();
  g.fill();
}
function boulder(g, cx, cy, R, seed) {
  const rng = C.mulberry32(seed),
    n = 8,
    pts = [];
  for (let i = 0; i < n; i++) {
    const a = i / n * 7,
      rr = R * (0.75 + rng() * 0.4);
    pts.push([cx + Math.cos(a) * rr, cy + Math.sin(a) * rr * 0.85]);
  }
  C.poly(g, pts);
  g.fillStyle = C.lg(g, cx, cy - R, cx, cy + R, STONE[0], STONE[1], STONE[2]);
  g.fill();
  g.strokeStyle = '#0e0f13';
  g.lineWidth = R * 0.06;
  g.lineJoin = 'round';
  g.stroke();
  g.strokeStyle = 'rgba(255,255,255,0.12)';
  g.lineWidth = R * 0.05;
  g.beginPath();
  g.moveTo(cx - R * 0.4, cy - R * 0.3);
  g.lineTo(cx + R * 0.2, cy - R * 0.5);
  g.stroke();
}
function tree(g, w, h, opt) {
  const rng = C.mulberry32(opt.seed),
    col = opt.bark,
    clumps = [];
  function branch(x, y, ang, len, wd, depth) {
    const x2 = x + Math.cos(ang) * len,
      y2 = y + Math.sin(ang) * len;
    g.strokeStyle = col;
    g.lineWidth = Math.max(0.6, wd);
    g.lineCap = 'round';
    const mx = x + Math.cos(ang + 0.15) * len * 0.5,
      my = y + Math.sin(ang + 0.15) * len * 0.5;
    g.beginPath();
    g.moveTo(x, y);
    g.quadraticCurveTo(mx, my, x2, y2);
    g.stroke();
    if (depth <= 0) {
      if (opt.canopy) clumps.push([x2, y2, wd * 2.6]);
      return;
    }
    const n = 2 + (rng() < 0.45 ? 1 : 0);
    for (let i = 0; i < n; i++) {
      const da = (rng() - 0.5) * 1.0 + (i - (n - 1) / 2) * 0.55;
      branch(x2, y2, ang + da, len * (0.68 + rng() * 0.16), wd * 0.64, depth - 1);
    }
  }
  const len0 = h * opt.len,
    wd0 = Math.min(w, h) * opt.wd;
  branch(w / 2, h * 0.92, -Math.PI / 2, len0, wd0, opt.depth);
  g.fillStyle = col;
  g.beginPath();
  g.moveTo(w / 2 - wd0 * 0.7, h * 0.93);
  g.lineTo(w / 2 - wd0 * 0.3, h * 0.93 - len0 * 0.5);
  g.lineTo(w / 2 + wd0 * 0.3, h * 0.93 - len0 * 0.5);
  g.lineTo(w / 2 + wd0 * 0.7, h * 0.93);
  g.closePath();
  g.fill();
  if (opt.canopy) for (const [x, y, r] of clumps) {
    const grd = g.createRadialGradient(x - r * 0.3, y - r * 0.3, 0, x, y, r);
    grd.addColorStop(0, opt.canopy[0]);
    grd.addColorStop(1, opt.canopy[1]);
    g.fillStyle = grd;
    g.beginPath();
    g.arc(x, y, r, 0, 7);
    g.fill();
  }
}
function crystalCluster(g, w, h, cols, seed) {
  const cx = w * 0.5,
    base = h * 0.9;
  C.glow(g, cx, base - h * 0.25, w * 0.55, cols.glow, 0.45);
  const shards = [[0, -0.78, 0.16], [-0.28, -0.55, 0.12], [0.3, -0.62, 0.13], [-0.12, -0.4, 0.1], [0.16, -0.36, 0.1]];
  for (const [ox, oy, wd] of shards) {
    const tx = cx + ox * w,
      ty = base + oy * h,
      bx = cx + ox * w * 0.4,
      bw = w * wd;
    C.poly(g, [[tx, ty], [bx - bw, base - h * 0.02], [bx, base + h * 0.02], [bx + bw, base - h * 0.02]]);
    g.fillStyle = C.lg(g, tx, ty, bx, base, cols.light, cols.mid, cols.dark);
    g.fill();
    g.strokeStyle = 'rgba(8,16,24,0.6)';
    g.lineWidth = w * 0.012;
    g.stroke();
    g.strokeStyle = 'rgba(255,255,255,0.5)';
    g.lineWidth = w * 0.01;
    g.beginPath();
    g.moveTo(tx, ty);
    g.lineTo(bx, base);
    g.stroke();
  }
}
function pot(g, w, h, body) {
  C.shadow(g, w, h, 0.34);
  const cx = w * 0.5;
  const grd = g.createRadialGradient(cx - w * 0.12, h * 0.5, 0, cx, h * 0.6, w * 0.34);
  grd.addColorStop(0, body[0]);
  grd.addColorStop(0.6, body[1]);
  grd.addColorStop(1, body[2]);
  g.fillStyle = grd;
  g.beginPath();
  g.ellipse(cx, h * 0.6, w * 0.3, h * 0.32, 0, 0, 7);
  g.fill();
  g.fillStyle = body[1];
  C.poly(g, [[cx - w * 0.14, h * 0.32], [cx + w * 0.14, h * 0.32], [cx + w * 0.1, h * 0.5], [cx - w * 0.1, h * 0.5]]);
  g.fill();
  g.fillStyle = body[0];
  C.rr(g, cx - w * 0.18, h * 0.24, w * 0.36, h * 0.1, w * 0.03);
  g.fill();
  g.strokeStyle = 'rgba(0,0,0,0.4)';
  g.lineWidth = w * 0.015;
  g.beginPath();
  g.ellipse(cx, h * 0.6, w * 0.3, h * 0.32, 0, 0, 7);
  g.stroke();
  g.strokeStyle = body[1];
  g.lineWidth = w * 0.04;
  for (const s of [-1, 1]) {
    g.beginPath();
    g.moveTo(cx + s * w * 0.15, h * 0.34);
    g.quadraticCurveTo(cx + s * w * 0.32, h * 0.42, cx + s * w * 0.2, h * 0.54);
    g.stroke();
  }
  g.fillStyle = 'rgba(255,255,255,0.18)';
  g.beginPath();
  g.ellipse(cx - w * 0.1, h * 0.52, w * 0.05, h * 0.12, 0.2, 0, 7);
  g.fill();
}
function oneMush(g, cx, base, sw, sh, cap, spot, glowc) {
  g.fillStyle = '#d8d0bc';
  g.beginPath();
  g.moveTo(cx - sw * 0.18, base);
  g.quadraticCurveTo(cx - sw * 0.1, base - sh * 0.5, cx - sw * 0.13, base - sh * 0.6);
  g.lineTo(cx + sw * 0.13, base - sh * 0.6);
  g.quadraticCurveTo(cx + sw * 0.1, base - sh * 0.5, cx + sw * 0.18, base);
  g.closePath();
  g.fill();
  if (glowc) C.glow(g, cx, base - sh * 0.62, sw * 0.9, glowc, 0.4);
  const cy = base - sh * 0.62;
  const grd = g.createRadialGradient(cx - sw * 0.15, cy - sh * 0.1, 0, cx, cy, sw * 0.5);
  grd.addColorStop(0, cap[0]);
  grd.addColorStop(1, cap[1]);
  g.fillStyle = grd;
  g.beginPath();
  g.ellipse(cx, cy, sw * 0.5, sh * 0.32, 0, Math.PI, 0);
  g.closePath();
  g.fill();
  g.fillStyle = 'rgba(0,0,0,0.25)';
  g.beginPath();
  g.ellipse(cx, cy, sw * 0.5, sh * 0.08, 0, 0, Math.PI);
  g.fill();
  g.fillStyle = spot;
  const r = C.mulberry32(cx | 0);
  for (let k = 0; k < 5; k++) {
    g.beginPath();
    g.arc(cx + (r() - 0.5) * sw * 0.7, cy - sh * 0.12 - r() * sh * 0.12, sw * 0.06, 0, 7);
    g.fill();
  }
}
function thorn(g, w, h, seed) {
  const rng = C.mulberry32(seed),
    base = h * 0.9,
    cx = w * 0.5;
  for (let v = 0; v < 5; v++) {
    const dir = (v - 2) * 0.4;
    let x = cx + (rng() - 0.5) * w * 0.2,
      y = base,
      ang = -Math.PI / 2 + dir;
    const segs = 4 + (rng() * 3 | 0);
    g.strokeStyle = '#2a3320';
    g.lineWidth = w * 0.04;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(x, y);
    const pts = [[x, y]];
    for (let s = 0; s < segs; s++) {
      ang += (rng() - 0.5) * 0.7;
      const len = h * 0.16 * (1 - s / segs * 0.4);
      x += Math.cos(ang) * len;
      y += Math.sin(ang) * len;
      g.lineTo(x, y);
      pts.push([x, y]);
    }
    g.stroke();
    g.fillStyle = '#1a2014';
    for (let s = 1; s < pts.length; s++) {
      const [px, py] = pts[s],
        a = Math.atan2(py - pts[s - 1][1], px - pts[s - 1][0]);
      for (const sgn of [-1, 1]) {
        g.beginPath();
        g.moveTo(px, py);
        g.lineTo(px + Math.cos(a + sgn * 1.4) * w * 0.06, py + Math.sin(a + sgn * 1.4) * w * 0.06);
        g.lineTo(px + Math.cos(a) * w * 0.03, py + Math.sin(a) * w * 0.03);
        g.closePath();
        g.fill();
      }
    }
  }
}
const F = {
  d: '#6e1e1e',
  m: '#b04a44',
  l: '#e0998a',
  v: '#4a0f0f'
};
function fleshLG(g, x0, y0, x1, y1) {
  return C.lg(g, x0, y0, x1, y1, F.l, F.m, F.d);
}
function eyeOrgan(g, cx, cy, R, iris) {
  g.fillStyle = '#e8e4d8';
  g.beginPath();
  g.ellipse(cx, cy, R, R * 0.82, 0, 0, 7);
  g.fill();
  g.strokeStyle = 'rgba(120,20,20,0.5)';
  g.lineWidth = R * 0.06;
  for (let k = 0; k < 5; k++) {
    const a = k / 5 * 7;
    g.beginPath();
    g.moveTo(cx + Math.cos(a) * R * 0.9, cy + Math.sin(a) * R * 0.7);
    g.lineTo(cx + Math.cos(a) * R * 0.4, cy + Math.sin(a) * R * 0.3);
    g.stroke();
  }
  g.fillStyle = iris;
  g.beginPath();
  g.arc(cx, cy, R * 0.5, 0, 7);
  g.fill();
  g.fillStyle = '#1b1d24';
  g.beginPath();
  g.arc(cx, cy, R * 0.24, 0, 7);
  g.fill();
  g.fillStyle = 'rgba(255,255,255,0.9)';
  g.beginPath();
  g.arc(cx - R * 0.15, cy - R * 0.15, R * 0.1, 0, 7);
  g.fill();
}
const DECOR = {
  'bones-1': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    const s = Math.min(w, h);
    longbone(g, w * 0.25, h * 0.8, w * 0.7, h * 0.7, s * 0.1);
    longbone(g, w * 0.35, h * 0.85, w * 0.75, h * 0.82, s * 0.08);
  },
  'bones-2': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    const s = Math.min(w, h);
    skull(g, w * 0.35, h * 0.6, s * 0.22);
    skull(g, w * 0.62, h * 0.72, s * 0.18);
    skull(g, w * 0.5, h * 0.5, s * 0.16);
  },
  'bones-3': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    const s = Math.min(w, h),
      cx = w * 0.5,
      cy = h * 0.78;
    g.strokeStyle = BONE[0];
    g.lineCap = 'round';
    g.lineWidth = s * 0.05;
    g.beginPath();
    g.moveTo(cx - s * 0.05, cy);
    g.lineTo(cx - s * 0.05, cy - s * 0.55);
    g.stroke();
    for (let r = 0; r < 4; r++) {
      g.beginPath();
      g.moveTo(cx - s * 0.05, cy - s * 0.1 - r * s * 0.13);
      g.quadraticCurveTo(cx - s * 0.4, cy - s * 0.15 - r * s * 0.13, cx - s * 0.3, cy + s * 0.02 - r * s * 0.13);
      g.moveTo(cx - s * 0.05, cy - s * 0.1 - r * s * 0.13);
      g.quadraticCurveTo(cx + s * 0.3, cy - s * 0.15 - r * s * 0.13, cx + s * 0.2, cy + s * 0.02 - r * s * 0.13);
      g.stroke();
    }
  },
  'bones-4': (g, w, h) => {
    C.shadow(g, w, h, 0.44);
    const s = Math.min(w, h);
    longbone(g, w * 0.2, h * 0.82, w * 0.8, h * 0.78, s * 0.09);
    longbone(g, w * 0.25, h * 0.88, w * 0.72, h * 0.9, s * 0.07);
    skull(g, w * 0.55, h * 0.62, s * 0.2);
  },
  'bones-5': (g, w, h) => {
    C.shadow(g, w, h, 0.32);
    const s = Math.min(w, h),
      cx = w * 0.5,
      cy = h * 0.85;
    for (let r = 0; r < 5; r++) {
      g.strokeStyle = BONE[0];
      g.lineWidth = s * 0.06;
      g.lineCap = 'round';
      g.beginPath();
      g.moveTo(cx, cy - r * s * 0.16);
      g.quadraticCurveTo(cx - s * 0.45, cy - r * s * 0.16 - s * 0.1, cx - s * 0.32, cy - r * s * 0.16 + s * 0.08);
      g.stroke();
    }
    g.strokeStyle = BONE[0];
    g.lineWidth = s * 0.07;
    g.beginPath();
    g.moveTo(cx, cy);
    g.lineTo(cx, cy - s * 0.8);
    g.stroke();
  },
  'bones-6': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    const s = Math.min(w, h);
    skull(g, w * 0.5, h * 0.58, s * 0.26);
    g.strokeStyle = BONE[1];
    g.lineWidth = s * 0.05;
    g.lineCap = 'round';
    for (const sgn of [-1, 1]) {
      g.beginPath();
      g.moveTo(w * 0.5 + sgn * s * 0.22, h * 0.45);
      g.quadraticCurveTo(w * 0.5 + sgn * s * 0.55, h * 0.3, w * 0.5 + sgn * s * 0.4, h * 0.12);
      g.stroke();
    }
  },
  'skull-pile': (g, w, h) => {
    C.shadow(g, w, h, 0.46);
    const s = Math.min(w, h);
    skull(g, w * 0.3, h * 0.78, s * 0.2);
    skull(g, w * 0.68, h * 0.8, s * 0.2);
    skull(g, w * 0.5, h * 0.62, s * 0.22);
    skull(g, w * 0.45, h * 0.84, s * 0.16);
  },
  'grave-1': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    C.rr(g, w * 0.3, h * 0.18, w * 0.4, h * 0.74, w * 0.04);
    g.fillStyle = C.lg(g, 0, h * 0.18, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.03;
    g.stroke();
  },
  'grave-2': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    g.save();
    g.translate(w / 2, h * 0.9);
    g.rotate(-0.12);
    C.poly(g, [[-w * 0.2, 0], [-w * 0.2, -h * 0.72], [w * 0.2, -h * 0.72], [w * 0.2, 0]]);
    g.fillStyle = C.lg(g, -w * 0.2, -h * 0.7, w * 0.2, 0, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.03;
    g.stroke();
    g.restore();
  },
  'grave-3': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    g.fillStyle = C.lg(g, 0, h * 0.2, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    g.beginPath();
    g.arc(w / 2, h * 0.42, w * 0.2, Math.PI, 0);
    g.lineTo(w * 0.7, h * 0.88);
    g.lineTo(w * 0.3, h * 0.88);
    g.closePath();
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.03;
    g.stroke();
  },
  'grave-4': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    C.rr(g, w * 0.22, h * 0.4, w * 0.56, h * 0.5, w * 0.03);
    g.fillStyle = C.lg(g, 0, h * 0.4, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.03;
    g.stroke();
  },
  'grave-5': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    g.fillStyle = C.lg(g, 0, h * 0.15, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    g.beginPath();
    g.moveTo(w * 0.3, h * 0.88);
    g.lineTo(w * 0.3, h * 0.4);
    g.arc(w / 2, h * 0.4, w * 0.2, Math.PI, 0);
    g.lineTo(w * 0.7, h * 0.88);
    g.closePath();
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.03;
    g.stroke();
    g.strokeStyle = 'rgba(0,0,0,0.45)';
    g.lineWidth = w * 0.025;
    g.beginPath();
    g.moveTo(w / 2, h * 0.32);
    g.lineTo(w / 2, h * 0.55);
    g.moveTo(w * 0.42, h * 0.4);
    g.lineTo(w * 0.58, h * 0.4);
    g.stroke();
  },
  'grave-6': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    C.poly(g, [[w * 0.38, h * 0.9], [w * 0.36, h * 0.12], [w * 0.5, h * 0.06], [w * 0.64, h * 0.12], [w * 0.62, h * 0.9]]);
    g.fillStyle = C.lg(g, w * 0.36, 0, w * 0.64, 0, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.025;
    g.stroke();
  },
  'ruin-1': (g, w, h) => {
    C.shadow(g, w, h, 0.46);
    g.fillStyle = C.lg(g, 0, h * 0.2, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    for (const x of [0.22, 0.66]) {
      g.fillRect(w * x, h * 0.3, w * 0.12, h * 0.6);
      g.strokeStyle = '#0e0f13';
      g.lineWidth = w * 0.012;
      g.strokeRect(w * x, h * 0.3, w * 0.12, h * 0.6);
    }
    C.poly(g, [[w * 0.2, h * 0.32], [w * 0.34, h * 0.18], [w * 0.66, h * 0.18], [w * 0.8, h * 0.32], [w * 0.66, h * 0.3], [w * 0.34, h * 0.3]]);
    g.fill();
    g.stroke();
  },
  'ruin-2': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    g.fillStyle = C.lg(g, 0, h * 0.2, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    g.fillRect(w * 0.42, h * 0.25, w * 0.16, h * 0.65);
    C.poly(g, [[w * 0.4, h * 0.25], [w * 0.44, h * 0.12], [w * 0.56, h * 0.15], [w * 0.6, h * 0.25]]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.012;
    g.strokeRect(w * 0.42, h * 0.25, w * 0.16, h * 0.65);
    for (let k = 0; k < 4; k++) {
      g.strokeStyle = 'rgba(0,0,0,0.35)';
      g.beginPath();
      g.moveTo(w * 0.42, h * 0.35 + k * h * 0.13);
      g.lineTo(w * 0.58, h * 0.35 + k * h * 0.13);
      g.stroke();
    }
    g.fillStyle = STONE[1];
    g.beginPath();
    g.arc(w * 0.7, h * 0.85, w * 0.08, 0, 7);
    g.arc(w * 0.28, h * 0.86, w * 0.06, 0, 7);
    g.fill();
  },
  'ruin-3': (g, w, h) => {
    C.shadow(g, w, h, 0.46);
    g.fillStyle = C.lg(g, 0, h * 0.5, 0, h * 0.9, STONE[0], STONE[1], STONE[2]);
    const rng = C.mulberry32(33);
    for (let k = 0; k < 6; k++) {
      const bx = w * (0.2 + rng() * 0.6),
        by = h * (0.6 + rng() * 0.28),
        bs = w * (0.08 + rng() * 0.08);
      g.save();
      g.translate(bx, by);
      g.rotate((rng() - 0.5) * 0.6);
      g.fillRect(-bs / 2, -bs / 2, bs, bs);
      g.strokeStyle = '#0e0f13';
      g.lineWidth = w * 0.01;
      g.strokeRect(-bs / 2, -bs / 2, bs, bs);
      g.restore();
    }
  },
  'rock-1': (g, w, h) => {
    C.shadow(g, w, h, 0.46);
    boulder(g, w * 0.38, h * 0.62, Math.min(w, h) * 0.3, 11);
    boulder(g, w * 0.66, h * 0.72, Math.min(w, h) * 0.24, 12);
  },
  'rock-2': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    boulder(g, w * 0.5, h * 0.65, Math.min(w, h) * 0.34, 21);
    boulder(g, w * 0.3, h * 0.8, Math.min(w, h) * 0.16, 22);
  },
  'rock-3': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    boulder(g, w * 0.5, h * 0.66, Math.min(w, h) * 0.36, 31);
  },
  'rock-4': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    boulder(g, w * 0.5, h * 0.7, Math.min(w, h) * 0.28, 41);
  },
  'stalagmite-1': (g, w, h) => {
    C.shadow(g, w, h, 0.34);
    C.poly(g, [[w * 0.3, h * 0.9], [w * 0.42, h * 0.1], [w * 0.5, h * 0.92]]);
    g.fillStyle = C.lg(g, w * 0.3, 0, w * 0.5, 0, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.02;
    g.stroke();
    C.poly(g, [[w * 0.5, h * 0.92], [w * 0.6, h * 0.35], [w * 0.7, h * 0.9]]);
    g.fillStyle = C.lg(g, w * 0.5, 0, w * 0.7, 0, STONE[1], STONE[2], '#0e0f13');
    g.fill();
    g.stroke();
  },
  'stalagmite-2': (g, w, h) => {
    C.shadow(g, w, h, 0.32);
    C.poly(g, [[w * 0.32, h * 0.9], [w * 0.5, h * 0.08], [w * 0.68, h * 0.9]]);
    g.fillStyle = C.lg(g, w * 0.32, 0, w * 0.68, 0, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.02;
    g.stroke();
    g.strokeStyle = 'rgba(0,0,0,0.3)';
    for (let k = 1; k < 4; k++) {
      g.beginPath();
      g.moveTo(w * 0.5 - w * 0.18 * (1 - k / 4), h * 0.08 + k * h * 0.2);
      g.lineTo(w * 0.5 + w * 0.18 * (1 - k / 4), h * 0.08 + k * h * 0.2);
      g.stroke();
    }
  },
  'stalagmite-3': (g, w, h) => {
    C.shadow(g, w, h, 0.3);
    C.poly(g, [[w * 0.36, h * 0.9], [w * 0.5, h * 0.25], [w * 0.64, h * 0.9]]);
    g.fillStyle = C.lg(g, w * 0.36, 0, w * 0.64, 0, STONE[0], STONE[1], STONE[2]);
    g.fill();
    g.strokeStyle = '#0e0f13';
    g.lineWidth = w * 0.025;
    g.stroke();
  },
  'dead-tree-1': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    tree(g, w, h, {
      seed: 101,
      bark: '#7a7363',
      len: 0.3,
      wd: 0.13,
      depth: 5
    });
  },
  'dead-tree-2': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    tree(g, w, h, {
      seed: 102,
      bark: '#6e6757',
      len: 0.3,
      wd: 0.12,
      depth: 5
    });
  },
  'dead-tree-3': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    tree(g, w, h, {
      seed: 103,
      bark: '#5e5848',
      len: 0.32,
      wd: 0.11,
      depth: 4
    });
  },
  'dead-tree-4': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    g.save();
    g.translate(w / 2, h * 0.78);
    g.rotate(0.08);
    g.fillStyle = '#5e5848';
    g.beginPath();
    g.ellipse(0, 0, w * 0.36, h * 0.12, 0, 0, 7);
    g.fill();
    g.fillStyle = '#3a3428';
    g.beginPath();
    g.ellipse(-w * 0.34, 0, w * 0.06, h * 0.1, 0, 0, 7);
    g.fill();
    g.strokeStyle = '#2a2620';
    g.lineWidth = w * 0.01;
    for (let k = 0; k < 3; k++) {
      g.beginPath();
      g.ellipse(-w * 0.34, 0, w * 0.04 - k * w * 0.012, h * 0.07 - k * h * 0.02, 0, 0, 7);
      g.stroke();
    }
    g.restore();
  },
  'tree-1': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    tree(g, w, h, {
      seed: 201,
      bark: '#2e2820',
      len: 0.26,
      wd: 0.14,
      depth: 5,
      canopy: ['#1f3318', '#0c1808']
    });
  },
  'tree-2': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    tree(g, w, h, {
      seed: 202,
      bark: '#2a241c',
      len: 0.26,
      wd: 0.13,
      depth: 5,
      canopy: ['#243a1c', '#0e1a0a']
    });
  },
  'tree-3': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    tree(g, w, h, {
      seed: 203,
      bark: '#2a241c',
      len: 0.28,
      wd: 0.12,
      depth: 4,
      canopy: ['#1f3318', '#0c1808']
    });
  },
  'crystal-1': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    crystalCluster(g, w, h, {
      dark: '#155244',
      mid: '#2fae78',
      light: '#a8ead0',
      glow: '#5fd0a0'
    }, 11);
  },
  'crystal-2': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    crystalCluster(g, w, h, {
      dark: '#155244',
      mid: '#2fae78',
      light: '#a8ead0',
      glow: '#5fd0a0'
    }, 12);
  },
  'crystal-3': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    crystalCluster(g, w, h, {
      dark: '#155244',
      mid: '#2fae78',
      light: '#a8ead0',
      glow: '#5fd0a0'
    }, 13);
  },
  'crystal-4': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    crystalCluster(g, w, h, {
      dark: '#173a66',
      mid: '#3f86c0',
      light: '#bfe4ff',
      glow: '#7fc4ff'
    }, 14);
  },
  'barrel': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    const bx = w * 0.5,
      top = h * 0.18,
      bot = h * 0.9,
      bw = w * 0.62;
    const grd = g.createLinearGradient(bx - bw / 2, 0, bx + bw / 2, 0);
    grd.addColorStop(0, '#3a2a18');
    grd.addColorStop(0.5, '#7a5630');
    grd.addColorStop(1, '#3a2a18');
    C.poly(g, [[bx - bw * 0.42, top], [bx + bw * 0.42, top], [bx + bw * 0.5, (top + bot) / 2], [bx + bw * 0.42, bot], [bx - bw * 0.42, bot], [bx - bw * 0.5, (top + bot) / 2]]);
    g.fillStyle = grd;
    g.fill();
    g.strokeStyle = '#1b140a';
    g.lineWidth = w * 0.02;
    g.stroke();
    g.strokeStyle = 'rgba(0,0,0,0.35)';
    g.lineWidth = w * 0.012;
    for (let k = -2; k <= 2; k++) {
      g.beginPath();
      g.moveTo(bx + k * bw * 0.16, top);
      g.lineTo(bx + k * bw * 0.18, bot);
      g.stroke();
    }
    g.fillStyle = '#5a5f6e';
    for (const yy of [top + h * 0.12, bot - h * 0.12]) g.fillRect(bx - bw * 0.5, yy, bw, h * 0.08);
    g.fillStyle = 'rgba(255,255,255,0.15)';
    for (const yy of [top + h * 0.12, bot - h * 0.12]) g.fillRect(bx - bw * 0.5, yy, bw, h * 0.02);
    g.fillStyle = '#4a3420';
    g.beginPath();
    g.ellipse(bx, top, bw * 0.42, h * 0.05, 0, 0, 7);
    g.fill();
  },
  'crate': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    const x = w * 0.2,
      y = h * 0.22,
      sw = w * 0.6,
      sh = h * 0.68;
    C.rr(g, x, y, sw, sh, w * 0.03);
    const grd = g.createLinearGradient(x, y, x, y + sh);
    grd.addColorStop(0, '#8a6038');
    grd.addColorStop(1, '#5a3e22');
    g.fillStyle = grd;
    g.fill();
    g.strokeStyle = '#2a1d10';
    g.lineWidth = w * 0.025;
    g.stroke();
    g.strokeStyle = 'rgba(0,0,0,0.3)';
    g.lineWidth = w * 0.012;
    for (let k = 1; k < 3; k++) {
      g.beginPath();
      g.moveTo(x, y + sh * k / 3);
      g.lineTo(x + sw, y + sh * k / 3);
      g.stroke();
    }
    g.strokeStyle = '#4a3018';
    g.lineWidth = w * 0.04;
    g.beginPath();
    g.moveTo(x, y);
    g.lineTo(x + sw, y + sh);
    g.moveTo(x + sw, y);
    g.lineTo(x, y + sh);
    g.stroke();
    g.fillStyle = '#3a3e4a';
    for (const [cx, cy] of [[x, y], [x + sw, y], [x, y + sh], [x + sw, y + sh]]) {
      g.beginPath();
      g.arc(cx, cy, w * 0.03, 0, 7);
      g.fill();
    }
  },
  'pot-amber': (g, w, h) => pot(g, w, h, ['#e0b56a', '#b07c32', '#5e3e16']),
  'pot-green': (g, w, h) => pot(g, w, h, ['#6fc09a', '#2f8a5e', '#134030']),
  'pot-red': (g, w, h) => pot(g, w, h, ['#d86a5a', '#a83020', '#561010']),
  'pot-white': (g, w, h) => pot(g, w, h, ['#e8e4d8', '#b8b2a0', '#6a6458']),
  'mushroom-1': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    oneMush(g, w * 0.5, h * 0.9, w * 0.7, h * 0.7, ['#b06cd8', '#5e2a8a'], '#e0c4ff', '#9b5cff');
  },
  'mushroom-2': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    oneMush(g, w * 0.42, h * 0.9, w * 0.6, h * 0.62, ['#b06cd8', '#5e2a8a'], '#e0c4ff', '#9b5cff');
    oneMush(g, w * 0.66, h * 0.92, w * 0.4, h * 0.42, ['#b06cd8', '#5e2a8a'], '#e0c4ff', null);
  },
  'mushroom-3': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    oneMush(g, w * 0.4, h * 0.9, w * 0.55, h * 0.6, ['#5a9ed8', '#1f4f8a'], '#bfe4ff', '#7fc4ff');
    oneMush(g, w * 0.66, h * 0.92, w * 0.45, h * 0.46, ['#5a9ed8', '#1f4f8a'], '#bfe4ff', null);
  },
  'mushroom-4': (g, w, h) => {
    C.shadow(g, w, h, 0.34);
    oneMush(g, w * 0.5, h * 0.9, w * 0.7, h * 0.68, ['#5a9ed8', '#1f4f8a'], '#bfe4ff', '#7fc4ff');
  },
  'mushroom-5': (g, w, h) => {
    C.shadow(g, w, h, 0.34);
    oneMush(g, w * 0.5, h * 0.9, w * 0.7, h * 0.66, ['#4fbf9e', '#15705a'], '#bfeed8', '#5fd0a0');
  },
  'thorn-plant-1': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    thorn(g, w, h, 71);
  },
  'thorn-plant-2': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    thorn(g, w, h, 72);
  },
  'thorn-plant-3': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    thorn(g, w, h, 73);
  },
  'horror-plant-1': (g, w, h) => {
    C.shadow(g, w, h, 0.34);
    const cx = w * 0.5;
    C.glow(g, cx, h * 0.4, w * 0.4, '#d23b3b', 0.3);
    g.fillStyle = fleshLG(g, cx - w * 0.1, h * 0.9, cx + w * 0.1, h * 0.5);
    g.beginPath();
    g.moveTo(cx - w * 0.1, h * 0.9);
    g.quadraticCurveTo(cx - w * 0.18, h * 0.6, cx - w * 0.12, h * 0.45);
    g.lineTo(cx + w * 0.12, h * 0.45);
    g.quadraticCurveTo(cx + w * 0.18, h * 0.6, cx + w * 0.1, h * 0.9);
    g.closePath();
    g.fill();
    eyeOrgan(g, cx, h * 0.38, w * 0.22, '#5fd0a0');
  },
  'horror-plant-2': (g, w, h) => {
    C.shadow(g, w, h, 0.42);
    const cx = w * 0.5,
      base = h * 0.9,
      rng = C.mulberry32(2);
    for (let t = 0; t < 5; t++) {
      const dir = (t - 2) * 0.32;
      let x = cx + (t - 2) * w * 0.08,
        y = base,
        ang = -Math.PI / 2 + dir;
      g.strokeStyle = F.m;
      g.lineCap = 'round';
      let lw = w * 0.13;
      g.beginPath();
      g.moveTo(x, y);
      for (let s = 0; s < 5; s++) {
        ang += (rng() - 0.5) * 0.6;
        const len = h * 0.14;
        x += Math.cos(ang) * len;
        y += Math.sin(ang) * len;
        g.lineWidth = lw * (1 - s / 5 * 0.7);
        g.lineTo(x, y);
      }
      g.stroke();
      g.fillStyle = F.l;
      g.beginPath();
      g.arc(x, y, lw * 0.2, 0, 7);
      g.fill();
    }
  },
  'horror-plant-3': (g, w, h) => {
    C.shadow(g, w, h, 0.36);
    const cx = w * 0.5,
      cy = h * 0.55;
    C.glow(g, cx, cy, w * 0.4, '#d23b3b', 0.35);
    g.fillStyle = fleshLG(g, cx, cy - h * 0.3, cx, cy + h * 0.35);
    g.beginPath();
    g.ellipse(cx, cy, w * 0.34, h * 0.36, 0, 0, 7);
    g.fill();
    g.fillStyle = '#2a0808';
    g.beginPath();
    g.ellipse(cx, cy, w * 0.2, h * 0.26, 0, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    const n = 9;
    for (let k = 0; k < n; k++) {
      const a = k / n * 7;
      g.beginPath();
      g.moveTo(cx + Math.cos(a) * w * 0.2, cy + Math.sin(a) * h * 0.26);
      g.lineTo(cx + Math.cos(a + 0.15) * w * 0.12, cy + Math.sin(a + 0.15) * h * 0.16);
      g.lineTo(cx + Math.cos(a - 0.15) * w * 0.12, cy + Math.sin(a - 0.15) * h * 0.16);
      g.closePath();
      g.fill();
    }
  },
  'horror-plant-4': (g, w, h) => {
    C.shadow(g, w, h, 0.38);
    const cx = w * 0.5,
      cy = h * 0.55;
    g.fillStyle = fleshLG(g, cx - w * 0.2, cy - h * 0.2, cx + w * 0.2, cy + h * 0.3);
    g.beginPath();
    g.arc(cx, cy, w * 0.34, 0, 7);
    g.fill();
    const irises = ['#5fd0a0', '#ffb03a', '#7fc4ff', '#d23b3b'],
      r = C.mulberry32(4),
      spots = [[0, 0, 0.16], [-0.5, -0.3, 0.1], [0.5, -0.2, 0.1], [-0.3, 0.45, 0.09], [0.4, 0.45, 0.09], [0, -0.55, 0.09]];
    for (const [ox, oy, rr] of spots) eyeOrgan(g, cx + ox * w * 0.34, cy + oy * w * 0.34, w * rr, irises[r() * 4 | 0]);
  },
  'horror-plant-5': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    const cx = w * 0.5,
      cy = h * 0.5;
    C.glow(g, cx, cy, w * 0.4, '#d23b3b', 0.3);
    const np = 7;
    for (let k = 0; k < np; k++) {
      const a = k / np * 7;
      g.save();
      g.translate(cx, cy);
      g.rotate(a);
      g.fillStyle = fleshLG(g, 0, 0, 0, -h * 0.4);
      g.beginPath();
      g.ellipse(0, -h * 0.26, w * 0.1, h * 0.22, 0, 0, 7);
      g.fill();
      g.strokeStyle = F.v;
      g.lineWidth = w * 0.01;
      g.stroke();
      g.restore();
    }
    g.fillStyle = '#2a0808';
    g.beginPath();
    g.arc(cx, cy, w * 0.14, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    for (let k = 0; k < 6; k++) {
      const a = k / 6 * 7;
      g.beginPath();
      g.moveTo(cx + Math.cos(a) * w * 0.13, cy + Math.sin(a) * w * 0.13);
      g.lineTo(cx + Math.cos(a + 0.2) * w * 0.06, cy + Math.sin(a + 0.2) * w * 0.06);
      g.lineTo(cx + Math.cos(a - 0.2) * w * 0.06, cy + Math.sin(a - 0.2) * w * 0.06);
      g.closePath();
      g.fill();
    }
  },
  'horror-plant-6': (g, w, h) => {
    C.shadow(g, w, h, 0.4);
    const pods = [[0.36, 0.7, 0.2], [0.62, 0.72, 0.18], [0.5, 0.55, 0.16]];
    for (const [ox, oy, rr] of pods) {
      const cx = w * ox,
        cy = h * oy;
      C.glow(g, cx, cy, w * rr * 1.6, '#aef07a', 0.3);
      const grd = g.createRadialGradient(cx - w * rr * 0.3, cy - w * rr * 0.3, 0, cx, cy, w * rr);
      grd.addColorStop(0, '#cfe89a');
      grd.addColorStop(0.6, '#7a9e4a');
      grd.addColorStop(1, '#3a4a20');
      g.fillStyle = grd;
      g.beginPath();
      g.ellipse(cx, cy, w * rr, h * rr * 1.3, 0, 0, 7);
      g.fill();
      g.strokeStyle = 'rgba(20,30,10,0.5)';
      g.lineWidth = w * 0.01;
      g.stroke();
      g.fillStyle = 'rgba(40,20,20,0.6)';
      g.beginPath();
      g.arc(cx, cy + w * rr * 0.2, w * rr * 0.4, 0.4, Math.PI - 0.4);
      g.fill();
    }
  }
};

// animated flame props (16×16, 4-frame loops)
function flameShape(g, cx, by, wd, ht, seed, c1, c2, c3) {
  const rng = C.mulberry32(seed);
  C.glow(g, cx, by - ht * 0.5, wd * 1.8, c1, 0.55, true);
  g.beginPath();
  g.moveTo(cx - wd * 0.5, by);
  g.quadraticCurveTo(cx - wd * 0.5, by - ht * 0.55, cx - wd * 0.15 + (rng() - 0.5) * wd * 0.2, by - ht * 0.8);
  g.quadraticCurveTo(cx, by - ht * 1.1, cx + wd * 0.15 + (rng() - 0.5) * wd * 0.2, by - ht * 0.8);
  g.quadraticCurveTo(cx + wd * 0.5, by - ht * 0.55, cx + wd * 0.5, by);
  g.closePath();
  const grd = g.createLinearGradient(cx, by, cx, by - ht);
  grd.addColorStop(0, c1);
  grd.addColorStop(0.5, c2);
  grd.addColorStop(1, c3);
  g.fillStyle = grd;
  g.fill();
  g.fillStyle = c3;
  g.beginPath();
  g.moveTo(cx - wd * 0.2, by);
  g.quadraticCurveTo(cx, by - ht * 0.6, cx + wd * 0.2, by);
  g.closePath();
  g.fill();
}
function brazier(f) {
  return (g, w, h) => {
    g.fillStyle = '#3a3e4a';
    g.beginPath();
    g.moveTo(w * 0.2, h * 0.55);
    g.lineTo(w * 0.8, h * 0.55);
    g.lineTo(w * 0.68, h * 0.82);
    g.lineTo(w * 0.32, h * 0.82);
    g.closePath();
    g.fill();
    g.strokeStyle = '#16171d';
    g.lineWidth = w * 0.04;
    g.stroke();
    g.fillStyle = '#5a5f6e';
    g.fillRect(w * 0.2, h * 0.5, w * 0.6, h * 0.08);
    g.strokeStyle = '#2a2d36';
    g.lineWidth = w * 0.05;
    g.beginPath();
    g.moveTo(w * 0.34, h * 0.82);
    g.lineTo(w * 0.3, h * 0.95);
    g.moveTo(w * 0.66, h * 0.82);
    g.lineTo(w * 0.7, h * 0.95);
    g.stroke();
    C.glow(g, w * 0.5, h * 0.54, w * 0.3, '#ff8a3a', 0.7, true);
    const ht = h * (0.42 + 0.1 * Math.sin(f * 1.6));
    flameShape(g, w * 0.5 + (f % 2 ? w * 0.03 : -w * 0.03), h * 0.52, w * 0.32, ht, f * 11, '#7a1e08', '#ff8a3a', '#ffe9a8');
  };
}
function candle(f) {
  return (g, w, h) => {
    g.fillStyle = '#d8d0bc';
    g.fillRect(w * 0.42, h * 0.45, w * 0.16, h * 0.45);
    g.fillStyle = '#b8b0a0';
    g.beginPath();
    g.ellipse(w * 0.5, h * 0.9, w * 0.08, h * 0.03, 0, 0, 7);
    g.fill();
    g.fillStyle = '#f0e8d4';
    g.beginPath();
    g.ellipse(w * 0.5, h * 0.45, w * 0.08, h * 0.03, 0, 0, 7);
    g.fill();
    g.strokeStyle = '#2a2620';
    g.lineWidth = w * 0.03;
    g.beginPath();
    g.moveTo(w * 0.5, h * 0.45);
    g.lineTo(w * 0.5, h * 0.38);
    g.stroke();
    C.glow(g, w * 0.5, h * 0.32, w * 0.22, '#ffb03a', 0.7, true);
    const ht = h * (0.2 + 0.06 * Math.sin(f * 1.8));
    flameShape(g, w * 0.5 + (f % 2 ? w * 0.02 : -w * 0.02), h * 0.38, w * 0.14, ht, f * 7 + 3, '#9a3008', '#ffb03a', '#fff4d8');
  };
}
function jobs() {
  const out = [];
  for (const [name, draw] of Object.entries(DECOR)) {
    const [w, h] = DIMS[name];
    out.push({
      path: `decor/${name}.png`,
      w,
      h,
      ss: 3,
      grain: 7,
      draw
    });
  }
  for (let f = 1; f <= 4; f++) out.push({
    path: `decor/anim/brazier-${f}.png`,
    w: 16,
    h: 16,
    ss: 5,
    draw: brazier(f)
  });
  for (let f = 1; f <= 4; f++) out.push({
    path: `decor/anim/candle-${f}.png`,
    w: 16,
    h: 16,
    ss: 5,
    draw: candle(f)
  });
  return out;
}
module.exports = {
  jobs
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/decor.js", error: String((e && e.message) || e) }); }

// tools/assetgen/fx.js
try { (() => {
/** Spell / projectile FX — frame strips, explosion grid, arrows sheet. Native pixel dims. */
const C = require('./core');
function flame(g, cx, cy, R, seed, c1, c2, c3) {
  const rng = C.mulberry32(seed);
  C.glow(g, cx, cy, R * 1.7, c1, 0.5, true);
  g.save();
  g.globalCompositeOperation = 'lighter';
  for (let k = 0; k < 7; k++) {
    const a = rng() * Math.PI * 2,
      len = R * (0.7 + rng() * 0.7),
      fx = cx + Math.cos(a) * R * 0.3,
      fy = cy + Math.sin(a) * R * 0.3;
    g.beginPath();
    g.moveTo(fx, fy);
    g.quadraticCurveTo(cx + Math.cos(a) * len * 0.6, cy + Math.sin(a) * len * 0.6, cx + Math.cos(a) * len, cy + Math.sin(a) * len);
    g.lineWidth = R * 0.4 * (1 - k / 9);
    g.strokeStyle = c2;
    g.lineCap = 'round';
    g.stroke();
  }
  g.restore();
  const grd = g.createRadialGradient(cx, cy, 0, cx, cy, R);
  grd.addColorStop(0, c3);
  grd.addColorStop(0.4, c2);
  grd.addColorStop(1, c1);
  g.fillStyle = grd;
  g.beginPath();
  g.arc(cx, cy, R * 0.8, 0, 7);
  g.fill();
  g.fillStyle = c3;
  g.beginPath();
  g.arc(cx, cy, R * 0.35, 0, 7);
  g.fill();
}

// strip: N square frames of size S=H laid horizontally; drawFrame(g,S,i,t)
function strip(N, drawFrame) {
  return (g, W, H) => {
    const S = H;
    for (let i = 0; i < N; i++) {
      g.save();
      g.translate(i * S, 0);
      drawFrame(g, S, i, i / (N - 1 || 1));
      g.restore();
    }
  };
}
function grid(cols, rows, drawCell) {
  return (g, W, H) => {
    const cw = W / cols,
      ch = H / rows;
    let i = 0;
    for (let r = 0; r < rows; r++) for (let cc = 0; cc < cols; cc++) {
      g.save();
      g.translate(cc * cw, r * ch);
      drawCell(g, cw, ch, i++, r, cc);
      g.restore();
    }
  };
}
const fireball = strip(6, (g, S, i, t) => {
  const c = S / 2;
  flame(g, c, c, S * (0.28 + t * 0.12), i * 7 + 3, '#7a1e08', '#ff8a3a', '#ffe9a8');
});
const firebomb = strip(6, (g, S, i, t) => {
  const c = S / 2;
  if (i < 3) {
    g.fillStyle = '#16171d';
    g.beginPath();
    g.arc(c, c + S * 0.05, S * 0.3, 0, 7);
    g.fill();
    g.strokeStyle = '#3a3e4a';
    g.lineWidth = S * 0.04;
    g.stroke();
    C.glow(g, c, c - S * 0.3, S * 0.25, '#ffd488', 0.9, true);
    g.fillStyle = '#ff8a3a';
    g.beginPath();
    g.arc(c, c - S * 0.3, S * 0.05, 0, 7);
    g.fill();
  } else flame(g, c, c, S * (0.3 + t * 0.18), i * 9, '#7a1e08', '#ff8a3a', '#ffe9a8');
});
const iceLance = strip(4, (g, S, i) => {
  const cy = S / 2,
    cx = S * 0.5;
  C.glow(g, cx, cy, S * 0.5, '#7fc4ff', 0.4, true);
  g.save();
  g.globalCompositeOperation = 'lighter';
  for (let k = 0; k < 4; k++) {
    g.fillStyle = `rgba(180,224,255,${0.4 - k * 0.08})`;
    g.beginPath();
    g.arc(cx - S * 0.2 - k * S * 0.12, cy + Math.sin(k + i) * S * 0.08, S * 0.05, 0, 7);
    g.fill();
  }
  g.restore();
  g.beginPath();
  g.moveTo(cx + S * 0.4, cy);
  g.lineTo(cx - S * 0.05, cy - S * 0.16);
  g.lineTo(cx - S * 0.25, cy);
  g.lineTo(cx - S * 0.05, cy + S * 0.16);
  g.closePath();
  g.fillStyle = C.lg(g, cx - S * 0.25, cy, cx + S * 0.4, cy, '#1e4f8a', '#7fc4ff', '#eaf6ff');
  g.fill();
  g.strokeStyle = 'rgba(10,30,60,0.6)';
  g.lineWidth = S * 0.03;
  g.stroke();
});
const arcaneBolt = strip(6, (g, S, i) => {
  const c = S / 2,
    rng = C.mulberry32(i * 13 + 1);
  C.glow(g, c, c, S * 0.6, '#b07ae8', 0.55, true);
  const grd = g.createRadialGradient(c, c, 0, c, c, S * 0.32);
  grd.addColorStop(0, '#f0e0ff');
  grd.addColorStop(0.5, '#b07ae8');
  grd.addColorStop(1, '#3d1a6e');
  g.fillStyle = grd;
  g.beginPath();
  g.arc(c, c, S * 0.3, 0, 7);
  g.fill();
  g.save();
  g.globalCompositeOperation = 'lighter';
  g.strokeStyle = '#d6abff';
  g.lineWidth = S * 0.03;
  for (let k = 0; k < 4; k++) {
    const a = rng() * 7;
    g.beginPath();
    g.moveTo(c, c);
    let x = c,
      y = c;
    for (let s = 0; s < 3; s++) {
      x += Math.cos(a) * S * 0.12 + (rng() - 0.5) * S * 0.1;
      y += Math.sin(a) * S * 0.12 + (rng() - 0.5) * S * 0.1;
      g.lineTo(x, y);
    }
    g.stroke();
  }
  g.restore();
});
const magicOrb = strip(6, (g, S, i, t) => {
  const c = S / 2,
    pulse = 0.26 + Math.sin(t * Math.PI * 2) * 0.06;
  C.glow(g, c, c, S * 0.7, '#9b5cff', 0.5, true);
  const grd = g.createRadialGradient(c, c, 0, c, c, S * pulse);
  grd.addColorStop(0, '#ffffff');
  grd.addColorStop(0.4, '#c79eff');
  grd.addColorStop(1, '#6a30b8');
  g.fillStyle = grd;
  g.beginPath();
  g.arc(c, c, S * pulse, 0, 7);
  g.fill();
  g.save();
  g.globalCompositeOperation = 'lighter';
  g.fillStyle = '#e8d8ff';
  for (let k = 0; k < 3; k++) {
    const a = t * Math.PI * 2 + k * 2.1;
    g.beginPath();
    g.arc(c + Math.cos(a) * S * 0.34, c + Math.sin(a) * S * 0.34, S * 0.04, 0, 7);
    g.fill();
  }
  g.restore();
});
const magicSparks = strip(6, (g, S, i, t) => {
  const c = S / 2,
    rng = C.mulberry32(99);
  C.glow(g, c, c, S * 0.5 * (0.5 + t), '#ffe9a8', 0.5 * (1 - t * 0.6), true);
  g.save();
  g.globalCompositeOperation = 'lighter';
  g.strokeStyle = '#ffd488';
  g.lineCap = 'round';
  for (let k = 0; k < 8; k++) {
    const a = k / 8 * Math.PI * 2 + rng(),
      r0 = S * 0.1 * t,
      r1 = S * (0.12 + 0.32 * t);
    g.lineWidth = S * 0.04 * (1 - t * 0.5);
    g.beginPath();
    g.moveTo(c + Math.cos(a) * r0, c + Math.sin(a) * r0);
    g.lineTo(c + Math.cos(a) * r1, c + Math.sin(a) * r1);
    g.stroke();
  }
  g.restore();
  g.fillStyle = `rgba(255,244,216,${1 - t})`;
  g.beginPath();
  g.arc(c, c, S * 0.08 * (1 - t * 0.5), 0, 7);
  g.fill();
});
const waterBolt = strip(6, (g, S) => {
  const cy = S / 2,
    cx = S * 0.52;
  C.glow(g, cx, cy, S * 0.45, '#3b6fd2', 0.4, true);
  g.save();
  g.globalCompositeOperation = 'lighter';
  for (let k = 0; k < 4; k++) {
    g.fillStyle = `rgba(127,163,236,${0.4 - k * 0.08})`;
    g.beginPath();
    g.arc(cx - S * 0.18 - k * S * 0.12, cy, S * 0.05, 0, 7);
    g.fill();
  }
  g.restore();
  const grd = g.createRadialGradient(cx - S * 0.05, cy - S * 0.05, 0, cx, cy, S * 0.28);
  grd.addColorStop(0, '#cfe0ff');
  grd.addColorStop(0.5, '#3b6fd2');
  grd.addColorStop(1, '#14306a');
  g.fillStyle = grd;
  g.beginPath();
  g.moveTo(cx + S * 0.32, cy);
  g.quadraticCurveTo(cx, cy - S * 0.22, cx - S * 0.18, cy);
  g.quadraticCurveTo(cx, cy + S * 0.22, cx + S * 0.32, cy);
  g.fill();
});
const rockSling = strip(1, (g, S) => {
  const c = S / 2,
    rng = C.mulberry32(3),
    pts = [];
  for (let k = 0; k < 7; k++) {
    const a = k / 7 * 7,
      rr = S * 0.3 * (0.7 + rng() * 0.5);
    pts.push([c + Math.cos(a) * rr, c + Math.sin(a) * rr]);
  }
  C.poly(g, pts);
  g.fillStyle = C.lg(g, c, c - S * 0.3, c, c + S * 0.3, '#4d5260', '#16171d');
  g.fill();
  g.strokeStyle = '#08090d';
  g.lineWidth = S * 0.04;
  g.stroke();
});
const splash = strip(6, (g, S, i, t) => {
  const c = S / 2;
  C.glow(g, c, c, S * 0.4 * (0.5 + t), '#7fc4ff', 0.4 * (1 - t * 0.5), true);
  g.save();
  g.globalCompositeOperation = 'lighter';
  g.strokeStyle = `rgba(180,224,255,${1 - t})`;
  g.lineWidth = S * 0.05 * (1 - t * 0.5);
  g.beginPath();
  g.arc(c, c, S * (0.08 + 0.36 * t), 0, 7);
  g.stroke();
  g.fillStyle = `rgba(220,240,255,${1 - t})`;
  for (let k = 0; k < 6; k++) {
    const a = k / 6 * 7,
      r = S * (0.1 + 0.34 * t);
    g.beginPath();
    g.arc(c + Math.cos(a) * r, c + Math.sin(a) * r, S * 0.04 * (1 - t * 0.4), 0, 7);
    g.fill();
  }
  g.restore();
});
const explosion = grid(4, 4, (g, W, H, i) => {
  const c = W / 2,
    t = i / 15,
    rng = C.mulberry32(i * 17 + 5),
    R = W * (0.12 + t * 0.34);
  if (t < 0.6) {
    C.glow(g, c, c, R * 2, '#ff8a3a', 0.6 * (1 - t), true);
    const grd = g.createRadialGradient(c, c, 0, c, c, R);
    grd.addColorStop(0, '#fff4d8');
    grd.addColorStop(0.4, '#ff8a3a');
    grd.addColorStop(0.8, '#c41f1f');
    grd.addColorStop(1, 'rgba(40,10,5,0)');
    g.fillStyle = grd;
    g.beginPath();
    g.arc(c, c, R, 0, 7);
    g.fill();
    g.save();
    g.globalCompositeOperation = 'lighter';
    g.fillStyle = '#ffd488';
    for (let k = 0; k < 8; k++) {
      const a = k / 8 * 7 + rng(),
        r = R * (0.9 + rng() * 0.5);
      g.beginPath();
      g.arc(c + Math.cos(a) * r, c + Math.sin(a) * r, W * 0.03, 0, 7);
      g.fill();
    }
    g.restore();
  } else {
    g.fillStyle = `rgba(60,60,68,${0.5 * (1 - t)})`;
    for (let k = 0; k < 5; k++) {
      const a = k / 5 * 7,
        r = R * 0.8;
      g.beginPath();
      g.arc(c + Math.cos(a) * r, c + Math.sin(a) * r, W * 0.12 * (1 - t * 0.3), 0, 7);
      g.fill();
    }
    C.glow(g, c, c, R, '#ff6a2a', 0.3 * (1 - t), true);
  }
});
const ACOLS = ['#c9a24b', '#ff8a3a', '#7fc4ff', '#b07ae8', '#aef07a', '#d7dbe3', '#d23b3b'];
const arrows = grid(11, 14, (g, W, H, i, r, cc) => {
  const c = W / 2,
    col = ACOLS[r % ACOLS.length],
    ang = cc / 11 * Math.PI * 2;
  g.save();
  g.translate(c, c);
  g.rotate(ang);
  C.glow(g, 0, 0, W * 0.4, col, 0.35, true);
  g.strokeStyle = col;
  g.lineWidth = W * 0.07;
  g.lineCap = 'round';
  g.beginPath();
  g.moveTo(-W * 0.32, 0);
  g.lineTo(W * 0.3, 0);
  g.stroke();
  g.fillStyle = col;
  g.beginPath();
  g.moveTo(W * 0.36, 0);
  g.lineTo(W * 0.18, -W * 0.12);
  g.lineTo(W * 0.18, W * 0.12);
  g.closePath();
  g.fill();
  g.strokeStyle = col;
  g.lineWidth = W * 0.04;
  g.beginPath();
  g.moveTo(-W * 0.32, 0);
  g.lineTo(-W * 0.24, -W * 0.1);
  g.moveTo(-W * 0.32, 0);
  g.lineTo(-W * 0.24, W * 0.1);
  g.stroke();
  g.restore();
});
function jobs() {
  return [{
    path: 'fx/spell_fireball.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: fireball
  }, {
    path: 'fx/spell_firebomb.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: firebomb
  }, {
    path: 'fx/spell_ice_lance.png',
    w: 64,
    h: 16,
    ss: 4,
    draw: iceLance
  }, {
    path: 'fx/spell_arcane_bolt.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: arcaneBolt
  }, {
    path: 'fx/spell_magic_orb.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: magicOrb
  }, {
    path: 'fx/spell_magic_sparks.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: magicSparks
  }, {
    path: 'fx/spell_water_bolt.png',
    w: 96,
    h: 16,
    ss: 4,
    draw: waterBolt
  }, {
    path: 'fx/spell_rock_sling.png',
    w: 16,
    h: 16,
    ss: 4,
    draw: rockSling
  }, {
    path: 'fx/spell_splash.png',
    w: 192,
    h: 32,
    ss: 4,
    draw: splash
  }, {
    path: 'fx/explosion-cuzco.png',
    w: 256,
    h: 256,
    ss: 3,
    draw: explosion
  }, {
    path: 'fx/spell_arrows.png',
    w: 352,
    h: 448,
    ss: 3,
    draw: arrows
  }];
}
module.exports = {
  jobs
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/fx.js", error: String((e && e.message) || e) }); }

// tools/assetgen/icons.js
try { (() => {
/** Loot icons — faceted gems, carved-stone runes, crafting materials (64×64). */
const C = require('./core');
const GEMS = {
  ruby: {
    dark: '#5e0a1c',
    mid: '#c41f3e',
    light: '#ff8a9c',
    glow: '#ff3b5c'
  },
  sapphire: {
    dark: '#12245e',
    mid: '#2f5bc0',
    light: '#9fbcff',
    glow: '#3b6fd2'
  },
  emerald: {
    dark: '#0a4a2c',
    mid: '#1f9e63',
    light: '#9fecc4',
    glow: '#2fd07a'
  },
  topaz: {
    dark: '#7a3e08',
    mid: '#e08a1e',
    light: '#ffd488',
    glow: '#ffb03a'
  },
  amethyst: {
    dark: '#3d1a6e',
    mid: '#8a44d6',
    light: '#d6abff',
    glow: '#9b5cff'
  },
  jade: {
    dark: '#155244',
    mid: '#3f9e7e',
    light: '#a8ead0',
    glow: '#5fd0a0'
  },
  diamond: {
    dark: '#7f9fc6',
    mid: '#cdddf2',
    light: '#ffffff',
    glow: '#bcd4ff'
  },
  onyx: {
    dark: '#0a0b10',
    mid: '#262932',
    light: '#5a5f70',
    glow: '#3a3e4a'
  }
};
const SEED = {
  ruby: 11,
  sapphire: 22,
  emerald: 33,
  topaz: 44,
  amethyst: 55,
  jade: 66,
  diamond: 77,
  onyx: 88,
  opal: 99
};
function drawGem(g, cx, cy, R, pal, seed, opal) {
  const rng = C.mulberry32(seed);
  C.glow(g, cx, cy, R * 1.7, pal.glow, 0.5);
  const N = 8,
    rt = R * 0.42,
    base = -Math.PI / 2,
    Pn = [],
    T = [];
  for (let i = 0; i < N; i++) {
    const a = base + i * 2 * Math.PI / N;
    Pn.push([cx + Math.cos(a) * R, cy + Math.sin(a) * R * 0.96]);
  }
  for (let i = 0; i < N; i++) {
    const a = base + Math.PI / N + i * 2 * Math.PI / N;
    T.push([cx + Math.cos(a) * rt, cy + Math.sin(a) * rt * 0.96]);
  }
  const L = [-0.5, -0.84];
  const ll = Math.hypot(L[0], L[1]);
  L[0] /= ll;
  L[1] /= ll;
  const pastel = ['#ff9ec7', '#9ec7ff', '#9effc7', '#fff0a0', '#c79eff', '#9efff0'];
  function shade(pts, flat) {
    let mx = 0,
      my = 0;
    for (const p of pts) {
      mx += p[0];
      my += p[1];
    }
    mx /= pts.length;
    my /= pts.length;
    let nx = mx - cx,
      ny = my - cy;
    const nl = Math.hypot(nx, ny) || 1;
    nx /= nl;
    ny /= nl;
    let b = flat ? 0.82 : 0.5 + 0.5 * (nx * L[0] + ny * L[1]);
    b += (rng() - 0.5) * 0.12;
    b = Math.max(0.05, Math.min(1, b));
    C.poly(g, pts);
    if (opal) {
      const col = pastel[Math.floor(rng() * pastel.length)];
      g.fillStyle = C.mix(C.mix('#e9eef7', col, 0.55), '#ffffff', b * 0.4);
    } else g.fillStyle = C.mix3(pal.dark, pal.mid, pal.light, b);
    g.fill();
  }
  for (let i = 0; i < N; i++) shade([Pn[i], Pn[(i + 1) % N], T[i]], false);
  for (let i = 0; i < N; i++) shade([T[(i - 1 + N) % N], Pn[i], T[i]], false);
  shade(T, true);
  g.strokeStyle = 'rgba(255,255,255,0.25)';
  g.lineWidth = R * 0.03;
  C.poly(g, T);
  g.stroke();
  g.strokeStyle = opal ? 'rgba(40,44,60,0.8)' : C.mix(pal.dark, C.P.ink950, 0.55);
  g.lineWidth = R * 0.08;
  g.lineJoin = 'round';
  C.poly(g, Pn);
  g.stroke();
  const sx = cx - R * 0.32,
    sy = cy - R * 0.34;
  C.glow(g, sx, sy, R * 0.5, '#ffffff', 0.9);
  g.fillStyle = 'rgba(255,255,255,0.95)';
  g.beginPath();
  g.arc(sx, sy, R * 0.07, 0, 7);
  g.fill();
}

// Rune glyphs in normalized -1..1 space (y down).
const RUNES = {
  el: [[[0, -0.7], [0, 0.7]], [[0, -0.7], [0.5, -0.3]]],
  dol: [[[-0.4, -0.7], [-0.4, 0.7]], [[-0.4, -0.05], [0.45, -0.55]], [[-0.4, 0.05], [0.45, 0.7]]],
  nef: [[[-0.42, 0.7], [-0.42, -0.7], [0.42, 0.35], [0.42, -0.7]]],
  ort: [[[0, -0.7], [0, 0.7]], [[-0.45, -0.7], [0.45, -0.7]], [[-0.3, 0.35], [0.3, 0.6]]],
  ral: [[[-0.4, 0.7], [-0.4, -0.65], [0.32, -0.65], [0.32, 0.0], [-0.4, 0.0]], [[-0.05, 0.0], [0.42, 0.7]]],
  sol: [[[0.42, -0.5], [-0.3, -0.62], [-0.3, -0.02], [0.3, 0.02], [0.3, 0.62], [-0.42, 0.5]]],
  thul: [[[-0.42, -0.7], [0.42, -0.7]], [[0, -0.7], [0, 0.7]], [[-0.28, 0.62], [0.28, 0.62]]],
  tir: [[[0, -0.72], [0, 0.7]], [[-0.42, -0.38], [0, -0.72], [0.42, -0.38]]],
  vex: [[[-0.46, -0.7], [0, 0.72], [0.46, -0.7]], [[-0.26, -0.12], [0.26, -0.12]]],
  zod: [[[-0.42, -0.62], [0.42, -0.62], [-0.42, 0.62], [0.42, 0.62]]]
};
const HOT = new Set(['vex', 'zod']);
function drawRune(g, w, h, name) {
  const rng = C.mulberry32(name.length * 97 + name.charCodeAt(0));
  const m = w * 0.12,
    tile = {
      x: m,
      y: m,
      w: w - 2 * m,
      h: h - 2 * m,
      r: w * 0.14
    };
  const glowCol = HOT.has(name) ? '#ff7a1a' : '#ffb03a';
  const lineCol = HOT.has(name) ? '#ffc070' : '#ffd488';
  C.rr(g, tile.x, tile.y, tile.w, tile.h, tile.r);
  g.fillStyle = C.lg(g, 0, tile.y, 0, tile.y + tile.h, '#2a2d36', '#1b1d24', '#0e0f13');
  g.fill();
  g.save();
  C.rr(g, tile.x, tile.y, tile.w, tile.h, tile.r);
  g.clip();
  g.strokeStyle = 'rgba(120,128,148,0.5)';
  g.lineWidth = w * 0.04;
  g.beginPath();
  g.moveTo(tile.x, tile.y + tile.h);
  g.lineTo(tile.x, tile.y);
  g.lineTo(tile.x + tile.w, tile.y);
  g.stroke();
  g.strokeStyle = 'rgba(0,0,0,0.6)';
  g.beginPath();
  g.moveTo(tile.x + tile.w, tile.y);
  g.lineTo(tile.x + tile.w, tile.y + tile.h);
  g.lineTo(tile.x, tile.y + tile.h);
  g.stroke();
  g.restore();
  C.rr(g, tile.x, tile.y, tile.w, tile.h, tile.r);
  g.strokeStyle = 'rgba(201,162,75,0.55)';
  g.lineWidth = w * 0.022;
  g.stroke();
  const cx = w / 2,
    cy = h / 2,
    S = Math.min(tile.w, tile.h) * 0.42,
    glyph = RUNES[name];
  function drawGlyph(stroke, lw, blur) {
    g.strokeStyle = stroke;
    g.lineWidth = lw;
    g.lineCap = 'round';
    g.lineJoin = 'round';
    g.shadowColor = blur ? glowCol : 'transparent';
    g.shadowBlur = blur || 0;
    for (const pl of glyph) {
      g.beginPath();
      pl.forEach((p, i) => {
        const X = cx + p[0] * S,
          Y = cy + p[1] * S;
        i ? g.lineTo(X, Y) : g.moveTo(X, Y);
      });
      g.stroke();
    }
    g.shadowBlur = 0;
  }
  g.save();
  g.translate(w * 0.012, h * 0.012);
  drawGlyph('rgba(0,0,0,0.7)', S * 0.22, 0);
  g.restore();
  drawGlyph(lineCol, S * 0.17, S * 0.9);
  drawGlyph('#fff4d8', S * 0.07, 0);
}
function drawEmberOre(g, w, h) {
  const cx = w / 2,
    cy = h * 0.56,
    R = Math.min(w, h) * 0.4,
    rng = C.mulberry32(5);
  C.glow(g, cx, cy, R * 1.5, '#ff7a1a', 0.4);
  const pts = [];
  for (let i = 0; i < 9; i++) {
    const a = i / 9 * 2 * Math.PI,
      rr = R * (0.78 + rng() * 0.4);
    pts.push([cx + Math.cos(a) * rr, cy + Math.sin(a) * rr * 0.92]);
  }
  C.poly(g, pts);
  g.fillStyle = C.lg(g, cx, cy - R, cx, cy + R, '#3a3e4a', '#16171d');
  g.fill();
  g.strokeStyle = C.P.ink950;
  g.lineWidth = R * 0.07;
  g.lineJoin = 'round';
  g.stroke();
  g.strokeStyle = '#ff8a3a';
  g.lineWidth = R * 0.08;
  g.lineCap = 'round';
  g.shadowColor = '#ff7a1a';
  g.shadowBlur = R * 0.4;
  for (let i = 0; i < 4; i++) {
    g.beginPath();
    let x = cx + (rng() - 0.5) * R,
      y = cy - R * 0.4;
    g.moveTo(x, y);
    for (let s = 0; s < 3; s++) {
      x += (rng() - 0.5) * R * 0.6;
      y += R * 0.3;
      g.lineTo(x, y);
    }
    g.stroke();
  }
  g.shadowBlur = 0;
  g.fillStyle = '#ffd488';
  for (let i = 0; i < 5; i++) {
    g.beginPath();
    g.arc(cx + (rng() - 0.5) * R * 1.2, cy + (rng() - 0.5) * R, R * 0.06, 0, 7);
    g.fill();
  }
}
function drawFrostCore(g, w, h) {
  const cx = w / 2,
    cy = h * 0.56,
    R = Math.min(w, h) * 0.38;
  C.glow(g, cx, cy, R * 1.6, '#7fc4ff', 0.5);
  const shards = [[0, -1.3, 0.42], [-0.7, -0.7, 0.3], [0.7, -0.8, 0.34], [-0.3, -0.5, 0.26], [0.35, -0.4, 0.26]];
  for (const [ox, oy, wd] of shards) {
    const tx = cx + ox * R,
      ty = cy + oy * R,
      bw = R * wd,
      bx = cx + ox * R * 0.4;
    C.poly(g, [[tx, ty], [bx - bw * 0.5, cy], [bx, cy + R * 0.15], [bx + bw * 0.5, cy]]);
    g.fillStyle = C.lg(g, tx, ty, bx, cy, '#eaf6ff', '#7fc4ff', '#1e4f8a');
    g.fill();
    g.strokeStyle = 'rgba(10,30,60,0.6)';
    g.lineWidth = R * 0.04;
    g.stroke();
  }
  C.glow(g, cx, cy, R * 0.4, '#ffffff', 0.8);
}
function drawRuneShard(g, w, h) {
  const cx = w / 2,
    cy = h * 0.55,
    R = Math.min(w, h) * 0.4;
  C.glow(g, cx, cy, R * 1.4, '#ffb03a', 0.4);
  C.poly(g, [[cx - R * 0.5, cy - R * 0.9], [cx + R * 0.55, cy - R * 0.7], [cx + R * 0.35, cy + R * 0.95], [cx - R * 0.45, cy + R * 0.8]]);
  g.fillStyle = C.lg(g, cx, cy - R, cx, cy + R, '#4d5260', '#1b1d24');
  g.fill();
  g.strokeStyle = C.P.ink950;
  g.lineWidth = R * 0.07;
  g.lineJoin = 'round';
  g.stroke();
  g.strokeStyle = '#ffd488';
  g.lineWidth = R * 0.1;
  g.lineCap = 'round';
  g.lineJoin = 'round';
  g.shadowColor = '#ffb03a';
  g.shadowBlur = R * 0.5;
  g.beginPath();
  g.moveTo(cx - R * 0.12, cy - R * 0.45);
  g.lineTo(cx - R * 0.12, cy + R * 0.45);
  g.lineTo(cx + R * 0.25, cy + R * 0.1);
  g.moveTo(cx - R * 0.12, cy - R * 0.1);
  g.lineTo(cx + R * 0.2, cy - R * 0.4);
  g.stroke();
  g.shadowBlur = 0;
}
function jobs() {
  const out = [];
  for (const name of ['amethyst', 'diamond', 'emerald', 'jade', 'onyx', 'opal', 'ruby', 'sapphire', 'topaz']) out.push({
    path: `icons/gem-${name}.png`,
    w: 64,
    h: 64,
    ss: 3,
    grain: 10,
    draw: (g, w, h) => drawGem(g, w / 2, h * 0.5, Math.min(w, h) * 0.4, GEMS[name] || GEMS.diamond, SEED[name] || 7, name === 'opal')
  });
  for (const name of Object.keys(RUNES)) out.push({
    path: `icons/rune-${name}.png`,
    w: 64,
    h: 64,
    ss: 3,
    grain: 9,
    draw: (g, w, h) => drawRune(g, w, h, name)
  });
  out.push({
    path: 'icons/material-ember-ore.png',
    w: 64,
    h: 64,
    ss: 3,
    grain: 12,
    draw: drawEmberOre
  });
  out.push({
    path: 'icons/material-frost-core.png',
    w: 64,
    h: 64,
    ss: 3,
    grain: 9,
    draw: drawFrostCore
  });
  out.push({
    path: 'icons/material-rune-shard.png',
    w: 64,
    h: 64,
    ss: 3,
    grain: 11,
    draw: drawRuneShard
  });
  return out;
}
module.exports = {
  jobs,
  drawGem,
  drawRune,
  GEMS,
  RUNES
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/icons.js", error: String((e && e.message) || e) }); }

// tools/assetgen/mobs.js
try { (() => {
/** Mob + hero roster — original top-down sprites, 64×64, foot-anchored. */
const C = require('./core');
const {
  limb,
  eyes,
  glow,
  shadow,
  lg,
  poly,
  mulberry32
} = C;
const MOBS = {
  hero: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    g.fillStyle = '#7a1e2e';
    g.beginPath();
    g.moveTo(cx - w * 0.16, h * 0.35);
    g.quadraticCurveTo(cx - w * 0.28, h * 0.7, cx - w * 0.18, h * 0.82);
    g.lineTo(cx + w * 0.18, h * 0.82);
    g.quadraticCurveTo(cx + w * 0.28, h * 0.7, cx + w * 0.16, h * 0.35);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.07, h * 0.62, cx - w * 0.08, h * 0.88, w * 0.09, '#3a3e4a');
    limb(g, cx + w * 0.07, h * 0.62, cx + w * 0.08, h * 0.88, w * 0.09, '#3a3e4a');
    g.fillStyle = '#2a2d36';
    g.beginPath();
    g.ellipse(cx - w * 0.08, h * 0.88, w * 0.07, h * 0.04, 0, 0, 7);
    g.ellipse(cx + w * 0.08, h * 0.88, w * 0.07, h * 0.04, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.32, cx, h * 0.64, '#8a93a4', '#4d5260');
    g.beginPath();
    g.moveTo(cx - w * 0.15, h * 0.36);
    g.lineTo(cx + w * 0.15, h * 0.36);
    g.lineTo(cx + w * 0.12, h * 0.64);
    g.lineTo(cx - w * 0.12, h * 0.64);
    g.closePath();
    g.fill();
    g.strokeStyle = '#c9a24b';
    g.lineWidth = w * 0.015;
    g.stroke();
    limb(g, cx - w * 0.13, h * 0.4, cx - w * 0.2, h * 0.6, w * 0.06, '#5a6170');
    limb(g, cx + w * 0.13, h * 0.4, cx + w * 0.22, h * 0.55, w * 0.06, '#5a6170');
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.04;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(cx + w * 0.22, h * 0.55);
    g.lineTo(cx + w * 0.32, h * 0.12);
    g.stroke();
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.06;
    g.beginPath();
    g.moveTo(cx + w * 0.16, h * 0.55);
    g.lineTo(cx + w * 0.28, h * 0.55);
    g.stroke();
    g.fillStyle = '#c79a6a';
    g.beginPath();
    g.arc(cx, h * 0.27, w * 0.1, 0, 7);
    g.fill();
    g.fillStyle = '#5a6170';
    g.beginPath();
    g.arc(cx, h * 0.24, w * 0.11, Math.PI, 0);
    g.fill();
    g.fillRect(cx - w * 0.11, h * 0.22, w * 0.22, h * 0.04);
    g.fillStyle = '#1b1d24';
    g.fillRect(cx - w * 0.07, h * 0.26, w * 0.14, h * 0.025);
  },
  hero_back: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    limb(g, cx - w * 0.07, h * 0.62, cx - w * 0.08, h * 0.88, w * 0.09, '#3a3e4a');
    limb(g, cx + w * 0.07, h * 0.62, cx + w * 0.08, h * 0.88, w * 0.09, '#3a3e4a');
    g.fillStyle = '#2a2d36';
    g.beginPath();
    g.ellipse(cx - w * 0.08, h * 0.88, w * 0.07, h * 0.04, 0, 0, 7);
    g.ellipse(cx + w * 0.08, h * 0.88, w * 0.07, h * 0.04, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.3, cx, h * 0.82, '#9a2838', '#5e1622');
    g.beginPath();
    g.moveTo(cx - w * 0.18, h * 0.34);
    g.quadraticCurveTo(cx - w * 0.24, h * 0.74, cx - w * 0.16, h * 0.82);
    g.lineTo(cx + w * 0.16, h * 0.82);
    g.quadraticCurveTo(cx + w * 0.24, h * 0.74, cx + w * 0.18, h * 0.34);
    g.quadraticCurveTo(cx, h * 0.28, cx - w * 0.18, h * 0.34);
    g.closePath();
    g.fill();
    g.strokeStyle = 'rgba(0,0,0,0.3)';
    g.lineWidth = w * 0.012;
    g.beginPath();
    g.moveTo(cx, h * 0.3);
    g.lineTo(cx, h * 0.8);
    g.stroke();
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.04;
    g.beginPath();
    g.moveTo(cx - w * 0.1, h * 0.3);
    g.lineTo(cx - w * 0.16, h * 0.12);
    g.stroke();
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.05;
    g.beginPath();
    g.moveTo(cx - w * 0.16, h * 0.3);
    g.lineTo(cx - w * 0.04, h * 0.28);
    g.stroke();
    g.fillStyle = '#5a6170';
    g.beginPath();
    g.arc(cx, h * 0.26, w * 0.11, 0, 7);
    g.fill();
    g.fillStyle = '#3a3e4a';
    g.beginPath();
    g.arc(cx, h * 0.28, w * 0.1, 0, Math.PI);
    g.fill();
  },
  hero_side: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    g.fillStyle = lg(g, cx, h * 0.34, cx, h * 0.82, '#7a1e2e', '#4e1018');
    g.beginPath();
    g.moveTo(cx - w * 0.02, h * 0.34);
    g.quadraticCurveTo(cx - w * 0.28, h * 0.6, cx - w * 0.2, h * 0.84);
    g.lineTo(cx - w * 0.02, h * 0.7);
    g.closePath();
    g.fill();
    limb(g, cx, h * 0.62, cx - w * 0.06, h * 0.88, w * 0.09, '#3a3e4a');
    limb(g, cx + w * 0.02, h * 0.62, cx + w * 0.1, h * 0.88, w * 0.09, '#4d5260');
    g.fillStyle = '#2a2d36';
    g.beginPath();
    g.ellipse(cx - w * 0.06, h * 0.88, w * 0.08, h * 0.04, 0, 0, 7);
    g.ellipse(cx + w * 0.12, h * 0.88, w * 0.08, h * 0.04, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.34, cx, h * 0.64, '#8a93a4', '#4d5260');
    g.beginPath();
    g.moveTo(cx - w * 0.1, h * 0.36);
    g.lineTo(cx + w * 0.12, h * 0.36);
    g.lineTo(cx + w * 0.1, h * 0.64);
    g.lineTo(cx - w * 0.08, h * 0.64);
    g.closePath();
    g.fill();
    limb(g, cx + w * 0.06, h * 0.42, cx + w * 0.2, h * 0.5, w * 0.06, '#5a6170');
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.04;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.5);
    g.lineTo(cx + w * 0.42, h * 0.4);
    g.stroke();
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.05;
    g.beginPath();
    g.moveTo(cx + w * 0.14, h * 0.46);
    g.lineTo(cx + w * 0.24, h * 0.54);
    g.stroke();
    g.fillStyle = '#c79a6a';
    g.beginPath();
    g.arc(cx + w * 0.04, h * 0.27, w * 0.1, 0, 7);
    g.fill();
    g.fillStyle = '#5a6170';
    g.beginPath();
    g.arc(cx + w * 0.04, h * 0.24, w * 0.11, Math.PI, 0.2);
    g.fill();
    g.fillStyle = '#1b1d24';
    g.fillRect(cx + w * 0.08, h * 0.26, w * 0.08, h * 0.025);
  },
  skeleton: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      B = '#dcd4bd',
      B2 = '#a39a82';
    limb(g, cx - w * 0.06, h * 0.6, cx - w * 0.08, h * 0.88, w * 0.055, B);
    limb(g, cx + w * 0.06, h * 0.6, cx + w * 0.08, h * 0.88, w * 0.055, B);
    g.strokeStyle = B;
    g.lineWidth = w * 0.07;
    g.beginPath();
    g.moveTo(cx, h * 0.38);
    g.lineTo(cx, h * 0.6);
    g.stroke();
    g.strokeStyle = B2;
    g.lineWidth = w * 0.025;
    for (let r = 0; r < 4; r++) {
      const yy = h * 0.42 + r * h * 0.045;
      g.beginPath();
      g.arc(cx, yy, w * 0.1, 0.4, Math.PI - 0.4);
      g.stroke();
    }
    limb(g, cx - w * 0.08, h * 0.4, cx - w * 0.2, h * 0.58, w * 0.045, B);
    limb(g, cx + w * 0.08, h * 0.4, cx + w * 0.22, h * 0.5, w * 0.045, B);
    g.strokeStyle = '#8a7a5a';
    g.lineWidth = w * 0.035;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(cx + w * 0.22, h * 0.5);
    g.lineTo(cx + w * 0.3, h * 0.16);
    g.stroke();
    g.fillStyle = B;
    g.beginPath();
    g.arc(cx - w * 0.1, h * 0.4, w * 0.04, 0, 7);
    g.arc(cx + w * 0.1, h * 0.4, w * 0.04, 0, 7);
    g.fill();
    g.beginPath();
    g.arc(cx, h * 0.28, w * 0.11, 0, 7);
    g.fill();
    g.fillRect(cx - w * 0.07, h * 0.32, w * 0.14, h * 0.06);
    eyes(g, cx, h * 0.28, w * 0.045, w * 0.025, '#1b1d24');
  },
  zombie: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      F = '#6e7a52',
      F2 = '#4a5436';
    limb(g, cx - w * 0.07, h * 0.62, cx - w * 0.1, h * 0.88, w * 0.08, F2);
    limb(g, cx + w * 0.07, h * 0.62, cx + w * 0.06, h * 0.88, w * 0.08, F2);
    g.fillStyle = lg(g, cx, h * 0.34, cx, h * 0.64, F, F2);
    g.beginPath();
    g.moveTo(cx - w * 0.14, h * 0.4);
    g.quadraticCurveTo(cx - w * 0.1, h * 0.34, cx + w * 0.12, h * 0.38);
    g.lineTo(cx + w * 0.1, h * 0.64);
    g.lineTo(cx - w * 0.12, h * 0.64);
    g.closePath();
    g.fill();
    g.fillStyle = '#3a3a32';
    g.fillRect(cx - w * 0.13, h * 0.5, w * 0.24, h * 0.1);
    limb(g, cx - w * 0.12, h * 0.42, cx - w * 0.24, h * 0.5, w * 0.06, F);
    limb(g, cx + w * 0.1, h * 0.42, cx + w * 0.24, h * 0.48, w * 0.06, F);
    g.fillStyle = F;
    g.beginPath();
    g.arc(cx + w * 0.03, h * 0.28, w * 0.1, 0, 7);
    g.fill();
    eyes(g, cx + w * 0.03, h * 0.27, w * 0.04, w * 0.018, '#aef07a');
  },
  ghoul: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      F = '#9aa37a',
      F2 = '#6a7050';
    limb(g, cx - w * 0.06, h * 0.64, cx - w * 0.1, h * 0.87, w * 0.07, F2);
    limb(g, cx + w * 0.06, h * 0.64, cx + w * 0.04, h * 0.87, w * 0.07, F2);
    g.fillStyle = lg(g, cx, h * 0.36, cx, h * 0.66, F, F2);
    g.beginPath();
    g.moveTo(cx - w * 0.12, h * 0.42);
    g.quadraticCurveTo(cx + w * 0.04, h * 0.34, cx + w * 0.13, h * 0.42);
    g.lineTo(cx + w * 0.09, h * 0.66);
    g.lineTo(cx - w * 0.1, h * 0.66);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.1, h * 0.44, cx - w * 0.26, h * 0.46, w * 0.05, F);
    limb(g, cx + w * 0.1, h * 0.44, cx + w * 0.26, h * 0.42, w * 0.05, F);
    g.fillStyle = F;
    g.beginPath();
    g.arc(cx + w * 0.04, h * 0.3, w * 0.1, 0, 7);
    g.fill();
    eyes(g, cx + w * 0.04, h * 0.29, w * 0.04, w * 0.018, '#ffd24a');
    g.fillStyle = '#1b1d24';
    g.beginPath();
    g.arc(cx + w * 0.04, h * 0.34, w * 0.04, 0.1, Math.PI - 0.1);
    g.fill();
    g.fillStyle = '#e8e4d8';
    for (let k = 0; k < 3; k++) g.fillRect(cx - w * 0.02 + k * w * 0.025, h * 0.34, w * 0.012, h * 0.02);
  },
  wraith: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    glow(g, cx, h * 0.5, w * 0.4, '#7d93c6', 0.3);
    g.fillStyle = 'rgba(40,45,60,0.5)';
    for (let k = 0; k < 4; k++) {
      g.beginPath();
      g.ellipse(cx + (k - 1.5) * w * 0.08, h * 0.85 - Math.abs(k - 1.5) * h * 0.04, w * 0.06, h * 0.05, 0, 0, 7);
      g.fill();
    }
    g.fillStyle = lg(g, cx, h * 0.25, cx, h * 0.85, '#2a2d36', '#14161c');
    g.beginPath();
    g.moveTo(cx - w * 0.16, h * 0.35);
    g.quadraticCurveTo(cx - w * 0.2, h * 0.7, cx - w * 0.08, h * 0.85);
    g.quadraticCurveTo(cx, h * 0.92, cx + w * 0.08, h * 0.85);
    g.quadraticCurveTo(cx + w * 0.2, h * 0.7, cx + w * 0.16, h * 0.35);
    g.quadraticCurveTo(cx, h * 0.2, cx - w * 0.16, h * 0.35);
    g.closePath();
    g.fill();
    g.fillStyle = '#08090d';
    g.beginPath();
    g.ellipse(cx, h * 0.34, w * 0.1, h * 0.1, 0, 0, 7);
    g.fill();
    eyes(g, cx, h * 0.34, w * 0.04, w * 0.022, '#7fc4ff');
    g.fillStyle = '#9aa3b2';
    g.beginPath();
    g.arc(cx - w * 0.22, h * 0.56, w * 0.03, 0, 7);
    g.fill();
  },
  banshee: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    glow(g, cx, h * 0.45, w * 0.45, '#bcd0ee', 0.35);
    g.fillStyle = lg(g, cx, h * 0.3, cx, h * 0.88, 'rgba(180,208,238,0.7)', 'rgba(60,90,140,0.1)');
    g.beginPath();
    g.moveTo(cx - w * 0.14, h * 0.36);
    g.quadraticCurveTo(cx - w * 0.24, h * 0.78, cx - w * 0.1, h * 0.88);
    g.quadraticCurveTo(cx, h * 0.82, cx + w * 0.1, h * 0.88);
    g.quadraticCurveTo(cx + w * 0.24, h * 0.78, cx + w * 0.14, h * 0.36);
    g.quadraticCurveTo(cx, h * 0.24, cx - w * 0.14, h * 0.36);
    g.closePath();
    g.fill();
    g.fillStyle = 'rgba(220,235,255,0.6)';
    g.beginPath();
    g.moveTo(cx - w * 0.12, h * 0.28);
    g.quadraticCurveTo(cx - w * 0.2, h * 0.5, cx - w * 0.12, h * 0.6);
    g.lineTo(cx + w * 0.12, h * 0.6);
    g.quadraticCurveTo(cx + w * 0.2, h * 0.5, cx + w * 0.12, h * 0.28);
    g.closePath();
    g.fill();
    g.fillStyle = 'rgba(230,240,255,0.85)';
    g.beginPath();
    g.arc(cx, h * 0.3, w * 0.09, 0, 7);
    g.fill();
    eyes(g, cx, h * 0.29, w * 0.035, w * 0.018, '#7fc4ff');
    g.fillStyle = '#3a5a8a';
    g.beginPath();
    g.ellipse(cx, h * 0.36, w * 0.025, h * 0.03, 0, 0, 7);
    g.fill();
  },
  reaper: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.48;
    glow(g, cx, h * 0.45, w * 0.4, '#6fbf5e', 0.2);
    g.fillStyle = lg(g, cx, h * 0.26, cx, h * 0.88, '#1b1d24', '#08090d');
    g.beginPath();
    g.moveTo(cx - w * 0.16, h * 0.38);
    g.quadraticCurveTo(cx - w * 0.22, h * 0.82, cx - w * 0.12, h * 0.88);
    g.quadraticCurveTo(cx, h * 0.82, cx + w * 0.12, h * 0.88);
    g.quadraticCurveTo(cx + w * 0.22, h * 0.82, cx + w * 0.16, h * 0.38);
    g.quadraticCurveTo(cx, h * 0.22, cx - w * 0.16, h * 0.38);
    g.closePath();
    g.fill();
    g.fillStyle = '#000';
    g.beginPath();
    g.ellipse(cx, h * 0.34, w * 0.09, h * 0.1, 0, 0, 7);
    g.fill();
    eyes(g, cx, h * 0.34, w * 0.035, w * 0.02, '#aef07a');
    g.strokeStyle = '#2a2620';
    g.lineWidth = w * 0.03;
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.9);
    g.lineTo(cx + w * 0.28, h * 0.1);
    g.stroke();
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.04;
    g.beginPath();
    g.moveTo(cx + w * 0.28, h * 0.12);
    g.quadraticCurveTo(cx + w * 0.05, h * 0.08, cx, h * 0.24);
    g.stroke();
  },
  lich: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    glow(g, cx, h * 0.5, w * 0.4, '#7fc4ff', 0.22);
    g.fillStyle = lg(g, cx, h * 0.28, cx, h * 0.88, '#2a2038', '#140e1c');
    g.beginPath();
    g.moveTo(cx - w * 0.16, h * 0.4);
    g.quadraticCurveTo(cx - w * 0.22, h * 0.82, cx - w * 0.16, h * 0.88);
    g.lineTo(cx + w * 0.16, h * 0.88);
    g.quadraticCurveTo(cx + w * 0.22, h * 0.82, cx + w * 0.16, h * 0.4);
    g.quadraticCurveTo(cx, h * 0.26, cx - w * 0.16, h * 0.4);
    g.closePath();
    g.fill();
    g.strokeStyle = '#3b6fd2';
    g.lineWidth = w * 0.012;
    g.beginPath();
    g.moveTo(cx, h * 0.42);
    g.lineTo(cx, h * 0.86);
    g.stroke();
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.arc(cx, h * 0.28, w * 0.1, 0, 7);
    g.fill();
    g.fillRect(cx - w * 0.06, h * 0.32, w * 0.12, h * 0.05);
    eyes(g, cx, h * 0.28, w * 0.04, w * 0.022, '#7fc4ff');
    g.fillStyle = '#c9a24b';
    g.beginPath();
    g.moveTo(cx - w * 0.1, h * 0.2);
    g.lineTo(cx - w * 0.1, h * 0.14);
    g.lineTo(cx - w * 0.05, h * 0.18);
    g.lineTo(cx, h * 0.12);
    g.lineTo(cx + w * 0.05, h * 0.18);
    g.lineTo(cx + w * 0.1, h * 0.14);
    g.lineTo(cx + w * 0.1, h * 0.2);
    g.closePath();
    g.fill();
    g.strokeStyle = '#3a2d20';
    g.lineWidth = w * 0.03;
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.9);
    g.lineTo(cx + w * 0.24, h * 0.2);
    g.stroke();
    glow(g, cx + w * 0.25, h * 0.16, w * 0.1, '#aef07a', 0.8);
    g.fillStyle = '#aef07a';
    g.beginPath();
    g.arc(cx + w * 0.25, h * 0.16, w * 0.04, 0, 7);
    g.fill();
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.arc(cx + w * 0.22, h * 0.5, w * 0.03, 0, 7);
    g.fill();
  },
  cultist: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    g.fillStyle = lg(g, cx, h * 0.28, cx, h * 0.88, '#4a3a5e', '#2a2038');
    g.beginPath();
    g.moveTo(cx - w * 0.15, h * 0.4);
    g.quadraticCurveTo(cx - w * 0.2, h * 0.8, cx - w * 0.16, h * 0.88);
    g.lineTo(cx + w * 0.16, h * 0.88);
    g.quadraticCurveTo(cx + w * 0.2, h * 0.8, cx + w * 0.15, h * 0.4);
    g.quadraticCurveTo(cx, h * 0.26, cx - w * 0.15, h * 0.4);
    g.closePath();
    g.fill();
    g.fillStyle = '#3a2d4a';
    g.beginPath();
    g.moveTo(cx - w * 0.13, h * 0.4);
    g.quadraticCurveTo(cx, h * 0.16, cx + w * 0.13, h * 0.4);
    g.closePath();
    g.fill();
    g.fillStyle = '#0a0810';
    g.beginPath();
    g.ellipse(cx, h * 0.34, w * 0.08, h * 0.09, 0, 0, 7);
    g.fill();
    eyes(g, cx, h * 0.35, w * 0.035, w * 0.018, '#ff2d6f');
    g.fillStyle = '#3a2d4a';
    g.beginPath();
    g.moveTo(cx + w * 0.1, h * 0.42);
    g.lineTo(cx + w * 0.22, h * 0.5);
    g.lineTo(cx + w * 0.18, h * 0.56);
    g.lineTo(cx + w * 0.06, h * 0.48);
    g.closePath();
    g.fill();
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.025;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.52);
    g.lineTo(cx + w * 0.28, h * 0.4);
    g.stroke();
  },
  demon: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      R = '#8a2020',
      R2 = '#c4402e';
    glow(g, cx, h * 0.5, w * 0.35, '#ff2d2d', 0.18);
    limb(g, cx - w * 0.1, h * 0.6, cx - w * 0.12, h * 0.86, w * 0.1, R2);
    limb(g, cx + w * 0.1, h * 0.6, cx + w * 0.12, h * 0.86, w * 0.1, R2);
    g.fillStyle = '#1b1d24';
    g.beginPath();
    g.ellipse(cx - w * 0.12, h * 0.88, w * 0.06, h * 0.03, 0, 0, 7);
    g.ellipse(cx + w * 0.12, h * 0.88, w * 0.06, h * 0.03, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.3, cx, h * 0.64, R2, R);
    g.beginPath();
    g.moveTo(cx - w * 0.22, h * 0.34);
    g.lineTo(cx + w * 0.22, h * 0.34);
    g.lineTo(cx + w * 0.16, h * 0.64);
    g.lineTo(cx - w * 0.16, h * 0.64);
    g.closePath();
    g.fill();
    g.strokeStyle = 'rgba(0,0,0,0.3)';
    g.lineWidth = w * 0.01;
    g.beginPath();
    g.moveTo(cx, h * 0.4);
    g.lineTo(cx, h * 0.6);
    g.stroke();
    limb(g, cx - w * 0.2, h * 0.36, cx - w * 0.28, h * 0.6, w * 0.08, R2);
    limb(g, cx + w * 0.2, h * 0.36, cx + w * 0.28, h * 0.6, w * 0.08, R2);
    g.strokeStyle = '#1b1d24';
    g.lineWidth = w * 0.02;
    for (const s of [-1, 1]) for (let c = 0; c < 3; c++) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.28, h * 0.62);
      g.lineTo(cx + s * w * 0.28 + (c - 1) * w * 0.03, h * 0.68);
      g.stroke();
    }
    g.fillStyle = R2;
    g.beginPath();
    g.arc(cx, h * 0.26, w * 0.12, 0, 7);
    g.fill();
    g.fillStyle = '#2a1810';
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.08, h * 0.18);
      g.quadraticCurveTo(cx + s * w * 0.2, h * 0.1, cx + s * w * 0.16, 0);
      g.lineTo(cx + s * w * 0.1, h * 0.14);
      g.closePath();
      g.fill();
    }
    eyes(g, cx, h * 0.25, w * 0.045, w * 0.022, '#ffb03a');
    g.strokeStyle = '#1b1d24';
    g.lineWidth = 1.5;
    g.beginPath();
    g.moveTo(cx - w * 0.05, h * 0.32);
    g.lineTo(cx + w * 0.05, h * 0.32);
    g.stroke();
  },
  imp: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      R = '#b03020',
      R2 = '#7a1c14';
    glow(g, cx, h * 0.5, w * 0.3, '#ff3b2d', 0.18);
    limb(g, cx - w * 0.05, h * 0.66, cx - w * 0.08, h * 0.85, w * 0.05, R2);
    limb(g, cx + w * 0.05, h * 0.66, cx + w * 0.08, h * 0.85, w * 0.05, R2);
    g.fillStyle = lg(g, cx, h * 0.46, cx, h * 0.68, R, R2);
    g.beginPath();
    g.ellipse(cx, h * 0.56, w * 0.11, h * 0.11, 0, 0, 7);
    g.fill();
    g.fillStyle = R2;
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.08, h * 0.46);
      g.quadraticCurveTo(cx + s * w * 0.28, h * 0.36, cx + s * w * 0.3, h * 0.5);
      g.lineTo(cx + s * w * 0.1, h * 0.54);
      g.closePath();
      g.fill();
    }
    limb(g, cx - w * 0.09, h * 0.5, cx - w * 0.16, h * 0.6, w * 0.04, R);
    limb(g, cx + w * 0.09, h * 0.5, cx + w * 0.16, h * 0.6, w * 0.04, R);
    g.strokeStyle = R2;
    g.lineWidth = w * 0.025;
    g.beginPath();
    g.moveTo(cx, h * 0.66);
    g.quadraticCurveTo(cx + w * 0.16, h * 0.74, cx + w * 0.1, h * 0.6);
    g.stroke();
    g.fillStyle = R;
    g.beginPath();
    g.arc(cx, h * 0.4, w * 0.1, 0, 7);
    g.fill();
    g.fillStyle = R2;
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.06, h * 0.33);
      g.lineTo(cx + s * w * 0.12, h * 0.24);
      g.lineTo(cx + s * w * 0.02, h * 0.32);
      g.closePath();
      g.fill();
    }
    eyes(g, cx, h * 0.4, w * 0.04, w * 0.018, '#ffd24a');
  },
  orc: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#5a7a3a',
      S2 = '#3a5424';
    limb(g, cx - w * 0.09, h * 0.62, cx - w * 0.11, h * 0.87, w * 0.1, S2);
    limb(g, cx + w * 0.09, h * 0.62, cx + w * 0.11, h * 0.87, w * 0.1, S2);
    g.fillStyle = '#3a2d20';
    g.beginPath();
    g.ellipse(cx - w * 0.11, h * 0.88, w * 0.07, h * 0.03, 0, 0, 7);
    g.ellipse(cx + w * 0.11, h * 0.88, w * 0.07, h * 0.03, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.32, cx, h * 0.64, S, S2);
    g.beginPath();
    g.moveTo(cx - w * 0.2, h * 0.36);
    g.lineTo(cx + w * 0.2, h * 0.36);
    g.lineTo(cx + w * 0.15, h * 0.64);
    g.lineTo(cx - w * 0.15, h * 0.64);
    g.closePath();
    g.fill();
    g.fillStyle = '#5a4028';
    g.fillRect(cx - w * 0.18, h * 0.42, w * 0.36, h * 0.08);
    limb(g, cx - w * 0.18, h * 0.38, cx - w * 0.26, h * 0.58, w * 0.075, S);
    limb(g, cx + w * 0.18, h * 0.38, cx + w * 0.24, h * 0.5, w * 0.075, S);
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.035;
    g.beginPath();
    g.moveTo(cx + w * 0.24, h * 0.52);
    g.lineTo(cx + w * 0.32, h * 0.12);
    g.stroke();
    g.fillStyle = '#9aa3b2';
    g.beginPath();
    g.moveTo(cx + w * 0.3, h * 0.16);
    g.quadraticCurveTo(cx + w * 0.44, h * 0.2, cx + w * 0.32, h * 0.3);
    g.closePath();
    g.fill();
    g.fillStyle = S;
    g.beginPath();
    g.arc(cx, h * 0.27, w * 0.12, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    g.beginPath();
    g.moveTo(cx - w * 0.05, h * 0.32);
    g.lineTo(cx - w * 0.04, h * 0.37);
    g.lineTo(cx - w * 0.02, h * 0.32);
    g.moveTo(cx + w * 0.05, h * 0.32);
    g.lineTo(cx + w * 0.04, h * 0.37);
    g.lineTo(cx + w * 0.02, h * 0.32);
    g.fill();
    eyes(g, cx, h * 0.25, w * 0.045, w * 0.02, '#ffd24a');
  },
  goblin: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#6a9e4a',
      S2 = '#4a7030';
    limb(g, cx - w * 0.06, h * 0.68, cx - w * 0.08, h * 0.86, w * 0.07, S2);
    limb(g, cx + w * 0.06, h * 0.68, cx + w * 0.08, h * 0.86, w * 0.07, S2);
    g.fillStyle = lg(g, cx, h * 0.45, cx, h * 0.7, S, S2);
    g.beginPath();
    g.ellipse(cx, h * 0.58, w * 0.12, h * 0.12, 0, 0, 7);
    g.fill();
    g.fillStyle = '#5a4028';
    g.fillRect(cx - w * 0.1, h * 0.58, w * 0.2, h * 0.08);
    limb(g, cx - w * 0.1, h * 0.5, cx - w * 0.18, h * 0.62, w * 0.05, S);
    limb(g, cx + w * 0.1, h * 0.5, cx + w * 0.2, h * 0.55, w * 0.05, S);
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = w * 0.025;
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.55);
    g.lineTo(cx + w * 0.26, h * 0.42);
    g.stroke();
    g.fillStyle = S;
    g.beginPath();
    g.arc(cx, h * 0.4, w * 0.11, 0, 7);
    g.fill();
    g.fillStyle = S2;
    g.beginPath();
    g.moveTo(cx - w * 0.09, h * 0.38);
    g.lineTo(cx - w * 0.22, h * 0.32);
    g.lineTo(cx - w * 0.09, h * 0.44);
    g.closePath();
    g.moveTo(cx + w * 0.09, h * 0.38);
    g.lineTo(cx + w * 0.22, h * 0.32);
    g.lineTo(cx + w * 0.09, h * 0.44);
    g.closePath();
    g.fill();
    eyes(g, cx, h * 0.39, w * 0.04, w * 0.018, '#ffd24a');
    g.fillStyle = '#1b1d24';
    g.beginPath();
    g.arc(cx, h * 0.44, w * 0.04, 0.1, Math.PI - 0.1);
    g.fill();
  },
  troll: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#6a7a5a',
      S2 = '#46523a';
    limb(g, cx - w * 0.1, h * 0.62, cx - w * 0.13, h * 0.86, w * 0.12, S2);
    limb(g, cx + w * 0.1, h * 0.62, cx + w * 0.13, h * 0.86, w * 0.12, S2);
    g.fillStyle = lg(g, cx, h * 0.28, cx, h * 0.64, S, S2);
    g.beginPath();
    g.moveTo(cx - w * 0.24, h * 0.36);
    g.quadraticCurveTo(cx, h * 0.26, cx + w * 0.24, h * 0.36);
    g.lineTo(cx + w * 0.18, h * 0.64);
    g.lineTo(cx - w * 0.18, h * 0.64);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.22, h * 0.36, cx - w * 0.3, h * 0.72, w * 0.09, S);
    limb(g, cx + w * 0.22, h * 0.36, cx + w * 0.3, h * 0.72, w * 0.09, S);
    g.fillStyle = S2;
    g.beginPath();
    g.arc(cx - w * 0.3, h * 0.74, w * 0.06, 0, 7);
    g.arc(cx + w * 0.3, h * 0.74, w * 0.06, 0, 7);
    g.fill();
    g.fillStyle = S;
    g.beginPath();
    g.arc(cx, h * 0.3, w * 0.1, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    g.beginPath();
    g.moveTo(cx - w * 0.04, h * 0.34);
    g.lineTo(cx - w * 0.03, h * 0.39);
    g.lineTo(cx - w * 0.01, h * 0.34);
    g.fill();
    eyes(g, cx, h * 0.29, w * 0.04, w * 0.018, '#ff7a1a');
  },
  minotaur: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      B = '#6a4a30',
      B2 = '#46301c';
    limb(g, cx - w * 0.1, h * 0.62, cx - w * 0.12, h * 0.86, w * 0.11, B2);
    limb(g, cx + w * 0.1, h * 0.62, cx + w * 0.12, h * 0.86, w * 0.11, B2);
    g.fillStyle = '#2a1d12';
    g.beginPath();
    g.ellipse(cx - w * 0.12, h * 0.88, w * 0.06, h * 0.03, 0, 0, 7);
    g.ellipse(cx + w * 0.12, h * 0.88, w * 0.06, h * 0.03, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.3, cx, h * 0.64, B, B2);
    g.beginPath();
    g.moveTo(cx - w * 0.23, h * 0.36);
    g.lineTo(cx + w * 0.23, h * 0.36);
    g.lineTo(cx + w * 0.16, h * 0.64);
    g.lineTo(cx - w * 0.16, h * 0.64);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.2, h * 0.38, cx - w * 0.28, h * 0.6, w * 0.08, B);
    limb(g, cx + w * 0.2, h * 0.38, cx + w * 0.28, h * 0.6, w * 0.08, B);
    g.strokeStyle = '#3a2d20';
    g.lineWidth = w * 0.035;
    g.beginPath();
    g.moveTo(cx + w * 0.28, h * 0.62);
    g.lineTo(cx + w * 0.34, h * 0.18);
    g.stroke();
    g.fillStyle = '#9aa3b2';
    g.beginPath();
    g.moveTo(cx + w * 0.3, h * 0.2);
    g.quadraticCurveTo(cx + w * 0.46, h * 0.26, cx + w * 0.34, h * 0.36);
    g.closePath();
    g.fill();
    g.fillStyle = B;
    g.beginPath();
    g.ellipse(cx, h * 0.26, w * 0.13, h * 0.1, 0, 0, 7);
    g.fill();
    g.beginPath();
    g.ellipse(cx, h * 0.32, w * 0.07, h * 0.05, 0, 0, 7);
    g.fill();
    g.strokeStyle = '#dcd4bd';
    g.lineWidth = w * 0.04;
    g.lineCap = 'round';
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.1, h * 0.22);
      g.quadraticCurveTo(cx + s * w * 0.22, h * 0.16, cx + s * w * 0.2, h * 0.08);
      g.stroke();
    }
    eyes(g, cx, h * 0.25, w * 0.045, w * 0.02, '#ff3b2d');
    g.fillStyle = '#2a1d12';
    g.beginPath();
    g.arc(cx - w * 0.03, h * 0.34, w * 0.015, 0, 7);
    g.arc(cx + w * 0.03, h * 0.34, w * 0.015, 0, 7);
    g.fill();
  },
  golem: (g, w, h) => {
    shadow(g, w, h, 0.4);
    const cx = w * 0.5,
      S = ['#5a5f6e', '#3a3e4a', '#1b1d24'];
    glow(g, cx, h * 0.55, w * 0.3, '#ff7a1a', 0.15);
    g.fillStyle = S[1];
    g.fillRect(cx - w * 0.18, h * 0.66, w * 0.14, h * 0.22);
    g.fillRect(cx + w * 0.04, h * 0.66, w * 0.14, h * 0.22);
    g.fillStyle = lg(g, cx, h * 0.3, cx, h * 0.66, S[0], S[2]);
    poly(g, [[cx - w * 0.24, h * 0.4], [cx - w * 0.1, h * 0.3], [cx + w * 0.12, h * 0.3], [cx + w * 0.24, h * 0.42], [cx + w * 0.18, h * 0.66], [cx - w * 0.18, h * 0.66]]);
    g.fill();
    g.strokeStyle = S[2];
    g.lineWidth = w * 0.02;
    g.stroke();
    g.strokeStyle = '#ff8a3a';
    g.lineWidth = w * 0.02;
    g.shadowColor = '#ff7a1a';
    g.shadowBlur = w * 0.2;
    g.beginPath();
    g.moveTo(cx - w * 0.06, h * 0.4);
    g.lineTo(cx, h * 0.52);
    g.lineTo(cx - w * 0.04, h * 0.6);
    g.moveTo(cx, h * 0.52);
    g.lineTo(cx + w * 0.06, h * 0.46);
    g.stroke();
    g.shadowBlur = 0;
    g.fillStyle = S[1];
    g.save();
    g.translate(cx - w * 0.24, h * 0.42);
    g.rotate(0.2);
    g.fillRect(-w * 0.08, 0, w * 0.12, h * 0.28);
    g.restore();
    g.save();
    g.translate(cx + w * 0.24, h * 0.42);
    g.rotate(-0.2);
    g.fillRect(-w * 0.04, 0, w * 0.12, h * 0.28);
    g.restore();
    g.fillStyle = S[0];
    g.fillRect(cx - w * 0.1, h * 0.18, w * 0.2, h * 0.16);
    g.strokeStyle = S[2];
    g.lineWidth = w * 0.015;
    g.strokeRect(cx - w * 0.1, h * 0.18, w * 0.2, h * 0.16);
    eyes(g, cx, h * 0.26, w * 0.045, w * 0.022, '#ff8a3a');
  },
  naga: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#2f8a5e',
      S2 = '#155244';
    g.fillStyle = lg(g, cx, h * 0.6, cx, h * 0.9, S, S2);
    g.beginPath();
    g.ellipse(cx, h * 0.78, w * 0.22, h * 0.12, 0, 0, 7);
    g.fill();
    g.strokeStyle = S2;
    g.lineWidth = w * 0.012;
    g.beginPath();
    g.ellipse(cx, h * 0.78, w * 0.14, h * 0.07, 0, 0, 7);
    g.stroke();
    g.fillStyle = lg(g, cx, h * 0.36, cx, h * 0.64, S, S2);
    g.beginPath();
    g.moveTo(cx - w * 0.13, h * 0.42);
    g.lineTo(cx + w * 0.13, h * 0.42);
    g.lineTo(cx + w * 0.1, h * 0.64);
    g.lineTo(cx - w * 0.1, h * 0.64);
    g.closePath();
    g.fill();
    g.fillStyle = '#5fd0a0';
    g.globalAlpha = 0.3;
    for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) {
      g.beginPath();
      g.arc(cx - w * 0.06 + c * w * 0.06, h * 0.46 + r * h * 0.05, w * 0.02, 0, 7);
      g.fill();
    }
    g.globalAlpha = 1;
    limb(g, cx - w * 0.12, h * 0.44, cx - w * 0.22, h * 0.36, w * 0.05, S);
    limb(g, cx + w * 0.12, h * 0.44, cx + w * 0.22, h * 0.52, w * 0.05, S);
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.02;
    g.beginPath();
    g.arc(cx - w * 0.26, h * 0.42, w * 0.12, -1, 1);
    g.stroke();
    g.fillStyle = S2;
    g.beginPath();
    g.moveTo(cx - w * 0.14, h * 0.32);
    g.quadraticCurveTo(cx, h * 0.2, cx + w * 0.14, h * 0.32);
    g.closePath();
    g.fill();
    g.fillStyle = S;
    g.beginPath();
    g.ellipse(cx, h * 0.3, w * 0.08, h * 0.07, 0, 0, 7);
    g.fill();
    eyes(g, cx, h * 0.29, w * 0.035, w * 0.016, '#ffd24a');
  },
  gorgon: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#7a8a6a',
      S2 = '#4e5840';
    g.fillStyle = lg(g, cx, h * 0.6, cx, h * 0.9, '#3f9e7e', '#155244');
    g.beginPath();
    g.ellipse(cx, h * 0.78, w * 0.2, h * 0.12, 0, 0, 7);
    g.fill();
    g.fillStyle = lg(g, cx, h * 0.36, cx, h * 0.64, S, S2);
    g.beginPath();
    g.moveTo(cx - w * 0.12, h * 0.42);
    g.lineTo(cx + w * 0.12, h * 0.42);
    g.lineTo(cx + w * 0.1, h * 0.64);
    g.lineTo(cx - w * 0.1, h * 0.64);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.11, h * 0.44, cx - w * 0.2, h * 0.54, w * 0.045, S);
    limb(g, cx + w * 0.11, h * 0.44, cx + w * 0.2, h * 0.5, w * 0.045, S);
    g.strokeStyle = '#6b5226';
    g.lineWidth = w * 0.02;
    g.beginPath();
    g.arc(cx + w * 0.24, h * 0.48, w * 0.1, -1, 1);
    g.stroke();
    g.fillStyle = S;
    g.beginPath();
    g.arc(cx, h * 0.3, w * 0.09, 0, 7);
    g.fill();
    g.strokeStyle = '#3f9e7e';
    g.lineWidth = w * 0.025;
    g.lineCap = 'round';
    for (let k = 0; k < 7; k++) {
      const a = Math.PI + k / 6 * Math.PI;
      g.beginPath();
      g.moveTo(cx + Math.cos(a) * w * 0.08, h * 0.27 + Math.sin(a) * h * 0.06);
      const ex = cx + Math.cos(a) * w * 0.2,
        ey = h * 0.22 + Math.sin(a) * h * 0.12;
      g.quadraticCurveTo(cx + Math.cos(a) * w * 0.18, h * 0.16, ex, ey);
      g.stroke();
      g.fillStyle = '#5fd0a0';
      g.beginPath();
      g.arc(ex, ey, w * 0.015, 0, 7);
      g.fill();
    }
    eyes(g, cx, h * 0.3, w * 0.035, w * 0.016, '#ffd24a');
  },
  hellhound: (g, w, h) => {
    shadow(g, w, h, 0.42);
    glow(g, w * 0.5, h * 0.62, w * 0.4, '#ff5a1a', 0.22);
    const D = '#2a2620',
      D2 = '#15120e';
    limb(g, w * 0.32, h * 0.6, w * 0.28, h * 0.84, w * 0.06, D);
    limb(g, w * 0.4, h * 0.62, w * 0.42, h * 0.85, w * 0.06, D2);
    limb(g, w * 0.6, h * 0.6, w * 0.58, h * 0.84, w * 0.06, D);
    limb(g, w * 0.68, h * 0.62, w * 0.72, h * 0.85, w * 0.06, D2);
    g.fillStyle = lg(g, w * 0.5, h * 0.4, w * 0.5, h * 0.66, D, D2);
    g.beginPath();
    g.ellipse(w * 0.5, h * 0.55, w * 0.24, h * 0.15, 0, 0, 7);
    g.fill();
    glow(g, w * 0.5, h * 0.64, w * 0.22, '#ff7a1a', 0.5);
    g.fillStyle = '#1b1d24';
    for (let k = 0; k < 4; k++) {
      const sx = w * 0.35 + k * w * 0.1;
      g.beginPath();
      g.moveTo(sx, h * 0.42);
      g.lineTo(sx + w * 0.03, h * 0.3);
      g.lineTo(sx + w * 0.06, h * 0.42);
      g.closePath();
      g.fill();
    }
    limb(g, w * 0.74, h * 0.5, w * 0.86, h * 0.4, w * 0.04, D);
    g.fillStyle = D;
    g.beginPath();
    g.ellipse(w * 0.28, h * 0.5, w * 0.12, h * 0.1, 0, 0, 7);
    g.fill();
    g.beginPath();
    g.moveTo(w * 0.18, h * 0.5);
    g.lineTo(w * 0.1, h * 0.54);
    g.lineTo(w * 0.2, h * 0.56);
    g.closePath();
    g.fill();
    g.fillStyle = D2;
    g.beginPath();
    g.moveTo(w * 0.3, h * 0.42);
    g.lineTo(w * 0.32, h * 0.32);
    g.lineTo(w * 0.36, h * 0.43);
    g.closePath();
    g.fill();
    eyes(g, w * 0.26, h * 0.48, w * 0.03, w * 0.022, '#ffb03a');
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.moveTo(w * 0.14, h * 0.54);
    g.lineTo(w * 0.15, h * 0.58);
    g.lineTo(w * 0.17, h * 0.54);
    g.fill();
  },
  bat: (g, w, h) => {
    shadow(g, w, h, 0.3);
    const cx = w * 0.5,
      cy = h * 0.45,
      D = '#2a2d36',
      D2 = '#16171d';
    g.fillStyle = lg(g, cx, cy, cx, cy + h * 0.1, D, D2);
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.04, cy);
      g.quadraticCurveTo(cx + s * w * 0.3, cy - h * 0.15, cx + s * w * 0.46, cy - h * 0.05);
      g.lineTo(cx + s * w * 0.4, cy + h * 0.04);
      g.quadraticCurveTo(cx + s * w * 0.34, cy - h * 0.02, cx + s * w * 0.32, cy + h * 0.08);
      g.quadraticCurveTo(cx + s * w * 0.26, cy + h * 0.02, cx + s * w * 0.22, cy + h * 0.1);
      g.quadraticCurveTo(cx + s * w * 0.14, cy + h * 0.04, cx + s * w * 0.04, cy + h * 0.06);
      g.closePath();
      g.fill();
      g.strokeStyle = D2;
      g.lineWidth = w * 0.01;
      g.beginPath();
      g.moveTo(cx + s * w * 0.04, cy);
      g.lineTo(cx + s * w * 0.4, cy);
      g.stroke();
    }
    g.fillStyle = D;
    g.beginPath();
    g.ellipse(cx, cy + h * 0.03, w * 0.07, h * 0.1, 0, 0, 7);
    g.fill();
    g.fillStyle = D2;
    for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(cx + s * w * 0.03, cy - h * 0.06);
      g.lineTo(cx + s * w * 0.06, cy - h * 0.15);
      g.lineTo(cx + s * w * 0.08, cy - h * 0.05);
      g.closePath();
      g.fill();
    }
    eyes(g, cx, cy - h * 0.02, w * 0.03, w * 0.018, '#ff2d6f');
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.moveTo(cx - w * 0.02, cy + h * 0.06);
    g.lineTo(cx - w * 0.01, cy + h * 0.1);
    g.lineTo(cx, cy + h * 0.06);
    g.moveTo(cx + w * 0.02, cy + h * 0.06);
    g.lineTo(cx + w * 0.01, cy + h * 0.1);
    g.lineTo(cx, cy + h * 0.06);
    g.fill();
  },
  spider: (g, w, h) => {
    shadow(g, w, h, 0.42);
    const cx = w * 0.5,
      cy = h * 0.58,
      D = '#1b1d24',
      D2 = '#08090d';
    g.strokeStyle = D;
    g.lineWidth = w * 0.025;
    g.lineCap = 'round';
    for (const s of [-1, 1]) for (let k = 0; k < 4; k++) {
      const jx = cx + s * w * 0.12,
        jy = cy - h * 0.02,
        mx = cx + s * w * (0.24 + k * 0.04),
        my = cy - h * 0.12 + k * h * 0.05,
        ex = cx + s * w * (0.34 + k * 0.02),
        ey = cy + h * 0.06 + k * h * 0.04;
      g.beginPath();
      g.moveTo(jx, jy);
      g.lineTo(mx, my);
      g.lineTo(ex, ey);
      g.stroke();
    }
    g.fillStyle = lg(g, cx, cy, cx, cy + h * 0.2, D, D2);
    g.beginPath();
    g.ellipse(cx, cy + h * 0.08, w * 0.16, h * 0.15, 0, 0, 7);
    g.fill();
    g.fillStyle = '#ff2d6f';
    g.beginPath();
    g.moveTo(cx, cy + h * 0.02);
    g.lineTo(cx - w * 0.04, cy + h * 0.12);
    g.lineTo(cx, cy + h * 0.08);
    g.lineTo(cx + w * 0.04, cy + h * 0.12);
    g.closePath();
    g.fill();
    g.fillStyle = D;
    g.beginPath();
    g.ellipse(cx, cy - h * 0.06, w * 0.1, h * 0.08, 0, 0, 7);
    g.fill();
    g.fillStyle = '#ff2d6f';
    for (let k = 0; k < 4; k++) {
      g.beginPath();
      g.arc(cx - w * 0.04 + k * w * 0.026, cy - h * 0.08, w * 0.012, 0, 7);
      g.fill();
    }
    glow(g, cx, cy - h * 0.08, w * 0.1, '#ff2d6f', 0.4);
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.moveTo(cx - w * 0.03, cy - h * 0.02);
    g.lineTo(cx - w * 0.02, cy + h * 0.02);
    g.lineTo(cx - w * 0.01, cy - h * 0.02);
    g.fill();
  },
  slime: (g, w, h) => {
    shadow(g, w, h, 0.4);
    const cx = w * 0.5,
      cy = h * 0.66;
    glow(g, cx, cy, w * 0.4, '#aef07a', 0.25);
    const grd = g.createRadialGradient(cx - w * 0.08, cy - h * 0.08, 0, cx, cy, w * 0.3);
    grd.addColorStop(0, '#cfe89a');
    grd.addColorStop(0.5, '#6fae3a');
    grd.addColorStop(1, '#2a4a14');
    g.fillStyle = grd;
    g.beginPath();
    g.moveTo(cx - w * 0.28, cy + h * 0.18);
    g.quadraticCurveTo(cx - w * 0.3, cy - h * 0.18, cx, cy - h * 0.2);
    g.quadraticCurveTo(cx + w * 0.3, cy - h * 0.18, cx + w * 0.28, cy + h * 0.18);
    g.closePath();
    g.fill();
    g.fillStyle = 'rgba(255,255,255,0.4)';
    g.beginPath();
    g.ellipse(cx - w * 0.1, cy - h * 0.08, w * 0.06, h * 0.05, 0.3, 0, 7);
    g.fill();
    g.fillStyle = 'rgba(255,255,255,0.2)';
    g.beginPath();
    g.arc(cx + w * 0.08, cy + h * 0.04, w * 0.04, 0, 7);
    g.fill();
    g.fillStyle = '#1b1d24';
    g.beginPath();
    g.arc(cx - w * 0.07, cy - h * 0.02, w * 0.03, 0, 7);
    g.arc(cx + w * 0.07, cy - h * 0.02, w * 0.03, 0, 7);
    g.fill();
    g.fillStyle = '#fff';
    g.beginPath();
    g.arc(cx - w * 0.08, cy - h * 0.03, w * 0.01, 0, 7);
    g.arc(cx + w * 0.06, cy - h * 0.03, w * 0.01, 0, 7);
    g.fill();
  },
  kobold: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5,
      S = '#8a6a3a',
      S2 = '#5e4624';
    limb(g, cx - w * 0.06, h * 0.66, cx - w * 0.08, h * 0.85, w * 0.06, S2);
    limb(g, cx + w * 0.06, h * 0.66, cx + w * 0.08, h * 0.85, w * 0.06, S2);
    g.fillStyle = lg(g, cx, h * 0.46, cx, h * 0.68, S, S2);
    g.beginPath();
    g.ellipse(cx, h * 0.56, w * 0.11, h * 0.12, 0, 0, 7);
    g.fill();
    g.strokeStyle = S2;
    g.lineWidth = w * 0.05;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(cx - w * 0.05, h * 0.62);
    g.quadraticCurveTo(cx - w * 0.22, h * 0.72, cx - w * 0.26, h * 0.6);
    g.stroke();
    limb(g, cx - w * 0.09, h * 0.5, cx - w * 0.16, h * 0.58, w * 0.045, S);
    limb(g, cx + w * 0.09, h * 0.5, cx + w * 0.2, h * 0.54, w * 0.045, S);
    g.strokeStyle = '#9aa3b2';
    g.lineWidth = w * 0.02;
    g.beginPath();
    g.moveTo(cx + w * 0.2, h * 0.54);
    g.lineTo(cx + w * 0.26, h * 0.44);
    g.stroke();
    g.fillStyle = S;
    g.beginPath();
    g.ellipse(cx + w * 0.02, h * 0.4, w * 0.1, h * 0.08, 0, 0, 7);
    g.fill();
    g.beginPath();
    g.moveTo(cx + w * 0.1, h * 0.4);
    g.lineTo(cx + w * 0.18, h * 0.42);
    g.lineTo(cx + w * 0.1, h * 0.45);
    g.closePath();
    g.fill();
    g.fillStyle = S2;
    for (let k = 0; k < 3; k++) {
      g.beginPath();
      g.moveTo(cx - w * 0.04 + k * w * 0.04, h * 0.33);
      g.lineTo(cx - w * 0.02 + k * w * 0.04, h * 0.27);
      g.lineTo(cx + k * w * 0.04, h * 0.33);
      g.closePath();
      g.fill();
    }
    eyes(g, cx + w * 0.02, h * 0.39, w * 0.035, w * 0.016, '#ffd24a');
  },
  myconid: (g, w, h) => {
    shadow(g, w, h);
    const cx = w * 0.5;
    glow(g, cx, h * 0.3, w * 0.3, '#aef07a', 0.18);
    limb(g, cx - w * 0.06, h * 0.66, cx - w * 0.08, h * 0.85, w * 0.06, '#c8c0a8');
    limb(g, cx + w * 0.06, h * 0.66, cx + w * 0.08, h * 0.85, w * 0.06, '#c8c0a8');
    g.fillStyle = lg(g, cx, h * 0.4, cx, h * 0.68, '#e8e0c8', '#a89e80');
    g.beginPath();
    g.moveTo(cx - w * 0.1, h * 0.44);
    g.lineTo(cx + w * 0.1, h * 0.44);
    g.lineTo(cx + w * 0.08, h * 0.68);
    g.lineTo(cx - w * 0.08, h * 0.68);
    g.closePath();
    g.fill();
    limb(g, cx - w * 0.09, h * 0.46, cx - w * 0.18, h * 0.56, w * 0.045, '#d8d0b8');
    limb(g, cx + w * 0.09, h * 0.46, cx + w * 0.18, h * 0.56, w * 0.045, '#d8d0b8');
    g.fillStyle = lg(g, cx, h * 0.18, cx, h * 0.36, '#7a3a8a', '#4a1f5e');
    g.beginPath();
    g.ellipse(cx, h * 0.34, w * 0.18, h * 0.16, 0, Math.PI, 0);
    g.closePath();
    g.fill();
    g.fillStyle = '#d8c0e8';
    for (let k = 0; k < 4; k++) {
      g.beginPath();
      g.arc(cx - w * 0.1 + k * w * 0.07, h * 0.26 - Math.sin(k) * h * 0.02, w * 0.022, 0, 7);
      g.fill();
    }
    eyes(g, cx, h * 0.4, w * 0.035, w * 0.016, '#aef07a');
  },
  'giant-rat': (g, w, h) => {
    shadow(g, w, h, 0.4);
    const D = '#6a5e4a',
      D2 = '#46402e';
    limb(g, w * 0.36, h * 0.66, w * 0.32, h * 0.84, w * 0.05, D2);
    limb(g, w * 0.5, h * 0.68, w * 0.52, h * 0.85, w * 0.05, D2);
    limb(g, w * 0.62, h * 0.66, w * 0.66, h * 0.84, w * 0.05, D2);
    g.strokeStyle = '#9a8a6a';
    g.lineWidth = w * 0.03;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(w * 0.7, h * 0.6);
    g.quadraticCurveTo(w * 0.92, h * 0.66, w * 0.86, h * 0.46);
    g.stroke();
    g.fillStyle = lg(g, w * 0.5, h * 0.45, w * 0.5, h * 0.68, D, D2);
    g.beginPath();
    g.ellipse(w * 0.52, h * 0.58, w * 0.24, h * 0.15, 0, 0, 7);
    g.fill();
    g.fillStyle = D;
    g.beginPath();
    g.ellipse(w * 0.28, h * 0.54, w * 0.13, h * 0.1, 0, 0, 7);
    g.fill();
    g.beginPath();
    g.moveTo(w * 0.16, h * 0.54);
    g.lineTo(w * 0.08, h * 0.57);
    g.lineTo(w * 0.18, h * 0.6);
    g.closePath();
    g.fill();
    g.fillStyle = D2;
    g.beginPath();
    g.arc(w * 0.32, h * 0.44, w * 0.06, 0, 7);
    g.fill();
    eyes(g, w * 0.26, h * 0.52, w * 0.03, w * 0.02, '#ff3b2d');
    g.fillStyle = '#e8e4d8';
    g.beginPath();
    g.moveTo(w * 0.1, h * 0.58);
    g.lineTo(w * 0.11, h * 0.62);
    g.lineTo(w * 0.13, h * 0.58);
    g.fill();
  },
  'giant-worm': (g, w, h) => {
    shadow(g, w, h, 0.36);
    const cx = w * 0.5,
      D = '#a86a6a',
      D2 = '#6e3e3e';
    g.fillStyle = lg(g, cx, h * 0.2, cx, h * 0.9, D2, D);
    g.beginPath();
    g.moveTo(cx - w * 0.18, h * 0.9);
    g.quadraticCurveTo(cx - w * 0.22, h * 0.4, cx - w * 0.13, h * 0.24);
    g.quadraticCurveTo(cx, h * 0.16, cx + w * 0.13, h * 0.24);
    g.quadraticCurveTo(cx + w * 0.22, h * 0.4, cx + w * 0.18, h * 0.9);
    g.closePath();
    g.fill();
    g.strokeStyle = D2;
    g.lineWidth = w * 0.02;
    for (let k = 0; k < 4; k++) {
      const yy = h * 0.36 + k * h * 0.13;
      g.beginPath();
      g.moveTo(cx - w * 0.18 + k * w * 0.01, yy);
      g.quadraticCurveTo(cx, yy + h * 0.03, cx + w * 0.18 - k * w * 0.01, yy);
      g.stroke();
    }
    g.fillStyle = '#2a0808';
    g.beginPath();
    g.ellipse(cx, h * 0.24, w * 0.11, h * 0.1, 0, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    const n = 10;
    for (let k = 0; k < n; k++) {
      const a = k / n * 7;
      g.beginPath();
      g.moveTo(cx + Math.cos(a) * w * 0.11, h * 0.24 + Math.sin(a) * h * 0.1);
      g.lineTo(cx + Math.cos(a) * w * 0.06, h * 0.24 + Math.sin(a) * h * 0.055);
      g.lineTo(cx + Math.cos(a + 0.3) * w * 0.1, h * 0.24 + Math.sin(a + 0.3) * h * 0.09);
      g.closePath();
      g.fill();
    }
  },
  'giant-centipede': (g, w, h) => {
    shadow(g, w, h, 0.42);
    const D = '#3a2d1a',
      D2 = '#1f1810';
    g.strokeStyle = '#1b1d24';
    g.lineWidth = w * 0.018;
    g.lineCap = 'round';
    const segs = [[0.28, 0.5], [0.4, 0.46], [0.52, 0.5], [0.64, 0.46], [0.74, 0.54]];
    for (const [sx, sy] of segs) for (const s of [-1, 1]) {
      g.beginPath();
      g.moveTo(w * sx, h * sy);
      g.lineTo(w * sx + s * w * 0.08, h * (sy + 0.12));
      g.stroke();
    }
    for (let i = 0; i < segs.length; i++) {
      const [sx, sy] = segs[i];
      g.fillStyle = lg(g, w * sx, h * (sy - 0.06), w * sx, h * (sy + 0.06), '#5a4424', D2);
      g.beginPath();
      g.arc(w * sx, h * sy, w * 0.08, 0, 7);
      g.fill();
      g.strokeStyle = D2;
      g.lineWidth = w * 0.01;
      g.stroke();
    }
    g.fillStyle = D;
    g.beginPath();
    g.arc(w * 0.24, h * 0.5, w * 0.09, 0, 7);
    g.fill();
    g.strokeStyle = '#1b1d24';
    g.lineWidth = w * 0.02;
    g.beginPath();
    g.moveTo(w * 0.16, h * 0.48);
    g.lineTo(w * 0.1, h * 0.44);
    g.moveTo(w * 0.16, h * 0.52);
    g.lineTo(w * 0.1, h * 0.56);
    g.stroke();
    eyes(g, w * 0.22, h * 0.48, w * 0.025, w * 0.016, '#ff3b2d');
  }
};
function jobs() {
  return Object.entries(MOBS).map(([name, draw]) => ({
    path: `mobs/${name}.png`,
    w: 64,
    h: 64,
    ss: 3,
    grain: 8,
    draw
  }));
}
module.exports = {
  jobs,
  MOBS
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/mobs.js", error: String((e && e.message) || e) }); }

// tools/assetgen/rig.js
try { (() => {
/**
 * Per-limb articulated rigs — true walk cycles (swinging legs w/ knee bend, counter-swinging
 * arms, torso bob) for the hero-class bipeds. Overrides the transform-based loops in anim.js for
 * these mobs. 4-frame idle / walk / attack strips (256×64).
 */
const C = require('./core');
const TAU = Math.PI * 2;

/** Mobs that have a hand-rigged walk (anim.js skips these so rig.js owns them). */
const RIGGED = ['hero', 'skeleton', 'orc', 'goblin'];
function seg(g, x, y, ang, len, wd, col) {
  const ex = x + Math.sin(ang) * len,
    ey = y + Math.cos(ang) * len;
  g.strokeStyle = col;
  g.lineWidth = wd;
  g.lineCap = 'round';
  g.beginPath();
  g.moveTo(x, y);
  g.lineTo(ex, ey);
  g.stroke();
  return [ex, ey];
}
function drawBiped(g, w, h, cfg, pose) {
  const cx = w / 2,
    S = w / 64,
    hipY = h * 0.62,
    shY = h * 0.4 + pose.bob,
    hipX = w * 0.075 * cfg.wide,
    shX = w * 0.12 * cfg.wide;
  const thL = h * 0.15 * cfg.tall,
    shL = h * 0.14 * cfg.tall,
    uA = h * 0.12,
    fA = h * 0.1;
  function leg(side, thighA, knee) {
    const hx = cx + side * hipX,
      hy = hipY;
    const [kx, ky] = seg(g, hx, hy, thighA, thL, cfg.legW * S, cfg.legD);
    const [fx, fy] = seg(g, kx, ky, thighA - knee, shL, cfg.legW * 0.85 * S, cfg.legD);
    g.fillStyle = cfg.foot;
    g.beginPath();
    g.ellipse(fx + Math.sin(thighA - knee) * 2, fy, w * 0.06, h * 0.03, 0, 0, 7);
    g.fill();
  }
  function arm(side, armA, hand) {
    const sx = cx + side * shX,
      sy = shY;
    const [ex, ey] = seg(g, sx, sy, armA, uA, cfg.armW * S, cfg.arm);
    const ha = armA + (hand || 0);
    const [hx, hy] = seg(g, ex, ey, ha, fA, cfg.armW * 0.85 * S, cfg.arm);
    return [hx, hy, ha];
  }
  leg(pose.back < 0 ? -1 : 1, pose.legB, pose.kneeB);
  if (cfg.cloak) {
    g.fillStyle = cfg.cloak;
    g.beginPath();
    g.moveTo(cx - shX, shY + 2);
    g.quadraticCurveTo(cx - shX * 1.6, hipY + h * 0.18, cx - shX * 0.7, h * 0.84);
    g.lineTo(cx + shX * 0.7, h * 0.84);
    g.quadraticCurveTo(cx + shX * 1.6, hipY + h * 0.18, cx + shX, shY + 2);
    g.closePath();
    g.fill();
  }
  arm(-1, pose.armBk, 0.1);
  leg(pose.back < 0 ? 1 : -1, pose.legF, pose.kneeF);
  g.fillStyle = cfg.bodyFill(g, shY, hipY);
  g.beginPath();
  g.moveTo(cx - shX, shY);
  g.lineTo(cx + shX, shY);
  g.lineTo(cx + hipX * 1.4, hipY + 2);
  g.lineTo(cx - hipX * 1.4, hipY + 2);
  g.closePath();
  g.fill();
  if (cfg.bodyStroke) {
    g.strokeStyle = cfg.bodyStroke;
    g.lineWidth = S;
    g.stroke();
  }
  if (cfg.torsoDetail) cfg.torsoDetail(g, cx, shY, hipY, S);
  cfg.head(g, cx, shY - h * 0.02, S, pose.bob);
  const [hx, hy, ha] = arm(1, pose.armF, pose.armHand || 0);
  if (cfg.weapon) cfg.weapon(g, hx, hy, ha, S, pose);
}
const POSE = {
  idle: i => {
    const p = i / 4 * TAU;
    return {
      legF: 0.06,
      legB: -0.06,
      kneeF: 0.06,
      kneeB: 0.06,
      bob: -Math.sin(p) * 0.9,
      armF: 0.12 + Math.sin(p) * 0.03,
      armBk: -0.12,
      back: -1
    };
  },
  walk: i => {
    const p = i / 4 * TAU;
    return {
      legF: Math.sin(p) * 0.55,
      legB: Math.sin(p + Math.PI) * 0.55,
      kneeF: Math.max(0, Math.sin(p + 1.4)) * 0.8,
      kneeB: Math.max(0, Math.sin(p + Math.PI + 1.4)) * 0.8,
      bob: -Math.abs(Math.cos(p)) * 2.2,
      armF: Math.sin(p + Math.PI) * 0.45,
      armBk: Math.sin(p) * 0.45,
      back: Math.sin(p)
    };
  },
  attack: i => {
    const A = [{
      armF: -1.4,
      bob: 1,
      legF: 0.2,
      legB: -0.3
    }, {
      armF: -1.7,
      bob: 0
    }, {
      armF: 0.5,
      bob: -2,
      legF: -0.3,
      legB: 0.3,
      armHand: 0.3
    }, {
      armF: 0.1,
      bob: 0
    }][i];
    return Object.assign({
      legF: 0,
      legB: 0,
      kneeF: 0.1,
      kneeB: 0.1,
      armBk: -0.3,
      back: -1,
      armHand: 0
    }, A);
  }
};
const heads = {
  helmet: (g, cx, y, S) => {
    g.fillStyle = '#c79a6a';
    g.beginPath();
    g.arc(cx, y - 6, 7 * S, 0, 7);
    g.fill();
    g.fillStyle = '#5a6170';
    g.beginPath();
    g.arc(cx, y - 8, 8 * S, Math.PI, 0);
    g.fill();
    g.fillRect(cx - 8 * S, y - 9, 16 * S, 3 * S);
    g.fillStyle = '#1b1d24';
    g.fillRect(cx - 5 * S, y - 6, 10 * S, 2 * S);
  },
  skull: (g, cx, y, S) => {
    g.fillStyle = '#dcd4bd';
    g.beginPath();
    g.arc(cx, y - 6, 7.5 * S, 0, 7);
    g.fill();
    g.fillRect(cx - 5 * S, y - 2, 10 * S, 4 * S);
    g.fillStyle = '#1b1d24';
    g.beginPath();
    g.arc(cx - 3 * S, y - 6, 2 * S, 0, 7);
    g.arc(cx + 3 * S, y - 6, 2 * S, 0, 7);
    g.fill();
    g.fillRect(cx - S, y - 3, 2 * S, 3 * S);
  },
  tusk: (g, cx, y, S) => {
    g.fillStyle = '#5a7a3a';
    g.beginPath();
    g.arc(cx, y - 6, 8 * S, 0, 7);
    g.fill();
    g.fillStyle = '#e8e4d8';
    g.beginPath();
    g.moveTo(cx - 4 * S, y - 2);
    g.lineTo(cx - 3 * S, y + 3 * S);
    g.lineTo(cx - 1.5 * S, y - 2);
    g.moveTo(cx + 4 * S, y - 2);
    g.lineTo(cx + 3 * S, y + 3 * S);
    g.lineTo(cx + 1.5 * S, y - 2);
    g.fill();
    C.glow(g, cx - 3 * S, y - 7, 4 * S, '#ffd24a', 0.7);
    C.glow(g, cx + 3 * S, y - 7, 4 * S, '#ffd24a', 0.7);
    g.fillStyle = '#ffd24a';
    g.beginPath();
    g.arc(cx - 3 * S, y - 7, 1.6 * S, 0, 7);
    g.arc(cx + 3 * S, y - 7, 1.6 * S, 0, 7);
    g.fill();
  },
  ear: (g, cx, y, S) => {
    g.fillStyle = '#6a9e4a';
    g.beginPath();
    g.arc(cx, y - 5, 7 * S, 0, 7);
    g.fill();
    g.fillStyle = '#4a7030';
    g.beginPath();
    g.moveTo(cx - 6 * S, y - 6);
    g.lineTo(cx - 14 * S, y - 9);
    g.lineTo(cx - 6 * S, y - 1);
    g.closePath();
    g.moveTo(cx + 6 * S, y - 6);
    g.lineTo(cx + 14 * S, y - 9);
    g.lineTo(cx + 6 * S, y - 1);
    g.closePath();
    g.fill();
    g.fillStyle = '#ffd24a';
    g.beginPath();
    g.arc(cx - 2.6 * S, y - 6, 1.5 * S, 0, 7);
    g.arc(cx + 2.6 * S, y - 6, 1.5 * S, 0, 7);
    g.fill();
  }
};
const weapons = {
  sword: (g, hx, hy, ang, S) => {
    g.strokeStyle = '#6b5226';
    g.lineWidth = 3 * S;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(hx - Math.sin(ang + 1.5) * 2 * S, hy - Math.cos(ang + 1.5) * 2 * S);
    g.lineTo(hx + Math.sin(ang + 1.5) * 4 * S, hy + Math.cos(ang + 1.5) * 4 * S);
    g.stroke();
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = 2.4 * S;
    g.beginPath();
    g.moveTo(hx, hy);
    g.lineTo(hx + Math.sin(ang) * 22 * S, hy + Math.cos(ang) * 22 * S);
    g.stroke();
  },
  axe: (g, hx, hy, ang, S) => {
    g.strokeStyle = '#6b5226';
    g.lineWidth = 2.6 * S;
    g.lineCap = 'round';
    const tx = hx + Math.sin(ang) * 20 * S,
      ty = hy + Math.cos(ang) * 20 * S;
    g.beginPath();
    g.moveTo(hx, hy);
    g.lineTo(tx, ty);
    g.stroke();
    g.fillStyle = '#9aa3b2';
    g.beginPath();
    g.moveTo(tx - Math.sin(ang + 1.5) * 2 * S, ty - Math.cos(ang + 1.5) * 2 * S);
    g.quadraticCurveTo(tx + Math.sin(ang) * 8 * S, ty + Math.cos(ang) * 8 * S, tx + Math.sin(ang + 1.5) * 7 * S, ty + Math.cos(ang + 1.5) * 7 * S);
    g.closePath();
    g.fill();
  },
  dagger: (g, hx, hy, ang, S) => {
    g.strokeStyle = '#c0c8d4';
    g.lineWidth = 2 * S;
    g.lineCap = 'round';
    g.beginPath();
    g.moveTo(hx, hy);
    g.lineTo(hx + Math.sin(ang) * 9 * S, hy + Math.cos(ang) * 9 * S);
    g.stroke();
  }
};
const CFG = {
  hero: {
    wide: 1,
    tall: 1,
    legW: 5.5,
    legD: '#3a3e4a',
    armW: 3.5,
    arm: '#5a6170',
    foot: '#2a2d36',
    cloak: '#7a1e2e',
    bodyFill: (g, s, hp) => C.lg(g, 0, s, 0, hp, '#8a93a4', '#4d5260'),
    bodyStroke: '#c9a24b',
    head: heads.helmet,
    weapon: weapons.sword
  },
  skeleton: {
    wide: 0.92,
    tall: 1,
    legW: 3.2,
    legD: '#dcd4bd',
    armW: 2.6,
    arm: '#dcd4bd',
    foot: '#a39a82',
    bodyFill: () => 'rgba(0,0,0,0)',
    torsoDetail: (g, cx, s, hp, S) => {
      g.strokeStyle = '#dcd4bd';
      g.lineWidth = 4 * S;
      g.beginPath();
      g.moveTo(cx, s);
      g.lineTo(cx, hp);
      g.stroke();
      g.strokeStyle = '#a39a82';
      g.lineWidth = 1.6 * S;
      for (let r = 0; r < 4; r++) {
        g.beginPath();
        g.arc(cx, s + (hp - s) * 0.2 + r * (hp - s) * 0.2, 6 * S, 0.4, Math.PI - 0.4);
        g.stroke();
      }
    },
    head: heads.skull,
    weapon: weapons.sword
  },
  orc: {
    wide: 1.15,
    tall: 0.98,
    legW: 6,
    legD: '#3a5424',
    armW: 4,
    arm: '#5a7a3a',
    foot: '#3a2d20',
    bodyFill: (g, s, hp) => C.lg(g, 0, s, 0, hp, '#5a7a3a', '#3a5424'),
    torsoDetail: (g, cx, s, hp, S) => {
      g.fillStyle = '#5a4028';
      g.fillRect(cx - 9 * S, s + (hp - s) * 0.4, 18 * S, 5 * S);
    },
    head: heads.tusk,
    weapon: weapons.axe
  },
  goblin: {
    wide: 0.85,
    tall: 0.82,
    legW: 4,
    legD: '#4a7030',
    armW: 2.8,
    arm: '#6a9e4a',
    foot: '#3a2d20',
    bodyFill: (g, s, hp) => C.lg(g, 0, s, 0, hp, '#6a9e4a', '#4a7030'),
    head: heads.ear,
    weapon: weapons.dagger
  }
};
function jobs() {
  const out = [];
  for (const [name, cfg] of Object.entries(CFG)) for (const [state, pf] of Object.entries(POSE)) out.push({
    path: `mobs/${name}_${state}.png`,
    w: 256,
    h: 64,
    ss: 3,
    grain: 7,
    draw: g => {
      for (let i = 0; i < 4; i++) {
        g.save();
        g.translate(i * 64, 0);
        C.shadow(g, 64, 64, 0.3);
        drawBiped(g, 64, 64, cfg, pf(i));
        g.restore();
      }
    }
  });
  return out;
}
module.exports = {
  jobs,
  RIGGED
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/rig.js", error: String((e && e.message) || e) }); }

// tools/assetgen/terrain.js
try { (() => {
/** Biome ground tilesheets — 16px grid, every cell a valid floor tile + placed detail cells. */
const C = require('./core');
const S = 16;
function vary(hex, d, rng) {
  const a = C.hx(hex);
  const n = (rng() - 0.5) * 2 * d;
  const cl = v => Math.max(0, Math.min(255, v)) | 0;
  return `rgb(${cl(a[0] + n)},${cl(a[1] + n)},${cl(a[2] + n)})`;
}
function slabCell(g, x, y, rng, rubble) {
  if (rubble) {
    g.fillStyle = '#1b1d24';
    g.fillRect(x, y, S, S);
    for (let k = 0; k < 5; k++) {
      const sx = x + rng() * S * 0.6,
        sy = y + rng() * S * 0.6,
        ss = S * (0.22 + rng() * 0.18);
      g.fillStyle = vary('#4a4e5a', 14, rng);
      g.beginPath();
      g.arc(sx + ss / 2, sy + ss / 2, ss / 2, 0, 7);
      g.fill();
    }
    return;
  }
  g.fillStyle = '#16171d';
  g.fillRect(x, y, S, S);
  g.fillStyle = vary('#2e323c', 10, rng);
  g.fillRect(x + 1, y + 1, S - 2, S - 2);
  g.fillStyle = vary('#3a3e4a', 8, rng);
  g.fillRect(x + 1, y + 1, S - 2, 2);
  for (let k = 0; k < 3; k++) {
    g.fillStyle = 'rgba(0,0,0,0.25)';
    g.fillRect(x + (rng() * S | 0), y + (rng() * S | 0), 1, 1);
  }
}
function cursedCell(g, x, y, rng, vein) {
  g.fillStyle = vary('#443842', 10, rng);
  g.fillRect(x, y, S, S);
  for (let k = 0; k < 4; k++) {
    g.fillStyle = 'rgba(20,10,16,0.4)';
    g.fillRect(x + (rng() * S | 0), y + (rng() * S | 0), 1, 1);
  }
  if (rng() < 0.5) {
    g.strokeStyle = 'rgba(20,8,12,0.5)';
    g.lineWidth = 1;
    g.beginPath();
    let px = x + rng() * S,
      py = y;
    g.moveTo(px, py);
    for (let s = 0; s < 3; s++) {
      px += (rng() - 0.5) * S * 0.5;
      py += S / 3;
      g.lineTo(px, py);
    }
    g.stroke();
  }
  if (vein) {
    g.strokeStyle = '#7a2424';
    g.lineWidth = 1.4;
    g.lineCap = 'round';
    for (let v = 0; v < 3; v++) {
      g.beginPath();
      let px = x + S * 0.5,
        py = y + S * 0.5;
      g.moveTo(px, py);
      const a = v / 3 * 7;
      for (let s = 0; s < 3; s++) {
        px += Math.cos(a + (rng() - 0.5)) * S * 0.22;
        py += Math.sin(a + (rng() - 0.5)) * S * 0.22;
        g.lineTo(px, py);
      }
      g.stroke();
    }
    g.fillStyle = '#b04a44';
    g.beginPath();
    g.arc(x + S * 0.5, y + S * 0.5, 1.6, 0, 7);
    g.fill();
  }
}
function undeadCell(g, x, y, rng, heavy) {
  g.fillStyle = vary('#3a352c', 9, rng);
  g.fillRect(x, y, S, S);
  g.fillStyle = vary('#4a4438', 6, rng);
  g.fillRect(x + 1, y + 1, S - 2, 2);
  const nc = heavy ? 3 : 1;
  g.strokeStyle = 'rgba(10,8,5,0.55)';
  g.lineWidth = 1;
  for (let c = 0; c < nc; c++) {
    g.beginPath();
    let px = x + rng() * S,
      py = y + rng() * S;
    g.moveTo(px, py);
    for (let s = 0; s < 3; s++) {
      px += (rng() - 0.5) * S * 0.6;
      py += (rng() - 0.5) * S * 0.6;
      g.lineTo(px, py);
    }
    g.stroke();
  }
  for (let k = 0; k < 2; k++) {
    g.fillStyle = 'rgba(120,112,90,0.4)';
    g.fillRect(x + (rng() * S | 0), y + (rng() * S | 0), 1, 1);
  }
}
function grassCell(g, x, y, rng, kind) {
  if (kind === 'dirt') {
    g.fillStyle = vary('#5a4632', 10, rng);
    g.fillRect(x, y, S, S);
    for (let k = 0; k < 5; k++) {
      g.fillStyle = 'rgba(30,20,12,0.4)';
      g.fillRect(x + (rng() * S | 0), y + (rng() * S | 0), 1, 1);
    }
    return;
  }
  g.fillStyle = vary('#345e2c', 10, rng);
  g.fillRect(x, y, S, S);
  for (let k = 0; k < 6; k++) {
    const bx = x + rng() * S,
      by = y + rng() * S;
    g.strokeStyle = rng() < 0.5 ? '#2a4e22' : '#427a36';
    g.lineWidth = 1;
    g.beginPath();
    g.moveTo(bx, by);
    g.lineTo(bx + (rng() - 0.5) * 2, by - 1.5 - rng());
    g.stroke();
  }
  if (kind === 'flower') {
    const cols = ['#d87a9e', '#6ea8ff', '#e8d46a'],
      fc = cols[rng() * 3 | 0];
    g.fillStyle = fc;
    for (let k = 0; k < 4; k++) {
      g.beginPath();
      g.arc(x + 2 + rng() * (S - 4), y + 2 + rng() * (S - 4), 1.3, 0, 7);
      g.fill();
    }
  }
}
function biome(name) {
  return (g, W, H) => {
    const cols = Math.floor(W / S),
      rows = Math.floor(H / S);
    for (let r = 0; r < rows; r++) for (let cc = 0; cc < cols; cc++) {
      const rng = C.mulberry32(cc * 73856093 ^ r * 19349663),
        x = cc * S,
        y = r * S;
      if (name === 'catacombs') slabCell(g, x, y, rng, (cc === 49 || cc === 50) && (r === 17 || r === 18));else if (name === 'cursed') cursedCell(g, x, y, rng, (cc === 19 || cc === 20) && (r === 5 || r === 6));else if (name === 'undead') undeadCell(g, x, y, rng, r === 22);else {
        let kind = 'grass';
        if (cc === 4 && r >= 1 && r <= 3) kind = 'dirt';else if (r >= 6 && r <= 7 && cc <= 3) kind = 'flower';
        grassCell(g, x, y, rng, kind);
      }
    }
  };
}
function jobs() {
  return [{
    path: 'terrain/catacombs.png',
    w: 1024,
    h: 640,
    ss: 1,
    draw: biome('catacombs')
  }, {
    path: 'terrain/cursed_ground.png',
    w: 720,
    h: 560,
    ss: 1,
    draw: biome('cursed')
  }, {
    path: 'terrain/undead_ground.png',
    w: 496,
    h: 592,
    ss: 1,
    draw: biome('undead')
  }, {
    path: 'terrain/forest_spring.png',
    w: 256,
    h: 256,
    ss: 1,
    draw: biome('forest')
  }];
}
module.exports = {
  jobs
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/terrain.js", error: String((e && e.message) || e) }); }

// tools/assetgen/ui.js
try { (() => {
/** HUD chrome — obsidian + gold nine-slice panels, bars, buttons (gw_* set). */
const C = require('./core');
const GOLD = '#c9a24b',
  GOLDHI = '#e7d9b0',
  GOLDDK = '#6b5226';
function panel(g, w, h, inset) {
  const grd = g.createLinearGradient(0, 0, 0, h);
  grd.addColorStop(0, inset ? '#070809' : '#15171e');
  grd.addColorStop(1, inset ? '#0a0b10' : '#0c0d12');
  C.rr(g, 1, 1, w - 2, h - 2, inset ? 3 : 5);
  g.fillStyle = grd;
  g.fill();
  if (inset) {
    g.save();
    C.rr(g, 1, 1, w - 2, h - 2, 3);
    g.clip();
    g.strokeStyle = 'rgba(0,0,0,0.6)';
    g.lineWidth = 3;
    g.beginPath();
    g.moveTo(2, 5);
    g.lineTo(2, 2);
    g.lineTo(w - 2, 2);
    g.stroke();
    g.restore();
    g.strokeStyle = 'rgba(201,162,75,0.35)';
    g.lineWidth = 1;
    C.rr(g, 1.5, 1.5, w - 3, h - 3, 3);
    g.stroke();
    return;
  }
  g.strokeStyle = GOLDDK;
  g.lineWidth = 4;
  C.rr(g, 3, 3, w - 6, h - 6, 5);
  g.stroke();
  g.strokeStyle = GOLD;
  g.lineWidth = 2;
  C.rr(g, 3, 3, w - 6, h - 6, 5);
  g.stroke();
  g.strokeStyle = GOLDHI;
  g.lineWidth = 0.8;
  C.rr(g, 5, 5, w - 10, h - 10, 4);
  g.stroke();
  g.fillStyle = GOLD;
  for (const [cx, cy] of [[7, 7], [w - 7, 7], [7, h - 7], [w - 7, h - 7]]) {
    g.beginPath();
    g.arc(cx, cy, 2.4, 0, 7);
    g.fill();
    g.fillStyle = GOLDHI;
    g.beginPath();
    g.arc(cx - 0.6, cy - 0.6, 0.9, 0, 7);
    g.fill();
    g.fillStyle = GOLD;
  }
}
function barTrack(g, w, h) {
  const grd = g.createLinearGradient(0, 0, 0, h);
  grd.addColorStop(0, '#05060a');
  grd.addColorStop(0.5, '#16171d');
  grd.addColorStop(1, '#1f2128');
  g.fillStyle = grd;
  g.fillRect(0, 0, w, h);
  g.strokeStyle = 'rgba(0,0,0,0.7)';
  g.lineWidth = 1;
  g.strokeRect(0.5, 0.5, w - 1, h - 1);
  g.strokeStyle = 'rgba(201,162,75,0.3)';
  g.beginPath();
  g.moveTo(0, h - 1);
  g.lineTo(w, h - 1);
  g.stroke();
}
function barFill(c1, c2, c3) {
  return (g, w, h) => {
    const grd = g.createLinearGradient(0, 0, 0, h);
    grd.addColorStop(0, c2);
    grd.addColorStop(0.5, c1);
    grd.addColorStop(1, c3);
    g.fillStyle = grd;
    g.fillRect(0, 0, w, h);
    g.fillStyle = 'rgba(255,255,255,0.35)';
    g.fillRect(0, 1, w, 2);
    g.fillStyle = 'rgba(0,0,0,0.3)';
    g.fillRect(0, h - 2, w, 2);
  };
}
function button(pressed) {
  return (g, w, h) => {
    const grd = g.createLinearGradient(0, 0, 0, h);
    if (pressed) {
      grd.addColorStop(0, '#0a0b10');
      grd.addColorStop(1, '#15171e');
    } else {
      grd.addColorStop(0, '#23262f');
      grd.addColorStop(1, '#12141a');
    }
    C.rr(g, 2, 2, w - 4, h - 4, 8);
    g.fillStyle = grd;
    g.fill();
    g.strokeStyle = GOLDDK;
    g.lineWidth = 3;
    C.rr(g, 2.5, 2.5, w - 5, h - 5, 8);
    g.stroke();
    g.strokeStyle = pressed ? GOLDDK : GOLD;
    g.lineWidth = 1.5;
    C.rr(g, 2.5, 2.5, w - 5, h - 5, 8);
    g.stroke();
    if (!pressed) {
      g.strokeStyle = 'rgba(231,217,176,0.5)';
      g.lineWidth = 1;
      g.beginPath();
      g.moveTo(10, 5);
      g.lineTo(w - 10, 5);
      g.stroke();
    }
  };
}
function roundButton(g, w, h) {
  const grd = g.createLinearGradient(0, 0, 0, h);
  grd.addColorStop(0, '#23262f');
  grd.addColorStop(1, '#12141a');
  g.fillStyle = grd;
  g.beginPath();
  g.arc(w / 2, h / 2, w / 2 - 3, 0, 7);
  g.fill();
  g.strokeStyle = GOLDDK;
  g.lineWidth = 3;
  g.stroke();
  g.strokeStyle = GOLD;
  g.lineWidth = 1.5;
  g.beginPath();
  g.arc(w / 2, h / 2, w / 2 - 3, 0, 7);
  g.stroke();
  g.strokeStyle = 'rgba(231,217,176,0.5)';
  g.lineWidth = 1;
  g.beginPath();
  g.arc(w / 2, h / 2 - 1, w / 2 - 6, Math.PI * 1.15, Math.PI * 1.85);
  g.stroke();
}
function jobs() {
  const red = barFill('#d23b3b', '#f08a8a', '#6e1414'),
    blue = barFill('#3b6fd2', '#7fa3ec', '#14306a');
  return [{
    path: 'ui/gw_panel.png',
    w: 100,
    h: 100,
    ss: 3,
    draw: (g, w, h) => panel(g, w, h, false)
  }, {
    path: 'ui/gw_panel_inset.png',
    w: 93,
    h: 94,
    ss: 3,
    draw: (g, w, h) => panel(g, w, h, true)
  }, {
    path: 'ui/gw_bar_back_left.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: barTrack
  }, {
    path: 'ui/gw_bar_back_mid.png',
    w: 18,
    h: 18,
    ss: 4,
    draw: barTrack
  }, {
    path: 'ui/gw_bar_back_right.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: barTrack
  }, {
    path: 'ui/gw_bar_red_left.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: red
  }, {
    path: 'ui/gw_bar_red_mid.png',
    w: 18,
    h: 18,
    ss: 4,
    draw: red
  }, {
    path: 'ui/gw_bar_red_right.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: red
  }, {
    path: 'ui/gw_bar_blue_left.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: blue
  }, {
    path: 'ui/gw_bar_blue_mid.png',
    w: 18,
    h: 18,
    ss: 4,
    draw: blue
  }, {
    path: 'ui/gw_bar_blue_right.png',
    w: 9,
    h: 18,
    ss: 4,
    draw: blue
  }, {
    path: 'ui/gw_button.png',
    w: 190,
    h: 49,
    ss: 2,
    draw: button(false)
  }, {
    path: 'ui/gw_button_pressed.png',
    w: 190,
    h: 45,
    ss: 2,
    draw: button(true)
  }, {
    path: 'ui/gw_button_round.png',
    w: 35,
    h: 38,
    ss: 3,
    draw: roundButton
  }];
}
module.exports = {
  jobs
};
})(); } catch (e) { __ds_ns.__errors.push({ path: "tools/assetgen/ui.js", error: String((e && e.message) || e) }); }

// ui_kits/gloomwood-hud/Hud.jsx
try { (() => {
/* Hud — the chrome overlay: topbar (area + pop), minimap, the player orbs, the
   potion belt + ability hotbar, the XP strip, and the chat log. Driven entirely
   by props from index.html so it stays a pure view. */
const HudNS = window.BrowserGameARPGDesignSystem_aa965c;
const {
  OrbGauge,
  AbilitySlot,
  IconSlot,
  ResourceBar,
  Badge
} = HudNS;
const FX = n => `../../assets/fx/${n}.png`;
function Chip({
  children,
  style = {}
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      alignItems: 'center',
      gap: 10,
      padding: '6px 11px',
      background: 'var(--surface-inset)',
      border: '1px solid var(--border-accent)',
      borderRadius: 'var(--radius-md)',
      fontSize: 'var(--text-sm)',
      color: 'var(--text-body)',
      backdropFilter: 'blur(2px)',
      ...style
    }
  }, children);
}
function Hud({
  player,
  abilities,
  onCast,
  belt,
  onDrink,
  chat,
  onOpenInventory,
  onOpenMerchant
}) {
  return /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 10,
      left: 10,
      display: 'flex',
      gap: 8,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement(Chip, null, /*#__PURE__*/React.createElement("span", {
    style: {
      fontFamily: 'var(--font-display)',
      textTransform: 'uppercase',
      letterSpacing: '0.08em',
      color: 'var(--text-display)'
    }
  }, "Gloomwood"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--text-faint)'
    }
  }, "\xB7"), /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--ok)'
    }
  }, "\u25CF 4")), /*#__PURE__*/React.createElement(Chip, {
    style: {
      borderColor: 'var(--border-subtle)'
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--coin)',
      fontFamily: 'var(--font-mono)',
      fontWeight: 700
    }
  }, "\u25C8 ", player.gold))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 10,
      right: 10,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 132,
      height: 132,
      background: 'var(--surface-panel)',
      border: '2px solid var(--border-accent)',
      borderRadius: 'var(--radius-md)',
      boxShadow: 'var(--shadow-panel)',
      position: 'relative',
      overflow: 'hidden'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      background: 'radial-gradient(circle at 50% 50%, #233019, #0d130b)',
      opacity: 0.9
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '50%',
      top: '52%',
      width: 7,
      height: 7,
      transform: 'translate(-50%,-50%)',
      borderRadius: '50%',
      background: 'var(--essence)',
      boxShadow: '0 0 6px var(--essence)'
    }
  }), [[34, 40], [66, 30], [70, 64], [44, 70]].map(([x, y], i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      position: 'absolute',
      left: `${x}%`,
      top: `${y}%`,
      width: 4,
      height: 4,
      borderRadius: '50%',
      background: 'var(--danger)'
    }
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      right: 6,
      top: '40%',
      width: 6,
      height: 6,
      borderRadius: '50%',
      background: 'var(--fx-arcane)',
      boxShadow: '0 0 6px var(--fx-arcane)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 3,
      left: 0,
      right: 0,
      textAlign: 'center',
      fontFamily: 'var(--font-display)',
      fontSize: 9,
      letterSpacing: '0.1em',
      textTransform: 'uppercase',
      color: 'var(--gold-500)'
    }
  }, "Gloomwood"))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 154,
      right: 10,
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement("button", {
    onClick: onOpenInventory,
    style: menuBtn
  }, "\u25A3", /*#__PURE__*/React.createElement("span", {
    style: menuKey
  }, "I")), /*#__PURE__*/React.createElement("button", {
    onClick: onOpenMerchant,
    style: menuBtn
  }, "\u25C8", /*#__PURE__*/React.createElement("span", {
    style: menuKey
  }, "M"))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 18,
      left: 18,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement(OrbGauge, {
    type: "health",
    value: player.hp,
    max: player.maxHp
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 18,
      right: 18,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement(OrbGauge, {
    type: "mana",
    value: player.mp,
    max: player.maxMp
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 26,
      left: '50%',
      transform: 'translateX(-50%)',
      display: 'flex',
      alignItems: 'flex-end',
      gap: 12,
      zIndex: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: 6
    }
  }, /*#__PURE__*/React.createElement(PotionSlot, {
    color: "var(--hp)",
    highlight: "var(--hp-glow)",
    count: belt.health,
    hotkey: "Q",
    onClick: () => onDrink('health')
  }), /*#__PURE__*/React.createElement(PotionSlot, {
    color: "var(--mana)",
    highlight: "var(--mana-glow)",
    count: belt.mana,
    hotkey: "E",
    onClick: () => onDrink('mana')
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: 10
    }
  }, abilities.map((a, i) => /*#__PURE__*/React.createElement(AbilitySlot, {
    key: i,
    src: FX(a.icon),
    hotkey: a.key,
    cooldown: a.cd,
    cooldownText: a.cd > 0 ? a.cdText : null,
    disabled: a.disabled,
    onClick: () => onCast(i)
  })))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 6,
      left: '50%',
      transform: 'translateX(-50%)',
      width: 'min(620px, 60vw)',
      zIndex: 9
    }
  }, /*#__PURE__*/React.createElement(ResourceBar, {
    kind: "xp",
    value: player.xp,
    max: player.xpMax,
    height: 6
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      bottom: 96,
      left: 14,
      width: 'min(330px, 40vw)',
      zIndex: 8
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 2,
      padding: '8px 10px',
      background: 'rgba(0,0,0,0.4)',
      borderRadius: 'var(--radius-md)',
      fontSize: 'var(--text-sm)',
      lineHeight: 1.4
    }
  }, chat.map((c, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      color: c.color || 'var(--text-body)'
    }
  }, c.who && /*#__PURE__*/React.createElement("span", {
    style: {
      color: 'var(--gold-500)',
      fontWeight: 600
    }
  }, c.who, ": "), c.text)))));
}
const menuBtn = {
  width: 38,
  height: 38,
  position: 'relative',
  background: 'var(--surface-inset)',
  border: '1px solid var(--border-accent)',
  borderRadius: 'var(--radius-md)',
  color: 'var(--gold-300)',
  fontSize: 16,
  cursor: 'pointer'
};
const menuKey = {
  position: 'absolute',
  bottom: 1,
  right: 3,
  fontSize: 8,
  color: 'var(--gold-600)',
  fontFamily: 'var(--font-body)',
  fontWeight: 700
};
function PotionSlot({
  color,
  highlight,
  count,
  hotkey,
  onClick
}) {
  return /*#__PURE__*/React.createElement("div", {
    onClick: onClick,
    style: {
      position: 'relative',
      width: 44,
      height: 44,
      background: 'var(--surface-panel)',
      border: '1.5px solid var(--gold-500)',
      borderRadius: 'var(--radius-slot)',
      cursor: 'pointer',
      display: 'grid',
      placeItems: 'center',
      opacity: count > 0 ? 1 : 0.4
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 18,
      height: 24,
      borderRadius: '40% 40% 50% 50%',
      background: `radial-gradient(circle at 38% 30%, ${highlight}, ${color})`,
      border: '1px solid rgba(0,0,0,0.5)',
      boxShadow: `0 0 7px ${color}`
    }
  }), /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      top: 1,
      left: 3,
      fontSize: 9,
      fontWeight: 700,
      color: 'var(--gold-500)'
    }
  }, hotkey), /*#__PURE__*/React.createElement("span", {
    style: {
      position: 'absolute',
      bottom: 1,
      right: 4,
      fontSize: 11,
      fontWeight: 700,
      color: 'var(--gold-300)'
    }
  }, count));
}
window.GloomHud = Hud;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/gloomwood-hud/Hud.jsx", error: String((e && e.message) || e) }); }

// ui_kits/gloomwood-hud/InventoryView.jsx
try { (() => {
/* InventoryView — the character + bag window. An equipment doll (gold slots) on
   the left, the bag grid on the right, and a live ItemTooltip on hover. Composes
   Panel + IconSlot + ItemTooltip + Badge from the design system. */
const InvNS = window.BrowserGameARPGDesignSystem_aa965c;
const {
  Panel: InvPanel,
  IconSlot: InvSlot,
  ItemTooltip: InvTooltip,
  Badge: InvBadge
} = InvNS;
const ICON = n => `../../assets/icons/${n}.png`;
const EQUIP_SLOTS = [{
  key: 'head',
  label: 'Head'
}, {
  key: 'chest',
  label: 'Chest'
}, {
  key: 'mainhand',
  label: 'Weapon'
}, {
  key: 'offhand',
  label: 'Off'
}, {
  key: 'ring',
  label: 'Ring'
}, {
  key: 'feet',
  label: 'Boots'
}];
function InventoryView({
  bag,
  equipped,
  onClose
}) {
  const [hover, setHover] = React.useState(null);
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative'
    }
  }, /*#__PURE__*/React.createElement(InvPanel, {
    title: "Inventory",
    subtitle: `${bag.length} / 30 · Aldermere`,
    onClose: onClose,
    width: 460,
    footer: "Tap an item to equip \xB7 sell at the Merchant to clear space \xB7 Esc to close"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: 16
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      letterSpacing: '0.16em',
      textTransform: 'uppercase',
      color: 'var(--text-label)',
      marginBottom: 8
    }
  }, "Equipped"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(2, 56px)',
      gap: 8
    }
  }, EQUIP_SLOTS.map(s => {
    const it = equipped[s.key];
    return /*#__PURE__*/React.createElement("div", {
      key: s.key,
      style: {
        textAlign: 'center'
      }
    }, /*#__PURE__*/React.createElement(InvSlot, {
      src: it ? ICON(it.icon) : null,
      rarity: it ? it.rarity : null,
      empty: !it,
      size: 56,
      onMouseEnter: () => it && setHover(it),
      onMouseLeave: () => setHover(null)
    }), /*#__PURE__*/React.createElement("div", {
      style: {
        fontSize: 9,
        color: 'var(--text-faint)',
        marginTop: 2
      }
    }, s.label));
  }))), /*#__PURE__*/React.createElement("div", {
    style: {
      flex: 1
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 10,
      letterSpacing: '0.16em',
      textTransform: 'uppercase',
      color: 'var(--text-label)',
      marginBottom: 8
    }
  }, "Bag"), /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(5, 1fr)',
      gap: 6
    }
  }, bag.map((it, i) => /*#__PURE__*/React.createElement(InvSlot, {
    key: i,
    src: ICON(it.icon),
    rarity: it.rarity,
    count: it.count,
    size: 52,
    onMouseEnter: () => setHover(it),
    onMouseLeave: () => setHover(null)
  })), Array.from({
    length: Math.max(0, 15 - bag.length)
  }).map((_, i) => /*#__PURE__*/React.createElement(InvSlot, {
    key: `e${i}`,
    empty: true,
    size: 52
  })))))), hover && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      top: 40,
      left: '100%',
      marginLeft: 12,
      zIndex: 70
    }
  }, /*#__PURE__*/React.createElement(InvTooltip, hover.tip)));
}
window.GloomInventory = InventoryView;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/gloomwood-hud/InventoryView.jsx", error: String((e && e.message) || e) }); }

// ui_kits/gloomwood-hud/MerchantView.jsx
try { (() => {
/* MerchantView — the vendor window: a stock grid of common gear (vendor rolls are
   always common), a gold balance, buy buttons, and an item tooltip on hover.
   Composes Panel + IconSlot + ItemTooltip + Button + Badge. */
const ShopNS = window.BrowserGameARPGDesignSystem_aa965c;
const {
  Panel: ShopPanel,
  IconSlot: ShopSlot,
  ItemTooltip: ShopTooltip,
  Button: ShopButton
} = ShopNS;
const SICON = n => `../../assets/icons/${n}.png`;
function MerchantView({
  stock,
  gold,
  onClose,
  onBuy
}) {
  const [sel, setSel] = React.useState(0);
  const item = stock[sel];
  return /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      gap: 14,
      alignItems: 'flex-start'
    }
  }, /*#__PURE__*/React.createElement(ShopPanel, {
    title: "Bartholomew",
    subtitle: "Merchant \xB7 Aldermere",
    onClose: onClose,
    width: 300,
    footer: /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("span", {
      style: {
        color: 'var(--coin)'
      }
    }, "\u25C8 ", gold, "g"), " \xA0\xB7\xA0 Common stock refreshes on rest")
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'grid',
      gridTemplateColumns: 'repeat(4, 1fr)',
      gap: 7
    }
  }, stock.map((it, i) => /*#__PURE__*/React.createElement(ShopSlot, {
    key: i,
    src: SICON(it.icon),
    rarity: it.rarity,
    size: 56,
    selected: i === sel,
    onClick: () => setSel(i)
  })))), item && /*#__PURE__*/React.createElement("div", {
    style: {
      display: 'flex',
      flexDirection: 'column',
      gap: 10,
      alignItems: 'center'
    }
  }, /*#__PURE__*/React.createElement(ShopTooltip, item.tip), /*#__PURE__*/React.createElement(ShopButton, {
    variant: "primary",
    size: "sm",
    block: true,
    disabled: gold < item.price,
    onClick: () => onBuy(item)
  }, "Buy \xB7 ", item.price, "g")));
}
window.GloomMerchant = MerchantView;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/gloomwood-hud/MerchantView.jsx", error: String((e && e.message) || e) }); }

// ui_kits/gloomwood-hud/Scene.jsx
try { (() => {
/* Scene — the 2.5D world viewport behind the HUD. Procedural-shape entities
   (matching the game's current renderer), scattered pixel-art decor, an edge
   vignette + corruption pall (atmosphere.ts), a torch-lit player, and monsters
   wearing Nameplates. Pure presentation; the parent passes the biome + entities. */
const SceneNS = window.BrowserGameARPGDesignSystem_aa965c;
const {
  Nameplate: SceneNameplate,
  RarityName: SceneRarityName
} = SceneNS;
const DECOR = n => `../../assets/decor/${n}.png`;
function EntityToken({
  x,
  y,
  color,
  ring,
  size = 30,
  light = 0
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: `${x}%`,
      top: `${y}%`,
      transform: 'translate(-50%,-50%)'
    }
  }, light > 0 && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '50%',
      top: '55%',
      width: light,
      height: light,
      transform: 'translate(-50%,-50%)',
      borderRadius: '50%',
      background: 'radial-gradient(circle, rgba(255,174,92,0.22), transparent 70%)',
      pointerEvents: 'none'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '50%',
      top: `${size * 0.72}px`,
      width: size * 0.9,
      height: size * 0.34,
      transform: 'translate(-50%,-50%)',
      borderRadius: '50%',
      background: 'rgba(0,0,0,0.45)',
      filter: 'blur(2px)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'relative',
      width: size,
      height: size,
      borderRadius: '46% 46% 48% 48% / 60% 60% 40% 40%',
      background: `radial-gradient(circle at 42% 30%, ${color}, #0c0d10 130%)`,
      border: `2px solid ${ring}`,
      boxShadow: `0 0 10px ${ring}66, inset 0 -4px 6px rgba(0,0,0,0.5)`
    }
  }));
}
function Scene({
  entities = [],
  decor = [],
  loot = []
}) {
  return /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      overflow: 'hidden',
      background: 'radial-gradient(140% 120% at 50% 18%, #28331f 0%, #1b241a 38%, #121a14 70%, #0c100b 100%)'
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      backgroundImage: 'radial-gradient(rgba(60,80,45,0.5) 1px, transparent 1.4px), radial-gradient(rgba(20,28,16,0.6) 1px, transparent 1.4px)',
      backgroundSize: '22px 22px, 31px 31px',
      backgroundPosition: '0 0, 11px 14px',
      opacity: 0.5
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: '-10%',
      top: '46%',
      width: '120%',
      height: '22%',
      background: 'linear-gradient(180deg, transparent, rgba(54,42,28,0.45) 50%, transparent)',
      transform: 'rotate(-4deg)',
      filter: 'blur(3px)'
    }
  }), decor.map((d, i) => /*#__PURE__*/React.createElement("img", {
    key: i,
    src: DECOR(d.img),
    alt: "",
    style: {
      position: 'absolute',
      left: `${d.x}%`,
      top: `${d.y}%`,
      transform: `translate(-50%,-100%) scale(${d.scale || 2})`,
      imageRendering: 'pixelated',
      filter: 'drop-shadow(0 3px 2px rgba(0,0,0,0.6)) brightness(0.92)',
      zIndex: Math.round(d.y)
    }
  })), loot.map((l, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      position: 'absolute',
      left: `${l.x}%`,
      top: `${l.y}%`,
      transform: 'translate(-50%,-50%)',
      textAlign: 'center',
      zIndex: 500
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 30,
      height: 60,
      margin: '0 auto',
      background: `linear-gradient(180deg, var(--rarity-${l.rarity}), transparent)`,
      opacity: 0.5,
      filter: 'blur(3px)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: -34,
      fontSize: 11
    }
  }, /*#__PURE__*/React.createElement(SceneRarityName, {
    rarity: l.rarity,
    size: "sm"
  }, l.name)))), entities.map((e, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      position: 'absolute',
      inset: 0,
      zIndex: Math.round(e.y) + 200,
      pointerEvents: 'none'
    }
  }, /*#__PURE__*/React.createElement(EntityToken, e), e.plate && /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      left: `${e.x}%`,
      top: `${e.y - 7}%`,
      transform: 'translate(-50%,-100%)'
    }
  }, /*#__PURE__*/React.createElement(SceneNameplate, e.plate)))), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      right: '3%',
      top: '40%',
      textAlign: 'center',
      zIndex: 400
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      width: 54,
      height: 80,
      borderRadius: '50%',
      background: 'radial-gradient(circle, rgba(176,122,232,0.6), rgba(40,12,60,0.2) 70%)',
      border: '2px solid var(--fx-arcane)',
      boxShadow: '0 0 24px var(--fx-arcane)'
    }
  }), /*#__PURE__*/React.createElement("div", {
    style: {
      marginTop: 4,
      fontFamily: 'var(--font-display)',
      fontSize: 10,
      letterSpacing: '0.08em',
      textTransform: 'uppercase',
      color: 'var(--fx-arcane)'
    }
  }, "Shadow Crypt \u2193")), /*#__PURE__*/React.createElement("div", {
    style: {
      position: 'absolute',
      inset: 0,
      pointerEvents: 'none',
      background: 'radial-gradient(120% 100% at 50% 45%, transparent 45%, rgba(0,0,0,0.55) 100%), radial-gradient(80% 80% at 50% 60%, transparent 60%, rgba(58,8,16,0.25) 100%)'
    }
  }));
}
window.GloomScene = Scene;
})(); } catch (e) { __ds_ns.__errors.push({ path: "ui_kits/gloomwood-hud/Scene.jsx", error: String((e && e.message) || e) }); }

__ds_ns.Button = __ds_scope.Button;

__ds_ns.IconSlot = __ds_scope.IconSlot;

__ds_ns.Panel = __ds_scope.Panel;

__ds_ns.AbilitySlot = __ds_scope.AbilitySlot;

__ds_ns.Nameplate = __ds_scope.Nameplate;

__ds_ns.OrbGauge = __ds_scope.OrbGauge;

__ds_ns.ResourceBar = __ds_scope.ResourceBar;

__ds_ns.Badge = __ds_scope.Badge;

__ds_ns.ItemTooltip = __ds_scope.ItemTooltip;

__ds_ns.RARITY_COLOR = __ds_scope.RARITY_COLOR;

__ds_ns.RarityName = __ds_scope.RarityName;

})();
