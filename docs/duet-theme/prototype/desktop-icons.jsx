// desktop-icons.jsx
// Original SVG marks for DuetOS. The Duet glyph is two interlocking arcs forming a "D".

// The Duet logomark — two arcs in counter-rotation, the OS's own thing.
function DuetMark({ size=20, accent="var(--accent)", accent2="var(--accent-2)", strokeWidth }) {
  const sw = strokeWidth ?? Math.max(1.6, size*0.11);
  const r = size*0.34;
  const c = size/2;
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} fill="none" aria-hidden="true">
      <circle cx={c-size*0.08} cy={c} r={r} stroke={accent} strokeWidth={sw}
              strokeLinecap="round" strokeDasharray={`${r*Math.PI*1.05} ${r*Math.PI*2}`}
              transform={`rotate(-30 ${c-size*0.08} ${c})`} />
      <circle cx={c+size*0.08} cy={c} r={r} stroke={accent2} strokeWidth={sw}
              strokeLinecap="round" strokeDasharray={`${r*Math.PI*1.05} ${r*Math.PI*2}`}
              transform={`rotate(150 ${c+size*0.08} ${c})`} />
    </svg>
  );
}

// Generic 1-color stroke icon helper
function Stroke({ d, size=16, sw=1.6, color="currentColor", style, ...rest }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
         stroke={color} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round"
         style={style} {...rest}>{d}</svg>
  );
}

const Icon = {
  Duet:  (p) => <DuetMark {...p} />,
  Search:(p) => <Stroke {...p} d={<><circle cx="11" cy="11" r="6"/><path d="M20 20l-3.5-3.5"/></>} />,
  Folder:(p) => <Stroke {...p} d={<><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/></>} />,
  Term:  (p) => <Stroke {...p} d={<><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/></>} />,
  Inspect:(p)=> <Stroke {...p} d={<><circle cx="11" cy="11" r="6"/><path d="M20 20l-3.5-3.5"/><path d="M8.5 11h5M11 8.5v5"/></>} />,
  TaskMgr:(p)=> <Stroke {...p} d={<><path d="M3 19h18"/><rect x="5" y="11" width="3" height="8"/><rect x="10.5" y="7" width="3" height="12"/><rect x="16" y="13" width="3" height="6"/></>} />,
  Klog:  (p) => <Stroke {...p} d={<><rect x="3" y="4" width="18" height="16" rx="2"/><path d="M6 8h12M6 12h8M6 16h10"/></>} />,
  Calc:  (p) => <Stroke {...p} d={<><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M8 7h8M8 12h.01M12 12h.01M16 12h.01M8 16h.01M12 16h.01M16 16h.01"/></>} />,
  Note:  (p) => <Stroke {...p} d={<><path d="M5 4h10l4 4v12a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1Z"/><path d="M14 4v5h5M8 13h8M8 17h6"/></>} />,
  Reg:   (p) => <Stroke {...p} d={<><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="8" cy="6" r="1.4"/><circle cx="14" cy="12" r="1.4"/><circle cx="10" cy="18" r="1.4"/></>} />,
  Gfx:   (p) => <Stroke {...p} d={<><rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 16l5-5 4 4 3-3 6 6"/><circle cx="9" cy="10" r="1.4"/></>} />,
  Power: (p) => <Stroke {...p} d={<><path d="M12 4v8"/><path d="M7.5 7.5a7 7 0 1 0 9 0"/></>} />,
  Pin:   (p) => <Stroke {...p} d={<><path d="M14 4l6 6-3 1-3 5-3-3-5 5 3-7-3-3 5-3 1-1Z"/></>} />,
  Cog:   (p) => <Stroke {...p} d={<><circle cx="12" cy="12" r="3"/><path d="M19.4 14a1.6 1.6 0 0 0 .3 1.7l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.7-.3 1.6 1.6 0 0 0-1 1.5V20a2 2 0 0 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.7.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.7 1.6 1.6 0 0 0-1.5-1H4a2 2 0 0 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.7l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.7.3H10a1.6 1.6 0 0 0 1-1.5V4a2 2 0 0 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.7-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.7V10a1.6 1.6 0 0 0 1.5 1H20a2 2 0 0 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z"/></>} />,
  Min:   (p) => <Stroke {...p} sw={1.4} d={<path d="M5 12h14"/>} />,
  Max:   (p) => <Stroke {...p} sw={1.4} d={<rect x="5" y="5" width="14" height="14"/>} />,
  Restore:(p)=> <Stroke {...p} sw={1.4} d={<><rect x="4" y="7" width="12" height="12"/><path d="M8 7V5h12v12h-2"/></>} />,
  X:     (p) => <Stroke {...p} sw={1.5} d={<path d="M6 6l12 12M18 6l-12 12"/>} />,
  Chev:  (p) => <Stroke {...p} d={<path d="M6 9l6 6 6-6"/>} />,
  Net:   (p) => <Stroke {...p} d={<><path d="M2 8c5-5 15-5 20 0"/><path d="M5 12c4-4 10-4 14 0"/><path d="M8 16c2-2 6-2 8 0"/><circle cx="12" cy="20" r=".8" fill="currentColor"/></>} />,
  Vol:   (p) => <Stroke {...p} d={<><path d="M4 10v4h3l5 4V6L7 10H4Z"/><path d="M16 9c1 1 1 5 0 6"/><path d="M19 7c2 2 2 8 0 10"/></>} />,
  Battery:(p)=> <Stroke {...p} d={<><rect x="3" y="8" width="16" height="8" rx="1.5"/><path d="M21 11v2"/><rect x="5" y="10" width="10" height="4" fill="currentColor" stroke="none"/></>} />,
  Cpu:   (p) => <Stroke {...p} d={<><rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 3v2M12 3v2M15 3v2M9 19v2M12 19v2M15 19v2M3 9h2M3 12h2M3 15h2M19 9h2M19 12h2M19 15h2"/></>} />,
  Wave:  (p) => <Stroke {...p} d={<path d="M3 12h2l2-6 3 12 3-9 2 6h6"/>} />,
  Linux: (p) => <Stroke {...p} d={<><path d="M9 4c-2 2-2 5-1 8-2 1-3 4-3 7h14c0-3-1-6-3-7 1-3 1-6-1-8a3 3 0 0 0-6 0Z"/><circle cx="10" cy="9" r=".8" fill="currentColor"/><circle cx="14" cy="9" r=".8" fill="currentColor"/></>} />,
  Pe:    (p) => <Stroke {...p} d={<><rect x="4" y="4" width="16" height="16" rx="1"/><path d="M8 8h4a2 2 0 0 1 0 4H8V8Zm0 0v8"/></>} />,
  Native:(p) => <Stroke {...p} d={<><circle cx="12" cy="12" r="8"/><path d="M12 4v16M4 12h16"/></>} />,
};

Object.assign(window, { Icon, DuetMark });
