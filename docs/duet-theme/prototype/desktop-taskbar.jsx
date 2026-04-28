// desktop-taskbar.jsx — Bottom taskbar with Start, search, pinned/running apps, tray, clock.

const { useState: useTbState, useEffect: useTbEffect } = React;

function Taskbar({ pos, density, onStartToggle, startOpen, runningWindows, onAppClick, pinned, onLaunch, showWidgets }) {
  const horizontal = pos === "bottom" || pos === "top";
  const tbH = density === "compact" ? 38 : 44;
  const tbW = density === "compact" ? 56 : 64;

  const containerStyle = {
    position:"absolute",
    background:"var(--chrome-2)",
    borderTop:    pos==="bottom" ? "1px solid var(--line-2)" : "0",
    borderBottom: pos==="top"    ? "1px solid var(--line-2)" : "0",
    borderRight:  pos==="left"   ? "1px solid var(--line-2)" : "0",
    borderLeft:   pos==="right"  ? "1px solid var(--line-2)" : "0",
    boxShadow: pos==="bottom" ? "0 -8px 24px -8px rgba(0,0,0,.45)"
             : pos==="top"    ? "0  8px 24px -8px rgba(0,0,0,.45)"
             :                  "0  0   24px -8px rgba(0,0,0,.45)",
    backdropFilter:"blur(20px) saturate(140%)",
    WebkitBackdropFilter:"blur(20px) saturate(140%)",
    zIndex:900,
    display:"flex",
    alignItems:"center",
    gap:2,
  };
  if (pos === "bottom") Object.assign(containerStyle, { left:0, right:0, bottom:0, height:tbH, padding:"0 8px" });
  if (pos === "top")    Object.assign(containerStyle, { left:0, right:0, top:0,    height:tbH, padding:"0 8px" });
  if (pos === "left")   Object.assign(containerStyle, { left:0, top:0, bottom:0,    width:tbW, padding:"8px 0", flexDirection:"column" });
  if (pos === "right")  Object.assign(containerStyle, { right:0, top:0, bottom:0,   width:tbW, padding:"8px 0", flexDirection:"column" });

  return (
    <div style={containerStyle}>
      <StartButton open={startOpen} onClick={onStartToggle} compact={!horizontal}/>
      {horizontal && <SearchPill/>}
      <span style={horizontal ? { width:6 } : { height:6 }}/>
      <div style={{
        display:"flex",
        flexDirection: horizontal ? "row" : "column",
        gap:2, alignItems:"center",
      }}>
        {pinned.map(p => {
          const running = runningWindows.find(w => w.appId === p.id);
          const focused = running && running.focused;
          return (
            <TaskbarApp key={p.id}
              icon={p.icon}
              label={p.label}
              running={!!running}
              focused={focused}
              minimized={running?.minimized}
              onClick={()=>{ running ? onAppClick(running.id) : onLaunch(p.id); }}
              vertical={!horizontal}
            />
          );
        })}
        {/* Running apps that aren't pinned */}
        {runningWindows.filter(w => !pinned.find(p => p.id === w.appId)).map(w => (
          <TaskbarApp key={w.id}
            icon={w.icon || Icon.Pe}
            label={w.title}
            running
            focused={w.focused}
            minimized={w.minimized}
            onClick={()=>onAppClick(w.id)}
            vertical={!horizontal}
          />
        ))}
      </div>
      <span style={{flex:1}}/>
      {showWidgets && horizontal && <WidgetsPill/>}
      <Tray vertical={!horizontal}/>
      <Clock vertical={!horizontal}/>
      {horizontal && <ShowDesktopRail/>}
    </div>
  );
}

function StartButton({ open, onClick, compact }) {
  const [hov, setHov] = useTbState(false);
  return (
    <button onClick={onClick}
      onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)}
      style={{
        appearance:"none", border:0, height:34, minWidth: compact ? 40 : 46,
        padding:"0 10px",
        display:"flex", alignItems:"center", gap:8, cursor:"default",
        background: open ? "color-mix(in oklab, var(--accent) 22%, transparent)"
                  : hov  ? "var(--hover)" : "transparent",
        color: open ? "var(--accent)" : "var(--ink)",
        borderRadius:6, position:"relative",
      }}
      title="Start (Ctrl+Esc)"
    >
      <DuetMark size={20} accent={open ? "var(--accent)" : "var(--accent)"} accent2={open ? "var(--accent-2)":"var(--accent-2)"}/>
      {!compact && <span style={{fontSize:12, fontWeight:600, letterSpacing:.2}}>Duet</span>}
    </button>
  );
}

function SearchPill() {
  return (
    <div style={{
      display:"flex", alignItems:"center", gap:8,
      height:30, padding:"0 12px",
      background:"var(--chrome-3)", border:"1px solid var(--line)",
      borderRadius:999, color:"var(--ink-3)",
      minWidth:220,
    }}>
      <Icon.Search size={13}/>
      <span style={{fontSize:11.5}}>Search apps · syscalls · pids</span>
    </div>
  );
}

function TaskbarApp({ icon:I, label, running, focused, minimized, onClick, vertical }) {
  const [hov, setHov] = useTbState(false);
  return (
    <button onClick={onClick}
      onMouseEnter={()=>setHov(true)} onMouseLeave={()=>setHov(false)}
      title={label}
      style={{
        appearance:"none", border:0, cursor:"default",
        width:34, height:34, borderRadius:6, padding:0,
        background: focused ? "color-mix(in oklab, var(--accent) 18%, transparent)"
                  : hov     ? "var(--hover)"
                  : "transparent",
        color: focused ? "var(--accent)" : "var(--ink-2)",
        display:"flex", alignItems:"center", justifyContent:"center",
        position:"relative",
      }}
    >
      <I size={16}/>
      {running && (
        <span style={{
          position:"absolute",
          ...(vertical
            ? { left:1, top:"50%", transform:"translateY(-50%)", width:2, height: focused ? 14 : 8 }
            : { bottom:1, left:"50%", transform:"translateX(-50%)", height:2, width: focused ? 14 : 8 }),
          background: minimized ? "var(--ink-3)" : "var(--accent)",
          borderRadius:1,
        }}/>
      )}
    </button>
  );
}

function WidgetsPill() {
  return (
    <div style={{
      display:"flex", alignItems:"center", gap:10,
      height:30, padding:"0 12px", marginRight:6,
      background:"var(--chrome-3)", border:"1px solid var(--line)", borderRadius:999,
    }}>
      <Icon.Cpu size={13} color="var(--accent)"/>
      <span className="mono" style={{fontSize:11, color:"var(--ink-2)"}}>CPU 14%</span>
      <span style={{width:1,height:12,background:"var(--line-2)"}}/>
      <Icon.Wave size={13} color="var(--accent-2)"/>
      <span className="mono" style={{fontSize:11, color:"var(--ink-2)"}}>60.0 fps</span>
    </div>
  );
}

function Tray({ vertical }) {
  return (
    <div style={{
      display:"flex", flexDirection: vertical ? "column" : "row",
      alignItems:"center", gap:2,
      padding: vertical ? "4px 0" : "0 4px",
      borderLeft: vertical ? "0" : "1px solid var(--line)",
      borderTop:  vertical ? "1px solid var(--line)" : "0",
      marginLeft: vertical ? 0 : 6, marginTop: vertical ? 6 : 0,
      paddingLeft: vertical ? 0 : 10,
    }}>
      <Icon.Chev size={12} color="var(--ink-3)"/>
      <span style={{width: vertical ? 0 : 4, height: vertical ? 4 : 0}}/>
      <Icon.Net     size={14} color="var(--ink-2)"/>
      <Icon.Vol     size={14} color="var(--ink-2)"/>
      <Icon.Battery size={14} color="var(--accent)"/>
    </div>
  );
}

function Clock({ vertical }) {
  const [t, setT] = useTbState(() => new Date());
  useTbEffect(() => {
    const id = setInterval(() => setT(new Date()), 30000);
    return () => clearInterval(id);
  }, []);
  const hh = t.getHours().toString().padStart(2,"0");
  const mm = t.getMinutes().toString().padStart(2,"0");
  const date = t.toLocaleDateString(undefined, { month:"short", day:"numeric" });
  return (
    <div className="mono" style={{
      display:"flex", flexDirection:"column", alignItems: vertical ? "center" : "flex-end",
      padding: vertical ? "8px 4px" : "0 12px 0 8px", lineHeight:1.15,
      fontSize:11.5, color:"var(--ink)",
    }}>
      <div style={{fontWeight:600}}>{hh}:{mm}</div>
      <div style={{fontSize:10, color:"var(--ink-3)"}}>{date}</div>
    </div>
  );
}

function ShowDesktopRail() {
  // Tiny rail at the right edge — nods to Win7's "Show desktop" button but rendered our way.
  return (
    <div title="Show desktop"
         style={{
           width:6, alignSelf:"stretch", marginLeft:2,
           background:"linear-gradient(180deg, var(--accent), var(--accent-2))",
           opacity:.65, borderRadius:2, cursor:"default",
         }}/>
  );
}

Object.assign(window, { Taskbar });
