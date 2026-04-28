// desktop-app.jsx — root component. Wires the desktop, taskbar, start menu, windows, tweaks.

const { useState: useAS, useEffect: useAE, useMemo: useAM, useRef: useAR } = React;

const APPS = {
  taskmgr: { id:"taskmgr", title:"Task Manager",            icon:Icon.TaskMgr, w:780, h:520, render:()=> <TaskManagerWindow/> },
  klog:    { id:"klog",    title:"Kernel Log",              icon:Icon.Klog,    w:680, h:440, render:()=> <KernelLogWindow/>,    subtitle:"/sys/klog · live" },
  inspect: { id:"inspect", title:"Inspect — windows-kill.exe", icon:Icon.Inspect, w:840, h:520, render:()=> <InspectWindow/>,   subtitle:"PE32+ · x86_64" },
};

const ACCENTS = {
  "teal-amber": { a:"#2dd4bf", b:"#f5b73a" },
  "blue":       { a:"#4aa3ff", b:"#80c8ff" },
  "violet":     { a:"#a78bfa", b:"#f0abfc" },
  "amber":      { a:"#f5b73a", b:"#ffe08a" },
  "duet-green": { a:"#36d399", b:"#aef0c2" },
};

function applyAccent(name) {
  const a = ACCENTS[name] || ACCENTS["teal-amber"];
  document.documentElement.style.setProperty("--accent",   a.a);
  document.documentElement.style.setProperty("--accent-2", a.b);
}

function App() {
  const [t, setTweak] = useTweaks(window.TWEAK_DEFAULTS);

  // Apply theme + accent on every change
  useAE(() => { document.documentElement.dataset.theme = t.theme; }, [t.theme]);
  useAE(() => applyAccent(t.accent), [t.accent]);
  useAE(() => {
    const tbH = t.density === "compact" ? 38 : 44;
    const tbW = t.density === "compact" ? 56 : 64;
    document.documentElement.style.setProperty("--taskbar-h", (t.taskbarPos==="bottom"||t.taskbarPos==="top") ? tbH+"px" : "0px");
    document.documentElement.style.setProperty("--taskbar-w", (t.taskbarPos==="left"||t.taskbarPos==="right") ? tbW+"px" : "0px");
  }, [t.taskbarPos, t.density]);

  // Window state
  const [wins, setWins] = useAS(() => initialWindows());
  const [startOpen, setStart] = useAS(!!t.startOpen);
  useAE(() => { setStart(!!t.startOpen); }, [t.startOpen]);

  function initialWindows() {
    const layout = [
      { ...APPS.klog,    x:36,  y:80,  z:1, focused:false },
      { ...APPS.taskmgr, x:240, y:140, z:2, focused:false },
      { ...APPS.inspect, x:520, y:90,  z:3, focused:true  },
    ].map((a,i) => ({
      id:"w"+i, appId:a.id, title:a.title, subtitle:a.subtitle, icon:a.icon,
      x:a.x, y:a.y, w:a.w, h:a.h, z:a.z, focused:a.focused,
      minimized:false, maximized:false, render: APPS[a.id].render,
    }));
    return layout;
  }

  const focusWin = (id) => setWins(ws => {
    const max = Math.max(...ws.map(w=>w.z));
    return ws.map(w => ({ ...w, focused: w.id===id, z: w.id===id ? max+1 : w.z }));
  });
  const closeWin = (id) => setWins(ws => ws.filter(w => w.id !== id));
  const toggleMin = (id) => setWins(ws => ws.map(w => w.id===id ? { ...w, minimized:!w.minimized, focused:false } : w));
  const toggleMax = (id) => setWins(ws => ws.map(w => w.id===id ? { ...w, maximized:!w.maximized } : w));
  const moveWin = (id, x, y) => setWins(ws => ws.map(w => w.id===id ? { ...w, x, y } : w));

  const launch = (appId) => {
    const a = APPS[appId];
    if (!a) return;
    setWins(ws => {
      const existing = ws.find(w => w.appId === appId);
      if (existing) {
        const max = Math.max(...ws.map(w=>w.z));
        return ws.map(w => w.id===existing.id ? { ...w, minimized:false, focused:true, z:max+1 } : { ...w, focused:false });
      }
      const max = ws.length ? Math.max(...ws.map(w=>w.z)) : 0;
      return [
        ...ws.map(w => ({ ...w, focused:false })),
        {
          id:"w"+Math.random().toString(36).slice(2,7),
          appId, title:a.title, subtitle:a.subtitle, icon:a.icon,
          x:120 + ws.length*30, y:120 + ws.length*30, w:a.w, h:a.h, z:max+1,
          focused:true, minimized:false, maximized:false, render:a.render,
        }
      ];
    });
    setStart(false);
  };

  // Pinned apps for taskbar
  const pinned = [
    { id:"klog",    label:"Kernel Log",   icon:Icon.Klog },
    { id:"taskmgr", label:"Task Manager", icon:Icon.TaskMgr },
    { id:"inspect", label:"Inspect",      icon:Icon.Inspect },
    { id:"calc",    label:"Calculator",   icon:Icon.Calc },
    { id:"note",    label:"Notepad",      icon:Icon.Note },
    { id:"files",   label:"Files",        icon:Icon.Folder },
  ];

  // Toast for not-yet-implemented apps
  const [toast, setToast] = useAS(null);
  useAE(() => { if (toast) { const id = setTimeout(()=>setToast(null), 2400); return () => clearTimeout(id); } }, [toast]);
  const handleLaunch = (id) => {
    if (APPS[id]) return launch(id);
    setToast(id);
  };

  // Layout offsets for taskbar
  const tbBottom = t.taskbarPos === "bottom";
  const tbTop    = t.taskbarPos === "top";
  const tbLeft   = t.taskbarPos === "left";
  const tbRight  = t.taskbarPos === "right";
  const tbH = t.density === "compact" ? 38 : 44;
  const tbW = t.density === "compact" ? 56 : 64;

  return (
    <div style={{position:"absolute", inset:0, overflow:"hidden", color:"var(--ink)"}}>
      <Wallpaper variant={t.wallpaper}/>

      {/* Desktop area — offsets the taskbar */}
      <div style={{
        position:"absolute",
        top:    tbTop    ? tbH : 0,
        bottom: tbBottom ? tbH : 0,
        left:   tbLeft   ? tbW : 0,
        right:  tbRight  ? tbW : 0,
      }}>
        <DesktopIcons onLaunch={handleLaunch}/>
        <ClockWidget show={t.showWidgets}/>
        <KernelStatsWidget show={t.showWidgets}/>
        {wins.map(w => (
          <Window key={w.id}
            win={w} focused={w.focused} density={t.density}
            onFocus={()=>focusWin(w.id)}
            onMin={()=>toggleMin(w.id)}
            onMax={()=>toggleMax(w.id)}
            onClose={()=>closeWin(w.id)}
            onDrag={(x,y)=>moveWin(w.id, x, y)}
          >
            {w.render()}
          </Window>
        ))}
      </div>

      <Taskbar
        pos={t.taskbarPos} density={t.density}
        onStartToggle={()=>setStart(s=>!s)}
        startOpen={startOpen}
        runningWindows={wins}
        onAppClick={(id)=>{
          const w = wins.find(x => x.id===id);
          if (!w) return;
          if (w.minimized) { toggleMin(id); focusWin(id); }
          else if (w.focused) { toggleMin(id); }
          else focusWin(id);
        }}
        pinned={pinned}
        onLaunch={handleLaunch}
        showWidgets={t.showWidgets}
      />

      <StartMenu open={startOpen} onLaunch={handleLaunch} onClose={()=>setStart(false)}/>

      {toast && (
        <div className="mono" style={{
          position:"absolute", left:"50%", bottom:"calc(var(--taskbar-h, 44px) + 18px)",
          transform:"translateX(-50%)", zIndex:1100,
          background:"var(--chrome)", color:"var(--ink)",
          border:"1px solid var(--line-2)", borderRadius:6,
          padding:"8px 14px", fontSize:11.5,
          boxShadow:"0 12px 32px -10px rgba(0,0,0,.5)",
        }}>
          <span style={{color:"var(--accent-2)"}}>{toast}.duet</span> — not in this prototype yet
        </div>
      )}

      {/* Tweaks panel */}
      <Tweaks t={t} setTweak={setTweak}/>
    </div>
  );
}

// Desktop icons (selectable, double-click to open)
function DesktopIcons({ onLaunch }) {
  const items = [
    { id:"taskmgr", label:"Task Manager", icon:Icon.TaskMgr },
    { id:"klog",    label:"Kernel Log",   icon:Icon.Klog },
    { id:"inspect", label:"Inspect",      icon:Icon.Inspect },
    { id:"files",   label:"Files",        icon:Icon.Folder },
    { id:"gfx",     label:"GFX Demo",     icon:Icon.Gfx },
  ];
  const [sel, setSel] = useAS(null);
  return (
    <div style={{
      position:"absolute", top:18, left:18,
      display:"grid", gridTemplateColumns:"86px", gap:6,
    }} onClick={(e)=>{ if (e.target === e.currentTarget) setSel(null); }}>
      {items.map(it => {
        const active = sel === it.id;
        return (
          <button key={it.id}
            onClick={(e)=>{ e.stopPropagation(); setSel(it.id); }}
            onDoubleClick={()=>onLaunch(it.id)}
            style={{
              appearance:"none", border:"1px solid " + (active ? "color-mix(in oklab, var(--accent) 50%, transparent)" : "transparent"),
              background: active ? "color-mix(in oklab, var(--accent) 18%, transparent)" : "transparent",
              borderRadius:4, padding:"8px 4px",
              display:"flex", flexDirection:"column", alignItems:"center", gap:6,
              color:"#fff", cursor:"default",
              textShadow:"0 1px 2px rgba(0,0,0,.55)",
            }}
          >
            <div style={{
              width:40, height:40, borderRadius:8,
              display:"flex", alignItems:"center", justifyContent:"center",
              background: "color-mix(in oklab, var(--accent) 18%, transparent)",
              color:"var(--accent)",
              border:"1px solid color-mix(in oklab, var(--accent) 35%, transparent)",
              boxShadow:"0 2px 8px rgba(0,0,0,.35)",
            }}><it.icon size={20}/></div>
            <span style={{fontSize:11, fontWeight:500, textAlign:"center", lineHeight:1.2}}>{it.label}</span>
          </button>
        );
      })}
    </div>
  );
}

// Clock widget on desktop (Win7 gadget vibe, our drawing)
function ClockWidget({ show }) {
  const [now, setNow] = useAS(() => new Date());
  useAE(() => { const id = setInterval(()=>setNow(new Date()), 1000); return () => clearInterval(id); }, []);
  if (!show) return null;
  const h = now.getHours() % 12 + now.getMinutes()/60;
  const m = now.getMinutes() + now.getSeconds()/60;
  const s = now.getSeconds();
  const ang = (deg) => `rotate(${deg-90}deg)`;
  return (
    <div style={{
      position:"absolute", right:24, top:22,
      width:170, padding:"14px 14px 12px",
      background:"color-mix(in oklab, var(--chrome) 78%, transparent)",
      border:"1px solid var(--line-2)", borderRadius:10,
      backdropFilter:"blur(18px) saturate(140%)", WebkitBackdropFilter:"blur(18px) saturate(140%)",
      color:"var(--ink)",
      boxShadow:"0 16px 36px -14px rgba(0,0,0,.5)",
    }}>
      <div style={{display:"flex", gap:12, alignItems:"center"}}>
        <div style={{
          width:64, height:64, borderRadius:999, position:"relative",
          background:"radial-gradient(circle at 50% 40%, var(--chrome-2), var(--chrome-3))",
          border:"1px solid var(--line-2)",
        }}>
          {[0,1,2,3,4,5,6,7,8,9,10,11].map(i => (
            <span key={i} style={{
              position:"absolute", left:"50%", top:"50%",
              width:1, height: i%3===0 ? 6 : 3, background:"var(--ink-3)",
              transform:`translate(-50%,-100%) rotate(${i*30}deg) translateY(-22px)`,
              transformOrigin:"50% 100%",
            }}/>
          ))}
          <div style={{position:"absolute", left:"50%", top:"50%", width:2, height:18,
            background:"var(--ink)", borderRadius:1,
            transformOrigin:"50% 100%", transform:`translate(-50%,-100%) ${ang(h*30)}`}}/>
          <div style={{position:"absolute", left:"50%", top:"50%", width:1.5, height:24,
            background:"var(--ink)", borderRadius:1,
            transformOrigin:"50% 100%", transform:`translate(-50%,-100%) ${ang(m*6)}`}}/>
          <div style={{position:"absolute", left:"50%", top:"50%", width:1, height:26,
            background:"var(--accent-2)",
            transformOrigin:"50% 100%", transform:`translate(-50%,-100%) ${ang(s*6)}`}}/>
          <div style={{position:"absolute", left:"50%", top:"50%", width:5, height:5, borderRadius:99,
            background:"var(--accent)", transform:"translate(-50%,-50%)"}}/>
        </div>
        <div className="mono">
          <div style={{fontSize:18, fontWeight:600, fontVariantNumeric:"tabular-nums"}}>
            {now.toTimeString().slice(0,5)}
          </div>
          <div style={{fontSize:10.5, color:"var(--ink-3)"}}>
            {now.toLocaleDateString(undefined,{weekday:"short", month:"short", day:"numeric"})}
          </div>
          <div style={{fontSize:10, color:"var(--ink-3)", marginTop:2}}>UTC+0 · uptime 14m</div>
        </div>
      </div>
    </div>
  );
}

function KernelStatsWidget({ show }) {
  if (!show) return null;
  const rows = [
    ["syscalls",  "57"],
    ["dlls",      "29"],
    ["exports",   "760"],
    ["processes", String(PROCESSES.length)],
    ["compositor","60.0 fps"],
    ["heap",      "412 / 8128 MiB"],
  ];
  return (
    <div style={{
      position:"absolute", right:24, top:228,
      width:198, padding:"10px 12px",
      background:"color-mix(in oklab, var(--chrome) 78%, transparent)",
      border:"1px solid var(--line-2)", borderRadius:10,
      backdropFilter:"blur(18px) saturate(140%)", WebkitBackdropFilter:"blur(18px) saturate(140%)",
      color:"var(--ink)",
      boxShadow:"0 16px 36px -14px rgba(0,0,0,.5)",
    }}>
      <div style={{display:"flex", alignItems:"center", gap:6, marginBottom:6}}>
        <DuetMark size={14}/>
        <span style={{fontSize:11, fontWeight:700, letterSpacing:.6, textTransform:"uppercase", color:"var(--ink-2)"}}>Kernel</span>
      </div>
      {rows.map(([k,v]) => (
        <div key={k} className="mono" style={{display:"flex", justifyContent:"space-between", fontSize:11, padding:"2px 0", color:"var(--ink-2)"}}>
          <span>{k}</span><span style={{color:"var(--ink)"}}>{v}</span>
        </div>
      ))}
    </div>
  );
}

// Tweaks panel
function Tweaks({ t, setTweak }) {
  return (
    <TweaksPanel>
      <TweakSection label="Theme"/>
      <TweakRadio label="Mode" value={t.theme} options={["slate","light","classic"]}
                  onChange={(v)=>setTweak("theme", v)}/>
      <TweakSelect label="Accent" value={t.accent}
                   options={Object.keys(ACCENTS)}
                   onChange={(v)=>setTweak("accent", v)}/>
      <TweakSelect label="Wallpaper" value={t.wallpaper}
                   options={["duet-arcs","topo","syscalls","solid"]}
                   onChange={(v)=>setTweak("wallpaper", v)}/>

      <TweakSection label="Layout"/>
      <TweakSelect label="Taskbar position" value={t.taskbarPos}
                   options={["bottom","top","left","right"]}
                   onChange={(v)=>setTweak("taskbarPos", v)}/>
      <TweakRadio label="Density" value={t.density} options={["compact","regular"]}
                  onChange={(v)=>setTweak("density", v)}/>

      <TweakSection label="State"/>
      <TweakToggle label="Start menu open" value={!!t.startOpen}
                   onChange={(v)=>setTweak("startOpen", v)}/>
      <TweakToggle label="Show desktop widgets" value={!!t.showWidgets}
                   onChange={(v)=>setTweak("showWidgets", v)}/>
    </TweaksPanel>
  );
}

function __mountWhenReady() {
  const need = ["TweaksPanel","useTweaks","Wallpaper","Window","TaskManagerWindow","KernelLogWindow","InspectWindow","StartMenu","Taskbar","Icon","DuetMark","KERNEL_LOG","PROCESSES","CPU_SERIES"];
  const missing = need.filter(k => typeof window[k] === "undefined");
  if (missing.length) { setTimeout(__mountWhenReady, 50); return; }
  ReactDOM.createRoot(document.getElementById("root")).render(<App/>);
}
__mountWhenReady();
