// desktop-startmenu.jsx — Slide-up Start menu in DuetOS's grammar.

const StartMenu = ({ open, onLaunch, onClose, accent }) => {
  if (!open) return null;
  const pinned = [
    { id:"taskmgr", label:"Task Manager", icon:Icon.TaskMgr },
    { id:"klog",    label:"Kernel Log",   icon:Icon.Klog },
    { id:"inspect", label:"Inspect",      icon:Icon.Inspect },
    { id:"calc",    label:"Calculator",   icon:Icon.Calc },
    { id:"note",    label:"Notepad",      icon:Icon.Note },
    { id:"files",   label:"Files",        icon:Icon.Folder },
    { id:"reg",     label:"Registry",     icon:Icon.Reg },
    { id:"gfx",     label:"GFX Demo",     icon:Icon.Gfx },
    { id:"term",    label:"Shell",        icon:Icon.Term },
  ];
  const recents = [
    { name:"windows-kill.exe", abi:"win32", note:"3 min ago"},
    { name:"hello_pe.exe",     abi:"win32", note:"4 min ago"},
    { name:"thread_stress.exe",abi:"win32", note:"7 min ago"},
    { name:"klog.duet",        abi:"native",note:"yesterday"},
  ];
  return (
    <>
      <div onClick={onClose} style={{position:"absolute",inset:0,zIndex:1000}}/>
      <div style={{
        position:"absolute", left:8, bottom:"calc(var(--taskbar-h, 44px) + 8px)",
        width:520, height:540, zIndex:1001,
        background:"var(--chrome)", color:"var(--ink)",
        border:"1px solid var(--line-2)", borderRadius:8,
        boxShadow:"0 24px 60px -10px rgba(0,0,0,.65), 0 0 0 1px var(--line)",
        display:"grid", gridTemplateRows:"auto 1fr auto", overflow:"hidden",
      }}>
        {/* Header */}
        <div style={{
          padding:"14px 18px",
          background:"linear-gradient(180deg, var(--chrome-2), var(--chrome))",
          borderBottom:"1px solid var(--line)",
          display:"flex", alignItems:"center", gap:12,
        }}>
          <DuetMark size={28}/>
          <div>
            <div style={{fontSize:14, fontWeight:700, letterSpacing:.2}}>DuetOS</div>
            <div className="mono" style={{fontSize:10.5, color:"var(--ink-3)"}}>build 0.9.4 · x86_64 · 4 cores</div>
          </div>
          <span style={{flex:1}}/>
          <div style={{
            display:"flex", alignItems:"center", gap:6, padding:"4px 10px",
            border:"1px solid var(--line)", borderRadius:999,
            background:"var(--chrome-3)",
          }}>
            <Icon.Search size={12} color="var(--ink-3)"/>
            <span className="mono" style={{fontSize:11, color:"var(--ink-3)"}}>Type to search apps & syscalls…</span>
          </div>
        </div>

        {/* Body — pinned grid + recents column */}
        <div style={{display:"grid", gridTemplateColumns:"1fr 200px", minHeight:0}}>
          <div style={{padding:"14px 18px", display:"flex", flexDirection:"column", gap:10, minHeight:0}}>
            <SectionLabel>Pinned</SectionLabel>
            <div style={{
              display:"grid", gridTemplateColumns:"repeat(3, 1fr)", gap:6,
            }}>
              {pinned.map(p => (
                <button key={p.id} onClick={()=>onLaunch(p.id)} className="duet-tile"
                  style={{
                    appearance:"none", border:"1px solid transparent",
                    background:"transparent", color:"var(--ink)",
                    display:"flex", flexDirection:"column", alignItems:"center", gap:8,
                    padding:"14px 6px", borderRadius:6, cursor:"default",
                  }}
                  onMouseEnter={(e)=>{ e.currentTarget.style.background = "var(--hover)"; e.currentTarget.style.borderColor = "var(--line)"; }}
                  onMouseLeave={(e)=>{ e.currentTarget.style.background = "transparent"; e.currentTarget.style.borderColor = "transparent"; }}
                >
                  <div style={{
                    width:40, height:40, borderRadius:6,
                    display:"flex", alignItems:"center", justifyContent:"center",
                    background: "color-mix(in oklab, var(--accent) 14%, transparent)",
                    color:"var(--accent)",
                    border:"1px solid color-mix(in oklab, var(--accent) 30%, transparent)",
                  }}>
                    <p.icon size={20}/>
                  </div>
                  <div style={{fontSize:11.5, fontWeight:500}}>{p.label}</div>
                </button>
              ))}
            </div>
            <SectionLabel style={{marginTop:6}}>Recommended</SectionLabel>
            <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:6}}>
              {[
                { t:"Inspect — windows-kill.exe", s:"5 syscall sites · 4 imports", icon:Icon.Inspect },
                { t:"Kernel Log",                  s:"21 lines since boot",          icon:Icon.Klog },
                { t:"Task Manager — Performance", s:"Compositor 60.0 fps",          icon:Icon.TaskMgr },
                { t:"GFX Demo",                    s:"present cadence 60 Hz",        icon:Icon.Gfx },
              ].map((r,i)=>(
                <div key={i} style={{
                  display:"flex", gap:10, padding:"8px 10px", borderRadius:6,
                  border:"1px solid var(--line)", background:"var(--chrome-3)",
                }}>
                  <div style={{
                    width:28, height:28, borderRadius:4,
                    display:"flex", alignItems:"center", justifyContent:"center",
                    background:"color-mix(in oklab, var(--accent-2) 16%, transparent)",
                    color:"var(--accent-2)",
                  }}><r.icon size={14}/></div>
                  <div style={{minWidth:0}}>
                    <div style={{fontSize:11.5, fontWeight:600, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis"}}>{r.t}</div>
                    <div className="mono" style={{fontSize:10.5, color:"var(--ink-3)", marginTop:2}}>{r.s}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{
            borderLeft:"1px solid var(--line)", background:"var(--chrome-3)",
            padding:"14px 14px", display:"flex", flexDirection:"column", gap:8, minHeight:0,
          }}>
            <SectionLabel>Recent PE</SectionLabel>
            {recents.map(r => (
              <div key={r.name} style={{display:"flex", alignItems:"center", gap:8}}>
                <Icon.Pe size={12} color={r.abi==="win32"?"var(--accent-2)":"var(--accent)"}/>
                <div style={{flex:1, minWidth:0}}>
                  <div className="mono" style={{fontSize:11, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis"}}>{r.name}</div>
                  <div className="mono" style={{fontSize:10, color:"var(--ink-3)"}}>{r.note}</div>
                </div>
              </div>
            ))}
            <span style={{flex:1}}/>
            <div className="mono" style={{fontSize:10, color:"var(--ink-3)", lineHeight:"15px"}}>
              <div>57 syscalls registered</div>
              <div>29 DLLs · 760 exports</div>
              <div>compositor: 60.0 Hz</div>
            </div>
          </div>
        </div>

        {/* Footer — user + power */}
        <div style={{
          height:48, display:"flex", alignItems:"center", padding:"0 12px",
          borderTop:"1px solid var(--line)", background:"var(--chrome-2)",
        }}>
          <div style={{
            width:28, height:28, borderRadius:999,
            background:"color-mix(in oklab, var(--accent) 30%, transparent)",
            color:"var(--accent)",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:12, fontWeight:700,
          }}>K</div>
          <div style={{marginLeft:10}}>
            <div style={{fontSize:12, fontWeight:600}}>krilliac</div>
            <div className="mono" style={{fontSize:10, color:"var(--ink-3)"}}>uid=1000 · ring 3</div>
          </div>
          <span style={{flex:1}}/>
          <FooterBtn icon={Icon.Cog}>Settings</FooterBtn>
          <FooterBtn icon={Icon.Power} accent>Power</FooterBtn>
        </div>
      </div>
    </>
  );
};

function SectionLabel({ children, style }) {
  return (
    <div style={{
      fontSize:10, fontWeight:700, letterSpacing:.7, textTransform:"uppercase",
      color:"var(--ink-3)", ...style,
    }}>{children}</div>
  );
}

function FooterBtn({ icon:I, children, accent }) {
  return (
    <button style={{
      appearance:"none", display:"flex", alignItems:"center", gap:6,
      padding:"6px 10px", border:"1px solid var(--line)", borderRadius:4,
      background:"transparent", color: accent ? "var(--accent-2)" : "var(--ink-2)",
      fontSize:11.5, fontWeight:500, cursor:"default", marginLeft:6,
    }}><I size={13}/>{children}</button>
  );
}

Object.assign(window, { StartMenu });
