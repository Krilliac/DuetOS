// desktop-windows.jsx — Window chrome + the three app windows.

const { useState, useRef, useEffect, useMemo } = React;

// Reusable chrome with titlebar buttons.
function Window({ win, focused, onFocus, onMin, onMax, onClose, onDrag, onResize, children, density }) {
  const dragRef = useRef(null);

  const onTitleDown = (e) => {
    if (win.maximized) return;
    onFocus();
    const sx = e.clientX, sy = e.clientY, ox = win.x, oy = win.y;
    const move = (ev) => onDrag(ox + (ev.clientX - sx), oy + (ev.clientY - sy));
    const up = () => { window.removeEventListener("mousemove", move); window.removeEventListener("mouseup", up); };
    window.addEventListener("mousemove", move); window.addEventListener("mouseup", up);
  };

  const titlebarH = density === "compact" ? 26 : 30;
  const padPx = density === "compact" ? 0 : 0;

  const style = win.maximized
    ? { left:0, top:0, width:"100%", height:"calc(100% - var(--taskbar-h, 44px))" }
    : { left:win.x, top:win.y, width:win.w, height:win.h };

  return (
    <div
      className="duet-win"
      onMouseDown={onFocus}
      style={{
        position:"absolute",
        ...style,
        background:"var(--chrome)",
        color:"var(--ink)",
        border:"1px solid var(--line-2)",
        borderRadius: win.maximized ? 0 : 6,
        boxShadow: focused
          ? "0 24px 48px -16px rgba(0,0,0,.55), 0 0 0 1px var(--line-2), 0 1px 0 rgba(255,255,255,.04) inset"
          : "0 12px 28px -16px rgba(0,0,0,.45), 0 0 0 1px var(--line)",
        opacity: focused ? 1 : 0.97,
        display: win.minimized ? "none" : "flex",
        flexDirection:"column",
        overflow:"hidden",
        transition:"box-shadow .15s ease, opacity .15s ease",
        zIndex: win.z,
      }}
    >
      <div
        ref={dragRef}
        onMouseDown={onTitleDown}
        onDoubleClick={onMax}
        style={{
          height: titlebarH, flex:`0 0 ${titlebarH}px`,
          display:"flex", alignItems:"center", gap:8,
          padding:"0 0 0 10px",
          background: focused
            ? "linear-gradient(180deg, var(--chrome-2), var(--chrome))"
            : "var(--chrome)",
          borderBottom:"1px solid var(--line)",
          cursor:"default", userSelect:"none",
          color: focused ? "var(--ink)" : "var(--ink-2)",
        }}
      >
        <div style={{display:"flex",alignItems:"center",gap:8,flex:1,minWidth:0}}>
          {win.icon ? <win.icon size={14} color="var(--ink-2)"/> : null}
          <div style={{
            fontSize:12, fontWeight:600, letterSpacing:.1,
            whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis",
          }}>{win.title}</div>
          {win.subtitle && (
            <div className="mono" style={{fontSize:11, color:"var(--ink-3)", whiteSpace:"nowrap"}}>
              {win.subtitle}
            </div>
          )}
        </div>
        <div style={{display:"flex"}}>
          <TitleBtn onClick={onMin} aria-label="Minimize"><Icon.Min size={14}/></TitleBtn>
          <TitleBtn onClick={onMax} aria-label="Maximize">
            {win.maximized ? <Icon.Restore size={12}/> : <Icon.Max size={12}/>}
          </TitleBtn>
          <TitleBtn close onClick={onClose} aria-label="Close"><Icon.X size={14}/></TitleBtn>
        </div>
      </div>
      <div style={{flex:1, minHeight:0, display:"flex", flexDirection:"column"}}>{children}</div>
    </div>
  );
}

function TitleBtn({ children, close, onClick, ...rest }) {
  const [hover, setHover] = useState(false);
  return (
    <button
      onClick={(e)=>{ e.stopPropagation(); onClick && onClick(); }}
      onMouseDown={(e)=>e.stopPropagation()}
      onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{
        appearance:"none", border:0, height:"100%", width:46,
        display:"flex", alignItems:"center", justifyContent:"center",
        background: hover ? (close ? "#e3413c" : "var(--hover)") : "transparent",
        color: hover && close ? "#fff" : "var(--ink-2)",
        cursor:"default",
      }}
      {...rest}
    >{children}</button>
  );
}

// ─────────────────────── Task Manager ───────────────────────
function TaskManagerWindow() {
  const [tab, setTab] = useState("processes");
  return (
    <div style={{display:"flex", flexDirection:"column", flex:1, minHeight:0}}>
      <Tabs value={tab} onChange={setTab} items={[
        {id:"processes", label:"Processes"},
        {id:"performance", label:"Performance"},
        {id:"abi", label:"ABI peers"},
        {id:"startup", label:"Startup"},
      ]}/>
      <div style={{flex:1, minHeight:0, display:"flex", flexDirection:"column"}}>
        {tab === "processes"  && <TmProcesses/>}
        {tab === "performance"&& <TmPerformance/>}
        {tab === "abi"        && <TmAbi/>}
        {tab === "startup"    && <TmStartup/>}
      </div>
      <StatusBar items={[
        `${PROCESSES.length} processes`,
        `${PROCESSES.reduce((a,p)=>a+p.thr,0)} threads`,
        `CPU ${PROCESSES.reduce((a,p)=>a+p.cpu,0).toFixed(1)}%`,
        "Memory 412 / 8128 MiB",
      ]}/>
    </div>
  );
}

function Tabs({ value, onChange, items }) {
  return (
    <div style={{
      display:"flex", padding:"0 10px", gap:2,
      borderBottom:"1px solid var(--line)",
      background:"var(--chrome)",
    }}>
      {items.map(it => {
        const active = it.id === value;
        return (
          <button key={it.id} onClick={()=>onChange(it.id)}
            style={{
              appearance:"none", border:0, padding:"10px 12px 9px",
              background:"transparent", color: active ? "var(--ink)" : "var(--ink-2)",
              fontSize:12, fontWeight: active ? 600 : 500, cursor:"default",
              borderBottom: active ? "2px solid var(--accent)" : "2px solid transparent",
              marginBottom:-1,
            }}>{it.label}</button>
        );
      })}
    </div>
  );
}

function TmProcesses() {
  const cols = ["Name","PID","ABI","CPU","Memory","Threads","St"];
  return (
    <div className="duet-scroll" style={{flex:1, minHeight:0, overflow:"auto"}}>
      <table style={{width:"100%", borderCollapse:"collapse", fontSize:12}}>
        <thead style={{position:"sticky", top:0, background:"var(--chrome)", zIndex:1}}>
          <tr style={{textAlign:"left", color:"var(--ink-2)"}}>
            {cols.map((c,i)=>(
              <th key={c} style={{
                padding:"8px 12px", borderBottom:"1px solid var(--line)",
                fontWeight:500, textAlign: i>=3 && i<=5 ? "right" : "left",
              }}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody className="mono">
          {PROCESSES.map((p, i) => (
            <tr key={p.pid} style={{
              background: i%2 ? "transparent" : "rgba(255,255,255,.015)",
            }}>
              <td style={td()}>
                <div style={{display:"flex",alignItems:"center",gap:8}}>
                  <AbiDot abi={p.abi}/>
                  <span style={{fontFamily:"Inter",fontWeight:500}}>{p.name}</span>
                </div>
              </td>
              <td style={td()}>0x{p.pid.toString(16).padStart(2,"0")}</td>
              <td style={td()}><AbiBadge abi={p.abi}/></td>
              <td style={tdR(p.cpu>5 ? "var(--accent-2)" : null)}>{p.cpu.toFixed(1)}%</td>
              <td style={tdR()}>{p.mem}</td>
              <td style={tdR()}>{p.thr}</td>
              <td style={td()}><StatusBadge s={p.status}/></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const td = () => ({ padding:"7px 12px", borderBottom:"1px solid var(--line)", color:"var(--ink-2)" });
const tdR = (c) => ({ ...td(), textAlign:"right", color: c || "var(--ink)", fontVariantNumeric:"tabular-nums" });

function AbiDot({ abi }) {
  const c = abi==="native" ? "var(--accent)" : abi==="win32" ? "var(--accent-2)" : "#9aa3af";
  return <span style={{width:6,height:6,borderRadius:6,background:c,display:"inline-block"}}/>;
}
function AbiBadge({ abi }) {
  const map = {
    native:{ bg:"color-mix(in oklab, var(--accent) 18%, transparent)", fg:"var(--accent)", t:"NATIVE" },
    win32: { bg:"color-mix(in oklab, var(--accent-2) 18%, transparent)", fg:"var(--accent-2)", t:"WIN32 PE" },
    linux: { bg:"rgba(154,163,175,.18)", fg:"#cfd5dd", t:"LINUX" },
  }[abi] || {bg:"transparent",fg:"var(--ink-2)",t:abi};
  return (
    <span style={{
      fontSize:10, fontWeight:600, letterSpacing:.5, padding:"1px 6px",
      borderRadius:3, background:map.bg, color:map.fg,
    }}>{map.t}</span>
  );
}
function StatusBadge({ s }) {
  const map = { R:{c:"var(--accent)",t:"running"}, S:{c:"var(--ink-3)",t:"sleeping"}, Z:{c:"#e87575",t:"zombie"} }[s] || {c:"var(--ink-3)",t:s};
  return <span title={map.t} style={{color:map.c,fontWeight:600}}>{s}</span>;
}

function TmPerformance() {
  return (
    <div style={{flex:1, minHeight:0, display:"grid", gridTemplateColumns:"220px 1fr", gap:0}}>
      <div style={{borderRight:"1px solid var(--line)", padding:"6px 0", background:"var(--chrome-3)"}}>
        {[
          {k:"CPU", v:"14% · 3.2 GHz", series:CPU_SERIES[0], active:true},
          {k:"Memory", v:"412 / 8128 MiB", series:CPU_SERIES[1].map(x=>20+x*0.4)},
          {k:"NVMe0", v:"0% · 4 KB/s", series:CPU_SERIES[2].map(x=>x*0.2)},
          {k:"e1000", v:"S — skeleton", series:CPU_SERIES[3].map(()=>0), warn:true},
          {k:"Compositor", v:"60.0 fps", series:CPU_SERIES[0].map(x=>x*0.5+30)},
        ].map((row, i) => (
          <div key={row.k} style={{
            display:"flex", alignItems:"center", gap:10, padding:"10px 12px",
            background: i===0 ? "var(--chrome)" : "transparent",
            borderLeft: i===0 ? "2px solid var(--accent)" : "2px solid transparent",
          }}>
            <Spark data={row.series} w={56} h={20} stroke={row.warn ? "var(--accent-2)" : "var(--accent)"}/>
            <div style={{flex:1, minWidth:0}}>
              <div style={{fontSize:12, fontWeight:600}}>{row.k}</div>
              <div className="mono" style={{fontSize:10.5, color:"var(--ink-3)"}}>{row.v}</div>
            </div>
          </div>
        ))}
      </div>
      <div style={{padding:"14px 18px", display:"flex", flexDirection:"column", gap:14, minHeight:0}}>
        <div style={{display:"flex", alignItems:"baseline", gap:10}}>
          <div style={{fontSize:14, fontWeight:600}}>CPU</div>
          <div className="mono" style={{fontSize:11, color:"var(--ink-3)"}}>4 logical · x86_64 · 3.20 GHz · QEMU/KVM</div>
        </div>
        <div style={{display:"grid", gridTemplateColumns:"1fr 1fr", gap:10}}>
          {CPU_SERIES.map((s, i) => (
            <CoreCard key={i} idx={i} data={s}/>
          ))}
        </div>
        <div style={{
          display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10,
          borderTop:"1px solid var(--line)", paddingTop:14,
        }}>
          <Stat label="Utilization" v="14%"/>
          <Stat label="Processes"   v={PROCESSES.length}/>
          <Stat label="Threads"     v={PROCESSES.reduce((a,p)=>a+p.thr,0)}/>
          <Stat label="Up time"     v="00:14:22"/>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, v }) {
  return (
    <div>
      <div style={{fontSize:10.5, color:"var(--ink-3)", textTransform:"uppercase", letterSpacing:.6}}>{label}</div>
      <div className="mono" style={{fontSize:18, fontWeight:600, marginTop:2, fontVariantNumeric:"tabular-nums"}}>{v}</div>
    </div>
  );
}

function CoreCard({ idx, data }) {
  const last = Math.round(data[data.length-1]);
  return (
    <div style={{
      border:"1px solid var(--line)", borderRadius:4, padding:"10px 12px",
      background:"var(--chrome-3)",
    }}>
      <div style={{display:"flex", justifyContent:"space-between", alignItems:"baseline", marginBottom:6}}>
        <div className="mono" style={{fontSize:11, color:"var(--ink-2)"}}>Core {idx}</div>
        <div className="mono" style={{fontSize:12, fontWeight:600}}>{last}%</div>
      </div>
      <Spark data={data} w={"100%"} h={36} stroke="var(--accent)" fill="color-mix(in oklab, var(--accent) 18%, transparent)"/>
    </div>
  );
}

function Spark({ data, w=120, h=24, stroke="var(--accent)", fill }) {
  const max = 100;
  const n = data.length;
  const path = data.map((v,i)=>`${i===0?"M":"L"}${(i/(n-1))*100} ${100-(v/max)*100}`).join(" ");
  return (
    <svg width={w} height={h} viewBox="0 0 100 100" preserveAspectRatio="none" style={{display:"block"}}>
      {fill && <path d={path + " L100 100 L0 100 Z"} fill={fill}/>}
      <path d={path} fill="none" stroke={stroke} strokeWidth="1.5" vectorEffect="non-scaling-stroke"/>
    </svg>
  );
}

function TmAbi() {
  const groups = { native:[], win32:[], linux:[] };
  PROCESSES.forEach(p => groups[p.abi]?.push(p));
  return (
    <div style={{flex:1, minHeight:0, padding:14, display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:12}}>
      <AbiCol title="Native (DuetOS)" subtitle="ELF · syscall numbers per /sys/abi/native" rows={groups.native} dot="var(--accent)"/>
      <AbiCol title="Win32 PE peer"   subtitle="MZ+PE32+ · 29 DLLs · 760 exports"          rows={groups.win32}  dot="var(--accent-2)"/>
      <AbiCol title="Linux peer"      subtitle="skeleton — bridge active"                  rows={groups.linux}  dot="#9aa3af"/>
    </div>
  );
}

function AbiCol({ title, subtitle, rows, dot }) {
  return (
    <div style={{
      border:"1px solid var(--line)", borderRadius:4, background:"var(--chrome-3)",
      display:"flex", flexDirection:"column", minHeight:0, overflow:"hidden",
    }}>
      <div style={{padding:"10px 12px", borderBottom:"1px solid var(--line)"}}>
        <div style={{display:"flex", alignItems:"center", gap:8}}>
          <span style={{width:8,height:8,borderRadius:8,background:dot}}/>
          <div style={{fontSize:12, fontWeight:600}}>{title}</div>
        </div>
        <div className="mono" style={{fontSize:10.5, color:"var(--ink-3)", marginTop:2}}>{subtitle}</div>
      </div>
      <div className="duet-scroll" style={{flex:1, overflow:"auto"}}>
        {rows.map(p => (
          <div key={p.pid} style={{
            display:"flex", alignItems:"baseline", gap:8,
            padding:"7px 12px", borderBottom:"1px solid var(--line)", fontSize:12,
          }}>
            <span style={{flex:1, minWidth:0, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap"}}>{p.name}</span>
            <span className="mono" style={{color:"var(--ink-3)", fontSize:11}}>0x{p.pid.toString(16).padStart(2,"0")}</span>
          </div>
        ))}
        {!rows.length && <div style={{padding:14, color:"var(--ink-3)", fontSize:12}}>(none)</div>}
      </div>
    </div>
  );
}

function TmStartup() {
  const items = [
    { name:"compositor",       impact:"high", t:"+12 ms"  },
    { name:"reg.svc",          impact:"low",  t:"+2 ms"   },
    { name:"vfs.svc",          impact:"med",  t:"+6 ms"   },
    { name:"audiod (HDA)",     impact:"low",  t:"+3 ms"   },
    { name:"shell",            impact:"med",  t:"+8 ms"   },
    { name:"linux-bridge",     impact:"low",  t:"+4 ms"   },
  ];
  return (
    <div style={{flex:1, padding:14}}>
      <div className="mono" style={{fontSize:11, color:"var(--ink-3)", marginBottom:10}}>last boot 184 ms · BSP→user @ 96 ms</div>
      <div style={{border:"1px solid var(--line)", borderRadius:4, overflow:"hidden"}}>
        {items.map((it,i)=>(
          <div key={it.name} style={{
            display:"grid", gridTemplateColumns:"1fr 90px 90px",
            padding:"9px 12px", fontSize:12,
            borderTop: i ? "1px solid var(--line)" : "0",
            background: i%2 ? "transparent" : "rgba(255,255,255,.015)",
          }}>
            <span>{it.name}</span>
            <span style={{
              fontSize:10.5, fontWeight:600, letterSpacing:.5, justifySelf:"start",
              padding:"1px 6px", borderRadius:3,
              background: it.impact==="high" ? "color-mix(in oklab, var(--accent-2) 22%, transparent)"
                       : it.impact==="med"   ? "color-mix(in oklab, var(--accent) 18%, transparent)"
                       : "rgba(154,163,175,.18)",
              color: it.impact==="high" ? "var(--accent-2)" : it.impact==="med" ? "var(--accent)" : "var(--ink-2)"
            }}>{it.impact.toUpperCase()}</span>
            <span className="mono" style={{textAlign:"right", color:"var(--ink-2)"}}>{it.t}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatusBar({ items }) {
  return (
    <div className="mono" style={{
      flex:"0 0 24px", height:24,
      display:"flex", alignItems:"center", gap:0,
      borderTop:"1px solid var(--line)", background:"var(--chrome-3)",
      padding:"0 12px", fontSize:11, color:"var(--ink-3)",
    }}>
      {items.map((it,i)=>(
        <React.Fragment key={i}>
          {i>0 && <span style={{width:1, height:12, background:"var(--line-2)", margin:"0 12px"}}/>}
          <span>{it}</span>
        </React.Fragment>
      ))}
    </div>
  );
}

// ─────────────────────── Kernel Log ───────────────────────
function KernelLogWindow() {
  const [filter, setFilter] = useState("");
  const [lvl, setLvl] = useState({ I:true, W:true, E:true });
  const lines = KERNEL_LOG.filter(([l,t,m]) => lvl[l] && (
    !filter || (t+m).toLowerCase().includes(filter.toLowerCase())
  ));
  return (
    <div style={{display:"flex", flexDirection:"column", flex:1, minHeight:0}}>
      <div style={{
        display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
        background:"var(--chrome)", borderBottom:"1px solid var(--line)",
      }}>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter (tag or text)…"
               className="mono"
               style={{
                 flex:1, height:24, padding:"0 8px", fontSize:11,
                 background:"var(--chrome-3)", border:"1px solid var(--line)",
                 color:"var(--ink)", borderRadius:3, outline:"none",
               }}/>
        {["I","W","E"].map(l => {
          const active = lvl[l];
          const c = l==="W" ? "var(--accent-2)" : l==="E" ? "#e87575" : "var(--accent)";
          return (
            <button key={l} onClick={()=>setLvl(s=>({...s,[l]:!s[l]}))}
              style={{
                appearance:"none", border:"1px solid var(--line)",
                background: active ? "color-mix(in oklab, "+c+" 16%, transparent)" : "var(--chrome-3)",
                color: active ? c : "var(--ink-3)",
                fontSize:10, fontWeight:700, padding:"3px 8px", borderRadius:3,
                cursor:"default", letterSpacing:.5,
              }}>{l}</button>
          );
        })}
      </div>
      <div className="duet-scroll mono" style={{
        flex:1, minHeight:0, overflow:"auto",
        padding:"8px 0",
        background:"var(--chrome-3)", color:"var(--ink-2)", fontSize:11.5, lineHeight:"18px",
      }}>
        {lines.map(([l,tag,msg], i) => {
          const c = l==="W" ? "var(--accent-2)" : l==="E" ? "#e87575" : "var(--accent)";
          const ts = (i*0.027 + 0.184).toFixed(6).padStart(11,"0");
          return (
            <div key={i} style={{display:"flex", padding:"0 12px", whiteSpace:"pre"}}>
              <span style={{color:"var(--ink-3)", width:96, flex:"0 0 auto"}}>[{ts}]</span>
              <span style={{color:c, width:18, flex:"0 0 auto", fontWeight:700}}>{l}</span>
              <span style={{color:"var(--ink-2)", width:80, flex:"0 0 auto"}}>{tag}</span>
              <span style={{color:l==="W"?"var(--accent-2)":"var(--ink)"}}>{msg}</span>
            </div>
          );
        })}
        <div style={{display:"flex", padding:"4px 12px", color:"var(--accent)"}}>
          <span style={{width:96}}/><span style={{width:18}}>▸</span>
          <span style={{borderLeft:"7px solid var(--accent)", height:13, marginLeft:2,
                        animation:"duet-cursor 1s steps(2,end) infinite"}}/>
        </div>
      </div>
      <StatusBar items={[`${lines.length} / ${KERNEL_LOG.length} lines`, "tail -F /sys/klog", "ring=64 KiB", "drops=0"]}/>
      <style>{`@keyframes duet-cursor{50%{opacity:0}}`}</style>
    </div>
  );
}

// ─────────────────────── Inspect / Disassembler ───────────────────────
function InspectWindow() {
  const [sel, setSel] = useState(0);
  return (
    <div style={{display:"flex", flexDirection:"column", flex:1, minHeight:0}}>
      <div style={{
        display:"flex", alignItems:"center", gap:8, padding:"6px 10px",
        background:"var(--chrome)", borderBottom:"1px solid var(--line)",
      }}>
        <Icon.Pe size={14} color="var(--accent-2)"/>
        <span className="mono" style={{fontSize:11, color:"var(--ink-2)"}}>/bin/windows-kill.exe</span>
        <span className="mono" style={{fontSize:10.5, color:"var(--ink-3)"}}>· PE32+ · x86_64 · GUI=N · imports 4 dlls</span>
        <span style={{flex:1}}/>
        <ToolBtn>Decode</ToolBtn>
        <ToolBtn>Trace</ToolBtn>
        <ToolBtn primary>Run in sandbox</ToolBtn>
      </div>
      <div style={{flex:1, minHeight:0, display:"grid", gridTemplateColumns:"180px 1fr 240px", gap:0}}>
        {/* Sections sidebar */}
        <div style={{
          borderRight:"1px solid var(--line)", background:"var(--chrome-3)",
          display:"flex", flexDirection:"column", minHeight:0,
        }}>
          <SidebarTitle>PE Sections</SidebarTitle>
          <div className="duet-scroll" style={{flex:1, overflow:"auto"}}>
            {PE_SECTIONS.map((s,i)=>(
              <button key={s.name} onClick={()=>setSel(i)}
                style={{
                  appearance:"none", border:0, width:"100%", textAlign:"left",
                  padding:"7px 12px", display:"flex", flexDirection:"column", gap:1,
                  background: sel===i ? "color-mix(in oklab, var(--accent) 14%, transparent)" : "transparent",
                  borderLeft: sel===i ? "2px solid var(--accent)" : "2px solid transparent",
                  color:"var(--ink)", cursor:"default",
                }}>
                <span className="mono" style={{fontSize:11.5, fontWeight:600}}>{s.name}</span>
                <span className="mono" style={{fontSize:10.5, color:"var(--ink-3)"}}>{s.rva} · {s.size} · {s.flags}</span>
              </button>
            ))}
          </div>
          <SidebarTitle>Imports</SidebarTitle>
          <div className="mono" style={{padding:"6px 12px 10px", fontSize:11, color:"var(--ink-2)", lineHeight:"18px"}}>
            <div>kernel32.dll <span style={{color:"var(--ink-3)"}}>· 6</span></div>
            <div>ntdll.dll <span style={{color:"var(--ink-3)"}}>· 3</span></div>
            <div>user32.dll <span style={{color:"var(--ink-3)"}}>· 2</span></div>
            <div>ucrtbase.dll <span style={{color:"var(--ink-3)"}}>· 4</span></div>
          </div>
        </div>
        {/* Disassembly */}
        <div className="duet-scroll mono" style={{
          minHeight:0, overflow:"auto",
          padding:"8px 0", background:"var(--chrome-3)", fontSize:11.5, lineHeight:"19px",
        }}>
          <div style={{padding:"4px 14px 8px", color:"var(--ink-3)", fontSize:11}}>
            ;  {PE_SECTIONS[sel].name} @ {PE_SECTIONS[sel].rva} ({PE_SECTIONS[sel].size}, {PE_SECTIONS[sel].flags})
          </div>
          {DISASM.map(([addr, bytes, asm], i) => {
            const isCall = asm.startsWith("call");
            const isJmp  = asm.startsWith("je") || asm.startsWith("jmp");
            const isRet  = asm.startsWith("ret");
            const annot  = SYSCALL_SITES.find(s => s.addr === addr);
            return (
              <div key={addr} style={{display:"flex", gap:14, padding:"0 14px",
                                       background: i===4 ? "color-mix(in oklab, var(--accent) 10%, transparent)" : "transparent"}}>
                <span style={{color:"var(--ink-3)", width:96, flex:"0 0 auto"}}>{addr}</span>
                <span style={{color:"var(--accent-2)", width:160, flex:"0 0 auto", opacity:.85}}>{bytes}</span>
                <span style={{
                  color: isCall ? "var(--accent)" : isRet ? "#e87575" : isJmp ? "var(--accent-2)" : "var(--ink)",
                  flex:1, whiteSpace:"pre",
                }}>{asm}</span>
                {annot && (
                  <span style={{color:"var(--accent)", fontSize:10.5, alignSelf:"center", whiteSpace:"nowrap"}}>
                    ⟶ {annot.name}
                  </span>
                )}
              </div>
            );
          })}
        </div>
        {/* Right rail: syscall sites */}
        <div style={{
          borderLeft:"1px solid var(--line)", background:"var(--chrome)",
          display:"flex", flexDirection:"column", minHeight:0,
        }}>
          <SidebarTitle>Syscall sites</SidebarTitle>
          <div className="duet-scroll" style={{flex:1, overflow:"auto"}}>
            {SYSCALL_SITES.map(s => (
              <div key={s.addr} style={{
                padding:"8px 12px", borderBottom:"1px solid var(--line)",
              }}>
                <div className="mono" style={{fontSize:11, color:"var(--accent)", fontWeight:600}}>{s.name} <span style={{color:"var(--ink-3)",fontWeight:400}}>{s.num}</span></div>
                <div className="mono" style={{fontSize:10.5, color:"var(--ink-3)", marginTop:2}}>{s.addr}</div>
                <div className="mono" style={{fontSize:11, color:"var(--ink-2)", marginTop:2}}>{s.caller}</div>
              </div>
            ))}
          </div>
          <SidebarTitle>Hashes</SidebarTitle>
          <div className="mono" style={{padding:"6px 12px 12px", fontSize:10.5, color:"var(--ink-3)", lineHeight:"16px"}}>
            <div>md5  29c4…7e</div>
            <div>sha1 4f12…aa</div>
            <div>sha256 a1b2…9f</div>
          </div>
        </div>
      </div>
      <StatusBar items={["windows-kill.exe", "PE32+ · 4 imports", "5 syscall sites", "no anti-debug"]}/>
    </div>
  );
}

function SidebarTitle({ children }) {
  return (
    <div style={{
      padding:"8px 12px 6px", fontSize:10, fontWeight:700, letterSpacing:.7,
      textTransform:"uppercase", color:"var(--ink-3)",
    }}>{children}</div>
  );
}

function ToolBtn({ children, primary, onClick }) {
  return (
    <button onClick={onClick} className="mono" style={{
      appearance:"none", padding:"3px 9px", fontSize:11, fontWeight:600,
      border:"1px solid " + (primary ? "var(--accent)" : "var(--line-2)"),
      background: primary ? "color-mix(in oklab, var(--accent) 18%, transparent)" : "var(--chrome-3)",
      color: primary ? "var(--accent)" : "var(--ink-2)",
      borderRadius:3, cursor:"default",
    }}>{children}</button>
  );
}

Object.assign(window, { Window, TaskManagerWindow, KernelLogWindow, InspectWindow });
