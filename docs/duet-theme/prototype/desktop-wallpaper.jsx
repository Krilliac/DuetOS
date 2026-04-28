// desktop-wallpaper.jsx — Abstract DuetOS-branded wallpaper. Two interlocking arcs +
// quiet topographic grid. Uses theme tokens so it shifts with light/dark/classic.

function Wallpaper({ variant = "duet-arcs" }) {
  if (variant === "solid")    return <div style={{position:"absolute",inset:0,background:"var(--bg-1)"}}/>;
  if (variant === "topo")     return <TopoWallpaper/>;
  if (variant === "syscalls") return <SyscallsWallpaper/>;
  return <ArcsWallpaper/>;
}

function ArcsWallpaper() {
  return (
    <div style={{position:"absolute",inset:0,overflow:"hidden",background:"var(--bg-1)"}}>
      <svg width="100%" height="100%" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice"
           style={{position:"absolute",inset:0,color:"var(--ink)"}}>
        <defs>
          <radialGradient id="bg-glow" cx="52%" cy="58%" r="72%">
            <stop offset="0%"  stopColor="var(--bg-2)" stopOpacity="1"/>
            <stop offset="100%" stopColor="var(--bg-1)" stopOpacity="1"/>
          </radialGradient>
          <pattern id="grid" width="48" height="48" patternUnits="userSpaceOnUse">
            <path d="M48 0H0V48" fill="none" stroke="currentColor" strokeWidth=".5" opacity=".06"/>
          </pattern>
          <linearGradient id="arc-a" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%"  stopColor="var(--accent)"   stopOpacity=".95"/>
            <stop offset="100%" stopColor="var(--accent)"  stopOpacity=".10"/>
          </linearGradient>
          <linearGradient id="arc-b" x1="1" y1="0" x2="0" y2="1">
            <stop offset="0%"  stopColor="var(--accent-2)" stopOpacity=".90"/>
            <stop offset="100%" stopColor="var(--accent-2)" stopOpacity=".10"/>
          </linearGradient>
        </defs>
        <rect width="1600" height="900" fill="url(#bg-glow)"/>
        <rect width="1600" height="900" fill="url(#grid)"/>

        <g transform="translate(820,470)" opacity=".82">
          {[0,1,2,3,4,5].map(i => (
            <circle key={"a"+i} r={170 + i*70} fill="none" stroke="url(#arc-a)" strokeWidth="1.4"
                    strokeDasharray={`${(170+i*70)*Math.PI*0.42} 9999`}
                    transform={`rotate(${-26 - i*3}) translate(-40,0)`}/>
          ))}
          {[0,1,2,3,4,5].map(i => (
            <circle key={"b"+i} r={170 + i*70} fill="none" stroke="url(#arc-b)" strokeWidth="1.4"
                    strokeDasharray={`${(170+i*70)*Math.PI*0.42} 9999`}
                    transform={`rotate(${154 + i*3}) translate(-40,0)`}/>
          ))}
          <circle r="5" fill="var(--accent)"/>
          <circle r="2.5" cx="80" fill="var(--accent-2)"/>
        </g>

        <g fill="var(--ink)" opacity=".55" style={{fontFamily:"'JetBrains Mono',ui-monospace,monospace"}}>
          <text x="56" y="60" fontSize="11" letterSpacing="3">DUETOS · BUILD 0.9.4 · X86_64</text>
        </g>
        <g fill="var(--ink)" opacity=".4" textAnchor="end" style={{fontFamily:"'JetBrains Mono',ui-monospace,monospace"}}>
          <text x="1544" y="848" fontSize="10" letterSpacing="2">SYSCALLS 57 · DLLS 29 · EXPORTS 760</text>
        </g>
      </svg>
    </div>
  );
}

function TopoWallpaper() {
  // Concentric rings of code-like contour lines.
  return (
    <div style={{position:"absolute",inset:0,overflow:"hidden",background:"var(--bg-1)"}}>
      <svg width="100%" height="100%" viewBox="0 0 1600 900" preserveAspectRatio="xMidYMid slice">
        <defs>
          <radialGradient id="topo-vig" cx="50%" cy="50%" r="70%">
            <stop offset="50%" stopColor="var(--bg-2)"/>
            <stop offset="100%" stopColor="var(--bg-1)"/>
          </radialGradient>
        </defs>
        <rect width="1600" height="900" fill="url(#topo-vig)"/>
        <g transform="translate(800,470)" fill="none" stroke="var(--accent)" strokeWidth=".6" opacity=".35">
          {Array.from({length:22}).map((_,i)=>(
            <ellipse key={i} rx={120 + i*42} ry={70 + i*28}
                     transform={`rotate(${i*3 - 12})`}/>
          ))}
        </g>
        <g transform="translate(800,470)" fill="none" stroke="var(--accent-2)" strokeWidth=".5" opacity=".22">
          {Array.from({length:14}).map((_,i)=>(
            <ellipse key={i} rx={60 + i*55} ry={36 + i*36}
                     transform={`rotate(${-i*4 + 18})`}/>
          ))}
        </g>
      </svg>
    </div>
  );
}

function SyscallsWallpaper() {
  // Hex byte grid backdrop — like a memory dump.
  const rows = Array.from({length:32}, (_,r) => (
    Array.from({length:48}, (_,c) => {
      const v = ((r*48+c)*1103515245 + 12345) & 0xff;
      return v.toString(16).padStart(2,"0");
    }).join(" ")
  ));
  return (
    <div style={{position:"absolute",inset:0,overflow:"hidden",background:"var(--bg-1)",
                 fontFamily:"'JetBrains Mono',ui-monospace,monospace",fontSize:12,lineHeight:"22px",
                 color:"var(--ink)",opacity:.85}}>
      <div style={{position:"absolute",inset:0,padding:"40px 56px",letterSpacing:1.5,whiteSpace:"pre",
                   color:"var(--ink-3)",opacity:.35}}>
        {rows.map((r,i)=> <div key={i}>{(i*0x10).toString(16).padStart(8,"0")}: {r}</div>)}
      </div>
      <div style={{position:"absolute",inset:0,background:
        "radial-gradient(ellipse at 50% 55%, transparent 0%, var(--bg-1) 75%)"}}/>
      <svg style={{position:"absolute",left:"50%",top:"50%",transform:"translate(-50%,-50%)"}}
           width="520" height="520" viewBox="0 0 520 520">
        <g transform="translate(260,260)" opacity=".9">
          <circle r="180" fill="none" stroke="var(--accent)"   strokeWidth="2"
                  strokeDasharray={180*Math.PI*0.42 + " 9999"} transform="rotate(-30) translate(-40,0)"/>
          <circle r="180" fill="none" stroke="var(--accent-2)" strokeWidth="2"
                  strokeDasharray={180*Math.PI*0.42 + " 9999"} transform="rotate(150) translate(-40,0)"/>
        </g>
      </svg>
    </div>
  );
}

Object.assign(window, { Wallpaper });
