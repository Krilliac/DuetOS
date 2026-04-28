// desktop-data.jsx
// Static data: kernel log lines, processes for Task Manager, disasm output for Inspect.

const KERNEL_LOG = [
  ["I", "boot", "DuetOS multiboot2 entry, 4-level paging armed"],
  ["I", "mm",   "frame allocator: 8128 MiB usable, 32 MiB reserved"],
  ["I", "mm",   "kheap: 64 MiB carved, slab buckets [16,32,64,128,256,512,1k,2k,4k]"],
  ["I", "smp",  "BSP=0 APs=[1,2,3] LAPIC calibrated against HPET (3.20 GHz)"],
  ["I", "sec",  "W^X SMEP SMAP ASLR retpoline kstack-canaries armed"],
  ["I", "pci",  "enumerated 17 devices, 1 NIC (e1000), 1 NVMe, 1 xHCI, 1 HDA"],
  ["I", "vfs",  "rootfs mounted (ramfs), bind /bin /etc /sys /proc"],
  ["I", "reg",  "registry hive opened, 2814 keys, 41 hives"],
  ["I", "ring3","registered 0x26 DLL(s) pid=0x13"],
  ["I", "pe",   "loader: validated MZ+PE32+, mapped 12 sections, ASLR slide=0x6c00"],
  ["I", "win32","kernel32:155 ntdll:114 user32:73 gdi32:44 ucrtbase:72 …"],
  ["I", "comp", "compositor up, kMaxWindows=16, present cadence 60.00 Hz"],
  ["I", "win",  "create pid=0x16 hwnd=7 rect=(500,400 420x220) title=\"WINDOWED HELLO\""],
  ["W", "net",  "ws2_32: socket() returns INVALID_SOCKET — stack is skeleton"],
  ["I", "msgbox","pid=0x16 caption=\"Windowed Hello\" text=\"Running on DuetOS!\""],
  ["I", "reg",  "ProductName=\"DuetOS\" (type=1, size=7)"],
  ["I", "loader","/bin/hello.exe first two bytes: 0x4d 0x5a  — MZ ok"],
  ["I", "test", "all checks passed (lkm:24 reg:31 io:18 win32:9)"],
  ["I", "exec", "Windows Kill 1.1.4 | Library 3.1.3"],
  ["I", "exec", "Not enough argument. Use -h for help."],
  ["I", "sys",  "exit rc val=0x1234"],
];

const PROCESSES = [
  { pid:0x01, name:"kernel",            abi:"native", cpu:1.4, mem:"148 MiB", thr:24, status:"R" },
  { pid:0x02, name:"compositor",        abi:"native", cpu:3.1, mem:"62 MiB",  thr:4,  status:"R" },
  { pid:0x03, name:"vfs.svc",           abi:"native", cpu:0.2, mem:"18 MiB",  thr:3,  status:"S" },
  { pid:0x04, name:"reg.svc",           abi:"native", cpu:0.0, mem:"11 MiB",  thr:2,  status:"S" },
  { pid:0x05, name:"audiod (HDA)",      abi:"native", cpu:0.4, mem:"14 MiB",  thr:3,  status:"S" },
  { pid:0x10, name:"shell",             abi:"native", cpu:0.1, mem:"7 MiB",   thr:1,  status:"S" },
  { pid:0x12, name:"taskmgr.duet",      abi:"native", cpu:1.7, mem:"22 MiB",  thr:2,  status:"R" },
  { pid:0x13, name:"klog.duet",         abi:"native", cpu:0.0, mem:"6 MiB",   thr:1,  status:"S" },
  { pid:0x14, name:"inspect.duet",      abi:"native", cpu:0.6, mem:"19 MiB",  thr:1,  status:"R" },
  { pid:0x16, name:"windowed_hello.exe",abi:"win32",  cpu:0.0, mem:"4 MiB",   thr:1,  status:"S" },
  { pid:0x17, name:"windows-kill.exe",  abi:"win32",  cpu:0.0, mem:"3 MiB",   thr:1,  status:"Z" },
  { pid:0x18, name:"hello_pe.exe",      abi:"win32",  cpu:0.0, mem:"2 MiB",   thr:1,  status:"Z" },
  { pid:0x1a, name:"thread_stress.exe", abi:"win32",  cpu:8.4, mem:"31 MiB",  thr:32, status:"R" },
  { pid:0x20, name:"linux-bridge",      abi:"linux",  cpu:0.1, mem:"9 MiB",   thr:2,  status:"S" },
];

const DISASM = [
  ["0x140001000","48 83 ec 28",          "sub    rsp, 0x28"],
  ["0x140001004","48 8d 0d e5 1f 00 00", "lea    rcx, [rip+0x1fe5]   ; \"Windows Kill 1.1.4\""],
  ["0x14000100b","ff 15 ef 20 00 00",    "call   [rip+0x20ef]        ; ucrtbase!printf"],
  ["0x140001011","b9 01 00 00 00",       "mov    ecx, 1"],
  ["0x140001016","ff 15 e4 20 00 00",    "call   [rip+0x20e4]        ; kernel32!ExitProcess"],
  ["0x14000101c","cc cc cc cc",          "int3                       ; padding"],
  ["0x140001020","40 53",                "push   rbx"],
  ["0x140001022","48 83 ec 20",          "sub    rsp, 0x20"],
  ["0x140001026","48 8b d9",             "mov    rbx, rcx"],
  ["0x140001029","e8 c2 00 00 00",       "call   0x1400010f0         ; helper"],
  ["0x14000102e","85 c0",                "test   eax, eax"],
  ["0x140001030","74 09",                "je     0x14000103b"],
  ["0x140001032","48 8b cb",             "mov    rcx, rbx"],
  ["0x140001035","ff 15 c5 20 00 00",    "call   [rip+0x20c5]        ; kernel32!CloseHandle"],
  ["0x14000103b","33 c0",                "xor    eax, eax"],
  ["0x14000103d","48 83 c4 20",          "add    rsp, 0x20"],
  ["0x140001041","5b",                   "pop    rbx"],
  ["0x140001042","c3",                   "ret"],
];

const SYSCALL_SITES = [
  { addr:"0x140001016", num:"0x01",  name:"SYS_EXIT",        caller:"kernel32!ExitProcess" },
  { addr:"0x14000100b", num:"0x04",  name:"SYS_WRITE",       caller:"ucrtbase!printf → fwrite" },
  { addr:"0x140001235", num:"0x3a",  name:"SYS_WIN_CREATE",  caller:"user32!CreateWindowExA" },
  { addr:"0x14000128c", num:"0x3c",  name:"SYS_WIN_SHOW",    caller:"user32!ShowWindow" },
  { addr:"0x1400012f0", num:"0x3d",  name:"SYS_WIN_MSGBOX",  caller:"user32!MessageBoxA" },
];

const PE_SECTIONS = [
  { name:".text",  rva:"0x1000", size:"0x1c00", flags:"R-X", entropy:6.21 },
  { name:".rdata", rva:"0x3000", size:"0x0a00", flags:"R--", entropy:5.04 },
  { name:".data",  rva:"0x4000", size:"0x0200", flags:"RW-", entropy:1.92 },
  { name:".pdata", rva:"0x5000", size:"0x0180", flags:"R--", entropy:3.11 },
  { name:".reloc", rva:"0x6000", size:"0x0080", flags:"R--", entropy:4.40 },
];

// CPU history for taskmgr sparklines (4 cores * 60 samples)
function _series(seed){
  let s = seed; const out = [];
  for(let i=0;i<60;i++){
    s = (s*9301+49297) % 233280;
    const base = 18 + 30*Math.abs(Math.sin((i+seed)/7));
    const noise = (s/233280) * 25;
    out.push(Math.max(2, Math.min(96, base + noise - 12)));
  }
  return out;
}
const CPU_SERIES = [ _series(11), _series(53), _series(97), _series(31) ];

Object.assign(window, { KERNEL_LOG, PROCESSES, DISASM, SYSCALL_SITES, PE_SECTIONS, CPU_SERIES });
