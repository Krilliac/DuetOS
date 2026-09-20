#!/usr/bin/env python3
"""Pin runtime LoadLibrary serialization and DLL-owned IAT binding."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    syscall = (ROOT / "kernel/syscall/syscall.cpp").read_text(encoding="utf-8")
    start = syscall.index("case SYS_DLL_LOAD_FROM_PATH:")
    end = syscall.index("case SYS_COMPAT_QUERY:", start)
    body = syscall[start:end]

    runtime_pos = body.index("ScopedProcessRuntimeAccess runtime_access(proc)")
    lookup_pos = body.index("ProcessFindDllBaseByName(proc, kname)")
    load_pos = body.index("DllLoadResult dl = DllLoad")
    bind_pos = body.index("PeResolveImportsForLoadedImage(dl.image.file")
    publish_pos = body.index("ProcessRegisterDllImage(proc, dl.image)")
    require(runtime_pos < lookup_pos, "runtime admission must precede DLL-table lookup")
    require(lookup_pos < load_pos < bind_pos < publish_pos, "runtime DLL must map, bind, then publish")
    require("if (!runtime_access)" in body, "runtime admission failure must return cleanly")
    require("[dll-load] import bind FAIL" in body, "runtime import-bind failure must be observable")
    require("[dll-load] runtime-map PASS" in body, "runtime map/publish path lost its VM oracle")
    require(
        "proc->as, dl.image.base_va" in body[bind_pos : bind_pos + 240],
        "runtime bind must receive the actual mapped base before publication",
    )
    sxs_load_pos = body.index("SxsLoadNamed(src, kname")
    sxs_recurse_pos = body.index("SxsResolveImports(src, root_image->file")
    sxs_rebind_pos = body.index("PeResolveImportsForLoadedImage(image.file", sxs_recurse_pos)
    require(sxs_load_pos < sxs_recurse_pos < sxs_rebind_pos, "side-by-side dependencies must load then cross-bind")
    require("proc->dll_image_count = first_new_image" in body, "failed side-by-side bind must hide tentative rows")

    base_start = syscall.index("case SYS_DLL_BASE_BY_NAME:")
    base_end = syscall.index("case SYS_MODULE_BASE_BY_VA:", base_start)
    module_end = syscall.index("case SYS_WAIT_ON_ADDRESS:", base_end)
    proc_start = syscall.index("case SYS_DLL_PROC_ADDRESS:")
    proc_end = syscall.index("case SYS_DIAG_FAULT_INJECT:", proc_start)
    require(
        "ScopedProcessRuntimeAccess runtime_access(proc)" in syscall[base_start:base_end],
        "named-module lookup must share runtime admission",
    )
    require(
        "ScopedProcessRuntimeAccess runtime_access(proc)" in syscall[base_end:module_end],
        "module-by-VA lookup must share runtime admission",
    )
    require(
        "ScopedProcessRuntimeAccess runtime_access(proc)" in syscall[proc_start:proc_end],
        "GetProcAddress lookup must share runtime admission",
    )
    miss_start = syscall.index("case SYS_WIN32_MISS_LOG:")
    miss_end = syscall.index("case SYS_WRITE:", miss_start)
    require(
        "ScopedProcessRuntimeAccess runtime_access(proc)" in syscall[miss_start:miss_end],
        "Win32 miss attribution must not observe tentative DLL rows",
    )

    loader = (ROOT / "kernel/loader/pe_loader.cpp").read_text(encoding="utf-8")
    resolver_start = loader.index("bool PeResolveImportsForLoadedImage(")
    resolver_end = loader.index("PeLoadResult PeLoad(", resolver_start)
    resolver = loader[resolver_start:resolver_end]
    require("u64 loaded_base" in resolver, "loaded-image resolver must accept the actual mapped base")
    require("h.image_base = loaded_base;" in resolver, "loaded-image resolver must patch at the actual mapped base")
    require(
        "preloaded_dlls[i].file == file" not in resolver,
        "loaded-image resolver must not require premature publication to discover its base",
    )

    fixture = (ROOT / "userland/libs/customdll2/customdll2.c").read_text(encoding="utf-8")
    builder = (ROOT / "tools/build/build-customdll2.sh").read_text(encoding="utf-8")
    smoke = (ROOT / "userland/apps/module_smoke/module_smoke.c").read_text(encoding="utf-8")
    profile = (ROOT / "tools/test/profile-boot-smoke.sh").read_text(encoding="utf-8")
    require("__declspec(dllimport) DWORD GetTickCount(void);" in fixture, "fixture lost kernel32 import")
    require("CustomImportedTick" in fixture, "fixture lost imported-call export")
    require('KERNEL32_LIB=' in builder and '"${KERNEL32_LIB}"' in builder, "fixture no longer links kernel32.lib")
    require("/dynamicbase" in builder, "fixture must remain relocatable so ASLR binding is exercised")
    require("/export:CustomImportedTick" in builder, "fixture export missing from linker command")
    require("GetProcAddress(m, \"CustomImportedTick\")" in smoke, "module smoke no longer calls imported export")
    require("[module_smoke] runtime-dll-iat PASS" in smoke, "runtime-IAT verdict marker missing")
    require("[dll-load] runtime-map PASS" in profile, "strict VM profile no longer proves the runtime map path")

    print("[runtime-dll-load-contract] PASS (ASLR-aware serialized map -> bind -> publish + imported export fixture)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, ValueError) as exc:
        print(f"[runtime-dll-load-contract] FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
