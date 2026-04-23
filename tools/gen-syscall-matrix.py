#!/usr/bin/env python3
"""Generate a unified syscall ownership/status matrix.

Inputs:
  - kernel/core/syscall.h
  - kernel/subsystems/linux/linux_syscall_table_generated.h
  - kernel/subsystems/win32/nt_syscall_table_generated.h
  - kernel/subsystems/translation/translate.cpp

Outputs:
  - Machine-readable JSON + CSV
  - Markdown report for docs/
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def parse_native_syscalls(path: Path):
    text = path.read_text()
    pattern = re.compile(r"\b(SYS_[A-Z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,")
    out = []
    for name, raw in pattern.findall(text):
        nr = int(raw, 0)
        out.append(
            {
                "abi": "native",
                "number": nr,
                "name": name,
                "status": "implemented",
                "owner": "kernel/core/syscall.h::SyscallNumber",
                "fallback": "none (native syscall entry)",
            }
        )
    out.sort(key=lambda r: r["number"])
    return out


def parse_linux_table(path: Path):
    text = path.read_text()
    pattern = re.compile(
        r'\{\s*(\d+)\s*,\s*(\d+)\s*,\s*HandlerState::(Implemented|Unimplemented|Unknown)\s*,\s*"([^"]+)"\s*\},'
    )
    out = {}
    for nr, _args, state, name in pattern.findall(text):
        out[int(nr)] = {"name": name, "state": state.lower()}
    return out


def parse_nt_table(path: Path):
    text = path.read_text()
    block_match = re.search(
        r"inline constexpr NtSyscallMapping kAllNtSyscalls\[\]\s*=\s*\{(.*?)\n\};",
        text,
        flags=re.S,
    )
    if not block_match:
        raise RuntimeError("kAllNtSyscalls block not found")
    block = block_match.group(1)
    row_re = re.compile(
        r'\{\s*"([^"]+)"\s*,\s*0x([0-9a-fA-F]+)\s*,\s*([^}]+)\},'
    )
    out = []
    for name, num_hex, mapping in row_re.findall(block):
        mapping = mapping.strip()
        nr = int(num_hex, 16)
        if "kSysNtNotImpl" in mapping:
            status = "unimplemented"
            owner = "kernel/subsystems/win32/stubs.cpp::NtStubCatchAll"
            fallback = "STATUS_NOT_IMPLEMENTED"
        else:
            m = re.search(r"::customos::core::(SYS_[A-Z0-9_]+)", mapping)
            sys_name = m.group(1) if m else "(unknown)"
            status = "translated"
            owner = f"kernel/subsystems/win32/nt_syscall_table_generated.h::{sys_name}"
            fallback = f"routes to native {sys_name}"
        out.append(
            {
                "abi": "nt",
                "number": nr,
                "name": name,
                "status": status,
                "owner": owner,
                "fallback": fallback,
            }
        )
    out.sort(key=lambda r: r["number"])
    return out


def parse_translation_map(path: Path):
    text = path.read_text()

    const_re = re.compile(r"\b(k(?:Sys|Native)[A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*,")
    constants = {name: int(value, 0) for name, value in const_re.findall(text)}

    def parse_gapfill(function_name: str):
        start = text.find(f"Result {function_name}(arch::TrapFrame* frame)")
        if start < 0:
            return {}
        end = text.find("return r;", start)
        if end < 0:
            return {}
        body = text[start:end]

        lines = body.splitlines()
        mapping = {}
        pending = []
        current_target = ""
        current_handler = ""
        for line in lines:
            s = line.strip()
            m_case = re.match(r"case\s+(k[A-Za-z0-9_]+)\s*:", s)
            if m_case:
                pending.append(m_case.group(1))
                continue

            m_log = re.search(r'LogTranslation\("[^"]+",\s*nr,\s*"([^"]+)"\)', s)
            if m_log:
                current_target = m_log.group(1)
                continue

            m_assign = re.search(r"r\s*=\s*\{true,\s*([A-Za-z0-9_]+)\(frame\)\}\s*;", s)
            if m_assign:
                current_handler = m_assign.group(1)
                continue

            if s == "break;" and pending:
                for label in pending:
                    nr = constants.get(label)
                    if nr is None:
                        continue
                    mapping[nr] = {
                        "handler": current_handler or "(unknown)",
                        "behavior": current_target or "(no-log-target)",
                    }
                pending = []
                current_target = ""
                current_handler = ""
        return mapping

    return parse_gapfill("LinuxGapFill"), parse_gapfill("NativeGapFill")


def render_markdown(rows):
    out = []
    out.append("# Syscall ABI Coverage Matrix\n")
    out.append("_Auto-generated; do not edit by hand._\n")
    out.append("\n")
    out.append("| ABI | number | name | status | owner file/function | fallback behavior |")
    out.append("| --- | ---: | --- | --- | --- | --- |")
    for r in rows:
        out.append(
            f"| {r['abi']} | {r['number']} | `{r['name']}` | {r['status']} | `{r['owner']}` | {r['fallback']} |"
        )
    out.append("")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syscall-h", type=Path, default=Path("kernel/core/syscall.h"))
    ap.add_argument(
        "--linux-table",
        type=Path,
        default=Path("kernel/subsystems/linux/linux_syscall_table_generated.h"),
    )
    ap.add_argument(
        "--nt-table",
        type=Path,
        default=Path("kernel/subsystems/win32/nt_syscall_table_generated.h"),
    )
    ap.add_argument(
        "--translate-cpp",
        type=Path,
        default=Path("kernel/subsystems/translation/translate.cpp"),
    )
    ap.add_argument("--out-json", type=Path, required=True)
    ap.add_argument("--out-csv", type=Path, required=True)
    ap.add_argument("--out-md", type=Path, required=True)
    args = ap.parse_args()

    native_rows = parse_native_syscalls(args.syscall_h)
    linux_by_nr = parse_linux_table(args.linux_table)
    nt_rows = parse_nt_table(args.nt_table)
    linux_gapfill, native_gapfill = parse_translation_map(args.translate_cpp)

    linux_rows = []
    for nr, entry in sorted(linux_by_nr.items()):
        if nr in linux_gapfill:
            status = "translated"
            owner = f"kernel/subsystems/translation/translate.cpp::{linux_gapfill[nr]['handler']}"
            fallback = linux_gapfill[nr]["behavior"]
        elif entry["state"] == "implemented":
            status = "implemented"
            owner = "kernel/subsystems/linux/syscall.cpp::Do*"
            fallback = "none (handled in linux dispatcher)"
        else:
            status = "unimplemented"
            owner = "kernel/subsystems/linux/syscall.cpp::DispatchSyscall"
            fallback = "-ENOSYS"

        linux_rows.append(
            {
                "abi": "linux",
                "number": nr,
                "name": entry["name"],
                "status": status,
                "owner": owner,
                "fallback": fallback,
            }
        )

    # Native translator extension pseudo-syscalls (0x200+) are not part
    # of core SyscallNumber. Track them so ownership is explicit.
    native_translation_rows = []
    for nr, entry in sorted(native_gapfill.items()):
        native_translation_rows.append(
            {
                "abi": "native",
                "number": nr,
                "name": f"native_gapfill_{nr:#x}",
                "status": "translated",
                "owner": f"kernel/subsystems/translation/translate.cpp::{entry['handler']}",
                "fallback": entry["behavior"],
            }
        )

    rows = native_rows + native_translation_rows + linux_rows + nt_rows
    rows.sort(key=lambda r: (r["abi"], r["number"], r["name"]))

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.parent.mkdir(parents=True, exist_ok=True)

    args.out_json.write_text(json.dumps(rows, indent=2) + "\n")

    with args.out_csv.open("w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["abi", "number", "name", "status", "owner", "fallback"]
        )
        writer.writeheader()
        writer.writerows(rows)

    args.out_md.write_text(render_markdown(rows))

    print(f"wrote {args.out_json}")
    print(f"wrote {args.out_csv}")
    print(f"wrote {args.out_md}")
    print(f"rows: {len(rows)}")


if __name__ == "__main__":
    main()
