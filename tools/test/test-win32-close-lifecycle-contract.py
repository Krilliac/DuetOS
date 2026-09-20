#!/usr/bin/env python3
"""Contract for Alt+F4 and USER32 close/destroy lifecycle semantics."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BOOT_TASKS = (ROOT / "kernel" / "core" / "boot_tasks.cpp").read_text(encoding="utf-8")
USER32 = (ROOT / "userland" / "libs" / "user32" / "user32.c").read_text(encoding="utf-8")
USER32_32 = (ROOT / "userland" / "libs" / "user32_32" / "user32_32.c").read_text(encoding="utf-8")
PE32_WINDOW = (ROOT / "userland" / "apps" / "pe32_window" / "pe32_window.c").read_text(encoding="utf-8")


def section(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


class Win32CloseLifecycleContract(unittest.TestCase):
    def test_alt_f4_posts_close_for_pe_and_hides_kernel_windows(self) -> None:
        block = section(BOOT_TASKS, "if (alt && ev.code == kKeyF4)", "// PE-routed keystrokes")
        self.assertIn("WindowSetVisible(active, false)", block)
        self.assertIn("constexpr duetos::u32 kWmClose = 0x0010", block)
        self.assertIn("WindowPostMessage(active, kWmClose, 0, 0)", block)
        self.assertNotIn("WindowClose(active)", block)

    def test_default_close_destroys_in_both_user32_abis(self) -> None:
        for name, source, next_export in (
            ("pe32+", USER32, "__declspec(dllexport) LRESULT DefWindowProcW",),
            ("pe32", USER32_32, "__declspec(dllexport) LRESULT __stdcall DefWindowProcW",),
        ):
            with self.subTest(abi=name):
                body = section(source, "DefWindowProcA(", next_export)
                self.assertIn("msg == WM_CLOSE", body)
                self.assertIn("DestroyWindow(h)", body)

    def test_destroy_lifecycle_is_guarded_and_ordered_in_both_abis(self) -> None:
        for name, source, start, end in (
            ("pe32+", USER32, "__declspec(dllexport) BOOL DestroyWindow", "__declspec(dllexport) BOOL ShowWindow"),
            (
                "pe32",
                USER32_32,
                "__declspec(dllexport) BOOL __stdcall DestroyWindow",
                "__declspec(dllexport) BOOL __stdcall ShowWindow",
            ),
        ):
            with self.subTest(abi=name):
                body = section(source, start, end)
                self.assertIn("s_destroying_window", body)
                destroy = body.index("WM_DESTROY")
                syscall = body.index("SYS_WIN_DESTROY")
                nc_destroy = body.index("WM_NCDESTROY")
                self.assertTrue(destroy < syscall < nc_destroy)

        pe32 = section(
            USER32_32,
            "__declspec(dllexport) BOOL __stdcall DestroyWindow",
            "__declspec(dllexport) BOOL __stdcall ShowWindow",
        )
        syscall = pe32.index("SYS_WIN_DESTROY")
        self.assertGreater(pe32.index("user32_dialog_on_destroy(h)"), syscall)
        self.assertGreater(pe32.index("user32_record_destroy(h)"), syscall)

    def test_always_on_pe32_fixture_proves_default_close_lifecycle(self) -> None:
        for token in (
            "PostMessageA(hwnd, WM_CLOSE",
            "g_destroy_calls",
            "g_nc_destroy_calls",
            "[pe32-window] close lifecycle ok",
        ):
            self.assertIn(token, PE32_WINDOW)


if __name__ == "__main__":
    unittest.main()
