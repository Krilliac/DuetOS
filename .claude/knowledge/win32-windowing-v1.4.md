# Win32 windowing v1.4 — SendMessage + styles + parent/focus + caret + beep + MessageBox types

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Landed — `windowed_hello` now round-trips
SendMessage → WndProc, GWL_STYLE set/get, SetFocus/GetFocus,
CreateCaret + SetCaretPos + ShowCaret, MessageBeep, all
end-to-end.

## What shipped (syscalls 94..100)

### Parent / child (94 / 95 / 96)

`RegisteredWindow.parent` holds a WindowHandle or
kWindowInvalid. `SetParent` / `GetParent` / `GetWindow(GW_*)`
back the Win32 names; `WindowGetRelated` walks z-order for
Next/Prev/First/Last and scans for Child. Owner is aliased to
parent in v1 (no separate owner field).

### Focus separate from active (97 / 98)

`g_focus_hwnd` is a distinct handle from `g_active_window`
(the topmost z-order). `SetFocus` fires
WM_KILLFOCUS(old, wParam=new_hwnd) and WM_SETFOCUS(new,
wParam=prev_hwnd). Callers that want "focus but don't raise"
finally have the API.

### Caret (99)

Single global blinking rectangle. One syscall (op + args) does
Create / Destroy / SetPos / Show / Hide. The compositor's
DesktopCompose toggles `g_caret_on` on every compose and
paints a solid rectangle when `on && shown && visible`. The
1-Hz ui-ticker drives the blink cadence.

### MessageBeep / Beep (100)

Forwards to `duetos::drivers::audio::PcSpeakerBeep(freq_hz,
duration_ms)` — 800 Hz / 100 ms defaults for `MessageBeep(0)`.
Blocking (PC speaker busy-loops in the driver), but the
duration is brief enough to accept.

## SendMessage — user32 only

`SendMessageA/W` + `SendNotifyMessageA/W` fetch the target's
GWLP_WNDPROC via SYS_WIN_GET_LONG and invoke it directly
(`__stdcall` ABI). Cross-process SendMessage naturally fails
— the kernel's HwndToCompositorHandleForCaller refuses reads
against another pid's HWND so GWLP_WNDPROC comes back 0.

## Window styles — client-side remap via GWL_STYLE / GWL_EXSTYLE

No new kernel state. User32's `user32_slot_from_index()`
recognises Win32's negative constants (GWLP_WNDPROC=-4,
GWLP_USERDATA=-21, GWL_STYLE=-16, GWL_EXSTYLE=-20) and
remaps to the 4-slot `RegisteredWindow.longs[]` array:
slot 0 = WNDPROC, slot 1 = USERDATA, slot 2 = STYLE, slot 3 =
EXSTYLE. CreateWindowEx captures `dwStyle` + `dwExStyle` into
slots 2/3 right after the window is created.

## MessageBox — real return codes

User32's `user32_msgbox_result(uType)` maps:

| uType & 0xF | Return code |
|-------------|-------------|
| MB_OK (0) | IDOK (1) |
| MB_OKCANCEL (1) | IDOK (1) |
| MB_ABORTRETRYIGNORE (2) | IDRETRY (4) |
| MB_YESNOCANCEL (3) | IDYES (6) |
| MB_YESNO (4) | IDYES (6) |
| MB_RETRYCANCEL (5) | IDRETRY (4) |

Simulates "user clicked the default button". No modal UI
still — the MessageBox text is serial-logged as before.

## New exports (user32.dll)

Beep, CreateCaret, DestroyCaret, GetCaretBlinkTime, GetFocus,
GetParent, GetWindow, HideCaret, MessageBeep, SendNotifyMessageA,
SendNotifyMessageW, SetCaretBlinkTime, SetCaretPos, SetFocus,
SetParent, ShowCaret. Plus upgrades to MessageBox[A/W/ExA/ExW]
(real return codes), SendMessage[A/W] (real WndProc invoke),
GetWindowLongPtr[A/W] (Win32 negative constant remap),
CreateWindowEx[A/W] (captures style/exstyle/parent).

## Verification

```
[odbg] windowed_hello: screen w=1280
[odbg] windowed_hello: screen h=800
[odbg] windowed_hello: paint done
[odbg] windowed_hello: drained 8
[odbg] windowed_hello: pumped 3
[odbg] windowed_hello: timers 3
[odbg] windowed_hello: wndproc 3
[odbg] windowed_hello: painted 1
[odbg] windowed_hello: send_rv 0      ← SendMessage returned DefWndProc's 0
[odbg] windowed_hello: send_ud 1      ← WndProc incremented USERDATA
[odbg] windowed_hello: style   3735928559  ← 0xDEADBEEF round-trip
[odbg] windowed_hello: focus   7            ← GetFocus = biased HWND
[odbg] windowed_hello: caret+beep done
[I] sys : exit rc val=0x57
```

## Still NOT done yet

- **Modal dialog loops** — DialogBox / EndDialog. Would need a
  nested message-pump + DialogProc dispatch.
- **Menus** — CreateMenu / AppendMenu / TrackPopupMenu not
  implemented. Menu bars and popup menus are a big slice.
- **Common controls** — no edit / button / list / treeview.
- **Scroll bars** — no SB_* API, no WM_HSCROLL / WM_VSCROLL.
- **Icon / bitmap rendering** — LoadBitmap etc. still return 0.
- **Font rendering** — only the 8×8 built-in font via TextOut.
- **Multi-threaded GetMessage** — the per-pid filter works for
  single-threaded PEs; a multi-threaded PE would see its
  threads' queues merged.
