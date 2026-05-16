#pragma once

// Boot task entry points hoisted out of kernel_main (core/main.cpp).
// These were non-capturing [](void*) lambdas assigned to a local
// and immediately handed to duetos::sched::SchedCreate as the task
// entry. A non-capturing lambda converts to the same
// void(*)(void*) TaskEntry a free function provides, so moving the
// bodies out is pure code motion — kernel_main spawns them at the
// exact point it used to.

namespace duetos::core
{

// 1 Hz desktop tick: log/fix-journal/session persistence flush,
// Sysmon sampling, and the compositor recompose (or login
// repaint / TTY clear).
void UiTickerTask(void* arg);

// Keyboard reader: Ps2 KeyEvent consumer, global shortcut +
// window/app keyboard dispatch, console + COM1 mirroring.
void KbdReaderTask(void* arg);

// Mouse reader: Ps2 packet consumer driving window
// focus/drag/resize/snap, menu/taskbar/tray + scrollbar
// interaction and the desktop context menu.
void MouseReaderTask(void* arg);

// Win32 per-window timer ticker (posts WM_TIMER).
void WinTimerTickerTask(void* arg);

// Scheduler self-test worker (mutex-guarded shared counter).
void SchedDemoWorkerTask(void* arg);

} // namespace duetos::core
