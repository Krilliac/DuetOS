repo: Krilliac/DuetOS
branch: main
path: docs/duet-theme/prototype, kernel/drivers/video

## Last sync
date: 2026-07-28T16:26:22Z

### Updated in this project
- Recreated the current Duet desktop (wallpaper, widgets, 3 app windows, taskbar) from the in-repo React prototype.
- New "Aurora" shell: Aero-lineage glass chrome, floating island taskbar, centred Start, quick settings, notification centre.
- Full app suite designed — Task Manager (4 tabs), Kernel Log, Inspect, Files, Settings → Personalization, Terminal, Notepad, Calculator, GFX Demo.
- Settings surfaces the real theme family and tactility bytes from `theme.h`; accent refined to native #31e0c0 / Win32 peer #ffc046.

## Screen map
| Project screen | Repo files |
|---|---|
| DuetOS Current.dc.html | docs/duet-theme/prototype/desktop.html (tokens), desktop-app.jsx (root, icons, widgets), desktop-taskbar.jsx, desktop-windows.jsx, desktop-startmenu.jsx, desktop-wallpaper.jsx, desktop-icons.jsx, desktop-data.jsx |
| Aurora — Desktop, taskbar, Start, flyouts | same prototype set + kernel/drivers/video/taskbar.h (tray, clock, show-desktop, dock), kernel/drivers/video/theme.h (chrome metrics, roles) |
| Aurora — Task Manager / Kernel Log / Inspect | desktop-windows.jsx, desktop-data.jsx (processes, kernel log, disasm, syscall sites, PE sections) |
| Aurora — Settings → Personalization | kernel/drivers/video/theme.h (ThemeId family, tactility_enabled + intensity bytes, title_bar_height, taskbar_height, font_kind, motion) |
| Aurora — Files / Terminal / Notepad / Calculator / GFX Demo | README.md (PE inventory, framebuffer + d3d11 path, shell output), kernel/apps/ (app roster: files, calculator, notes, gfxdemo, terminal) |
| Aurora — Sign in / Boot | docs/screenshots/01-login-screen.png, README.md (build strings, security posture) |
| Reference rasters | docs/screenshots/06-desktop-duet.png, 01-login-screen.png |
