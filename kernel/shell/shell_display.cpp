// Display / GPU / monitor shell commands (gpu, gfx, vbe,
// dpms, monitor, hdajacks, mei). Split out of
// shell_hardware.cpp to keep TUs within the size
// guideline; behaviour is unchanged.

#include "shell/shell_internal.h"
#include "shell/shell.h"
#include "arch/x86_64/cet.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/cpu_info.h"
#include "arch/x86_64/cpu_mitigations.h"
#include "arch/x86_64/hpet.h"
#include "arch/x86_64/lapic.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/smbios.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/smp.h"
#include "arch/x86_64/thermal.h"
#include "arch/x86_64/timer.h"
#include "diag/cleanroom_trace.h"
#include "diag/fix_journal.h"
#include "drivers/audio/audio.h"
#include "drivers/audio/hda.h"
#include "drivers/audio/hda_jack.h"
#include "drivers/audio/hda_jack_inventory.h"
#include "drivers/mei/mei.h"
#include "drivers/npu/npu.h"
#include "env/autonomic.h"
#include "drivers/gpu/bochs_vbe.h"
#include "drivers/gpu/cea861.h"
#include "drivers/gpu/cvt.h"
#include "drivers/gpu/dpms.h"
#include "drivers/gpu/edid.h"
#include "drivers/gpu/gpu.h"
#include "drivers/gpu/virtio_gpu.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/net/net.h"
#include "drivers/pci/pci.h"
#include "drivers/power/power.h"
#include "drivers/storage/ahci.h"
#include "drivers/storage/block.h"
#include "drivers/storage/nvme.h"
#include "drivers/usb/usb.h"
#include "drivers/usb/xhci.h"
#include "drivers/video/console.h"
#include "drivers/video/display_info.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/render_stats.h"
#include "mm/kheap.h"
#include "mm/page.h"
#include "mm/paging.h"
#include "sched/sched.h"
#include "subsystems/graphics/graphics.h"
#include "time/tick.h"
#include "util/symbols.h"

namespace duetos::core::shell::internal
{

namespace
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;
using duetos::drivers::video::ConsoleWriteln;

} // namespace

void CmdGpu()
{
    const u64 n = duetos::drivers::gpu::GpuCount();
    if (n == 0)
    {
        ConsoleWriteln("GPU: (none discovered)");
        return;
    }
    bool saw_virtio = false;
    for (u64 i = 0; i < n; ++i)
    {
        const auto& g = duetos::drivers::gpu::Gpu(i);
        ConsoleWrite("GPU ");
        WriteU64Dec(i);
        ConsoleWrite(": vid=");
        WriteU64Hex(g.vendor_id, 4);
        ConsoleWrite(" did=");
        WriteU64Hex(g.device_id, 4);
        ConsoleWrite("  vendor=");
        ConsoleWrite(g.vendor);
        ConsoleWrite(" tier=");
        ConsoleWrite(g.tier);
        if (g.family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(g.family);
        }
        ConsoleWriteChar('\n');
        if (g.mmio_size != 0)
        {
            ConsoleWrite("       BAR0=");
            WriteU64Hex(g.mmio_phys, 0);
            ConsoleWrite("/");
            WriteU64Hex(g.mmio_size, 0);
            if (g.mmio_live)
            {
                ConsoleWrite("  MMIO=LIVE  probe_reg=");
                WriteU64Hex(g.probe_reg, 8);
                if (g.arch != nullptr)
                {
                    ConsoleWrite(" arch=");
                    ConsoleWrite(g.arch);
                }
            }
            else if (g.mmio_virt != nullptr)
            {
                ConsoleWrite("  MMIO=DECODE-FAIL");
            }
            else
            {
                ConsoleWrite("  MMIO=unmapped");
            }
            ConsoleWriteChar('\n');
        }
        if (g.vendor_id == duetos::drivers::gpu::kVendorRedHatVirt && g.device_id == 0x1050)
            saw_virtio = true;
    }

    if (saw_virtio)
    {
        const auto v = duetos::drivers::gpu::VirtioGpuLastLayout();
        if (v.present)
        {
            ConsoleWriteln("virtio-gpu layout:");
            ConsoleWrite("  common_cfg phys=");
            WriteU64Hex(v.common_cfg_phys, 0);
            ConsoleWrite("  num_queues=");
            WriteU64Dec(v.num_queues);
            ConsoleWrite("  device_features_lo=");
            WriteU64Hex(v.device_features_lo, 8);
            ConsoleWrite("  status_after_reset=");
            WriteU64Hex(v.device_status_after_reset, 2);
            ConsoleWriteChar('\n');
        }
        else
        {
            ConsoleWriteln("virtio-gpu: device present but probe incomplete (no common_cfg)");
        }

        const auto& d = duetos::drivers::gpu::VirtioGpuLastDisplayInfo();
        if (d.valid)
        {
            ConsoleWrite("virtio-gpu displays: ");
            WriteU64Dec(d.active_scanouts);
            ConsoleWriteln(" active scanout(s)");
            for (u32 i = 0; i < duetos::drivers::gpu::kVirtioGpuMaxScanouts; ++i)
            {
                if (d.enabled[i] == 0)
                    continue;
                ConsoleWrite("  scanout ");
                WriteU64Dec(i);
                ConsoleWrite(": ");
                WriteU64Dec(d.rects[i].width);
                ConsoleWrite("x");
                WriteU64Dec(d.rects[i].height);
                ConsoleWrite(" @ (");
                WriteU64Dec(d.rects[i].x);
                ConsoleWrite(",");
                WriteU64Dec(d.rects[i].y);
                ConsoleWriteln(")");
            }
        }
        else
        {
            ConsoleWriteln("virtio-gpu displays: GET_DISPLAY_INFO not issued or failed");
        }

        const auto& sc = duetos::drivers::gpu::VirtioGpuScanoutInfo();
        if (sc.ready)
        {
            ConsoleWrite("virtio-gpu scanout ");
            WriteU64Dec(sc.scanout_id);
            ConsoleWrite(": resource=");
            WriteU64Dec(sc.resource_id);
            ConsoleWrite(" ");
            WriteU64Dec(sc.width);
            ConsoleWrite("x");
            WriteU64Dec(sc.height);
            ConsoleWrite("x32 BGRA  backing phys=");
            WriteU64Hex(sc.backing_phys, 0);
            ConsoleWrite(" / ");
            WriteU64Dec(sc.backing_bytes);
            ConsoleWriteln(" B");
        }
    }
}

void CmdGfx(u32 argc, char** argv)
{
    // Subcommands: `gfx reset` clears the render-stats counters
    // so the operator can measure a specific scenario (open the
    // Files app, drag a window, etc.) without prior history. The
    // ICD handle-table counters and the GPU discovery cache are
    // boot-stable and not part of the reset.
    if (argc >= 2 && argv != nullptr && argv[1] != nullptr)
    {
        if (StrEq(argv[1], "reset"))
        {
            duetos::drivers::video::RenderStatsReset();
            ConsoleWriteln("gfx: render stats reset");
            return;
        }
        ConsoleWrite("gfx: unknown subcommand '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("' (try: gfx, gfx reset)");
        return;
    }

    // Surfaces the graphics ICD handle-pool counters. The ICD now
    // implements a real CPU-side Vulkan lifecycle (Instance, Device,
    // CommandPool, ShaderModule, Pipeline, RenderPass, ...) plus a
    // command tape that vkQueueSubmit replays — see
    // subsystems/graphics/graphics.h. D3D translation thunks still
    // E_FAIL for now.
    const auto s = duetos::subsystems::graphics::GraphicsStatsRead();
    ConsoleWriteln("Graphics ICD (Vulkan v0; D3D translation skeleton)");
    ConsoleWrite("  Vulkan instances:    live=");
    WriteU64Dec(s.vk_instances_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_instances_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_instances_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  Vulkan devices:      live=");
    WriteU64Dec(s.vk_devices_live);
    ConsoleWrite(" created=");
    WriteU64Dec(s.vk_devices_created);
    ConsoleWrite(" destroyed=");
    WriteU64Dec(s.vk_devices_destroyed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  Vulkan resources live: cmdpools=");
    WriteU64Dec(s.vk_command_pools_live);
    ConsoleWrite(" cmdbufs=");
    WriteU64Dec(s.vk_command_buffers_live);
    ConsoleWrite(" shaders=");
    WriteU64Dec(s.vk_shader_modules_live);
    ConsoleWrite(" pipelines=");
    WriteU64Dec(s.vk_pipelines_live);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         renderpasses=");
    WriteU64Dec(s.vk_render_passes_live);
    ConsoleWrite(" framebuffers=");
    WriteU64Dec(s.vk_framebuffers_live);
    ConsoleWrite(" images=");
    WriteU64Dec(s.vk_images_live);
    ConsoleWrite(" views=");
    WriteU64Dec(s.vk_image_views_live);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         buffers=");
    WriteU64Dec(s.vk_buffers_live);
    ConsoleWrite(" memory=");
    WriteU64Dec(s.vk_device_memory_live);
    ConsoleWrite(" fences=");
    WriteU64Dec(s.vk_fences_live);
    ConsoleWrite(" semaphores=");
    WriteU64Dec(s.vk_semaphores_live);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         dsl=");
    WriteU64Dec(s.vk_descriptor_set_layouts_live);
    ConsoleWrite(" dpools=");
    WriteU64Dec(s.vk_descriptor_pools_live);
    ConsoleWrite(" dsets=");
    WriteU64Dec(s.vk_descriptor_sets_live);
    ConsoleWrite(" dwrites=");
    WriteU64Dec(s.vk_descriptor_writes);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         surfaces=");
    WriteU64Dec(s.vk_surfaces_live);
    ConsoleWrite(" swapchains=");
    WriteU64Dec(s.vk_swapchains_live);
    ConsoleWrite(" acquires=");
    WriteU64Dec(s.vk_swapchain_acquires);
    ConsoleWrite(" presents=");
    WriteU64Dec(s.vk_swapchain_presents);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         samplers=");
    WriteU64Dec(s.vk_samplers_live);
    ConsoleWrite(" events=");
    WriteU64Dec(s.vk_events_live);
    ConsoleWrite(" pcaches=");
    WriteU64Dec(s.vk_pipeline_caches_live);
    ConsoleWrite(" qpools=");
    WriteU64Dec(s.vk_query_pools_live);
    ConsoleWriteChar('\n');
    ConsoleWrite("  Vulkan submit traffic: submits=");
    WriteU64Dec(s.vk_queue_submits);
    ConsoleWrite(" recorded=");
    WriteU64Dec(s.vk_command_recorded);
    ConsoleWrite(" replayed=");
    WriteU64Dec(s.vk_command_replayed);
    ConsoleWrite(" clear-px=");
    WriteU64Dec(s.vk_clear_pixels_painted);
    ConsoleWrite(" upload-px=");
    WriteU64Dec(s.vk_image_upload_pixels);
    ConsoleWrite(" triangles=");
    WriteU64Dec(s.vk_triangles_drawn);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         copy-bytes=");
    WriteU64Dec(s.vk_buffer_copy_bytes);
    ConsoleWrite(" fill-bytes=");
    WriteU64Dec(s.vk_buffer_fill_bytes);
    ConsoleWrite(" pushes=");
    WriteU64Dec(s.vk_push_constant_writes);
    ConsoleWrite(" barriers=");
    WriteU64Dec(s.vk_pipeline_barriers);
    ConsoleWrite(" dispatches=");
    WriteU64Dec(s.vk_dispatches);
    ConsoleWriteChar('\n');
    ConsoleWrite("                         queries=");
    WriteU64Dec(s.vk_queries_executed);
    ConsoleWrite(" maps=");
    WriteU64Dec(s.vk_memory_maps);
    ConsoleWriteChar('\n');
    ConsoleWrite("  SPIR-V parser: modules=");
    WriteU64Dec(s.vk_spirv_modules_parsed);
    ConsoleWrite(" rejected=");
    WriteU64Dec(s.vk_invalid_spirv_rejections);
    ConsoleWrite(" entry-points=");
    WriteU64Dec(s.vk_spirv_entry_points_seen);
    ConsoleWrite(" capabilities=");
    WriteU64Dec(s.vk_spirv_capabilities_seen);
    ConsoleWrite(" execution-modes=");
    WriteU64Dec(s.vk_spirv_execution_modes_seen);
    ConsoleWrite(" decorations=");
    WriteU64Dec(s.vk_spirv_decorations_seen);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D3D11/12 create calls: ");
    WriteU64Dec(s.d3d_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DXGI create calls:     ");
    WriteU64Dec(s.dxgi_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D3D9 create calls:     ");
    WriteU64Dec(s.d3d9_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DInput8 create calls:  ");
    WriteU64Dec(s.dinput8_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  XInput poll calls:     ");
    WriteU64Dec(s.xinput_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  XAudio2 create calls:  ");
    WriteU64Dec(s.xaudio2_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DSound create calls:   ");
    WriteU64Dec(s.dsound_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DDraw create calls:    ");
    WriteU64Dec(s.ddraw_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  D2D1 create calls:     ");
    WriteU64Dec(s.d2d1_create_calls);
    ConsoleWriteChar('\n');
    ConsoleWrite("  DWrite create calls:   ");
    WriteU64Dec(s.dwrite_create_calls);
    ConsoleWriteChar('\n');

    const u64 ngpu = duetos::drivers::gpu::GpuCount();
    ConsoleWrite("  Physical devices visible to ICD: ");
    WriteU64Dec(ngpu);
    ConsoleWriteChar('\n');

    // Display info — bundles framebuffer + GPU + present backend.
    // Comes after the ICD section so the operator sees the
    // "skeleton ICD" first and the "but here's what's actually
    // driving the screen" reality second.
    const auto di = duetos::drivers::video::Query();
    ConsoleWriteln("Display");
    if (!di.available)
    {
        ConsoleWriteln("  framebuffer: <not available> — boot stayed on serial");
    }
    else
    {
        ConsoleWrite("  framebuffer: ");
        WriteU64Dec(di.width);
        ConsoleWrite("x");
        WriteU64Dec(di.height);
        ConsoleWrite(" pitch=");
        WriteU64Dec(di.pitch);
        ConsoleWrite(" bpp=");
        WriteU64Dec(di.bpp);
        ConsoleWriteChar('\n');
        ConsoleWrite("  fb_phys=");
        WriteU64Hex(di.fb_phys);
        ConsoleWrite(" fb_virt=");
        WriteU64Hex(di.fb_virt);
        ConsoleWriteChar('\n');
    }
    ConsoleWrite("  backend: ");
    ConsoleWrite(duetos::drivers::video::PresentBackendName(di.backend));
    if (di.compose_active)
        ConsoleWrite(" (compose-active)");
    ConsoleWriteChar('\n');
    if (di.gpu_present)
    {
        ConsoleWrite("  primary GPU: vendor=");
        ConsoleWrite(di.gpu_vendor != nullptr ? di.gpu_vendor : "<unknown>");
        ConsoleWrite(" tier=");
        ConsoleWrite(di.gpu_tier != nullptr ? di.gpu_tier : "<unknown>");
        if (di.gpu_family != nullptr)
        {
            ConsoleWrite(" family=");
            ConsoleWrite(di.gpu_family);
        }
        if (di.gpu_arch != nullptr)
        {
            ConsoleWrite(" arch=");
            ConsoleWrite(di.gpu_arch);
        }
        ConsoleWriteChar('\n');
        if (di.gpu_mmio_size != 0)
        {
            ConsoleWrite("  bar0=");
            WriteU64Hex(di.gpu_mmio_phys);
            ConsoleWrite("/");
            WriteU64Hex(di.gpu_mmio_size, 0);
            ConsoleWriteChar('\n');
        }
    }
    else
    {
        ConsoleWriteln("  primary GPU: <none discovered>");
    }

    // Render stats — accumulated since boot (or since the last
    // RenderStatsReset). Reads as a one-shot snapshot, no
    // side effects.
    const auto rs = duetos::drivers::video::RenderStatsRead();
    ConsoleWriteln("Render stats (since boot)");
    ConsoleWrite("  frames composed:   ");
    WriteU64Dec(rs.frames_composed);
    ConsoleWriteChar('\n');
    ConsoleWrite("  frames presented:  ");
    WriteU64Dec(rs.frames_presented);
    ConsoleWrite("  (clean=");
    WriteU64Dec(rs.frames_clean);
    ConsoleWrite(" partial=");
    WriteU64Dec(rs.frames_partial);
    ConsoleWrite(" full=");
    WriteU64Dec(rs.frames_full);
    ConsoleWrite(")\n");
    if (rs.surface_pixels_total != 0)
    {
        // Per-mille rather than percent so a 5% partial frame
        // doesn't round to "0%". The compositor's chrome-heavy
        // frames usually land in the 1-20% range when only the
        // taskbar / clock / cursor blink.
        const u64 permille = (rs.dirty_pixels_total * 1000ULL) / rs.surface_pixels_total;
        ConsoleWrite("  avg dirty fraction: ");
        WriteU64Dec(permille);
        ConsoleWrite("‰ (");
        WriteU64Dec(rs.dirty_pixels_total);
        ConsoleWrite(" / ");
        WriteU64Dec(rs.surface_pixels_total);
        ConsoleWrite(" px)\n");
    }
    if (rs.last_damage_valid)
    {
        ConsoleWrite("  last damage rect: ");
        WriteU64Dec(rs.last_damage_w);
        ConsoleWrite("x");
        WriteU64Dec(rs.last_damage_h);
        ConsoleWrite(" @ (");
        WriteU64Dec(rs.last_damage_x);
        ConsoleWrite(",");
        WriteU64Dec(rs.last_damage_y);
        ConsoleWrite(")\n");
    }
}

void CmdVbe(u32 argc, char** argv)
{
    using duetos::drivers::gpu::VbeCaps;
    using duetos::drivers::gpu::VbeQuery;
    using duetos::drivers::gpu::VbeSetMode;

    if (argc == 1)
    {
        const VbeCaps c = VbeQuery();
        if (!c.present)
        {
            ConsoleWriteln("VBE: not present (no Bochs / BGA-compatible GPU found)");
            return;
        }
        ConsoleWrite("VBE: id=0xB0C");
        WriteU64Hex(c.version, 1);
        ConsoleWrite("  current=");
        WriteU64Dec(c.cur_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.cur_bpp);
        ConsoleWrite(c.enabled ? " LIVE" : " DISABLED");
        ConsoleWrite("  max=");
        WriteU64Dec(c.max_xres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_yres);
        ConsoleWrite("x");
        WriteU64Dec(c.max_bpp);
        ConsoleWriteChar('\n');
        ConsoleWriteln("Usage: vbe <width> <height> [bpp]   — set mode (bpp defaults to 32)");
        ConsoleWriteln("       vbe                          — show current + max");
        ConsoleWriteln("NOTE: mode-set programs the controller; the framebuffer driver");
        ConsoleWriteln("      keeps its original layout until the compositor rewires.");
        return;
    }

    if (argc < 3)
    {
        ConsoleWriteln("VBE: usage: vbe [width height [bpp]]");
        return;
    }
    u16 width = 0, height = 0, bpp = 32;
    if (!ParseU16Decimal(argv[1], &width) || !ParseU16Decimal(argv[2], &height))
    {
        ConsoleWriteln("VBE: width/height must be decimal integers");
        return;
    }
    if (argc >= 4 && !ParseU16Decimal(argv[3], &bpp))
    {
        ConsoleWriteln("VBE: bpp must be decimal (8, 15, 16, 24, or 32)");
        return;
    }
    if (VbeSetMode(width, height, bpp))
    {
        ConsoleWrite("VBE: mode set OK — ");
        WriteU64Dec(width);
        ConsoleWrite("x");
        WriteU64Dec(height);
        ConsoleWrite("x");
        WriteU64Dec(bpp);
        ConsoleWriteln("");

        // Rebind the kernel framebuffer driver to the Bochs-
        // stdvga BAR0 at the new dimensions so subsequent
        // paints land at the requested resolution. Find the
        // Bochs GPU in the discovery cache — BAR0 is the
        // linear framebuffer aperture.
        u64 lfb_phys = 0;
        const u64 gn = duetos::drivers::gpu::GpuCount();
        for (u64 i = 0; i < gn; ++i)
        {
            const auto& g = duetos::drivers::gpu::Gpu(i);
            if (g.vendor_id == duetos::drivers::gpu::kVendorQemuBochs && g.mmio_phys != 0)
            {
                lfb_phys = g.mmio_phys;
                break;
            }
        }
        if (lfb_phys == 0)
        {
            ConsoleWriteln("VBE: hardware programmed, but no Bochs BAR0 found — fb not rebound");
            return;
        }
        const u32 pitch = static_cast<u32>(width) * 4;
        if (duetos::drivers::video::FramebufferRebind(lfb_phys, width, height, pitch, static_cast<u8>(bpp)))
        {
            duetos::drivers::video::FramebufferClear(0);
            ConsoleWriteln("VBE: framebuffer rebound; next recompose paints at the new size");
            ConsoleWriteln("     (overlay widgets retain boot-time positions — known limitation)");
        }
        else
        {
            ConsoleWriteln("VBE: hardware programmed, but framebuffer rebind failed");
        }
    }
    else
    {
        ConsoleWriteln("VBE: mode-set rejected (dimensions exceed max, bpp unsupported, or no BGA)");
    }
}

void CmdDpms(u32 argc, char** argv)
{
    using duetos::drivers::gpu::DpmsGet;
    using duetos::drivers::gpu::DpmsSetState;
    using duetos::drivers::gpu::DpmsState;
    using duetos::drivers::gpu::DpmsStateName;
    using duetos::drivers::gpu::DpmsTransitionCount;

    if (argc < 2)
    {
        ConsoleWrite("DPMS: state=");
        ConsoleWrite(DpmsStateName(DpmsGet()));
        ConsoleWrite("  driver-hook transitions=");
        WriteU64Dec(DpmsTransitionCount());
        ConsoleWriteChar('\n');
        ConsoleWriteln("USAGE: DPMS ON|STANDBY|SUSPEND|OFF");
        ConsoleWriteln("  ON       both syncs active (full power)");
        ConsoleWriteln("  STANDBY  H-sync off (~80% power)");
        ConsoleWriteln("  SUSPEND  V-sync off (~30% power)");
        ConsoleWriteln("  OFF      both syncs off (panel sleep, <8W)");
        return;
    }

    DpmsState target;
    if (StrEq(argv[1], "on") || StrEq(argv[1], "ON"))
        target = DpmsState::On;
    else if (StrEq(argv[1], "standby") || StrEq(argv[1], "STANDBY"))
        target = DpmsState::Standby;
    else if (StrEq(argv[1], "suspend") || StrEq(argv[1], "SUSPEND"))
        target = DpmsState::Suspend;
    else if (StrEq(argv[1], "off") || StrEq(argv[1], "OFF"))
        target = DpmsState::Off;
    else
    {
        ConsoleWrite("DPMS: UNKNOWN STATE '");
        ConsoleWrite(argv[1]);
        ConsoleWriteln("' (ON|STANDBY|SUSPEND|OFF)");
        return;
    }

    if (DpmsSetState(target))
    {
        ConsoleWrite("DPMS: -> ");
        ConsoleWriteln(DpmsStateName(target));
    }
    else
    {
        ConsoleWrite("DPMS: transition to ");
        ConsoleWrite(DpmsStateName(target));
        ConsoleWriteln(" VETOED by driver hook (state unchanged)");
    }
}

namespace
{

// Decode a single hex nibble. Returns 0xFF on failure.
u8 NibbleFromHex(char c)
{
    if (c >= '0' && c <= '9')
        return static_cast<u8>(c - '0');
    if (c >= 'a' && c <= 'f')
        return static_cast<u8>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return static_cast<u8>(c - 'A' + 10);
    return 0xFF;
}

// Parse a hex stream of EXACTLY 256 hex digits (whitespace + colons
// allowed) into 128 bytes. Returns false on any malformed digit or
// short input.
bool ParseEdidHex(const char* s, u8 out[128])
{
    u32 written = 0;
    u8 hi = 0xFF;
    while (*s != '\0' && written < 128)
    {
        const char c = *s++;
        if (c == ' ' || c == '\t' || c == ':' || c == ',' || c == '\n' || c == '\r')
            continue;
        const u8 nib = NibbleFromHex(c);
        if (nib == 0xFF)
            return false;
        if (hi == 0xFF)
        {
            hi = nib;
        }
        else
        {
            out[written++] = static_cast<u8>((hi << 4) | nib);
            hi = 0xFF;
        }
    }
    return written == 128 && hi == 0xFF;
}

void RunSyntheticDump()
{
    // Build the same 1080p fixture the boot self-test exercises so
    // operators can see a known-good decode without needing a real
    // monitor wired through DDC.
    u8 buf[128];
    for (u32 i = 0; i < 128; ++i)
        buf[i] = 0;
    buf[0] = 0x00;
    buf[1] = 0xFF;
    buf[2] = 0xFF;
    buf[3] = 0xFF;
    buf[4] = 0xFF;
    buf[5] = 0xFF;
    buf[6] = 0xFF;
    buf[7] = 0x00;
    // "DEL" PnP code = 0x10AC big-endian
    buf[8] = 0x10;
    buf[9] = 0xAC;
    buf[10] = 0xC4;
    buf[11] = 0x0A;
    buf[12] = 0x78;
    buf[13] = 0x56;
    buf[14] = 0x34;
    buf[15] = 0x12;
    buf[16] = 12;
    buf[17] = 30;
    buf[18] = 1;
    buf[19] = 4;
    buf[20] = static_cast<u8>(0x80 | (2 << 4) | 5);
    buf[21] = 60;
    buf[22] = 34;
    buf[23] = 120;
    buf[24] = 0xE0 | 0x04 | 0x02;
    buf[35] = 0x21;
    buf[36] = 0x08;
    buf[38] = static_cast<u8>((1280u / 8u) - 31u);
    buf[39] = static_cast<u8>((2u << 6) | (60 - 60));
    for (u32 i = 1; i < 8; ++i)
    {
        buf[38 + i * 2] = 0x01;
        buf[39 + i * 2] = 0x01;
    }
    // DTD: 1920x1080@60 — same shape as the self-test fixture.
    const u16 px = 14850;
    buf[54] = static_cast<u8>(px & 0xFF);
    buf[55] = static_cast<u8>((px >> 8) & 0xFF);
    buf[56] = 1920 & 0xFF;
    buf[57] = 280 & 0xFF;
    buf[58] = static_cast<u8>(((1920 >> 4) & 0xF0) | ((280 >> 8) & 0x0F));
    buf[59] = 1080 & 0xFF;
    buf[60] = 45 & 0xFF;
    buf[61] = static_cast<u8>(((1080 >> 4) & 0xF0) | ((45 >> 8) & 0x0F));
    buf[62] = 88;
    buf[63] = 44;
    buf[64] = static_cast<u8>(((4 & 0x0F) << 4) | (5 & 0x0F));
    buf[65] = 0;
    buf[66] = 600 & 0xFF;
    buf[67] = 340 & 0xFF;
    buf[68] = static_cast<u8>(((600 >> 4) & 0xF0) | ((340 >> 8) & 0x0F));
    buf[69] = 0;
    buf[70] = 0;
    buf[71] = static_cast<u8>((3u << 3) | 0x04 | 0x02);
    // DTD slot 1 — monitor name
    buf[72] = 0;
    buf[73] = 0;
    buf[74] = 0;
    buf[75] = 0xFC;
    buf[76] = 0;
    const char name[] = "DUET-DEMO-1";
    for (u32 i = 0; i < sizeof(name) - 1; ++i)
        buf[77 + i] = static_cast<u8>(name[i]);
    buf[77 + sizeof(name) - 1] = 0x0A;
    for (u32 i = 77 + sizeof(name); i < 90; ++i)
        buf[i] = 0x20;
    // DTD slot 2 — range limits
    buf[90] = 0;
    buf[91] = 0;
    buf[92] = 0;
    buf[93] = 0xFD;
    buf[94] = 0;
    buf[95] = 50;
    buf[96] = 75;
    buf[97] = 30;
    buf[98] = 80;
    buf[99] = 17;
    buf[100] = 0;
    for (u32 i = 101; i < 108; ++i)
        buf[i] = 0x20;
    // DTD slot 3 — dummy
    buf[111] = 0x10;

    u32 sum = 0;
    for (u32 i = 0; i < 127; ++i)
        sum += buf[i];
    buf[127] = static_cast<u8>((256u - (sum & 0xFFu)) & 0xFFu);

    auto res = duetos::drivers::gpu::EdidParseBaseBlock(buf, sizeof(buf));
    if (!res.has_value())
    {
        ConsoleWriteln("monitor: synthetic EDID failed to parse (parser bug?)");
        return;
    }
    duetos::drivers::gpu::EdidDumpToConsole(res.value());
}

} // namespace

void RunCvtDemo(u32 w, u32 h, u32 ref_mhz)
{
    duetos::drivers::gpu::CvtRequest req = {};
    req.h_active = static_cast<u16>(w);
    req.v_active = static_cast<u16>(h);
    req.refresh_mhz = ref_mhz;
    req.mode = duetos::drivers::gpu::CvtMode::ReducedBlankingV1;
    auto rb = duetos::drivers::gpu::CvtGenerate(req);
    if (rb.has_value())
    {
        const duetos::drivers::gpu::EdidDtd& t = rb.value();
        ConsoleWrite("  CVT-RB:    ");
        WriteU64Dec(t.h_active);
        ConsoleWrite("x");
        WriteU64Dec(t.v_active);
        ConsoleWrite("  htotal=");
        WriteU64Dec(t.h_active + t.h_blanking);
        ConsoleWrite("  vtotal=");
        WriteU64Dec(t.v_active + t.v_blanking);
        ConsoleWrite("  pclk=");
        WriteU64Dec(t.pixel_clock_khz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.pixel_clock_khz % 1000);
        ConsoleWrite(" MHz  refresh=");
        WriteU64Dec(t.refresh_mhz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.refresh_mhz % 1000);
        ConsoleWriteln(" Hz");
    }
    req.mode = duetos::drivers::gpu::CvtMode::Standard;
    auto std_res = duetos::drivers::gpu::CvtGenerate(req);
    if (std_res.has_value())
    {
        const duetos::drivers::gpu::EdidDtd& t = std_res.value();
        ConsoleWrite("  CVT-STD:   ");
        WriteU64Dec(t.h_active);
        ConsoleWrite("x");
        WriteU64Dec(t.v_active);
        ConsoleWrite("  htotal=");
        WriteU64Dec(t.h_active + t.h_blanking);
        ConsoleWrite("  vtotal=");
        WriteU64Dec(t.v_active + t.v_blanking);
        ConsoleWrite("  pclk=");
        WriteU64Dec(t.pixel_clock_khz / 1000);
        ConsoleWrite(".");
        WriteU64Dec(t.pixel_clock_khz % 1000);
        ConsoleWriteln(" MHz");
    }
}

void CmdMonitor(u32 argc, char** argv)
{
    if (argc == 1)
    {
        ConsoleWriteln("monitor — dump parsed EDID for the system display");
        ConsoleWriteln("");
        ConsoleWriteln("Usage:");
        ConsoleWriteln("  monitor                 — show synthetic test EDID + CVT modes");
        ConsoleWriteln("  monitor demo            — same; explicit synonym");
        ConsoleWriteln("  monitor parse <hex>     — parse + decode a 256-hex-digit EDID blob");
        ConsoleWriteln("  monitor cea <hex>       — parse + decode a 256-hex-digit CEA-861 ext block");
        ConsoleWriteln("  monitor cvt W H R       — generate a CVT timing for WxH @ R Hz");
        ConsoleWriteln("");
        ConsoleWriteln("NOTE: GPU drivers are probe-only in v0; no DDC/I2C transport is live.");
        ConsoleWriteln("      Once a vendor driver gains DDC, this command will pick up real data.");
        ConsoleWriteln("");
        RunSyntheticDump();
        ConsoleWriteln("");
        ConsoleWriteln("CVT timings for common modes:");
        RunCvtDemo(1920, 1080, 60000);
        RunCvtDemo(2560, 1440, 60000);
        RunCvtDemo(3840, 2160, 60000);
        return;
    }
    if (argc == 2 && (argv[1][0] == 'd' || argv[1][0] == 'D'))
    {
        RunSyntheticDump();
        return;
    }
    if (argc >= 3 && (argv[1][0] == 'p' || argv[1][0] == 'P'))
    {
        u8 buf[128];
        if (!ParseEdidHex(argv[2], buf))
        {
            ConsoleWriteln("monitor: hex blob must be exactly 256 hex digits (128 bytes).");
            ConsoleWriteln("         Whitespace, colons and commas are allowed as separators.");
            return;
        }
        auto res = duetos::drivers::gpu::EdidParseBaseBlock(buf, sizeof(buf));
        if (!res.has_value())
        {
            ConsoleWriteln("monitor: parser rejected the input (length check failed).");
            return;
        }
        duetos::drivers::gpu::EdidDumpToConsole(res.value());
        return;
    }
    if (argc >= 3 && argv[1][0] == 'c' && argv[1][1] == 'e')
    {
        u8 buf[128];
        if (!ParseEdidHex(argv[2], buf))
        {
            ConsoleWriteln("monitor cea: hex blob must be exactly 256 hex digits (128 bytes).");
            return;
        }
        auto res = duetos::drivers::gpu::Cea861ParseBlock(buf, sizeof(buf));
        if (!res.has_value())
        {
            ConsoleWriteln("monitor cea: parser rejected the input.");
            return;
        }
        duetos::drivers::gpu::Cea861DumpToConsole(res.value());
        return;
    }
    if (argc >= 5 && argv[1][0] == 'c' && argv[1][1] == 'v')
    {
        u16 w = 0, h = 0;
        u16 r = 60;
        if (!ParseU16Decimal(argv[2], &w) || !ParseU16Decimal(argv[3], &h) || !ParseU16Decimal(argv[4], &r))
        {
            ConsoleWriteln("monitor cvt: usage: monitor cvt <width> <height> <refresh-hz>");
            return;
        }
        RunCvtDemo(w, h, static_cast<u32>(r) * 1000u);
        return;
    }
    ConsoleWriteln("monitor: unrecognised arguments — try `monitor` for usage.");
}

void CmdHdaJacks()
{
    namespace hda = duetos::drivers::audio::hda;
    const u32 count = hda::HdaJackInventoryCount();
    if (count == 0)
    {
        ConsoleWriteln("HDA-JACKS: no records — codec walker hasn't run, or controller absent");
        return;
    }
    ConsoleWrite("HDA-JACKS: ");
    WriteU64Dec(count);
    ConsoleWriteln(" pin record(s)");
    for (u32 i = 0; i < count; ++i)
    {
        hda::HdaJackRecord r{};
        if (!hda::HdaJackInventoryRead(i, &r))
            continue;
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] codec=");
        WriteU64Hex(r.codec_slot, 2);
        ConsoleWrite(" pin=");
        WriteU64Hex(r.pin_node, 2);
        ConsoleWrite(" raw=");
        WriteU64Hex(r.config.raw, 8);
        ConsoleWrite(" port=");
        ConsoleWrite(hda::HdaPortConnectivityTag(r.config.port_connectivity));
        ConsoleWrite(" device=");
        ConsoleWrite(hda::HdaDefaultDeviceTag(r.config.default_device));
        ConsoleWrite(" conn=");
        ConsoleWrite(hda::HdaConnectionTypeTag(r.config.connection_type));
        ConsoleWrite(" color=");
        ConsoleWrite(hda::HdaJackColorTag(r.config.color));
        ConsoleWrite(" assoc=");
        WriteU64Hex(r.config.default_association, 1);
        ConsoleWrite("/seq=");
        WriteU64Hex(r.config.sequence, 1);
        if (r.jack_present_known)
        {
            ConsoleWrite(" present=");
            ConsoleWrite(r.jack_present ? "yes" : "no");
        }
        else
        {
            ConsoleWrite(" present=?");
        }
        ConsoleWriteln("");
    }

    // Helpful summary: which pin would the audio server pick for
    // common output / input requests?
    u8 codec = 0xFF;
    u8 pin = 0xFF;
    ConsoleWriteln("  ---");
    if (hda::HdaJackInventoryFindByDevice(hda::HdaDefaultDevice::Speaker, &codec, &pin))
    {
        ConsoleWrite("  speaker pick: codec=");
        WriteU64Hex(codec, 2);
        ConsoleWrite(" pin=");
        WriteU64Hex(pin, 2);
        ConsoleWriteln("");
    }
    if (hda::HdaJackInventoryFindByDevice(hda::HdaDefaultDevice::HpOut, &codec, &pin))
    {
        ConsoleWrite("  headphone pick: codec=");
        WriteU64Hex(codec, 2);
        ConsoleWrite(" pin=");
        WriteU64Hex(pin, 2);
        ConsoleWriteln("");
    }
    if (hda::HdaJackInventoryFindByDevice(hda::HdaDefaultDevice::MicIn, &codec, &pin))
    {
        ConsoleWrite("  mic-in pick: codec=");
        WriteU64Hex(codec, 2);
        ConsoleWrite(" pin=");
        WriteU64Hex(pin, 2);
        ConsoleWriteln("");
    }
}

void CmdMei()
{
    namespace mei = duetos::drivers::mei;
    const u32 count = mei::MeiDeviceCount();
    if (count == 0)
    {
        ConsoleWriteln("MEI: no Intel MEI/HECI device found");
        ConsoleWriteln("    (looking for vendor=0x8086 class=0x07 subclass=0x80)");
        return;
    }
    ConsoleWrite("MEI: ");
    WriteU64Dec(count);
    ConsoleWriteln(" device(s)");
    for (u32 i = 0; i < count; ++i)
    {
        const auto& d = mei::MeiDevice(i);
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] vendor=");
        WriteU64Hex(d.vendor_id, 4);
        ConsoleWrite(" device=");
        WriteU64Hex(d.device_id, 4);
        ConsoleWrite(" role=");
        ConsoleWrite(d.role_tag);
        ConsoleWrite(" bus=");
        WriteU64Hex(d.bus, 2);
        ConsoleWrite(":");
        WriteU64Hex(d.device, 2);
        ConsoleWrite(".");
        WriteU64Hex(d.function, 1);
        ConsoleWrite(" mmio_phys=");
        WriteU64Hex(d.mmio_phys, 8);
        ConsoleWrite(" size=");
        WriteU64Hex(d.mmio_size, 4);
        ConsoleWriteln("");
    }
    ConsoleWriteln("  (HECI bus protocol not yet implemented — driver is probe-only)");
}

void CmdNpu()
{
    namespace npu = duetos::drivers::npu;
    const u32 count = npu::NpuDeviceCount();
    if (count == 0)
    {
        ConsoleWriteln("NPU: no NPU / AI-accelerator device found");
        ConsoleWriteln("    (looking for PCI class=0x12, or a known Intel NPU device-ID)");
        return;
    }
    ConsoleWrite("NPU: ");
    WriteU64Dec(count);
    ConsoleWriteln(" device(s)");
    for (u32 i = 0; i < count; ++i)
    {
        const auto& d = npu::NpuDevice(i);
        ConsoleWrite("  [");
        WriteU64Dec(i);
        ConsoleWrite("] vendor=");
        WriteU64Hex(d.vendor_id, 4);
        ConsoleWrite(" device=");
        WriteU64Hex(d.device_id, 4);
        ConsoleWrite(" kind=");
        ConsoleWrite(d.kind_tag);
        ConsoleWrite(" bus=");
        WriteU64Hex(d.bus, 2);
        ConsoleWrite(":");
        WriteU64Hex(d.device, 2);
        ConsoleWrite(".");
        WriteU64Hex(d.function, 1);
        ConsoleWrite(" mmio_phys=");
        WriteU64Hex(d.mmio_phys, 8);
        ConsoleWrite(" size=");
        WriteU64Hex(d.mmio_size, 4);
        ConsoleWriteln("");
    }
    ConsoleWriteln("  (firmware / command-ring not yet implemented — driver is probe-only)");
}

void CmdAutonomic()
{
    namespace e = duetos::env;
    const e::AutonomicReport& r = e::AutonomicStatus();
    ConsoleWrite("AUTONOMIC: ticks=");
    WriteU64Dec(r.ticks);
    ConsoleWrite(" actions=");
    WriteU64Dec(r.actions_fired);
    ConsoleWrite(" sched-bias=");
    ConsoleWrite(duetos::sched::SchedPowerBiasName(duetos::sched::SchedPowerBias()));
    ConsoleWrite(" balance-period=");
    WriteU64Dec(duetos::sched::SchedBalancePeriodTicks());
    ConsoleWriteln(" ticks");
    if (r.actions_fired == 0)
    {
        ConsoleWriteln("  (no rule has fired — clean run)");
    }
    else
    {
        ConsoleWrite("  last: ");
        ConsoleWrite(e::AutoActionName(r.last));
        ConsoleWrite(" by ");
        ConsoleWriteln(e::AutoRuleName(r.last_rule));
        for (u32 i = 1; i < static_cast<u32>(e::AutoAction::Count); ++i)
        {
            if (r.per_action[i] == 0)
                continue;
            ConsoleWrite("  ");
            ConsoleWrite(e::AutoActionName(static_cast<e::AutoAction>(i)));
            ConsoleWrite(" x");
            WriteU64Dec(r.per_action[i]);
            ConsoleWriteln("");
        }
    }
}


} // namespace duetos::core::shell::internal
