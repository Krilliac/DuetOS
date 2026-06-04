#include "apps/browser/start_page.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"

namespace duetos::apps::browser
{
void StartPageSelfTest()
{
    auto fail = [](duetos::u32 c)
    {
        arch::SerialWrite("[startpage-selftest] FAIL check=");
        arch::SerialWriteHex(c);
        arch::SerialWrite("\n");
        KBP_PROBE_V(duetos::debug::ProbeId::kBootSelftestFail, c);
    };

    const Rect content{0, 0, 640, 400};
    StartPage p;
    p.InitDefault();

    // 1: five default tiles.
    if (p.tileCount != 5)
    {
        fail(1);
        return;
    }
    // 2: the tile row is centred — total 5*58 + 4*11 = 334; startX = (640-334)/2 = 153.
    if (p.TileRect(0, content).x != 153 || p.TileRect(1, content).x != 222)
    {
        fail(2);
        return;
    }
    // 3: hit-test the centre of tile 2 (x = 153 + 2*69 + 29 = 320; y = 240 + 29 = 269).
    StartHit h = p.HitTest(content, 320, 269);
    if (h.kind != StartHitKind::Tile || h.index != 2)
    {
        fail(3);
        return;
    }
    // 4: prompt is centred at 62% width — w = 396, x = (640-396)/2 = 122; y = 152.
    const Rect pr = p.PromptRect(content);
    if (pr.x != 122 || pr.w != 396)
    {
        fail(4);
        return;
    }
    // 5: hit-test the prompt centre.
    h = p.HitTest(content, 320, 171);
    if (h.kind != StartHitKind::Prompt)
    {
        fail(5);
        return;
    }

    arch::SerialWrite("[startpage-selftest] PASS (5 tiles, centred row, tile+prompt hit-test, prompt width)\n");
}

} // namespace duetos::apps::browser
