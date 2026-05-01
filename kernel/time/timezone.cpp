#include "time/timezone.h"

#include "arch/x86_64/serial.h"

namespace duetos::time
{

namespace
{

constinit i32 g_offset_minutes = 0;

i32 Clamp(i32 v)
{
    if (v < kTzMinutesMin)
    {
        return kTzMinutesMin;
    }
    if (v > kTzMinutesMax)
    {
        return kTzMinutesMax;
    }
    return v;
}

} // namespace

i32 TimezoneOffsetMinutes()
{
    return g_offset_minutes;
}

void SetTimezoneOffsetMinutes(i32 minutes)
{
    g_offset_minutes = Clamp(minutes);
}

void TimezoneStep(bool up)
{
    g_offset_minutes = Clamp(g_offset_minutes + (up ? kTzStepMinutes : -kTzStepMinutes));
}

void TimezoneSelfTest()
{
    using duetos::arch::SerialWrite;
    bool ok = true;
    const i32 save = g_offset_minutes;

    SetTimezoneOffsetMinutes(0);
    ok = ok && TimezoneOffsetMinutes() == 0;

    SetTimezoneOffsetMinutes(60);
    ok = ok && TimezoneOffsetMinutes() == 60;

    SetTimezoneOffsetMinutes(kTzMinutesMax + 1000);
    ok = ok && TimezoneOffsetMinutes() == kTzMinutesMax;

    SetTimezoneOffsetMinutes(kTzMinutesMin - 1000);
    ok = ok && TimezoneOffsetMinutes() == kTzMinutesMin;

    SetTimezoneOffsetMinutes(0);
    TimezoneStep(true);
    ok = ok && TimezoneOffsetMinutes() == kTzStepMinutes;
    TimezoneStep(false);
    TimezoneStep(false);
    ok = ok && TimezoneOffsetMinutes() == -kTzStepMinutes;

    g_offset_minutes = save;
    SerialWrite(ok ? "[timezone] self-test OK\n" : "[timezone] self-test FAILED\n");
}

} // namespace duetos::time
