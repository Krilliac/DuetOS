#include "drivers/video/modal_input.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/cursor.h"

namespace duetos::drivers::video
{

namespace
{

constinit ModalInputCallbacks g_cb = {};
constinit bool g_active = false;
constinit CursorShape g_pre_session_shape = CursorShape::Arrow;

} // namespace

bool ModalInputBegin(const ModalInputCallbacks& cb)
{
    if (g_active)
        return false;
    g_cb = cb;
    g_active = true;
    g_pre_session_shape = CursorGetShape();
    CursorSetShape(cb.cursor);
    duetos::arch::SerialWrite("[modal] begin\n");
    return true;
}

bool ModalInputIsActive()
{
    return g_active;
}

void ModalInputOnMotion(u32 cx, u32 cy)
{
    if (!g_active || g_cb.motion == nullptr)
        return;
    g_cb.motion(cx, cy, g_cb.user);
}

void ModalInputOnPress(u32 cx, u32 cy)
{
    if (!g_active)
        return;
    auto cb = g_cb.commit;
    void* user = g_cb.user;
    g_active = false;
    CursorSetShape(g_pre_session_shape);
    if (cb != nullptr)
        cb(cx, cy, user);
    duetos::arch::SerialWrite("[modal] commit\n");
}

void ModalInputOnCancel()
{
    if (!g_active)
        return;
    auto cb = g_cb.cancel;
    void* user = g_cb.user;
    g_active = false;
    CursorSetShape(g_pre_session_shape);
    if (cb != nullptr)
        cb(user);
    duetos::arch::SerialWrite("[modal] cancel\n");
}

} // namespace duetos::drivers::video
