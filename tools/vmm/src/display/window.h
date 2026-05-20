#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <thread>

namespace duetos::vmm
{
// A Win32 top-level window that scans out a host-side 32bpp BGRA
// framebuffer. Runs its own thread (Win32 requires the message pump
// on the window's creating thread). Input is delivered to caller-
// supplied sinks. Lockless FB read (tearing acceptable for a dev
// viewer).
struct InputSink
{
    std::function<void(uint32_t vk, bool down, bool extended)> onKey;
    std::function<void(int dx, int dy, uint32_t buttons, int wheel)> onMouse;
};

class FbWindow
{
public:
    bool Start(uint8_t* fb, uint32_t pitch, uint32_t w, uint32_t h,
               const char* title, InputSink sink,
               std::function<void()> onClose);
    void Stop();
    void SetTitle(const char* s);
    bool Minimized() const { return m_minimized.load(); }
    ~FbWindow();

    uint8_t*         Fb()    { return m_fb; }
    uint32_t         W()     const { return m_w; }
    uint32_t         H()     const { return m_h; }
    const InputSink& Sink()  const { return m_sink; }
    void             FireClose() { if (m_onClose) m_onClose(); }
    void*            Hwnd()  const { return m_hwnd; }

private:
    void ThreadMain(const char* title);
    std::thread          m_thread;
    std::atomic<bool>    m_run{false};
    std::atomic<bool>    m_minimized{true};
    uint8_t*             m_fb = nullptr;
    uint32_t             m_pitch = 0, m_w = 0, m_h = 0;
    InputSink            m_sink;
    std::function<void()> m_onClose;
    void*                m_hwnd = nullptr; // HWND (opaque here)
};
} // namespace duetos::vmm
