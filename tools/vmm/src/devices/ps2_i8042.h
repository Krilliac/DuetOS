#pragma once
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>

namespace duetos::vmm
{
// i8042 PS/2 controller. Port 0x60 (data) / 0x64 (status+cmd).
// PushKey/PushAux are called from the UI thread; In/Out from the
// vCPU thread. RaiseIrq(1)/RaiseIrq(12) are invoked when a byte
// becomes available and the device is enabled.
class Ps2I8042
{
public:
    explicit Ps2I8042(std::function<void(uint32_t irq)> raiseIrq)
        : m_raise(std::move(raiseIrq)) {}

    uint8_t In(uint16_t port);            // 0x60 / 0x64
    void    Out(uint16_t port, uint8_t v);

    void PushKey(const uint8_t* b, size_t n);  // UI thread
    void PushAux(const uint8_t* b, size_t n);  // UI thread

private:
    void Refill();
    std::mutex                       m_mx;
    std::deque<uint8_t>              m_kbd, m_aux;
    uint8_t                          m_data = 0;
    bool                             m_full = false;
    bool                             m_dataIsAux = false;
    uint8_t                          m_cfg = 0x47;
    uint8_t                          m_pendingCmd = 0;
    std::function<void(uint32_t)>    m_raise;
};
} // namespace duetos::vmm
