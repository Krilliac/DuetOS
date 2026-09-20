#pragma once

#include "drivers/net/net.h"

namespace duetos::drivers::net
{

bool Rtl8125BringUp(NicInfo& nic, u32 iface_index);
bool Rtl8125QuiesceAll();

} // namespace duetos::drivers::net
