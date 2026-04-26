/*
 * DuetOS — xHCI driver: completion-code name lookup.
 *
 * First sibling translation unit in the xhci.cpp per-aspect split.
 * Houses just the spec §6.4.5 completion-code → string mapping;
 * its only callers are failure-path log lines in xhci.cpp, so the
 * decomposition starts here as a low-risk seam. Cross-TU surface
 * lives in xhci_internal.h.
 */

#include "xhci_internal.h"

namespace duetos::drivers::usb::xhci::internal
{

const char* CompletionCodeName(u32 code)
{
    switch (code)
    {
    case 0:
        return "Invalid";
    case 1:
        return "Success";
    case 2:
        return "Data Buffer Error";
    case 3:
        return "Babble Detected Error";
    case 4:
        return "USB Transaction Error";
    case 5:
        return "TRB Error";
    case 6:
        return "Stall Error";
    case 7:
        return "Resource Error";
    case 8:
        return "Bandwidth Error";
    case 9:
        return "No Slots Available";
    case 10:
        return "Invalid Stream Type";
    case 11:
        return "Slot Not Enabled";
    case 12:
        return "Endpoint Not Enabled";
    case 13:
        return "Short Packet";
    case 14:
        return "Ring Underrun";
    case 15:
        return "Ring Overrun";
    case 16:
        return "VF Event Ring Full";
    case 17:
        return "Parameter Error";
    case 18:
        return "Bandwidth Overrun";
    case 19:
        return "Context State Error";
    case 20:
        return "No Ping Response";
    case 21:
        return "Event Ring Full";
    case 22:
        return "Incompatible Device";
    case 23:
        return "Missed Service";
    case 24:
        return "Command Ring Stopped";
    case 25:
        return "Command Aborted";
    case 26:
        return "Stopped";
    case 27:
        return "Stopped - Length Invalid";
    case 28:
        return "Stopped - Short Packet";
    case 29:
        return "Max Exit Latency Too Large";
    case 31:
        return "Isoch Buffer Overrun";
    case 32:
        return "Event Lost";
    case 33:
        return "Undefined Error";
    case 34:
        return "Invalid Stream ID";
    case 35:
        return "Secondary Bandwidth Error";
    case 36:
        return "Split Transaction Error";
    }
    return "Reserved/Vendor";
}

} // namespace duetos::drivers::usb::xhci::internal
