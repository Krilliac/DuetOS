#pragma once

#include "util/types.h"

namespace duetos::net::wireless::diag
{
enum class Layer : u8
{
    Driver = 0,
    FwUpload,
    Rings,
    Mlme,
    Eapol,
    KeyMgmt,
    Tx,
    Rx,
    Wdev,
    Diag,
};

inline void Record(Layer, const char*, u64 = 0, u64 = 0, u64 = 0, u32 = 0, const char* = nullptr) {}
inline void RecordOk(Layer, const char*, u64 = 0, u64 = 0, u64 = 0, const char* = nullptr) {}
inline void RecordErr(Layer, const char*, u32, u64 = 0, u64 = 0, u64 = 0, const char* = nullptr) {}
inline void Init() {}
inline void Clear() {}
inline void Dump(u32) {}
} // namespace duetos::net::wireless::diag
