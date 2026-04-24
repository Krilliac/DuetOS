#pragma once

/*
 * DuetOS — fundamental kernel integer types.
 *
 * Kernel code uses fixed-width aliases exclusively. `int`/`long`/`size_t`
 * et al. are avoided in interfaces because their widths depend on the host
 * ABI — which is meaningless for freestanding kernel code.
 */

namespace duetos
{

using u8  = unsigned char;
using u16 = unsigned short;
using u32 = unsigned int;
using u64 = unsigned long long;

using i8  = signed char;
using i16 = signed short;
using i32 = signed int;
using i64 = signed long long;

using uptr  = unsigned long long;   /* pointer-sized unsigned integer */
using iptr  = signed long long;     /* pointer-sized signed integer   */
using usize = unsigned long long;   /* size of any object in bytes    */

static_assert(sizeof(u8)    == 1, "u8 must be 1 byte");
static_assert(sizeof(u16)   == 2, "u16 must be 2 bytes");
static_assert(sizeof(u32)   == 4, "u32 must be 4 bytes");
static_assert(sizeof(u64)   == 8, "u64 must be 8 bytes");
static_assert(sizeof(uptr)  == 8, "uptr must be 8 bytes on x86_64");
static_assert(sizeof(usize) == 8, "usize must be 8 bytes on x86_64");

} // namespace duetos
