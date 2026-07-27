#pragma once

namespace duetos::win32
{

inline constexpr const char* kRetiredKernel32Imports[] = {
#define DUETOS_RETIRED_KERNEL32_IMPORT(name) name,
#include "subsystems/win32/thunk_retirement_wave1.inc"
#undef DUETOS_RETIRED_KERNEL32_IMPORT
};

inline constexpr bool ThunkRetirementStringEqual(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr)
        return false;
    while (*left != '\0' && *right != '\0')
    {
        if (*left != *right)
            return false;
        ++left;
        ++right;
    }
    return *left == *right;
}

inline constexpr bool ThunkRetirementDllEqual(const char* left, const char* right)
{
    if (left == nullptr || right == nullptr)
        return false;
    while (*left != '\0' && *right != '\0')
    {
        char a = *left++;
        char b = *right++;
        if (a >= 'A' && a <= 'Z')
            a = static_cast<char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = static_cast<char>(b + ('a' - 'A'));
        if (a != b)
            return false;
    }
    return *left == *right;
}

inline constexpr bool IsRetiredKernel32ImportName(const char* function_name)
{
    for (const char* retired : kRetiredKernel32Imports)
    {
        if (ThunkRetirementStringEqual(retired, function_name))
            return true;
    }
    return false;
}

inline constexpr bool IsKernel32ProviderDll(const char* dll_name)
{
    return ThunkRetirementDllEqual(dll_name, "kernel32.dll") || ThunkRetirementDllEqual(dll_name, "kernel32") ||
           ThunkRetirementDllEqual(dll_name, "kernelbase.dll") || ThunkRetirementDllEqual(dll_name, "kernelbase");
}

inline constexpr bool ThunkRetirementRequiresRealDll(const char* dll_name, const char* function_name)
{
    return IsKernel32ProviderDll(dll_name) && IsRetiredKernel32ImportName(function_name);
}

} // namespace duetos::win32
