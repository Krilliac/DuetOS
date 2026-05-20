#pragma once
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vmmtest
{
struct Case
{
    const char*           name;
    std::function<void()> fn;
};
std::vector<Case>& Registry();

struct Reg
{
    Reg(const char* n, std::function<void()> f)
    {
        Registry().push_back({n, std::move(f)});
    }
};
} // namespace vmmtest

#define TEST(name)                                                       \
    static void name();                                                  \
    static vmmtest::Reg reg_##name(#name, name);                         \
    static void name()

#define CHECK(cond)                                                      \
    do                                                                   \
    {                                                                    \
        if (!(cond))                                                     \
            throw std::runtime_error(std::string("CHECK failed: " #cond  \
                                                 " @ ") +                \
                                     __FILE__ + ":" +                    \
                                     std::to_string(__LINE__));          \
    } while (0)

#define CHECK_EQ(a, b)                                                   \
    do                                                                   \
    {                                                                    \
        auto _va = (a);                                                  \
        auto _vb = (b);                                                  \
        if (!(_va == _vb))                                               \
            throw std::runtime_error(std::string("CHECK_EQ failed: " #a  \
                                                 " == " #b " @ ") +      \
                                     __FILE__ + ":" +                    \
                                     std::to_string(__LINE__));          \
    } while (0)
