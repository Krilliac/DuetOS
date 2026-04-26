#include "apps/calculator.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/framebuffer.h"

namespace duetos::apps::calculator
{

namespace
{

// Logical key value of each button. Index i in this array is
// the value sent as {kIdBase + i}. Ordering matches the on-
// screen grid row-major top-to-bottom.
constexpr char kButtonKeys[kIdCount] = {
    '7', '8', '9', '+', '4', '5', '6', '-', '1', '2', '3', '*', 'C', '0', '=', '/',
};

// Grid layout inside the calculator window. Numbers are
// offsets from the window origin; the chrome's title bar
// takes up the first ~28 pixels and the display takes up the
// next ~32, so the button grid starts at y = kGridTopOffset.
constexpr u32 kGridTopOffset = 60;
constexpr u32 kGridLeftOffset = 8;
constexpr u32 kBtnW = 68;
constexpr u32 kBtnH = 36;
constexpr u32 kBtnGap = 4;

constexpr u32 kDisplayCap = 16;

// Colour scheme. Light-grey digit keys, orange operators,
// green equals, red clear. Contrast chosen to read cleanly
// on the window's dark client colour (0x00101828 picked in
// main.cpp).
struct KeyColours
{
    u32 normal;
    u32 pressed;
    u32 label;
};
constexpr KeyColours kColDigit = {0x00D0D0D0, 0x00FFFFFF, 0x00101828};
constexpr KeyColours kColOp = {0x00E08040, 0x00FFB070, 0x00101828};
constexpr KeyColours kColEq = {0x0060A060, 0x0080D080, 0x00101828};
constexpr KeyColours kColClear = {0x00C04040, 0x00E06060, 0x00FFFFFF};

KeyColours ColoursFor(char k)
{
    if (k >= '0' && k <= '9')
        return kColDigit;
    if (k == 'C')
        return kColClear;
    if (k == '=')
        return kColEq;
    return kColOp; // '+' '-' '*' '/'
}

struct State
{
    duetos::drivers::video::WindowHandle handle;
    // Displayed string — always NUL-terminated; length <= kDisplayCap.
    char display[kDisplayCap + 1];
    u32 display_len;
    // Running evaluation state. When `has_pending` is true,
    // `accumulator` holds the LHS and `pending_op` the operator;
    // the digits currently being typed will be combined with
    // these on the next operator / '='.
    i64 accumulator;
    char pending_op; // 0 when no pending op
    bool has_pending;
    bool fresh_entry; // true iff next digit starts a new number (post-op or post-=)
    bool error;       // sticky — cleared by 'C'
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid, {}, 0, 0, 0, false, true, false};

// Copy a literal NUL-terminated string into the display.
void SetDisplayLiteral(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0' && n < kDisplayCap)
    {
        g_state.display[n] = s[n];
        ++n;
    }
    g_state.display[n] = '\0';
    g_state.display_len = n;
}

// Format an i64 into the display. Signed decimal, no thousands
// separator. If the number doesn't fit in kDisplayCap, sets
// error state and shows "ERR".
void SetDisplayI64(i64 v)
{
    char tmp[24];
    u32 n = 0;
    bool neg = false;
    u64 abs_v;
    if (v < 0)
    {
        neg = true;
        abs_v = static_cast<u64>(-v);
    }
    else
    {
        abs_v = static_cast<u64>(v);
    }
    if (abs_v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (abs_v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (abs_v % 10));
            abs_v /= 10;
        }
    }
    const u32 total = n + (neg ? 1 : 0);
    if (total > kDisplayCap)
    {
        SetDisplayLiteral("ERR");
        g_state.error = true;
        return;
    }
    u32 o = 0;
    if (neg)
        g_state.display[o++] = '-';
    for (u32 i = 0; i < n; ++i)
        g_state.display[o++] = tmp[n - 1 - i];
    g_state.display[o] = '\0';
    g_state.display_len = o;
}

// Parse the current display string as an i64. Returns 0 on an
// empty/invalid display (the state machine treats a blank
// display as zero, which matches most physical calculators).
i64 ReadDisplayAsI64()
{
    if (g_state.display_len == 0)
        return 0;
    bool neg = false;
    u32 i = 0;
    if (g_state.display[0] == '-')
    {
        neg = true;
        i = 1;
    }
    i64 v = 0;
    for (; i < g_state.display_len; ++i)
    {
        const char c = g_state.display[i];
        if (c < '0' || c > '9')
            return 0; // defensive — shouldn't happen
        v = v * 10 + (c - '0');
    }
    return neg ? -v : v;
}

// Commit a pending operation against the given RHS, store the
// result in `accumulator`, and write it to the display.
void ApplyPending(i64 rhs)
{
    if (!g_state.has_pending)
    {
        g_state.accumulator = rhs;
        SetDisplayI64(g_state.accumulator);
        return;
    }
    i64 lhs = g_state.accumulator;
    i64 result = 0;
    switch (g_state.pending_op)
    {
    case '+':
        result = lhs + rhs;
        break;
    case '-':
        result = lhs - rhs;
        break;
    case '*':
        result = lhs * rhs;
        break;
    case '/':
        if (rhs == 0)
        {
            SetDisplayLiteral("ERR");
            g_state.error = true;
            g_state.accumulator = 0;
            g_state.has_pending = false;
            g_state.fresh_entry = true;
            return;
        }
        result = lhs / rhs;
        break;
    default:
        result = rhs;
        break;
    }
    g_state.accumulator = result;
    g_state.has_pending = false;
    g_state.pending_op = 0;
    SetDisplayI64(result);
}

void HandleDigit(char d)
{
    if (g_state.error)
        return;
    if (g_state.fresh_entry)
    {
        g_state.display_len = 0;
        g_state.display[0] = '\0';
        g_state.fresh_entry = false;
    }
    if (g_state.display_len >= kDisplayCap)
        return; // silently ignore over-long entry
    g_state.display[g_state.display_len++] = d;
    g_state.display[g_state.display_len] = '\0';
}

void HandleOp(char op)
{
    if (g_state.error)
        return;
    const i64 rhs = ReadDisplayAsI64();
    ApplyPending(rhs);
    if (g_state.error)
        return; // ApplyPending may have clamped on divide-by-zero
    g_state.pending_op = op;
    g_state.has_pending = true;
    g_state.fresh_entry = true;
}

void HandleEquals()
{
    if (g_state.error)
        return;
    const i64 rhs = ReadDisplayAsI64();
    ApplyPending(rhs);
    g_state.has_pending = false;
    g_state.pending_op = 0;
    g_state.fresh_entry = true;
}

void HandleClear()
{
    g_state.accumulator = 0;
    g_state.pending_op = 0;
    g_state.has_pending = false;
    g_state.fresh_entry = true;
    g_state.error = false;
    SetDisplayLiteral("0");
}

void DispatchKey(char k)
{
    if (k >= '0' && k <= '9')
        HandleDigit(k);
    else if (k == '+' || k == '-' || k == '*' || k == '/')
        HandleOp(k);
    else if (k == '=')
        HandleEquals();
    else if (k == 'C' || k == 'c')
        HandleClear();
}

// Content-draw callback: paints the display strip across the
// top of the client area. The buttons below are regular widgets
// painted by WidgetDrawAll — the compositor calls that after
// each window's content-draw, so they appear on top of the
// client fill naturally.
void DrawFn(u32 cx, u32 cy, u32 cw, u32 /*ch*/, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawRect;
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    constexpr u32 kDisplayPadY = 4;
    constexpr u32 kDisplayH = 28;
    if (cw <= 16 || kDisplayH + 2 * kDisplayPadY > 80)
        return;
    const u32 x = cx + 8;
    const u32 y = cy + kDisplayPadY;
    const u32 w = (cw >= 16) ? cw - 16 : cw;
    constexpr u32 kDisplayBg = 0x00202830;
    constexpr u32 kDisplayFg = 0x0080F088;
    constexpr u32 kDisplayBorder = 0x00081018;
    FramebufferFillRect(x, y, w, kDisplayH, kDisplayBg);
    FramebufferDrawRect(x, y, w, kDisplayH, kDisplayBorder, 1);
    // Right-align the text: calculators always push digits to
    // the right margin so the next digit appears on the left.
    const char* s = (g_state.display_len == 0) ? "0" : g_state.display;
    u32 len = 0;
    while (s[len] != '\0')
        ++len;
    const u32 text_w = len * 8;
    const u32 text_x = (text_w + 12 < w) ? x + w - text_w - 6 : x + 4;
    const u32 text_y = y + (kDisplayH > 8 ? (kDisplayH - 8) / 2 : 0);
    FramebufferDrawString(text_x, text_y, s, kDisplayFg, kDisplayBg);
}

} // namespace

void CalculatorInit(duetos::drivers::video::WindowHandle handle)
{
    g_state.handle = handle;
    HandleClear();
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);

    // Register 16 buttons as a 4x4 grid inside the window. Each
    // button's `owner` field is `handle` so the widget layer
    // translates the stored (x, y) offsets into absolute
    // framebuffer coordinates relative to the live window
    // position — drag the window, buttons move too.
    for (u32 i = 0; i < kIdCount; ++i)
    {
        const u32 row = i / 4;
        const u32 col = i % 4;
        const char key = kButtonKeys[i];
        const KeyColours cols = ColoursFor(key);
        duetos::drivers::video::ButtonWidget b{};
        b.id = kIdBase + i;
        b.owner = handle;
        b.x = kGridLeftOffset + col * (kBtnW + kBtnGap);
        b.y = kGridTopOffset + row * (kBtnH + kBtnGap);
        b.w = kBtnW;
        b.h = kBtnH;
        b.colour_normal = cols.normal;
        b.colour_pressed = cols.pressed;
        b.colour_border = 0x00081018;
        b.colour_label = cols.label;
        // Store the label via a pointer to a one-char static
        // string. FramebufferDrawString walks until NUL so we
        // need a real NUL after each char.
        static constexpr char kLabel0[] = "0";
        static constexpr char kLabel1[] = "1";
        static constexpr char kLabel2[] = "2";
        static constexpr char kLabel3[] = "3";
        static constexpr char kLabel4[] = "4";
        static constexpr char kLabel5[] = "5";
        static constexpr char kLabel6[] = "6";
        static constexpr char kLabel7[] = "7";
        static constexpr char kLabel8[] = "8";
        static constexpr char kLabel9[] = "9";
        static constexpr char kLabelPlus[] = "+";
        static constexpr char kLabelMinus[] = "-";
        static constexpr char kLabelMul[] = "*";
        static constexpr char kLabelDiv[] = "/";
        static constexpr char kLabelEq[] = "=";
        static constexpr char kLabelClear[] = "C";
        switch (key)
        {
        case '0':
            b.label = kLabel0;
            break;
        case '1':
            b.label = kLabel1;
            break;
        case '2':
            b.label = kLabel2;
            break;
        case '3':
            b.label = kLabel3;
            break;
        case '4':
            b.label = kLabel4;
            break;
        case '5':
            b.label = kLabel5;
            break;
        case '6':
            b.label = kLabel6;
            break;
        case '7':
            b.label = kLabel7;
            break;
        case '8':
            b.label = kLabel8;
            break;
        case '9':
            b.label = kLabel9;
            break;
        case '+':
            b.label = kLabelPlus;
            break;
        case '-':
            b.label = kLabelMinus;
            break;
        case '*':
            b.label = kLabelMul;
            break;
        case '/':
            b.label = kLabelDiv;
            break;
        case '=':
            b.label = kLabelEq;
            break;
        case 'C':
            b.label = kLabelClear;
            break;
        default:
            b.label = nullptr;
            break;
        }
        duetos::drivers::video::WidgetRegisterButton(b);
    }
}

duetos::drivers::video::WindowHandle CalculatorWindow()
{
    return g_state.handle;
}

bool CalculatorOnWidgetEvent(u32 id)
{
    if (id < kIdBase || id >= kIdBase + kIdCount)
        return false;
    const u32 idx = id - kIdBase;
    DispatchKey(kButtonKeys[idx]);
    return true;
}

bool CalculatorFeedChar(char c)
{
    if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '*' || c == '/' || c == '=' || c == 'c' || c == 'C')
    {
        DispatchKey(c);
        return true;
    }
    if (static_cast<u8>(c) == 0x0A) // Enter -> '='
    {
        DispatchKey('=');
        return true;
    }
    if (static_cast<u8>(c) == 0x08) // Backspace -> Clear
    {
        DispatchKey('C');
        return true;
    }
    return false;
}

void CalculatorSelfTest()
{
    using duetos::arch::SerialWrite;
    struct Case
    {
        const char* keys;
        i64 expect;
    };
    // Keys are fed one character at a time through DispatchKey,
    // just as a real click or keypress would. '=' commits the
    // expression; 'C' resets state between cases so each test
    // starts from a clean calculator.
    const Case cases[] = {
        {"2+3=", 5},
        {"9-4=", 5},
        {"6*7=", 42},
    };
    bool all_pass = true;
    for (const Case& tc : cases)
    {
        HandleClear();
        for (const char* p = tc.keys; *p != 0; ++p)
            DispatchKey(*p);
        const i64 got = ReadDisplayAsI64();
        if (got != tc.expect || g_state.error)
        {
            all_pass = false;
            break;
        }
    }
    HandleClear();
    SerialWrite(all_pass ? "[calc] self-test OK (2+3=5, 9-4=5, 6*7=42)\n" : "[calc] self-test FAILED\n");
}

} // namespace duetos::apps::calculator
