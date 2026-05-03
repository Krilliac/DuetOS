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
    // Memory register — survives 'C' (only MC clears it). When
    // `memory_set` is true and `memory != 0` the display gains
    // an "M" indicator so the user knows there's a stash.
    i64 memory;
    bool memory_set;
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid, {}, 0, 0, 0, false, true, false, 0, false};

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

// Negate the current display value. Acts on whatever's typed (or
// the accumulator if `fresh_entry` is set, since the display is
// then showing the last result). Toggles sign in place by rewriting
// the display via SetDisplayI64 — keeps formatting consistent with
// every other path.
void HandleSignToggle()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (cur == 0)
        return; // -0 == 0; no point flipping
    SetDisplayI64(-cur);
    // Once sign-toggled, the digit-typing path should not append
    // to the existing string — that would produce e.g. "-50" + "1"
    // = "-501" which is fine, but more usefully a fresh op
    // commits the new sign. Leaving fresh_entry alone preserves
    // the ability to type more digits if the user is mid-entry.
}

// Pop the last digit (or sign) off the display. Mirrors the
// Backspace key on a real calculator. No-op when the display is
// already showing a single character or after an error.
void HandleBackspace()
{
    if (g_state.error)
        return;
    if (g_state.fresh_entry)
    {
        // Backspace after `=` / op should clear the accumulator
        // view rather than chip away at the previous result.
        g_state.display_len = 0;
        g_state.display[0] = '\0';
        return;
    }
    if (g_state.display_len == 0)
        return;
    --g_state.display_len;
    g_state.display[g_state.display_len] = '\0';
    if (g_state.display_len == 0 || (g_state.display_len == 1 && g_state.display[0] == '-'))
    {
        g_state.display[0] = '\0';
        g_state.display_len = 0;
    }
}

// Percent: two semantics depending on whether an op is pending.
// With a pending op (the common bank-calc convention): treat the
// display value as a percentage OF the accumulator and combine
// per the pending op. Examples:
//     200 + 15 % =       -> 230  (i.e. 200 + 200*15/100)
//     400 - 10 % =       -> 360
//     100 * 50 % =       -> 50   (rare, but matches Win10 calc)
// Without a pending op: divide the display by 100, integer-trunc.
void HandlePercent()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (g_state.has_pending)
    {
        // Compute (lhs * cur) / 100 with overflow-resistant order:
        // do the multiply first so the % of small numbers stays
        // accurate; integer i64 holds up to 9.2e18 so even with
        // a 10-digit operand we don't overflow.
        const i64 lhs = g_state.accumulator;
        const i64 scaled = (lhs * cur) / 100;
        SetDisplayI64(scaled);
    }
    else
    {
        SetDisplayI64(cur / 100);
    }
    // Following calc convention, percent leaves the result on the
    // display but doesn't auto-commit — the user still hits `=` to
    // close the expression.
    g_state.fresh_entry = false;
}

// Memory recall (MR): pull the stored memory register into the
// display, marking fresh_entry so the next digit starts a new
// number. No-op if memory has never been written.
void HandleMemRecall()
{
    if (g_state.error)
        return;
    if (!g_state.memory_set)
        return;
    SetDisplayI64(g_state.memory);
    g_state.fresh_entry = true;
}

// Memory store (MS): copy the current display value into the
// memory register. Does NOT clear the display or alter pending
// op state — same convention as physical bank calculators.
void HandleMemStore()
{
    if (g_state.error)
        return;
    g_state.memory = ReadDisplayAsI64();
    g_state.memory_set = true;
}

// Memory clear (MC): reset the register and drop the indicator.
void HandleMemClear()
{
    g_state.memory = 0;
    g_state.memory_set = false;
}

// Memory add (M+): memory += display. Same display behaviour as
// MS — leaves the visible value alone, lifts memory.
void HandleMemAdd()
{
    if (g_state.error)
        return;
    g_state.memory += ReadDisplayAsI64();
    g_state.memory_set = true;
}

// Memory subtract (M-): memory -= display. Mirror of M+.
void HandleMemSub()
{
    if (g_state.error)
        return;
    g_state.memory -= ReadDisplayAsI64();
    g_state.memory_set = true;
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
    else if (k == '%')
        HandlePercent();
    else if (k == 'n' || k == 'N' || k == '_')
        HandleSignToggle();
    else if (static_cast<u8>(k) == 0x08) // ASCII Backspace
        HandleBackspace();
    else if (k == 'm' || k == 'M')
        HandleMemRecall();
    else if (k == 's' || k == 'S')
        HandleMemStore();
    else if (k == 'l' || k == 'L')
        HandleMemClear();
    else if (k == 'a' || k == 'A')
        HandleMemAdd();
    else if (k == 'b' || k == 'B')
        HandleMemSub();
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
    // Memory indicator: small "M" in the top-left of the display
    // strip when the register has a non-zero value. Painted before
    // the right-aligned number so it doesn't get pushed off-screen
    // on long results.
    if (g_state.memory_set && g_state.memory != 0)
    {
        constexpr u32 kMemFg = 0x00FFC848; // amber, distinguishes from main fg
        FramebufferDrawString(x + 4, y + 2, "M", kMemFg, kDisplayBg);
    }
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
    const u8 uc = static_cast<u8>(c);
    if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '*' || c == '/' || c == '=' || c == 'c' || c == 'C' ||
        c == '%' || c == 'n' || c == 'N' || c == '_' || uc == 0x08 || c == 'm' || c == 'M' || c == 's' || c == 'S' ||
        c == 'l' || c == 'L' || c == 'a' || c == 'A' || c == 'b' || c == 'B')
    {
        DispatchKey(c);
        return true;
    }
    if (static_cast<u8>(c) == 0x0A) // Enter -> '='
    {
        DispatchKey('=');
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
        // Sign toggle: 5n produces -5; another n flips back to 5.
        {"5n=", -5},
        {"5nn=", 5},
        // Backspace ('\b' = 0x08): "1234" then BS twice -> "12".
        {"1234\b\b=", 12},
        // Percent without pending op: 200% -> 2 (integer trunc).
        {"200%=", 2},
        // Percent with pending op: 200 + 15% = 230 (200 + 200*15/100).
        {"200+15%=", 230},
        // Percent with subtract: 400 - 10% = 360.
        {"400-10%=", 360},
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

    // Memory-register self-test: walk through MS / MR / M+ / M- /
    // MC and verify the register state at each step. Done outside
    // the table-driven loop because the keys produce side effects
    // on g_state.memory that the table format doesn't capture.
    HandleClear();
    HandleMemClear();
    if (g_state.memory_set || g_state.memory != 0)
        all_pass = false;

    // 50 MS — store 50, register = 50.
    DispatchKey('5');
    DispatchKey('0');
    DispatchKey('s');
    if (!g_state.memory_set || g_state.memory != 50)
        all_pass = false;

    // C, then 25 A — memory += 25 → 75. Display unchanged.
    HandleClear();
    DispatchKey('2');
    DispatchKey('5');
    DispatchKey('a');
    if (g_state.memory != 75)
        all_pass = false;

    // C, then 10 B — memory -= 10 → 65.
    HandleClear();
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('b');
    if (g_state.memory != 65)
        all_pass = false;

    // m — recall puts 65 on the display.
    DispatchKey('m');
    if (ReadDisplayAsI64() != 65)
        all_pass = false;

    // l — clear drops the indicator and zeroes the register.
    DispatchKey('l');
    if (g_state.memory_set || g_state.memory != 0)
        all_pass = false;

    // After MC the recall is a no-op (display stays where it was).
    DispatchKey('m');
    if (ReadDisplayAsI64() != 65)
        all_pass = false;

    HandleClear();
    HandleMemClear();
    SerialWrite(all_pass ? "[calc] self-test OK (arith + percent + sign + backspace + memory)\n"
                         : "[calc] self-test FAILED\n");
}

} // namespace duetos::apps::calculator
