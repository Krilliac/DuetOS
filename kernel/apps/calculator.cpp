#include "apps/calculator.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::apps::calculator
{

namespace
{

// Logical key value of each button. Index i in this array is the key
// fed into DispatchKey when button i fires. Ordering matches the on-
// screen 4×4 grid row-major, top-to-bottom — same as the legacy
// pre-app_widgets layout so visual fidelity is preserved.
constexpr char kButtonKeys[kIdCount] = {
    '7', '8', '9', '+', '4', '5', '6', '-', '1', '2', '3', '*', 'C', '0', '=', '/',
};

// Per-button labels. The widget stores the label by pointer, so the
// strings live in .rodata and outlive every paint.
constexpr const char* kButtonLabels[kIdCount] = {
    "7", "8", "9", "+", "4", "5", "6", "-", "1", "2", "3", "*", "C", "0", "=", "/",
};

// Grid layout inside the calculator window. All values are offsets
// from the window's client-area origin (cx, cy as delivered by the
// content-draw callback). The display strip takes the first ~60 px
// of vertical space; the multi-radix preview band takes the next 28
// px; the 4×4 button grid starts at kGridTopOffset and uses
// 68×36 buttons separated by 4 px gaps.
constexpr u32 kGridTopOffset = 100;
constexpr u32 kGridLeftOffset = 8;
constexpr u32 kBtnW = 68;
constexpr u32 kBtnH = 36;
constexpr u32 kBtnGap = 4;

constexpr u32 kDisplayCap = 16;

// Colour scheme. Light-grey digit keys, orange operators, green
// equals, red clear. Kept identical to the pre-app_widgets palette
// so users notice the typography + tactility upgrade rather than a
// chrome re-tone. The label colour rides on the AppButton fg field;
// the background overrides AppButton::bg_rgb directly.
struct KeyColours
{
    u32 normal;
    u32 label;
};
constexpr KeyColours kColDigit = {0x00D0D0D0, 0x00101828};
constexpr KeyColours kColOp = {0x00E08040, 0x00101828};
constexpr KeyColours kColEq = {0x0060A060, 0x00101828};
constexpr KeyColours kColClear = {0x00C04040, 0x00FFFFFF};

constexpr KeyColours ColoursFor(char k)
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
    // the digits currently being typed will be combined with these
    // on the next operator / '='.
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
// separator. If the number doesn't fit in kDisplayCap, sets error
// state and shows "ERR".
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

// Parse the current display string as an i64. Returns 0 on an empty/
// invalid display (the state machine treats a blank display as zero,
// which matches most physical calculators).
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

// Commit a pending operation against the given RHS, store the result
// in `accumulator`, and write it to the display.
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
    // Arithmetic overflow routes to the same sticky ERR state as
    // divide-by-zero. The bare lhs+rhs / lhs-rhs / lhs*rhs are signed-
    // overflow UB on large operands (a GUI keystroke fuzz hit the `*`
    // case); the __builtin_*_overflow forms compute the result and
    // report overflow without UB.
    bool ovf = false;
    switch (g_state.pending_op)
    {
    case '+':
        ovf = __builtin_add_overflow(lhs, rhs, &result);
        break;
    case '-':
        ovf = __builtin_sub_overflow(lhs, rhs, &result);
        break;
    case '*':
        ovf = __builtin_mul_overflow(lhs, rhs, &result);
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
    case '&':
        result = lhs & rhs;
        break;
    case '|':
        result = lhs | rhs;
        break;
    case '^':
        result = lhs ^ rhs;
        break;
    case '<': // shift left (unsigned semantics — a signed << that
              // shifts into/through the sign bit is UB; compute via u64)
        if (rhs < 0 || rhs >= 64)
            result = 0;
        else
            result = static_cast<i64>(static_cast<u64>(lhs) << rhs);
        break;
    case '>': // shift right (arithmetic — keeps sign bit)
        if (rhs < 0 || rhs >= 64)
            result = (lhs < 0) ? -1 : 0;
        else
            result = lhs >> rhs;
        break;
    default:
        result = rhs;
        break;
    }
    if (ovf)
    {
        SetDisplayLiteral("ERR");
        g_state.error = true;
        g_state.accumulator = 0;
        g_state.has_pending = false;
        g_state.fresh_entry = true;
        return;
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

void HandleSignToggle()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (cur == 0)
        return;
    SetDisplayI64(-cur);
}

void HandleBackspace()
{
    if (g_state.error)
        return;
    if (g_state.fresh_entry)
    {
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

// Percent: with a pending op, treat display as a percentage OF the
// accumulator and combine via the pending op (Win10-calc convention).
// Without a pending op, divide display by 100 with integer trunc.
void HandlePercent()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (g_state.has_pending)
    {
        const i64 lhs = g_state.accumulator;
        // lhs and cur are each up to a 16-digit display value, so the
        // product can reach ~1e32 — guard the multiply (UB otherwise).
        i64 prod = 0;
        if (__builtin_mul_overflow(lhs, cur, &prod))
        {
            // TripErr() is defined below this function; inline its body.
            g_state.error = true;
            SetDisplayLiteral("ERR");
            return;
        }
        const i64 scaled = prod / 100;
        SetDisplayI64(scaled);
    }
    else
    {
        SetDisplayI64(cur / 100);
    }
    g_state.fresh_entry = false;
}

void HandleMemRecall()
{
    if (g_state.error)
        return;
    if (!g_state.memory_set)
        return;
    SetDisplayI64(g_state.memory);
    g_state.fresh_entry = true;
}

void HandleMemStore()
{
    if (g_state.error)
        return;
    g_state.memory = ReadDisplayAsI64();
    g_state.memory_set = true;
}

void HandleMemClear()
{
    g_state.memory = 0;
    g_state.memory_set = false;
}

void HandleMemAdd()
{
    if (g_state.error)
        return;
    g_state.memory += ReadDisplayAsI64();
    g_state.memory_set = true;
}

void HandleMemSub()
{
    if (g_state.error)
        return;
    g_state.memory -= ReadDisplayAsI64();
    g_state.memory_set = true;
}

// Integer square root via Newton's method. Returns floor(sqrt(v)) for
// non-negative input; returns -1 for negative input (caller flips
// ERR).
i64 IntSqrt(i64 v)
{
    if (v < 0)
        return -1;
    if (v < 2)
        return v;
    i64 x = 1;
    while (x * x <= v && x < (1ll << 31))
        x <<= 1;
    for (u32 i = 0; i < 64; ++i)
    {
        const i64 nx = (x + v / x) / 2;
        if (nx >= x)
            break;
        x = nx;
    }
    while (x * x > v)
        --x;
    return x;
}

void TripErr()
{
    g_state.error = true;
    SetDisplayLiteral("ERR");
}

void HandleSqrt()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    const i64 r = IntSqrt(cur);
    if (r < 0)
    {
        TripErr();
        return;
    }
    SetDisplayI64(r);
    g_state.fresh_entry = true;
}

void HandleSquare()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (cur > 3037000499ll || cur < -3037000499ll)
    {
        TripErr();
        return;
    }
    SetDisplayI64(cur * cur);
    g_state.fresh_entry = true;
}

void HandleAbs()
{
    if (g_state.error)
        return;
    i64 cur = ReadDisplayAsI64();
    if (cur < 0)
        cur = -cur;
    SetDisplayI64(cur);
    g_state.fresh_entry = true;
}

void HandleFactorial()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (cur < 0 || cur > 20)
    {
        TripErr();
        return;
    }
    i64 r = 1;
    for (i64 i = 2; i <= cur; ++i)
        r *= i;
    SetDisplayI64(r);
    g_state.fresh_entry = true;
}

void HandleBitwiseNot()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    SetDisplayI64(~cur);
    g_state.fresh_entry = true;
}

void HandleReciprocal()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64();
    if (cur == 0)
    {
        TripErr();
        return;
    }
    SetDisplayI64(1 / cur);
    g_state.fresh_entry = true;
}

void DispatchKey(char k)
{
    if (k >= '0' && k <= '9')
        HandleDigit(k);
    else if (k == '+' || k == '-' || k == '*' || k == '/' || k == '&' || k == '|' || k == '^' || k == '<' || k == '>')
        HandleOp(k);
    else if (k == '~')
        HandleBitwiseNot();
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
    else if (k == 'q' || k == 'Q')
        HandleSqrt();
    else if (k == 'x' || k == 'X')
        HandleSquare();
    else if (k == 'y' || k == 'Y')
        HandleAbs();
    else if (k == '!')
        HandleFactorial();
    else if (k == 'r' || k == 'R')
        HandleReciprocal();
}

// One free-function per on-screen button. AppButton::on_click is a
// plain `void (*)()`, so we can't pack the key value into the
// callback — each button needs its own trampoline. Trivial wrappers
// keep the dispatch site honest (one call site per visible key) and
// they compile to a single tail-call.
void Click0()
{
    DispatchKey('0');
}
void Click1()
{
    DispatchKey('1');
}
void Click2()
{
    DispatchKey('2');
}
void Click3()
{
    DispatchKey('3');
}
void Click4()
{
    DispatchKey('4');
}
void Click5()
{
    DispatchKey('5');
}
void Click6()
{
    DispatchKey('6');
}
void Click7()
{
    DispatchKey('7');
}
void Click8()
{
    DispatchKey('8');
}
void Click9()
{
    DispatchKey('9');
}
void ClickPlus()
{
    DispatchKey('+');
}
void ClickMinus()
{
    DispatchKey('-');
}
void ClickMul()
{
    DispatchKey('*');
}
void ClickDiv()
{
    DispatchKey('/');
}
void ClickEq()
{
    DispatchKey('=');
}
void ClickClear()
{
    DispatchKey('C');
}

using ClickFn = void (*)();
constexpr ClickFn kClickFns[kIdCount] = {
    Click7, Click8, Click9, ClickPlus, Click4,     Click5, Click6,  ClickMinus,
    Click1, Click2, Click3, ClickMul,  ClickClear, Click0, ClickEq, ClickDiv,
};

// ----- App-widget composition --------------------------------------
//
// The calculator is a panel + a label (display readout) + 16 buttons,
// laid out in declaration order back-to-front so the panel paints
// first and the buttons land on top.
//
// Bounds are recomputed every paint from the live window client
// rect — the window can move or resize, so caching screen-absolute
// bounds in the constinit instance would put buttons in the wrong
// place after a drag. The display label's text pointer is bound
// directly to `g_state.display` for the same reason: the display
// updates every keypress, and a static initialiser would lock us to
// whatever was visible at boot.

using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::app_widgets::AppButton;
using duetos::drivers::video::app_widgets::AppLabel;
using duetos::drivers::video::app_widgets::AppPanel;
using duetos::drivers::video::app_widgets::Compose;
using duetos::drivers::video::app_widgets::Event;
using duetos::drivers::video::app_widgets::EventKind;
using duetos::drivers::video::app_widgets::MakeWidgetGroup;
using duetos::drivers::video::app_widgets::Rect;

constinit auto g_calc = MakeWidgetGroup(AppPanel{}, AppLabel{},
                                        // 4×4 button grid, row-major top-to-bottom — order matches
                                        // kButtonKeys / kClickFns / kButtonLabels so RebindBounds and
                                        // self-test stay table-driven.
                                        AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                                        AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                                        AppButton{}, AppButton{}, AppButton{}, AppButton{});

// Walk the widget chain by hand to set per-button label / colour /
// callback once at init. The chain layout matches g_calc's argument
// list above: head = AppPanel, tail.head = AppLabel, then 16
// AppButton nodes in row-major order.
void BindButtonsOnce()
{
    auto& panel = g_calc.chain.head;
    panel.bg_rgb = 0x00101828U;
    panel.border_rgb = 0x00081018U;
    panel.shadow_radius = 0; // panel is INSIDE the window, no own shadow

    auto& label = g_calc.chain.tail.head;
    label.text = g_state.display;
    label.role = ChromeTextRole::Display;
    label.weight = ChromeTextWeight::Regular;
    label.fg_rgb = 0x0080F088U;
    label.bg_rgb = 0x00202830U;
    label.align_left = false;

    auto& b0 = g_calc.chain.tail.tail.head;
    auto& b1 = g_calc.chain.tail.tail.tail.head;
    auto& b2 = g_calc.chain.tail.tail.tail.tail.head;
    auto& b3 = g_calc.chain.tail.tail.tail.tail.tail.head;
    auto& b4 = g_calc.chain.tail.tail.tail.tail.tail.tail.head;
    auto& b5 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b6 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b7 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b8 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b9 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b10 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b11 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b12 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b13 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b14 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    auto& b15 = g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    AppButton* buttons[kIdCount] = {&b0, &b1, &b2,  &b3,  &b4,  &b5,  &b6,  &b7,
                                    &b8, &b9, &b10, &b11, &b12, &b13, &b14, &b15};
    for (u32 i = 0; i < kIdCount; ++i)
    {
        const KeyColours c = ColoursFor(kButtonKeys[i]);
        buttons[i]->label = kButtonLabels[i];
        buttons[i]->on_click = kClickFns[i];
        buttons[i]->bg_rgb = c.normal;
        buttons[i]->fg_rgb = c.label;
        buttons[i]->weight =
            (kButtonKeys[i] == '=' || kButtonKeys[i] == 'C') ? ChromeTextWeight::Bold : ChromeTextWeight::Regular;
    }
}

// Re-anchor widget bounds to the live client rect. Called from
// DrawFn before PaintAll and from CalculatorMouseInput before
// DispatchEvent so hit-tests + visuals stay consistent across
// window moves / resizes.
void RebindBoundsToClient(u32 cx, u32 cy, u32 cw)
{
    auto& panel = g_calc.chain.head;
    panel.bounds = Rect{cx, cy, cw, /*h=*/256u};

    auto& label = g_calc.chain.tail.head;
    label.bounds = Rect{cx + 8u, cy + 4u, (cw >= 16u) ? cw - 16u : cw, 28u};

    AppButton* buttons[kIdCount];
    buttons[0] = &g_calc.chain.tail.tail.head;
    buttons[1] = &g_calc.chain.tail.tail.tail.head;
    buttons[2] = &g_calc.chain.tail.tail.tail.tail.head;
    buttons[3] = &g_calc.chain.tail.tail.tail.tail.tail.head;
    buttons[4] = &g_calc.chain.tail.tail.tail.tail.tail.tail.head;
    buttons[5] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[6] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[7] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[8] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[9] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[10] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[11] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[12] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[13] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[14] = &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    buttons[15] =
        &g_calc.chain.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.tail.head;
    for (u32 i = 0; i < kIdCount; ++i)
    {
        const u32 row = i / 4;
        const u32 col = i % 4;
        buttons[i]->bounds = Rect{cx + kGridLeftOffset + col * (kBtnW + kBtnGap),
                                  cy + kGridTopOffset + row * (kBtnH + kBtnGap), kBtnW, kBtnH};
    }
}

// Multi-radix preview formatters — preserved as a carve-out below
// the widget-group paint so the hex / bin / oct strip keeps reading
// alongside the main decimal display. Carve-out justification per
// CLAUDE.md: the multi-radix strip is part of the calculator's
// character; AppLabel(Display) can render the decimal value but
// can't compose three separate per-radix strings into one band.

void FmtHex(i64 v, char* out, u32 width)
{
    if (width < 19)
    {
        if (width > 0)
            out[0] = '\0';
        return;
    }
    out[0] = '0';
    out[1] = 'x';
    u64 u = static_cast<u64>(v);
    bool nonzero = false;
    u32 o = 2;
    for (i32 i = 60; i >= 0; i -= 4)
    {
        const u32 nib = static_cast<u32>((u >> static_cast<u32>(i)) & 0xFu);
        if (nib != 0 || nonzero || i == 0)
        {
            nonzero = true;
            out[o++] = (nib < 10) ? static_cast<char>('0' + nib) : static_cast<char>('A' + nib - 10);
        }
    }
    out[o] = '\0';
}

void FmtBin(i64 v, char* out, u32 width)
{
    if (width < 4)
    {
        if (width > 0)
            out[0] = '\0';
        return;
    }
    u64 u = static_cast<u64>(v);
    out[0] = '0';
    out[1] = 'b';
    u32 o = 2;
    i32 hi = -1;
    for (i32 i = 63; i >= 0; --i)
    {
        if ((u >> static_cast<u32>(i)) & 1ull)
        {
            hi = i;
            break;
        }
    }
    if (hi < 0)
    {
        out[o++] = '0';
        out[o] = '\0';
        return;
    }
    if (hi < 16)
    {
        for (i32 i = hi; i >= 0; --i)
        {
            const u64 b = (u >> static_cast<u32>(i)) & 1ull;
            if (o + 1 < width)
                out[o++] = b ? '1' : '0';
        }
    }
    else
    {
        if (o + 5 < width)
        {
            out[o++] = '1';
            out[o++] = '.';
            out[o++] = '.';
            out[o++] = '.';
        }
        for (i32 i = 15; i >= 0; --i)
        {
            const u64 b = (u >> static_cast<u32>(i)) & 1ull;
            if (o + 1 < width)
                out[o++] = b ? '1' : '0';
        }
    }
    out[o] = '\0';
}

void FmtOct(i64 v, char* out, u32 width)
{
    if (width < 25)
    {
        if (width > 0)
            out[0] = '\0';
        return;
    }
    out[0] = '0';
    out[1] = 'o';
    u64 u = static_cast<u64>(v);
    if (u == 0)
    {
        out[2] = '0';
        out[3] = '\0';
        return;
    }
    char tmp[24];
    u32 n = 0;
    while (u > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (u & 0x7));
        u >>= 3;
    }
    u32 o = 2;
    while (n > 0 && o + 1 < width)
        out[o++] = tmp[--n];
    out[o] = '\0';
}

// Content-draw callback. Paints the app_widgets group (panel +
// display readout + 16 buttons) first, then overlays the
// multi-radix preview band carve-out and the "M" memory indicator
// directly via the framebuffer primitives — neither of those has a
// clean widget shape yet, and they're load-bearing for the
// calculator's character (the original v0 design).
void DrawFn(u32 cx, u32 cy, u32 cw, u32 /*ch*/, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (cw <= 16)
        return;

    // 1) Re-anchor widgets to the live client rect, then paint the
    //    widget group. PaintAll runs panel -> label -> 16 buttons in
    //    declaration order; buttons land on top of the panel.
    RebindBoundsToClient(cx, cy, cw);
    // Make sure the label sees the live display string (a fresh
    // calculator boot leaves it pointing at g_state.display, but a
    // future SessionRestore could swap pointers).
    g_calc.chain.tail.head.text = (g_state.display_len == 0) ? "0" : g_state.display;
    Compose c{};
    g_calc.PaintAll(c);

    // 2) Memory indicator — small "M" in the top-left of the display
    //    strip when the register has a non-zero value. Painted after
    //    the widget label so it sits on top.
    constexpr u32 kDisplayBg = 0x00202830U;
    if (g_state.memory_set && g_state.memory != 0)
    {
        constexpr u32 kMemFg = 0x00FFC848U;
        FramebufferDrawString(cx + 8u + 4u, cy + 4u + 2u, "M", kMemFg, kDisplayBg);
    }

    // 3) Multi-radix preview band — sits between the display strip
    //    (cy+4..cy+32) and the button grid (cy+100..). Skipped in
    //    error state to avoid hex-formatting noise.
    if (g_state.error)
        return;
    constexpr u32 kAuxFg = 0x0060B0E0U;
    const u32 x = cx + 8u;
    const u32 y = cy + 4u;
    const u32 w = (cw >= 16u) ? cw - 16u : cw;
    constexpr u32 kDisplayH = 28u;
    constexpr u32 kAuxBandH = 28u;
    FramebufferFillRect(x, y + kDisplayH, w, kAuxBandH, kDisplayBg);
    const i64 v = ReadDisplayAsI64();
    char hex_buf[24];
    char bin_buf[28];
    char oct_buf[28];
    FmtHex(v, hex_buf, sizeof(hex_buf));
    FmtBin(v, bin_buf, sizeof(bin_buf));
    FmtOct(v, oct_buf, sizeof(oct_buf));
    const u32 aux_y = y + kDisplayH + 4u;
    u32 hlen = 0;
    while (hex_buf[hlen] != '\0')
        ++hlen;
    const u32 hx = (hlen * 8u + 12u < w) ? x + w - hlen * 8u - 6u : x + 4u;
    FramebufferDrawString(hx, aux_y, hex_buf, kAuxFg, kDisplayBg);
    char low[60];
    u32 lo = 0;
    for (u32 i = 0; bin_buf[i] != '\0' && lo + 1 < sizeof(low); ++i)
        low[lo++] = bin_buf[i];
    low[lo++] = ' ';
    low[lo++] = ' ';
    for (u32 i = 0; oct_buf[i] != '\0' && lo + 1 < sizeof(low); ++i)
        low[lo++] = oct_buf[i];
    low[lo] = '\0';
    const u32 lx = (lo * 8u + 12u < w) ? x + w - lo * 8u - 6u : x + 4u;
    FramebufferDrawString(lx, aux_y + 12u, low, kAuxFg, kDisplayBg);
}

// Edge-detection state for mouse input. The legacy widget table
// kept its own g_prev_left_down; the migrated app needs the same
// shape so MouseDown / MouseUp event pairs fire per click rather
// than per packet.
constinit bool g_prev_left_down = false;

// Self-test result flag for the Pass D umbrella aggregator.
constinit bool g_self_test_passed = false;

} // namespace

void CalculatorInit(duetos::drivers::video::WindowHandle handle)
{
    g_state.handle = handle;
    HandleClear();
    BindButtonsOnce();
    duetos::drivers::video::WindowSetContentDraw(handle, DrawFn, nullptr);
}

duetos::drivers::video::WindowHandle CalculatorWindow()
{
    return g_state.handle;
}

bool CalculatorOnWidgetEvent(u32 /*id*/)
{
    // Legacy widget-table dispatch path. The migrated calculator
    // owns its own hit-testing via g_calc.DispatchEvent (see
    // CalculatorMouseInput) so no IDs in the legacy `kIdBase`
    // range are ever produced. Kept as a no-op so the boot-time
    // mouse loop's call site doesn't need a conditional removal.
    return false;
}

void CalculatorMouseInput(u32 cx, u32 cy, u8 button_mask)
{
    using duetos::drivers::input::kMouseButtonLeft;
    if (g_state.handle == duetos::drivers::video::kWindowInvalid)
        return;
    u32 wx = 0, wy = 0, ww = 0, wh = 0;
    if (!duetos::drivers::video::WindowGetBounds(g_state.handle, &wx, &wy, &ww, &wh))
        return;
    // Translate framebuffer-absolute cursor into client coords
    // relative to the window's title-bar-below client origin. The
    // widget bounds set by RebindBoundsToClient use the same origin.
    u32 client_x = cx;
    u32 client_y = cy;
    RebindBoundsToClient(wx, wy + 22u, ww);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

    // Always send MouseMove so hover state tracks the cursor on
    // tactility themes. Hover only matters when the cursor is
    // actually over the window; ignoring out-of-window motion keeps
    // hover stickiness from leaking into other windows.
    const bool inside_window = (cx >= wx && cx < wx + ww && cy >= wy + 22u && cy < wy + wh);
    if (inside_window)
    {
        const Event m{EventKind::MouseMove, client_x, client_y, 0u, 0u};
        g_calc.DispatchEvent(m);
    }
    if (press_edge && inside_window)
    {
        const Event d{EventKind::MouseDown, client_x, client_y, 0u, 0u};
        g_calc.DispatchEvent(d);
    }
    if (release_edge)
    {
        // Always send MouseUp (even outside the window) so a button
        // pressed inside and dragged off clears its Pressed flag.
        const Event u{EventKind::MouseUp, client_x, client_y, 0u, 0u};
        g_calc.DispatchEvent(u);
    }
}

bool CalculatorFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '*' || c == '/' || c == '=' || c == 'c' || c == 'C' ||
        c == '%' || c == 'n' || c == 'N' || c == '_' || uc == 0x08 || c == 'm' || c == 'M' || c == 's' || c == 'S' ||
        c == 'l' || c == 'L' || c == 'a' || c == 'A' || c == 'b' || c == 'B' || c == 'q' || c == 'Q' || c == 'x' ||
        c == 'X' || c == 'y' || c == 'Y' || c == '!' || c == 'r' || c == 'R' || c == '&' || c == '|' || c == '^' ||
        c == '<' || c == '>' || c == '~')
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

namespace
{

// Drive synthetic mouse events through g_calc and verify the click
// fires the right state mutation. Returns true iff the click chain
// runs end-to-end. Bounds for g_calc are set to a known rect so we
// can target each button without having a live window.
bool ClickViaWidget(u32 button_index)
{
    if (button_index >= kIdCount)
        return false;
    // Anchor bounds at (0, 22) — same shape as a live window would
    // hand us through DrawFn (client-area origin under the title
    // bar). Width 300 matches the boot-time window size.
    RebindBoundsToClient(0u, 22u, 300u);

    const u32 row = button_index / 4u;
    const u32 col = button_index % 4u;
    const u32 bx = 0u + kGridLeftOffset + col * (kBtnW + kBtnGap) + kBtnW / 2u;
    const u32 by = 22u + kGridTopOffset + row * (kBtnH + kBtnGap) + kBtnH / 2u;

    const Event move{EventKind::MouseMove, bx, by, 0u, 0u};
    if (g_calc.DispatchEvent(move) != duetos::drivers::video::app_widgets::EventResult::Consumed)
        return false;
    const Event down{EventKind::MouseDown, bx, by, 0u, 0u};
    if (g_calc.DispatchEvent(down) != duetos::drivers::video::app_widgets::EventResult::Consumed)
        return false;
    const Event up{EventKind::MouseUp, bx, by, 0u, 0u};
    if (g_calc.DispatchEvent(up) != duetos::drivers::video::app_widgets::EventResult::Consumed)
        return false;
    return true;
}

// Look up the button index whose key matches `k`. Returns kIdCount
// (out-of-range) on miss so the caller short-circuits.
u32 IndexOfKey(char k)
{
    for (u32 i = 0; i < kIdCount; ++i)
    {
        if (kButtonKeys[i] == k)
            return i;
    }
    return kIdCount;
}

} // namespace

void CalculatorSelfTest()
{
    using duetos::arch::SerialWrite;
    g_self_test_passed = false;
    BindButtonsOnce(); // self-test runs before CalculatorInit on the
                       // boot path is guaranteed to have fired

    struct Case
    {
        const char* keys;
        i64 expect;
    };
    const Case cases[] = {
        {"2+3=", 5},       {"9-4=", 5},  {"6*7=", 42},      {"5n=", -5},       {"5nn=", 5},
        {"1234\b\b=", 12}, {"200%=", 2}, {"200+15%=", 230}, {"400-10%=", 360},
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

    // Memory register walk.
    HandleClear();
    HandleMemClear();
    if (g_state.memory_set || g_state.memory != 0)
        all_pass = false;
    DispatchKey('5');
    DispatchKey('0');
    DispatchKey('s');
    if (!g_state.memory_set || g_state.memory != 50)
        all_pass = false;
    HandleClear();
    DispatchKey('2');
    DispatchKey('5');
    DispatchKey('a');
    if (g_state.memory != 75)
        all_pass = false;
    HandleClear();
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('b');
    if (g_state.memory != 65)
        all_pass = false;
    DispatchKey('m');
    if (ReadDisplayAsI64() != 65)
        all_pass = false;
    DispatchKey('l');
    if (g_state.memory_set || g_state.memory != 0)
        all_pass = false;
    DispatchKey('m');
    if (ReadDisplayAsI64() != 65)
        all_pass = false;
    HandleClear();
    HandleMemClear();

    // Scientific.
    HandleClear();
    DispatchKey('1');
    DispatchKey('4');
    DispatchKey('4');
    DispatchKey('q');
    if (ReadDisplayAsI64() != 12 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('7');
    DispatchKey('x');
    if (ReadDisplayAsI64() != 49 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('9');
    DispatchKey('n');
    DispatchKey('y');
    if (ReadDisplayAsI64() != 9 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('6');
    DispatchKey('!');
    if (ReadDisplayAsI64() != 720 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('2');
    DispatchKey('1');
    DispatchKey('!');
    if (!g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('4');
    DispatchKey('n');
    DispatchKey('q');
    if (!g_state.error)
        all_pass = false;

    // Bitwise.
    HandleClear();
    DispatchKey('1');
    DispatchKey('2');
    DispatchKey('&');
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 8 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('1');
    DispatchKey('2');
    DispatchKey('|');
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 14 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('1');
    DispatchKey('2');
    DispatchKey('^');
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 6 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('1');
    DispatchKey('<');
    DispatchKey('4');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 16 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('6');
    DispatchKey('4');
    DispatchKey('>');
    DispatchKey('2');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 16 || g_state.error)
        all_pass = false;
    HandleClear();
    DispatchKey('5');
    DispatchKey('~');
    if (ReadDisplayAsI64() != -6 || g_state.error)
        all_pass = false;
    HandleClear();

    // app_widgets dispatch path — the Pass D acceptance criterion.
    // Drives synthetic Down/Up events through g_calc and confirms
    // the same arithmetic engine fires. "2 + 3 ="
    HandleClear();
    if (!ClickViaWidget(IndexOfKey('2')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('+')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('3')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('=')))
        all_pass = false;
    if (ReadDisplayAsI64() != 5 || g_state.error)
        all_pass = false;
    HandleClear();

    g_self_test_passed = all_pass;
    SerialWrite(all_pass ? "[calculator-selftest] PASS\n" : "[calculator-selftest] FAIL\n");
}

bool CalculatorSelfTestPassed()
{
    return g_self_test_passed;
}

i64 CalculatorMemoryValue()
{
    return g_state.memory;
}
bool CalculatorMemorySet()
{
    return g_state.memory_set;
}
void CalculatorMemoryRestore(i64 value, bool set)
{
    g_state.memory = set ? value : 0;
    g_state.memory_set = set;
}

} // namespace duetos::apps::calculator
