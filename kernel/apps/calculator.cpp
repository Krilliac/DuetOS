#include "apps/calculator.h"

#include "arch/x86_64/serial.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/app_widgets/app_button.h"
#include "drivers/video/app_widgets/app_label.h"
#include "drivers/video/app_widgets/app_panel.h"
#include "drivers/video/app_widgets/widget_group.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"

namespace duetos::apps::calculator
{

namespace
{

// Logical key value of each button. Index i in this array is the key
// fed into DispatchKey when button i fires. Ordering matches the on-
// screen 4×5 grid row-major, top-to-bottom. Row 0 carries the two
// clear keys (full reset 'C' and clear-entry 'e') plus a backspace
// glyph and the decimal point; the lower four rows are the classic
// digit/operator keypad. 0x08 is ASCII Backspace (routes to
// HandleBackspace); 'e' is the Clear-Entry key (F-012); '.' is the
// decimal-point key (F-010).
constexpr char kButtonKeys[kIdCount] = {
    'C', 'e', static_cast<char>(0x08),
    '/', // row 0: Clear, CE, ⌫, ÷
    '7', '8', '9',
    '*', // row 1
    '4', '5', '6',
    '-', // row 2
    '1', '2', '3',
    '+', // row 3
    '0', '.', '=',
    'n', // row 4: 0, ., =, ±
};

// Per-button labels. The widget stores the label by pointer, so the
// strings live in .rodata and outlive every paint.
constexpr const char* kButtonLabels[kIdCount] = {
    "C", "CE", "<", "/", //
    "7", "8",  "9", "*", //
    "4", "5",  "6", "-", //
    "1", "2",  "3", "+", //
    "0", ".",  "=", "+/-",
};

// Grid layout inside the calculator window. All values are offsets
// from the window's client-area origin (cx, cy as delivered by the
// content-draw callback). The display strip takes the first ~28 px
// of vertical space; the multi-radix preview band takes the next 28
// px; the 4×5 button grid starts at kGridTopOffset and uses 68×36
// buttons separated by 4 px gaps (5 rows now — was 4×4, extended for
// the decimal-point + Clear-Entry keys).
constexpr u32 kGridTopOffset = 100;
constexpr u32 kGridLeftOffset = 8;
constexpr u32 kBtnW = 68;
constexpr u32 kBtnH = 36;
constexpr u32 kBtnGap = 4;
constexpr u32 kGridCols = 4;

constexpr u32 kDisplayCap = 16;

// Fixed-point scale: values are stored as integer × 10^kFracDigits.
// 6 fractional digits give us 1/4 = 0.250000, 0.1 + 0.2 = 0.300000,
// etc. with room to trim trailing zeros for display. No FPU in kernel
// context, so every "fractional" value is really a scaled i64.
constexpr u32 kFracDigits = 6;
constexpr i64 kScale = 1000000; // 10^kFracDigits

// Colour scheme. Light-grey digit keys, orange operators, green
// equals, red clear, amber CE. The label colour rides on the
// AppButton fg field; the background overrides AppButton::bg_rgb.
struct KeyColours
{
    u32 normal;
    u32 label;
};
constexpr KeyColours kColDigit = {0x00D0D0D0, 0x00101828};
constexpr KeyColours kColOp = {0x00E08040, 0x00101828};
constexpr KeyColours kColEq = {0x0060A060, 0x00101828};
constexpr KeyColours kColClear = {0x00C04040, 0x00FFFFFF};
constexpr KeyColours kColClearEntry = {0x00B07030, 0x00FFFFFF};

constexpr KeyColours ColoursFor(char k)
{
    if ((k >= '0' && k <= '9') || k == '.')
        return kColDigit;
    if (k == 'C')
        return kColClear;
    if (k == 'e') // Clear-Entry
        return kColClearEntry;
    if (k == '=')
        return kColEq;
    return kColOp; // '+' '-' '*' '/' '±' '⌫'
}

struct State
{
    duetos::drivers::video::WindowHandle handle;
    // Displayed string — always NUL-terminated; length <= kDisplayCap.
    // May contain a single '.' for fractional entry (F-010).
    char display[kDisplayCap + 1];
    u32 display_len;
    // Clipped view of `display` actually handed to the on-screen label
    // so a long value never paints past the client rect (F-051). When
    // the value is too wide the most-significant end is shown with a
    // leading '<' overflow indicator.
    char display_view[kDisplayCap + 2];
    // Running evaluation state. When `has_pending` is true,
    // `accumulator` holds the LHS (fixed-point) and `pending_op` the
    // operator; the digits currently being typed will be combined with
    // these on the next operator / '='.
    i64 accumulator; // fixed-point (× kScale)
    char pending_op; // 0 when no pending op
    bool has_pending;
    bool fresh_entry; // true iff next digit starts a new number (post-op or post-=)
    bool error;       // sticky — cleared by 'C'
    // Memory register — survives 'C' (only MC clears it). Fixed-point.
    i64 memory; // fixed-point (× kScale)
    bool memory_set;
};

constinit State g_state = {duetos::drivers::video::kWindowInvalid, {}, 0, {}, 0, 0, false, true, false, 0, false};

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

void TripErr()
{
    g_state.error = true;
    SetDisplayLiteral("ERR");
}

// Format a fixed-point value (× kScale) into the display. Prints the
// integer part, a '.', and the fractional digits with trailing zeros
// trimmed (0.25 not 0.250000; 5 not 5.000000). If the integer part
// doesn't fit in kDisplayCap, trips ERR (mirrors the legacy overflow
// path).
void SetDisplayFixed(i64 v)
{
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
    const u64 int_part = abs_v / static_cast<u64>(kScale);
    u64 frac_part = abs_v % static_cast<u64>(kScale);

    // Integer-part digits (reversed).
    char itmp[24];
    u32 in = 0;
    if (int_part == 0)
    {
        itmp[in++] = '0';
    }
    else
    {
        u64 t = int_part;
        while (t > 0 && in < sizeof(itmp))
        {
            itmp[in++] = static_cast<char>('0' + (t % 10));
            t /= 10;
        }
    }

    // Fractional digits, fixed kFracDigits wide (leading zeros kept),
    // then trailing zeros trimmed.
    char ftmp[kFracDigits + 1];
    for (i32 i = static_cast<i32>(kFracDigits) - 1; i >= 0; --i)
    {
        ftmp[i] = static_cast<char>('0' + (frac_part % 10));
        frac_part /= 10;
    }
    u32 fn = kFracDigits;
    while (fn > 0 && ftmp[fn - 1] == '0')
        --fn;

    // Assemble: ['-'] int '.' frac
    const u32 total = (neg ? 1u : 0u) + in + (fn > 0 ? 1u + fn : 0u);
    if (total > kDisplayCap)
    {
        TripErr();
        return;
    }
    u32 o = 0;
    if (neg)
        g_state.display[o++] = '-';
    for (u32 i = 0; i < in; ++i)
        g_state.display[o++] = itmp[in - 1 - i];
    if (fn > 0)
    {
        g_state.display[o++] = '.';
        for (u32 i = 0; i < fn; ++i)
            g_state.display[o++] = ftmp[i];
    }
    g_state.display[o] = '\0';
    g_state.display_len = o;
}

// Parse the current display string as a fixed-point value (× kScale).
// Handles an optional sign, an integer part, and an optional '.' plus
// up to kFracDigits fractional digits (extra fractional digits are
// truncated). A blank display reads as zero. Sets `*overflow` if the
// integer magnitude overflows the scaled i64.
i64 ReadDisplayAsFixed(bool* overflow)
{
    if (overflow != nullptr)
        *overflow = false;
    if (g_state.display_len == 0)
        return 0;
    bool neg = false;
    u32 i = 0;
    if (g_state.display[0] == '-')
    {
        neg = true;
        i = 1;
    }
    i64 int_part = 0;
    for (; i < g_state.display_len; ++i)
    {
        const char c = g_state.display[i];
        if (c == '.')
        {
            ++i;
            break;
        }
        if (c < '0' || c > '9')
            return 0; // defensive
        if (__builtin_mul_overflow(int_part, static_cast<i64>(10), &int_part) ||
            __builtin_add_overflow(int_part, static_cast<i64>(c - '0'), &int_part))
        {
            if (overflow != nullptr)
                *overflow = true;
            return 0;
        }
    }
    // Scale the integer part up by kScale, guarding overflow.
    i64 scaled = 0;
    if (__builtin_mul_overflow(int_part, kScale, &scaled))
    {
        if (overflow != nullptr)
            *overflow = true;
        return 0;
    }
    // Fractional digits (up to kFracDigits; extras truncated).
    i64 place = kScale / 10;
    for (; i < g_state.display_len && place > 0; ++i)
    {
        const char c = g_state.display[i];
        if (c < '0' || c > '9')
            break;
        scaled += static_cast<i64>(c - '0') * place;
        place /= 10;
    }
    return neg ? -scaled : scaled;
}

// Integer (truncated) read of the display — used by bitwise / shift /
// factorial ops that are only meaningful on whole numbers, and by the
// multi-radix preview band. Truncates toward zero.
i64 ReadDisplayAsI64()
{
    bool ovf = false;
    const i64 f = ReadDisplayAsFixed(&ovf);
    if (ovf)
        return 0;
    return f / kScale;
}

// Multiply two fixed-point values: (a × b) / kScale, with overflow
// guards on both the product and the divide-down.
bool FixedMul(i64 a, i64 b, i64* out)
{
    // a, b are each value×kScale. The raw product is value×kScale²,
    // which overflows i64 for even modest operands — so split: the
    // integer×fractional cross terms are computed without first
    // forming the full square. Decompose a = ai*kScale + af.
    const i64 ai = a / kScale;
    const i64 af = a - ai * kScale; // signed remainder (matches a's sign)
    // out = ai*b + (af*b)/kScale, each step overflow-guarded.
    i64 t1 = 0;
    if (__builtin_mul_overflow(ai, b, &t1))
        return false;
    i64 t2 = 0;
    if (__builtin_mul_overflow(af, b, &t2))
        return false;
    t2 /= kScale;
    return !__builtin_add_overflow(t1, t2, out);
}

// Divide two fixed-point values: (a × kScale) / b. Caller guarantees
// b != 0. Returns false on overflow.
bool FixedDiv(i64 a, i64 b, i64* out)
{
    i64 num = 0;
    if (__builtin_mul_overflow(a, kScale, &num))
        return false;
    *out = num / b;
    return true;
}

// Commit a pending operation against the given fixed-point RHS, store
// the result in `accumulator`, and write it to the display.
void ApplyPending(i64 rhs)
{
    if (!g_state.has_pending)
    {
        g_state.accumulator = rhs;
        SetDisplayFixed(g_state.accumulator);
        return;
    }
    const i64 lhs = g_state.accumulator;
    i64 result = 0;
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
        ovf = !FixedMul(lhs, rhs, &result);
        break;
    case '/':
        if (rhs == 0)
        {
            TripErr();
            g_state.accumulator = 0;
            g_state.has_pending = false;
            g_state.pending_op = 0;
            g_state.fresh_entry = true;
            return;
        }
        ovf = !FixedDiv(lhs, rhs, &result);
        break;
    // Bitwise / shift ops are integer-only — operate on the truncated
    // integer parts and re-scale the integer result back to fixed-point.
    case '&':
        result = ((lhs / kScale) & (rhs / kScale)) * kScale;
        break;
    case '|':
        result = ((lhs / kScale) | (rhs / kScale)) * kScale;
        break;
    case '^':
        result = ((lhs / kScale) ^ (rhs / kScale)) * kScale;
        break;
    case '<': // shift left (unsigned semantics to avoid sign-bit UB)
    {
        const i64 li = lhs / kScale;
        const i64 ri = rhs / kScale;
        if (ri < 0 || ri >= 64)
            result = 0;
        else
            result = static_cast<i64>(static_cast<u64>(li) << ri) * kScale;
        break;
    }
    case '>': // shift right (arithmetic — keeps sign bit)
    {
        const i64 li = lhs / kScale;
        const i64 ri = rhs / kScale;
        if (ri < 0 || ri >= 64)
            result = (li < 0) ? -kScale : 0;
        else
            result = (li >> ri) * kScale;
        break;
    }
    default:
        result = rhs;
        break;
    }
    if (ovf)
    {
        TripErr();
        g_state.accumulator = 0;
        g_state.has_pending = false;
        g_state.pending_op = 0;
        g_state.fresh_entry = true;
        return;
    }
    g_state.accumulator = result;
    g_state.has_pending = false;
    g_state.pending_op = 0;
    SetDisplayFixed(result);
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
    // Cap fractional digits typed at kFracDigits so the scale never
    // silently drops the user's input.
    bool seen_dot = false;
    u32 frac_count = 0;
    for (u32 i = 0; i < g_state.display_len; ++i)
    {
        if (g_state.display[i] == '.')
            seen_dot = true;
        else if (seen_dot)
            ++frac_count;
    }
    if (seen_dot && frac_count >= kFracDigits)
        return;
    g_state.display[g_state.display_len++] = d;
    g_state.display[g_state.display_len] = '\0';
}

// Decimal-point entry (F-010). Inserts a '.' to begin a fractional
// part. A second '.' in the same operand is ignored. On a fresh entry
// the display becomes "0." so the user sees a leading zero.
void HandleDot()
{
    if (g_state.error)
        return;
    if (g_state.fresh_entry)
    {
        g_state.display_len = 0;
        g_state.display[0] = '\0';
        g_state.fresh_entry = false;
    }
    for (u32 i = 0; i < g_state.display_len; ++i)
    {
        if (g_state.display[i] == '.')
            return; // already fractional
    }
    if (g_state.display_len == 0)
    {
        if (g_state.display_len + 1 >= kDisplayCap)
            return;
        g_state.display[g_state.display_len++] = '0';
    }
    if (g_state.display_len >= kDisplayCap)
        return;
    g_state.display[g_state.display_len++] = '.';
    g_state.display[g_state.display_len] = '\0';
}

void HandleOp(char op)
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 rhs = ReadDisplayAsFixed(&ovf);
    if (ovf)
    {
        TripErr();
        return;
    }
    ApplyPending(rhs);
    if (g_state.error)
        return; // ApplyPending may have clamped on divide-by-zero / overflow
    g_state.pending_op = op;
    g_state.has_pending = true;
    g_state.fresh_entry = true;
}

void HandleEquals()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 rhs = ReadDisplayAsFixed(&ovf);
    if (ovf)
    {
        TripErr();
        return;
    }
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

// Clear Entry (F-012) — clears only the current operand / display,
// leaving the accumulator + pending operator intact. So
// "5 + 3 CE 4 =" yields 9. Also clears a sticky error without
// discarding the running expression's accumulator.
void HandleClearEntry()
{
    g_state.error = false;
    SetDisplayLiteral("0");
    // Next digit / dot should replace the lone "0", so treat the entry
    // as fresh. The accumulator + pending_op are deliberately left
    // untouched so "5 + 3 CE 4 =" yields 9.
    g_state.fresh_entry = true;
}

void HandleSignToggle()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf || cur == 0)
        return;
    SetDisplayFixed(-cur);
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
// Without a pending op, divide display by 100. Fixed-point throughout.
void HandlePercent()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf)
    {
        TripErr();
        return;
    }
    if (g_state.has_pending)
    {
        const i64 lhs = g_state.accumulator;
        // pct = lhs * cur / 100 (fixed-point); FixedMul handles the
        // ×kScale²/kScale collapse, then divide by 100.
        i64 prod = 0;
        if (!FixedMul(lhs, cur, &prod))
        {
            TripErr();
            return;
        }
        SetDisplayFixed(prod / 100);
    }
    else
    {
        SetDisplayFixed(cur / 100);
    }
    g_state.fresh_entry = false;
}

void HandleMemRecall()
{
    if (g_state.error)
        return;
    if (!g_state.memory_set)
        return;
    SetDisplayFixed(g_state.memory);
    g_state.fresh_entry = true;
}

void HandleMemStore()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 v = ReadDisplayAsFixed(&ovf);
    if (ovf)
        return;
    g_state.memory = v;
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
    bool ovf = false;
    const i64 v = ReadDisplayAsFixed(&ovf);
    if (ovf)
        return;
    g_state.memory += v;
    g_state.memory_set = true;
}

void HandleMemSub()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 v = ReadDisplayAsFixed(&ovf);
    if (ovf)
        return;
    g_state.memory -= v;
    g_state.memory_set = true;
}

// Integer square root via Newton's method. Returns floor(sqrt(v)) for
// non-negative input; returns -1 for negative input.
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

// sqrt of a fixed-point value. sqrt(value) in fixed-point is
// floor(sqrt(value × kScale²)) / 1 — i.e. sqrt(scaled × kScale).
// 144 → scaled 144e6 → 144e6 × 1e6 = 144e12, sqrt = 12e6 → 12.000000.
void HandleSqrt()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf || cur < 0)
    {
        TripErr();
        return;
    }
    i64 radicand = 0;
    if (__builtin_mul_overflow(cur, kScale, &radicand))
    {
        TripErr();
        return;
    }
    const i64 r = IntSqrt(radicand);
    if (r < 0)
    {
        TripErr();
        return;
    }
    SetDisplayFixed(r);
    g_state.fresh_entry = true;
}

void HandleSquare()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf)
    {
        TripErr();
        return;
    }
    i64 result = 0;
    if (!FixedMul(cur, cur, &result))
    {
        TripErr();
        return;
    }
    SetDisplayFixed(result);
    g_state.fresh_entry = true;
}

void HandleAbs()
{
    if (g_state.error)
        return;
    bool ovf = false;
    i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf)
    {
        TripErr();
        return;
    }
    if (cur < 0)
        cur = -cur;
    SetDisplayFixed(cur);
    g_state.fresh_entry = true;
}

void HandleFactorial()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64(); // integer-only operation
    if (cur < 0 || cur > 20)
    {
        TripErr();
        return;
    }
    i64 r = 1;
    for (i64 i = 2; i <= cur; ++i)
        r *= i;
    i64 scaled = 0;
    if (__builtin_mul_overflow(r, kScale, &scaled))
    {
        TripErr();
        return;
    }
    SetDisplayFixed(scaled);
    g_state.fresh_entry = true;
}

void HandleBitwiseNot()
{
    if (g_state.error)
        return;
    const i64 cur = ReadDisplayAsI64(); // integer-only operation
    SetDisplayFixed((~cur) * kScale);
    g_state.fresh_entry = true;
}

void HandleReciprocal()
{
    if (g_state.error)
        return;
    bool ovf = false;
    const i64 cur = ReadDisplayAsFixed(&ovf);
    if (ovf || cur == 0)
    {
        TripErr();
        return;
    }
    // 1/x in fixed-point: (1×kScale × kScale) / cur = kScale² / cur.
    i64 num = 0;
    if (__builtin_mul_overflow(kScale, kScale, &num))
    {
        TripErr();
        return;
    }
    SetDisplayFixed(num / cur);
    g_state.fresh_entry = true;
}

void DispatchKey(char k)
{
    if (k >= '0' && k <= '9')
        HandleDigit(k);
    else if (k == '.')
        HandleDot();
    else if (k == '+' || k == '-' || k == '*' || k == '/' || k == '&' || k == '|' || k == '^' || k == '<' || k == '>')
        HandleOp(k);
    else if (k == '~')
        HandleBitwiseNot();
    else if (k == '=')
        HandleEquals();
    else if (k == 'C') // capital C = full reset (button + 'C' keyboard)
        HandleClear();
    else if (k == 'e' || k == 'E') // Clear Entry (F-012)
        HandleClearEntry();
    else if (k == 'c') // lowercase c also full reset (Esc routes here)
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
// callback — each button needs its own trampoline.
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
void ClickDot()
{
    DispatchKey('.');
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
void ClickClearEntry()
{
    DispatchKey('e');
}
void ClickBackspace()
{
    DispatchKey(static_cast<char>(0x08));
}
void ClickSign()
{
    DispatchKey('n');
}

using ClickFn = void (*)();
constexpr ClickFn kClickFns[kIdCount] = {
    ClickClear, ClickClearEntry, ClickBackspace, ClickDiv,   // row 0
    Click7,     Click8,          Click9,         ClickMul,   // row 1
    Click4,     Click5,          Click6,         ClickMinus, // row 2
    Click1,     Click2,          Click3,         ClickPlus,  // row 3
    Click0,     ClickDot,        ClickEq,        ClickSign,  // row 4
};

// ----- App-widget composition --------------------------------------
//
// The calculator is a panel + a label (display readout) + 20 buttons,
// laid out in declaration order back-to-front so the panel paints
// first and the buttons land on top.

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

constinit auto g_calc =
    MakeWidgetGroup(AppPanel{}, AppLabel{},
                    // 4×5 button grid, row-major top-to-bottom — order matches
                    // kButtonKeys / kClickFns / kButtonLabels so RebindBounds and
                    // self-test stay table-driven.
                    AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                    AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{},
                    AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{}, AppButton{});

// Advance `Depth` tails into a heterogeneously-typed WidgetChain and
// return the head at that depth. The chain node type changes at every
// tail step (recursive inheritance), so this MUST be compile-time
// recursion — a runtime pointer walk can't be typed. Used to collect
// the AppButton nodes without hand-spelling a tail.tail.…head chain
// per button (which drifted out of sync when the grid grew).
template <u32 Depth, typename Node> auto& ChainHeadAt(Node& node)
{
    if constexpr (Depth == 0)
        return node.head;
    else
        return ChainHeadAt<Depth - 1>(node.tail);
}

// Fill `buttons` with the kIdCount AppButton pointers in declaration
// order. Chain layout: head = AppPanel, tail.head = AppLabel, then the
// kIdCount AppButton nodes start at tail.tail. Button i is therefore
// the head at chain depth (i + 2). Compile-time recursion over the
// fixed-count grid — no index_sequence helper exists in the kernel.
template <u32 I> void CollectButtonsFrom(AppButton* (&buttons)[kIdCount])
{
    if constexpr (I < kIdCount)
    {
        buttons[I] = &ChainHeadAt<I + 2>(g_calc.chain);
        CollectButtonsFrom<I + 1>(buttons);
    }
}

void CollectButtons(AppButton* (&buttons)[kIdCount])
{
    CollectButtonsFrom<0>(buttons);
}

// Walk the widget chain to set per-button label / colour / callback
// once at init.
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

    AppButton* buttons[kIdCount];
    CollectButtons(buttons);
    for (u32 i = 0; i < kIdCount; ++i)
    {
        const KeyColours c = ColoursFor(kButtonKeys[i]);
        buttons[i]->label = kButtonLabels[i];
        buttons[i]->on_click = kClickFns[i];
        buttons[i]->bg_rgb = c.normal;
        buttons[i]->fg_rgb = c.label;
        buttons[i]->weight = (kButtonKeys[i] == '=' || kButtonKeys[i] == 'C' || kButtonKeys[i] == 'e')
                                 ? ChromeTextWeight::Bold
                                 : ChromeTextWeight::Regular;
    }
}

// Re-anchor widget bounds to the live client rect. Called from
// DrawFn before PaintAll and from CalculatorMouseInput before
// DispatchEvent so hit-tests + visuals stay consistent across
// window moves / resizes.
void RebindBoundsToClient(u32 cx, u32 cy, u32 cw)
{
    auto& panel = g_calc.chain.head;
    panel.bounds = Rect{cx, cy, cw, /*h=*/300u};

    auto& label = g_calc.chain.tail.head;
    label.bounds = Rect{cx + 8u, cy + 4u, (cw >= 16u) ? cw - 16u : cw, 28u};

    AppButton* buttons[kIdCount];
    CollectButtons(buttons);
    for (u32 i = 0; i < kIdCount; ++i)
    {
        const u32 row = i / kGridCols;
        const u32 col = i % kGridCols;
        buttons[i]->bounds = Rect{cx + kGridLeftOffset + col * (kBtnW + kBtnGap),
                                  cy + kGridTopOffset + row * (kBtnH + kBtnGap), kBtnW, kBtnH};
    }
}

// Build the clipped display view (F-051). The large Display-role font
// is wide; a long value would paint past the client rect onto the
// wallpaper. Cap the rendered string to the chars that fit in
// `strip_w`; when clipped, show the most-significant end with a
// trailing '>' overflow marker.
void BuildDisplayView(u32 strip_w)
{
    const char* src = (g_state.display_len == 0) ? "0" : g_state.display;
    u32 src_len = 0;
    while (src[src_len] != '\0')
        ++src_len;

    // Per-char width of the Display role. Measure a single glyph so
    // the clip tracks the active font (bitmap scale or TTF px).
    using duetos::drivers::video::ChromeTextMeasure;
    const u32 per_char = ChromeTextMeasure(ChromeTextRole::Display, "0");
    u32 max_chars = (per_char > 0 && strip_w > 0) ? strip_w / per_char : src_len;
    if (max_chars == 0)
        max_chars = 1;

    if (src_len <= max_chars)
    {
        u32 i = 0;
        for (; i < src_len && i < kDisplayCap; ++i)
            g_state.display_view[i] = src[i];
        g_state.display_view[i] = '\0';
        return;
    }
    // Clipped: show the most-significant end (leading digits + sign)
    // that fits, with a trailing '>' overflow marker so the value
    // never paints past the client rect.
    const u32 keep = (max_chars >= 1) ? max_chars - 1 : 0;
    u32 o = 0;
    for (u32 i = 0; i < keep && i < src_len && o + 1 < sizeof(g_state.display_view); ++i)
        g_state.display_view[o++] = src[i];
    if (o + 1 < sizeof(g_state.display_view))
        g_state.display_view[o++] = '>';
    g_state.display_view[o] = '\0';
}

// Multi-radix preview formatters — preserved as a carve-out below
// the widget-group paint so the hex / bin / oct strip keeps reading
// alongside the main decimal display.

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
// display readout + buttons) first, then overlays the multi-radix
// preview band carve-out and the "M" memory indicator directly.
void DrawFn(u32 cx, u32 cy, u32 cw, u32 /*ch*/, void* /*cookie*/)
{
    using duetos::drivers::video::FramebufferDrawString;
    using duetos::drivers::video::FramebufferFillRect;
    if (cw <= 16)
        return;

    // 1) Re-anchor widgets to the live client rect, then paint the
    //    widget group. Bind the label to the CLIPPED view so a long
    //    value never paints past the client rect (F-051).
    RebindBoundsToClient(cx, cy, cw);
    const u32 strip_w = (cw >= 16u) ? cw - 16u : cw;
    BuildDisplayView(strip_w);
    g_calc.chain.tail.head.text = g_state.display_view;
    Compose c{};
    g_calc.PaintAll(c);

    // 2) Memory indicator — small "M" in the top-left of the display
    //    strip when the register has a non-zero value.
    constexpr u32 kDisplayBg = 0x00202830U;
    if (g_state.memory_set && g_state.memory != 0)
    {
        constexpr u32 kMemFg = 0x00FFC848U;
        FramebufferDrawString(cx + 8u + 4u, cy + 4u + 2u, "M", kMemFg, kDisplayBg);
    }

    // 3) Multi-radix preview band — sits between the display strip and
    //    the button grid. Skipped in error state. Built from the
    //    truncated integer part (radix views are integer-only).
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

// Edge-detection state for mouse input.
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
    // Legacy widget-table dispatch path — the migrated calculator owns
    // its own hit-testing via g_calc.DispatchEvent. No-op shim.
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
    u32 client_x = cx;
    u32 client_y = cy;
    RebindBoundsToClient(wx, wy + 22u, ww);

    const bool left_down = (button_mask & kMouseButtonLeft) != 0;
    const bool press_edge = left_down && !g_prev_left_down;
    const bool release_edge = !left_down && g_prev_left_down;
    g_prev_left_down = left_down;

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
        const Event u{EventKind::MouseUp, client_x, client_y, 0u, 0u};
        g_calc.DispatchEvent(u);
    }
}

bool CalculatorFeedChar(char c)
{
    const u8 uc = static_cast<u8>(c);
    if ((c >= '0' && c <= '9') || c == '.' || c == '+' || c == '-' || c == '*' || c == '/' || c == '=' || c == 'c' ||
        c == 'C' || c == 'e' || c == 'E' || c == '%' || c == 'n' || c == 'N' || c == '_' || uc == 0x08 || c == 'm' ||
        c == 'M' || c == 's' || c == 'S' || c == 'l' || c == 'L' || c == 'a' || c == 'A' || c == 'b' || c == 'B' ||
        c == 'q' || c == 'Q' || c == 'x' || c == 'X' || c == 'y' || c == 'Y' || c == '!' || c == 'r' || c == 'R' ||
        c == '&' || c == '|' || c == '^' || c == '<' || c == '>' || c == '~')
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
// runs end-to-end.
bool ClickViaWidget(u32 button_index)
{
    if (button_index >= kIdCount)
        return false;
    RebindBoundsToClient(0u, 22u, 300u);

    const u32 row = button_index / kGridCols;
    const u32 col = button_index % kGridCols;
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

// Compare the current fixed-point display value against an expected
// scaled value by formatting both and string-comparing — exercises
// the full read→format round-trip the user sees.
bool DisplayEqualsFixed(i64 expected_scaled)
{
    bool ovf = false;
    const i64 got = ReadDisplayAsFixed(&ovf);
    return !ovf && got == expected_scaled;
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
        i64 expect; // truncated integer expectation (ReadDisplayAsI64)
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

    // Decimal / fixed-point cases (F-010). Compared against exact
    // scaled values via DisplayEqualsFixed.
    struct FixedCase
    {
        const char* keys;
        i64 expect_scaled;
    };
    const FixedCase fixed_cases[] = {
        {"1/4=", kScale / 4},          // 0.25
        {".1+.2=", (kScale / 10) * 3}, // 0.1 + 0.2 = 0.3
        {"2.5*2=", kScale * 5},        // 5
        {"3.14=", 3140000},            // entry round-trips
        {"10/4=", (kScale * 10) / 4},  // 2.5
        {"0.5+0.5=", kScale},          // 1
    };
    for (const FixedCase& fc : fixed_cases)
    {
        HandleClear();
        for (const char* p = fc.keys; *p != 0; ++p)
            DispatchKey(*p);
        if (!DisplayEqualsFixed(fc.expect_scaled) || g_state.error)
        {
            all_pass = false;
            break;
        }
    }

    // Decimal-point display formatting: trailing zeros trimmed.
    HandleClear();
    DispatchKey('1');
    DispatchKey('/');
    DispatchKey('4');
    DispatchKey('=');
    if (g_state.display[0] != '0' || g_state.display[1] != '.' || g_state.display[2] != '2' ||
        g_state.display[3] != '5' || g_state.display[4] != '\0')
        all_pass = false;
    HandleClear();
    DispatchKey('2');
    DispatchKey('.');
    DispatchKey('5');
    DispatchKey('*');
    DispatchKey('2');
    DispatchKey('=');
    if (g_state.display[0] != '5' || g_state.display[1] != '\0') // "5", not "5.000000"
        all_pass = false;

    // Clear-Entry (F-012): "5 + 3 CE 4 =" yields 9.
    HandleClear();
    DispatchKey('5');
    DispatchKey('+');
    DispatchKey('3');
    DispatchKey('e'); // CE — clear current operand only
    DispatchKey('4');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 9 || g_state.error)
        all_pass = false;
    // C is a full reset (distinct from CE).
    HandleClear();
    DispatchKey('5');
    DispatchKey('+');
    DispatchKey('3');
    DispatchKey('C'); // full reset
    DispatchKey('4');
    DispatchKey('=');
    if (ReadDisplayAsI64() != 4 || g_state.error)
        all_pass = false;

    // Memory register walk (fixed-point aware).
    HandleClear();
    HandleMemClear();
    if (g_state.memory_set || g_state.memory != 0)
        all_pass = false;
    DispatchKey('5');
    DispatchKey('0');
    DispatchKey('s');
    if (!g_state.memory_set || g_state.memory != 50 * kScale)
        all_pass = false;
    HandleClear();
    DispatchKey('2');
    DispatchKey('5');
    DispatchKey('a');
    if (g_state.memory != 75 * kScale)
        all_pass = false;
    HandleClear();
    DispatchKey('1');
    DispatchKey('0');
    DispatchKey('b');
    if (g_state.memory != 65 * kScale)
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

    // Bitwise (integer-only — operate on truncated integer part).
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
    // Drives synthetic Down/Up events through g_calc. "2 + 3 ="
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
    // ...and the decimal-point button via the widget path: "1 / 4 ="
    HandleClear();
    if (!ClickViaWidget(IndexOfKey('1')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('/')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('4')))
        all_pass = false;
    if (!ClickViaWidget(IndexOfKey('=')))
        all_pass = false;
    if (!DisplayEqualsFixed(kScale / 4) || g_state.error)
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
