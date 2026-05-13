#include "security/auth.h"

#include "core/panic.h"
#include "log/klog.h"
#include "security/event_ring.h"
#include "security/password_hash.h"
#include "time/timekeeper.h"

namespace duetos::core
{

namespace
{

struct Account
{
    bool in_use;
    bool has_password;
    AuthRole role;
    duetos::security::PasswordHashRecord record;
    char name[kAuthNameMax];

    // Audit + lockout metadata. All zero-initialised when the slot
    // is allocated; updated on the relevant verify / login paths.
    u64 created_ns;
    u64 last_login_ns;
    u64 last_attempt_ns;
    u64 locked_until_ns;
    u32 failed_attempts;
    u32 total_logins;
};

constinit Account g_accounts[kAuthMaxAccounts] = {};

struct Session
{
    bool active;
    AuthRole role;
    char name[kAuthNameMax];
};

constinit Session g_session = {};

// A "decoy" hash record kept for constant-time verifies against
// inputs that have no real account behind them. PasswordHashVerify
// always runs the full PBKDF2 chain then a constant-time compare,
// so calling it with the decoy burns the same wall-clock as a real
// verify and the return value is discarded. The decoy uses the
// default iteration count, an all-zeros salt, and an all-zeros
// hash; no real password derives to that record (~2^-256). The
// same record is also used to flatten the timing of "this account
// exists but has no password set" — see VerifyPasswordOnAccount.
constinit duetos::security::PasswordHashRecord g_decoy_record = {
    duetos::security::PasswordAlgorithm::Pbkdf2HmacSha256,
    duetos::security::kPasswordDefaultIterations,
    {0},
    {0},
};

u32 StrLen(const char* s)
{
    u32 n = 0;
    while (s != nullptr && s[n] != '\0')
    {
        ++n;
    }
    return n;
}

bool StrEq(const char* a, const char* b)
{
    if (a == nullptr || b == nullptr)
    {
        return false;
    }
    for (u32 i = 0;; ++i)
    {
        if (a[i] != b[i])
        {
            return false;
        }
        if (a[i] == '\0')
        {
            return true;
        }
    }
}

void StrCopy(char* dst, const char* src, u32 cap)
{
    if (dst == nullptr || cap == 0)
    {
        return;
    }
    u32 i = 0;
    for (; i + 1 < cap && src != nullptr && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

// Validate a username / password: printable ASCII, no spaces,
// length within cap. Returns false on any violation.
bool IsValidAuthString(const char* s, u32 cap, bool allow_empty)
{
    if (s == nullptr)
    {
        return false;
    }
    const u32 n = StrLen(s);
    if (n == 0)
    {
        return allow_empty;
    }
    if (n + 1 > cap)
    {
        return false;
    }
    for (u32 i = 0; i < n; ++i)
    {
        const char c = s[i];
        if (c <= 0x20 || c >= 0x7F)
        {
            return false;
        }
    }
    return true;
}

u64 NowNs()
{
    return duetos::time::MonotonicNs();
}

// True iff `a->locked_until_ns` is in the future relative to the
// supplied wall clock. Side effect: if the lockout has expired,
// clear it (and the failed-attempt counter) and publish an
// AuthAccountUnlocked event. The expiry path is intentionally
// inline here so every entry into AuthVerify / AuthIsLocked
// auto-thaws an expired lockout without needing a separate sweep.
bool AccountIsLocked(Account* a, u64 now_ns)
{
    if (a->locked_until_ns == 0)
    {
        return false;
    }
    if (now_ns < a->locked_until_ns)
    {
        return true;
    }
    a->locked_until_ns = 0;
    a->failed_attempts = 0;
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountUnlocked, 0, 0,
                                           static_cast<u64>(a->role), a->name);
    return false;
}

// Set the (possibly empty) password on an account slot. Empty
// password ⇒ has_password = false and the record is zeroed; the
// account can be logged into by supplying an empty password (the
// guest seed relies on this). Non-empty password ⇒ a fresh
// PBKDF2-HMAC-SHA256 record is derived through the kernel entropy
// pool's salt and the default iteration count.
void SetAccountPassword(Account* a, const char* password)
{
    const u32 pw_len = StrLen(password);
    if (pw_len == 0)
    {
        a->has_password = false;
        a->record = duetos::security::PasswordHashRecord{};
        return;
    }
    duetos::security::PasswordHashCreate(password, pw_len, &a->record);
    a->has_password = true;
}

// Verify a supplied password against an existing account in
// constant-ish time. Always performs a full PBKDF2 derivation
// (against the account record if one exists, against the decoy
// otherwise) so "wrong password" and "no password set, caller
// supplied a non-empty password" take the same wall-clock.
bool VerifyPasswordOnAccount(const Account* a, const char* password)
{
    const char* pw = password != nullptr ? password : "";
    const u32 pw_len = StrLen(pw);
    const bool pbkdf2_match =
        duetos::security::PasswordHashVerify(pw, pw_len, a->has_password ? a->record : g_decoy_record);
    if (a->has_password)
    {
        return pbkdf2_match;
    }
    // The PBKDF2 result is intentionally discarded for no-password
    // accounts — only an empty supplied password authenticates.
    (void)pbkdf2_match;
    return pw_len == 0;
}

Account* FindAccount(const char* username)
{
    if (username == nullptr)
    {
        return nullptr;
    }
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use && StrEq(g_accounts[i].name, username))
        {
            return &g_accounts[i];
        }
    }
    return nullptr;
}

Account* AllocAccount()
{
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
        {
            return &g_accounts[i];
        }
    }
    return nullptr;
}

bool StoreAccount(Account* a, const char* username, const char* password, AuthRole role)
{
    *a = Account{};
    a->in_use = true;
    a->role = role;
    SetAccountPassword(a, password);
    StrCopy(a->name, username, kAuthNameMax);
    a->created_ns = NowNs();
    return true;
}

u32 CountAdmins()
{
    u32 n = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use && g_accounts[i].role == AuthRole::Admin)
        {
            ++n;
        }
    }
    return n;
}

void PopulateView(const Account* a, u64 now_ns, AccountView* view)
{
    view->username = a->name;
    view->role = a->role;
    view->has_password = a->has_password;
    view->locked = a->locked_until_ns != 0 && now_ns < a->locked_until_ns;
    view->created_ns = a->created_ns;
    view->last_login_ns = a->last_login_ns;
    view->last_attempt_ns = a->last_attempt_ns;
    view->locked_until_ns = a->locked_until_ns;
    view->failed_attempts = a->failed_attempts;
    view->total_logins = a->total_logins;
}

} // namespace

void AuthInit()
{
    // Re-anchor the decoy record's iteration count to the runtime
    // value of PasswordDefaultIterations(). The constinit
    // initializer hard-codes kPasswordDefaultIterations (the
    // production 100 000) because constinit needs a compile-time
    // constant; PasswordDefaultIterations() is a runtime function
    // that returns kPasswordEmulatorIterations (1 000) under any
    // VMM. Without this re-anchor every "unknown account" or
    // "no-password account" verify burns the production budget
    // even on emulators — which is the path the auth self-test
    // takes (`AuthVerify("nobody", "x")`) and the path that wedged
    // the Bochs row of diff-boot-smoke (~10× longer per call).
    g_decoy_record.iterations = duetos::security::PasswordDefaultIterations();

    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        g_accounts[i] = {};
    }
    g_session = {};
    Account* a = AllocAccount();
    StoreAccount(a, "admin", "admin", AuthRole::Admin);
    a = AllocAccount();
    StoreAccount(a, "guest", "", AuthRole::Guest);
    KLOG_INFO("auth", "seeded default accounts (admin, guest) — PBKDF2-HMAC-SHA256 hashed");
}

bool AuthIsAuthenticated()
{
    return g_session.active;
}

const char* AuthCurrentUserName()
{
    return g_session.active ? g_session.name : "";
}

AuthRole AuthCurrentRole()
{
    return g_session.active ? g_session.role : AuthRole::Guest;
}

bool AuthIsAdmin()
{
    return g_session.active && g_session.role == AuthRole::Admin;
}

bool AuthVerify(const char* username, const char* password)
{
    namespace sec = duetos::security;
    const u64 now_ns = NowNs();
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        // Burn an equivalent PBKDF2 cycle against the decoy record
        // so an unknown user doesn't respond faster than a bad
        // password against a real user.
        const char* pw = password != nullptr ? password : "";
        (void)sec::PasswordHashVerify(pw, StrLen(pw), g_decoy_record);
        sec::EventRingPublishKind(sec::EventKind::AuthLoginFailure, 0, 0, 0, username != nullptr ? username : "");
        return false;
    }

    a->last_attempt_ns = now_ns;

    // Locked-out account: still burn a PBKDF2 cycle so the wall
    // clock doesn't betray the lock state, then refuse.
    if (AccountIsLocked(a, now_ns))
    {
        const char* pw = password != nullptr ? password : "";
        (void)sec::PasswordHashVerify(pw, StrLen(pw), g_decoy_record);
        sec::EventRingPublishKind(sec::EventKind::AuthLoginFailure, 0, 1 /*locked*/, 0, a->name);
        return false;
    }

    if (!VerifyPasswordOnAccount(a, password))
    {
        if (a->failed_attempts < 0xFFFFFFFFu)
        {
            ++a->failed_attempts;
        }
        if (a->failed_attempts >= kAuthLockoutThreshold && a->locked_until_ns == 0)
        {
            a->locked_until_ns = now_ns + kAuthLockoutDurationNs;
            sec::EventRingPublishKind(sec::EventKind::AuthAccountLocked, 0, a->failed_attempts, kAuthLockoutDurationNs,
                                      a->name);
            KLOG_WARN("auth", "account locked (consecutive failures)");
        }
        sec::EventRingPublishKind(sec::EventKind::AuthLoginFailure, 0, 0, a->failed_attempts, a->name);
        return false;
    }

    a->failed_attempts = 0;
    a->last_login_ns = now_ns;
    if (a->total_logins < 0xFFFFFFFFu)
    {
        ++a->total_logins;
    }
    sec::EventRingPublishKind(sec::EventKind::AuthLoginSuccess, 0, static_cast<u64>(a->role), a->total_logins, a->name);
    return true;
}

bool AuthLogin(const char* username, const char* password)
{
    if (!AuthVerify(username, password))
    {
        return false;
    }
    const Account* a = FindAccount(username);
    g_session.active = true;
    g_session.role = a->role;
    StrCopy(g_session.name, a->name, kAuthNameMax);
    KLOG_INFO("auth", "session begin");
    return true;
}

void AuthLogout()
{
    if (!g_session.active)
    {
        return;
    }
    g_session.active = false;
    g_session.name[0] = '\0';
    g_session.role = AuthRole::Guest;
    KLOG_INFO("auth", "session end");
}

bool AuthAddUser(const char* username, const char* password, AuthRole role)
{
    if (!IsValidAuthString(username, kAuthNameMax, false))
    {
        return false;
    }
    if (!IsValidAuthString(password, kAuthPasswordMax, true))
    {
        return false;
    }
    if (FindAccount(username) != nullptr)
    {
        return false;
    }
    Account* a = AllocAccount();
    if (a == nullptr)
    {
        return false;
    }
    StoreAccount(a, username, password, role);
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountCreated, 0, static_cast<u64>(role),
                                           a->has_password ? 1 : 0, a->name);
    return true;
}

bool AuthDeleteUser(const char* username)
{
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    if (a->role == AuthRole::Admin && CountAdmins() <= 1)
    {
        return false;
    }
    const bool was_session_user = g_session.active && StrEq(g_session.name, a->name);
    char name_copy[kAuthNameMax];
    StrCopy(name_copy, a->name, kAuthNameMax);
    const AuthRole role = a->role;
    *a = Account{};
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountDeleted, 0, static_cast<u64>(role),
                                           0, name_copy);
    if (was_session_user)
    {
        AuthLogout();
    }
    return true;
}

bool AuthChangePassword(const char* username, const char* old_password, const char* new_password)
{
    if (!IsValidAuthString(new_password, kAuthPasswordMax, true))
    {
        return false;
    }
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    if (old_password != nullptr)
    {
        if (!VerifyPasswordOnAccount(a, old_password))
        {
            return false;
        }
    }
    SetAccountPassword(a, new_password);
    // Password change is a clean slate: zero the failure counter
    // and lift any standing lockout. A user who just demonstrated
    // they hold the old password (self-service) or an admin who
    // just force-reset deserves a working account.
    a->failed_attempts = 0;
    a->locked_until_ns = 0;
    duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthPasswordChanged, 0,
                                           old_password != nullptr ? 0 : 1 /*forced*/, a->has_password ? 1 : 0,
                                           a->name);
    return true;
}

bool AuthUnlockUser(const char* username)
{
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    const bool was_locked = a->locked_until_ns != 0;
    a->failed_attempts = 0;
    a->locked_until_ns = 0;
    if (was_locked)
    {
        duetos::security::EventRingPublishKind(duetos::security::EventKind::AuthAccountUnlocked, 0, 1 /*manual*/,
                                               static_cast<u64>(a->role), a->name);
    }
    return true;
}

bool AuthIsLocked(const char* username)
{
    Account* a = FindAccount(username);
    if (a == nullptr)
    {
        return false;
    }
    return AccountIsLocked(a, NowNs());
}

u32 AuthAccountCount()
{
    u32 n = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (g_accounts[i].in_use)
        {
            ++n;
        }
    }
    return n;
}

bool AuthAccountAt(u32 idx, AccountView* view)
{
    if (view == nullptr)
    {
        return false;
    }
    const u64 now_ns = NowNs();
    u32 seen = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
        {
            continue;
        }
        if (seen == idx)
        {
            PopulateView(&g_accounts[i], now_ns, view);
            return true;
        }
        ++seen;
    }
    return false;
}

bool AuthAccountByName(const char* username, AccountView* view)
{
    const Account* a = FindAccount(username);
    if (a == nullptr || view == nullptr)
    {
        return false;
    }
    PopulateView(a, NowNs(), view);
    return true;
}

void AuthSelfTest()
{
    if (!AuthVerify("admin", "admin"))
    {
        Panic("auth", "self-test: seeded admin/admin rejected");
    }
    if (AuthVerify("admin", "wrong"))
    {
        Panic("auth", "self-test: wrong password for admin accepted");
    }
    if (AuthVerify("nobody", "x"))
    {
        Panic("auth", "self-test: unknown account accepted");
    }
    if (!AuthVerify("guest", ""))
    {
        Panic("auth", "self-test: empty password for guest rejected");
    }
    if (AuthVerify("guest", "x"))
    {
        Panic("auth", "self-test: non-empty password accepted for empty-password guest");
    }
    AccountView v{};
    if (!AuthAccountByName("admin", &v) || !v.has_password)
    {
        Panic("auth", "self-test: admin account view missing has_password");
    }
    if (!AuthAccountByName("guest", &v) || v.has_password)
    {
        Panic("auth", "self-test: guest account view reports has_password");
    }

    // Lockout state machine: drive a probe account through the
    // threshold, confirm it locks, confirm AuthUnlockUser releases
    // it, confirm a successful verify after unlock zeros the
    // failure counter.
    if (!AuthAddUser("probe", "p4ss", AuthRole::User))
    {
        Panic("auth", "self-test: failed to seed probe account");
    }
    for (u32 i = 0; i < kAuthLockoutThreshold; ++i)
    {
        if (AuthVerify("probe", "wrong"))
        {
            Panic("auth", "self-test: probe accepted wrong password during lockout drive");
        }
    }
    if (!AuthIsLocked("probe"))
    {
        Panic("auth", "self-test: probe failed to lock after threshold");
    }
    if (AuthVerify("probe", "p4ss"))
    {
        Panic("auth", "self-test: locked probe accepted correct password");
    }
    if (!AuthUnlockUser("probe"))
    {
        Panic("auth", "self-test: AuthUnlockUser refused known account");
    }
    if (AuthIsLocked("probe"))
    {
        Panic("auth", "self-test: probe still reports locked after unlock");
    }
    if (!AuthVerify("probe", "p4ss"))
    {
        Panic("auth", "self-test: unlocked probe rejected correct password");
    }
    if (!AuthAccountByName("probe", &v) || v.failed_attempts != 0 || v.total_logins == 0)
    {
        Panic("auth", "self-test: probe metadata wrong after success");
    }
    if (!AuthDeleteUser("probe"))
    {
        Panic("auth", "self-test: failed to delete probe account");
    }

    KLOG_INFO("auth", "self-test OK");
}

} // namespace duetos::core
