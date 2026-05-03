#include "security/auth.h"

#include "core/panic.h"
#include "log/klog.h"
#include "security/password_hash.h"

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
    a->in_use = true;
    a->role = role;
    SetAccountPassword(a, password);
    StrCopy(a->name, username, kAuthNameMax);
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

} // namespace

void AuthInit()
{
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
    const Account* a = FindAccount(username);
    if (a == nullptr)
    {
        // Burn an equivalent PBKDF2 cycle against the decoy record
        // so an unknown user doesn't respond faster than a bad
        // password against a real user.
        const char* pw = password != nullptr ? password : "";
        (void)duetos::security::PasswordHashVerify(pw, StrLen(pw), g_decoy_record);
        return false;
    }
    return VerifyPasswordOnAccount(a, password);
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
    return StoreAccount(a, username, password, role);
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
    *a = Account{};
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
    return true;
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
    u32 seen = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
        {
            continue;
        }
        if (seen == idx)
        {
            view->username = g_accounts[i].name;
            view->role = g_accounts[i].role;
            view->has_password = g_accounts[i].has_password;
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
    view->username = a->name;
    view->role = a->role;
    view->has_password = a->has_password;
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
    KLOG_INFO("auth", "self-test OK");
}

} // namespace duetos::core
