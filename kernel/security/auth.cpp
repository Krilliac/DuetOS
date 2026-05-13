#include "security/auth.h"

#include "core/panic.h"
#include "log/klog.h"
#include "security/event_ring.h"
#include "security/password_hash.h"
#include "security/persistence.h"
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
    duetos::security::PasswordHashRecordV2 record;
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

// A "decoy" V2 record kept for constant-time verifies against
// inputs that have no real account behind them. PasswordHashVerifyV2
// always runs the full KDF chain then a constant-time compare, so
// calling it with the decoy burns the same wall-clock as a real
// verify and the return value is discarded. The decoy is PBKDF2 —
// not Argon2id — so the decoy path costs PBKDF2-iterations CPU
// rather than an Argon2id memory allocation per unknown-user verify,
// which keeps boot self-test wall-clock predictable and avoids
// kheap churn on the brute-force probe loop.
//
// AuthInit re-anchors the iteration count to the runtime
// PasswordDefaultIterations() (emulator vs production); the
// constinit initialiser uses the production value at compile time
// because constinit needs a constant.
constinit duetos::security::PasswordHashRecordV2 g_decoy_record = {
    duetos::security::kPasswordRecordV2Version,
    duetos::security::PasswordAlgorithm::Pbkdf2HmacSha256,
    {0}, // salt
    {0}, // hash
    {{duetos::security::kPasswordDefaultIterations, {0, 0, 0}}},
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
// Argon2id record is derived (V2 default; see password_hash.cpp's
// PasswordHashCreateV2). PBKDF2 fallback fires only when Argon2id
// can't run (KMalloc exhaustion under heavy heap pressure).
void SetAccountPassword(Account* a, const char* password)
{
    const u32 pw_len = StrLen(password);
    if (pw_len == 0)
    {
        a->has_password = false;
        a->record = duetos::security::PasswordHashRecordV2{};
        return;
    }
    duetos::security::PasswordHashCreateV2(password, pw_len, &a->record);
    a->has_password = true;
}

// Verify a supplied password against an existing account in
// constant-ish time. Always performs a full KDF derivation
// (against the account record if one exists, against the decoy
// otherwise) so "wrong password" and "no password set, caller
// supplied a non-empty password" take the same wall-clock.
//
// The decoy is PBKDF2-tagged. A no-password account also routes to
// the decoy on a non-empty supplied password, again to keep the
// wall-clock indistinguishable.
bool VerifyPasswordOnAccount(const Account* a, const char* password)
{
    const char* pw = password != nullptr ? password : "";
    const u32 pw_len = StrLen(pw);
    const bool kdf_match =
        duetos::security::PasswordHashVerifyV2(pw, pw_len, a->has_password ? a->record : g_decoy_record);
    if (a->has_password)
    {
        return kdf_match;
    }
    // The KDF result is intentionally discarded for no-password
    // accounts — only an empty supplied password authenticates.
    (void)kdf_match;
    return pw_len == 0;
}

// Lazy-migration: if the account's stored record is the older
// PBKDF2 algorithm tag, re-hash with the current default
// (Argon2id) and overwrite. Called on a successful verify when
// we still hold the plaintext password. Skipped silently if the
// record is already Argon2id.
//
// "Lazy" because the upgrade only happens on a successful
// authenticated touch — never on a wrong-password path (which
// has nothing to hash with) and never proactively without a
// plaintext password (which would require holding the user's
// password in memory between logins).
void MaybeUpgradeHash(Account* a, const char* password)
{
    if (!a->has_password)
        return;
    if (a->record.algorithm == duetos::security::PasswordAlgorithm::Argon2id)
        return;
    const u32 pw_len = StrLen(password);
    if (pw_len == 0)
        return;
    duetos::security::PasswordHashCreateV2(password, pw_len, &a->record);
    // PasswordHashCreateV2 sets algorithm = Argon2id on success
    // (or back to PBKDF2 on a KMalloc-failure fallback). We
    // accept either outcome silently — the record is still
    // valid; a future successful verify will retry the upgrade.
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
    // Re-anchor the PBKDF2 decoy iteration count to the runtime
    // value of PasswordDefaultIterations(). The constinit
    // initialiser hard-codes the production count because constinit
    // needs a compile-time constant; the runtime function returns
    // the cheaper emulator count under any VMM. Without this
    // re-anchor every "unknown account" or "no-password account"
    // verify burns the production budget even on emulators.
    g_decoy_record.params.pbkdf2.iterations = duetos::security::PasswordDefaultIterations();

    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        g_accounts[i] = {};
    }
    g_session = {};
    Account* a = AllocAccount();
    StoreAccount(a, "admin", "admin", AuthRole::Admin);
    a = AllocAccount();
    StoreAccount(a, "guest", "", AuthRole::Guest);
    KLOG_INFO("auth", "seeded default accounts (admin, guest) — V2 records, Argon2id default");
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
        // Burn an equivalent KDF cycle against the decoy record so
        // an unknown user doesn't respond faster than a bad password
        // against a real user. The decoy is PBKDF2 (no Argon2id heap
        // allocation per probe), which gives a stable wall-clock for
        // the brute-force probe without serialising on the kheap.
        const char* pw = password != nullptr ? password : "";
        (void)sec::PasswordHashVerifyV2(pw, StrLen(pw), g_decoy_record);
        sec::EventRingPublishKind(sec::EventKind::AuthLoginFailure, 0, 0, 0, username != nullptr ? username : "");
        return false;
    }

    a->last_attempt_ns = now_ns;

    // Locked-out account: still burn a KDF cycle so the wall clock
    // doesn't betray the lock state, then refuse.
    if (AccountIsLocked(a, now_ns))
    {
        const char* pw = password != nullptr ? password : "";
        (void)sec::PasswordHashVerifyV2(pw, StrLen(pw), g_decoy_record);
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

    // Successful verify. Pull the lazy-migration trigger: if the
    // stored record is the older PBKDF2 algorithm tag (legacy from
    // an imported snapshot or a previous kernel's seed), re-hash
    // with the current default (Argon2id) and overwrite. We have
    // the plaintext password here — the only place in the kernel
    // where we do — so this is the only safe spot to do the
    // upgrade. See wiki/security/Persistence.md "Lazy migration".
    MaybeUpgradeHash(a, password);

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

// ---------------------------------------------------------------------
// Persistence bridge — see auth.h header comments and
// wiki/security/Persistence.md.
//
// On-disk record format (snapshot v1):
//
//   struct AccountSnapshotRecord {
//     u8  name[kAuthNameMax];        // 32, NUL-padded
//     u8  role;                       //  1, AuthRole
//     u8  has_password;               //  1, 0/1
//     u8  reserved[2];                //  2, zero
//     PasswordHashRecordV2 record;    // 72, algorithm-tagged KDF record
//     u64 created_ns;                 //  8
//     u64 last_login_ns;              //  8
//     u64 last_attempt_ns;            //  8
//     u64 locked_until_ns;            //  8
//     u32 failed_attempts;            //  4
//     u32 total_logins;               //  4
//   };  // 32 + 1 + 1 + 2 + 72 + 8*4 + 4*2 = 148 bytes
//
// Records with `name[0] == '\0'` are not encoded (the table is
// sparse — empty slots are skipped on write, allocated freshly on
// read). `record_count` in the envelope reflects the number of
// in-use slots at write time.
//
// The persistence-envelope record_size field carries the 148-byte
// stamp so a future format bump can be detected on read.
// ---------------------------------------------------------------------

namespace
{

constexpr u32 kAccountSnapshotRecordBytes = 148;
static_assert(kAuthNameMax == 32, "AccountSnapshotRecord layout assumes name=32");
static_assert(sizeof(duetos::security::PasswordHashRecordV2) == 72,
              "AccountSnapshotRecord layout assumes V2 record=72");

void StoreU32LE(u8* p, u32 v)
{
    p[0] = static_cast<u8>(v);
    p[1] = static_cast<u8>(v >> 8);
    p[2] = static_cast<u8>(v >> 16);
    p[3] = static_cast<u8>(v >> 24);
}

void StoreU64LE(u8* p, u64 v)
{
    for (u32 i = 0; i < 8; ++i)
        p[i] = static_cast<u8>(v >> (8u * i));
}

u32 LoadU32LE(const u8* p)
{
    return static_cast<u32>(p[0]) | (static_cast<u32>(p[1]) << 8) | (static_cast<u32>(p[2]) << 16) |
           (static_cast<u32>(p[3]) << 24);
}

u64 LoadU64LE(const u8* p)
{
    u64 v = 0;
    for (u32 i = 0; i < 8; ++i)
        v |= static_cast<u64>(p[i]) << (8u * i);
    return v;
}

void EncodeAccount(const Account& a, u8 out[kAccountSnapshotRecordBytes])
{
    for (u32 i = 0; i < kAccountSnapshotRecordBytes; ++i)
        out[i] = 0;
    for (u32 i = 0; i < kAuthNameMax; ++i)
        out[i] = static_cast<u8>(a.name[i]);
    out[kAuthNameMax + 0] = static_cast<u8>(a.role);
    out[kAuthNameMax + 1] = a.has_password ? 1u : 0u;
    // [+2..+3] reserved.
    u32 off = kAuthNameMax + 4;
    // PasswordHashRecordV2: version(4) + algorithm(4) + salt(16) + hash(32) + params(16) = 72.
    StoreU32LE(out + off, a.record.version);
    off += 4;
    StoreU32LE(out + off, static_cast<u32>(a.record.algorithm));
    off += 4;
    for (u32 i = 0; i < duetos::security::kPasswordSaltBytes; ++i)
        out[off + i] = a.record.salt[i];
    off += duetos::security::kPasswordSaltBytes;
    for (u32 i = 0; i < duetos::security::kPasswordHashBytes; ++i)
        out[off + i] = a.record.hash[i];
    off += duetos::security::kPasswordHashBytes;
    // Union: 16 bytes. We serialise the raw 16 bytes regardless of
    // which arm is live; the algorithm tag above tells the reader
    // how to interpret them.
    const u8* params_bytes = reinterpret_cast<const u8*>(&a.record.params);
    for (u32 i = 0; i < 16; ++i)
        out[off + i] = params_bytes[i];
    off += 16;
    // Metadata.
    StoreU64LE(out + off, a.created_ns);
    off += 8;
    StoreU64LE(out + off, a.last_login_ns);
    off += 8;
    StoreU64LE(out + off, a.last_attempt_ns);
    off += 8;
    StoreU64LE(out + off, a.locked_until_ns);
    off += 8;
    StoreU32LE(out + off, a.failed_attempts);
    off += 4;
    StoreU32LE(out + off, a.total_logins);
    off += 4;
    KASSERT(off == kAccountSnapshotRecordBytes, "auth/persist", "record encoder size drift");
}

void DecodeAccount(const u8 in[kAccountSnapshotRecordBytes], Account& a)
{
    a = Account{};
    a.in_use = true;
    for (u32 i = 0; i < kAuthNameMax; ++i)
        a.name[i] = static_cast<char>(in[i]);
    a.role = static_cast<AuthRole>(in[kAuthNameMax + 0]);
    a.has_password = (in[kAuthNameMax + 1] != 0);
    u32 off = kAuthNameMax + 4;
    a.record.version = LoadU32LE(in + off);
    off += 4;
    a.record.algorithm = static_cast<duetos::security::PasswordAlgorithm>(LoadU32LE(in + off));
    off += 4;
    for (u32 i = 0; i < duetos::security::kPasswordSaltBytes; ++i)
        a.record.salt[i] = in[off + i];
    off += duetos::security::kPasswordSaltBytes;
    for (u32 i = 0; i < duetos::security::kPasswordHashBytes; ++i)
        a.record.hash[i] = in[off + i];
    off += duetos::security::kPasswordHashBytes;
    u8* params_bytes = reinterpret_cast<u8*>(&a.record.params);
    for (u32 i = 0; i < 16; ++i)
        params_bytes[i] = in[off + i];
    off += 16;
    a.created_ns = LoadU64LE(in + off);
    off += 8;
    a.last_login_ns = LoadU64LE(in + off);
    off += 8;
    a.last_attempt_ns = LoadU64LE(in + off);
    off += 8;
    a.locked_until_ns = LoadU64LE(in + off);
    off += 8;
    a.failed_attempts = LoadU32LE(in + off);
    off += 4;
    a.total_logins = LoadU32LE(in + off);
    off += 4;
    KASSERT(off == kAccountSnapshotRecordBytes, "auth/persist", "record decoder size drift");
}

u32 CountActiveAccounts()
{
    u32 n = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
        if (g_accounts[i].in_use)
            ++n;
    return n;
}

} // namespace

u32 AuthSnapshotEncodedSize()
{
    const u32 n = CountActiveAccounts();
    if (n == 0)
        return 0;
    return duetos::security::PersistenceEncodedSize(n, kAccountSnapshotRecordBytes);
}

bool AuthExportSnapshot(const char* password, const AuthSnapshotParams& params, u8* out, u32 out_capacity, u32* out_len)
{
    if (password == nullptr || out == nullptr)
        return false;
    const u32 pw_len = StrLen(password);
    if (pw_len == 0)
        return false;
    const u32 n = CountActiveAccounts();
    if (n == 0)
        return false;
    // Pack each in-use slot.
    u8 plain[kAuthMaxAccounts * kAccountSnapshotRecordBytes];
    u32 idx = 0;
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
    {
        if (!g_accounts[i].in_use)
            continue;
        EncodeAccount(g_accounts[i], plain + idx * kAccountSnapshotRecordBytes);
        ++idx;
    }
    duetos::security::PersistenceParams pp{};
    pp.memory_kib = params.memory_kib;
    pp.time_cost = params.time_cost;
    pp.parallelism = params.parallelism;
    return duetos::security::PersistenceEncode(plain, n, kAccountSnapshotRecordBytes, password, pw_len, pp, out,
                                               out_capacity, out_len);
}

bool AuthImportSnapshot(const char* password, const u8* in, u32 in_len)
{
    if (password == nullptr || in == nullptr)
        return false;
    const u32 pw_len = StrLen(password);
    if (pw_len == 0)
        return false;
    u8 plain[kAuthMaxAccounts * kAccountSnapshotRecordBytes];
    u32 record_count = 0;
    u32 record_size = 0;
    if (!duetos::security::PersistenceDecode(in, in_len, password, pw_len, plain, sizeof(plain), &record_count,
                                             &record_size))
        return false;
    if (record_size != kAccountSnapshotRecordBytes)
        return false;
    if (record_count == 0 || record_count > kAuthMaxAccounts)
        return false;
    // Atomic replace: decode into a scratch table first; only swap
    // in on success of every record.
    Account scratch[kAuthMaxAccounts] = {};
    for (u32 i = 0; i < record_count; ++i)
    {
        DecodeAccount(plain + i * kAccountSnapshotRecordBytes, scratch[i]);
    }
    // Commit.
    for (u32 i = 0; i < kAuthMaxAccounts; ++i)
        g_accounts[i] = scratch[i];
    g_session = {};
    return true;
}

void AuthSnapshotSelfTest()
{
    // Seed-state has admin/guest already (AuthInit ran). Add a
    // probe slot so we can tell whether import reverted a runtime
    // mutation.
    KASSERT(AuthAddUser("snapseed", "snapseed-pw", AuthRole::User), "auth/snapshot",
            "self-test: failed to seed snapseed");

    // Export.
    AuthSnapshotParams params{};
    params.memory_kib = 32;
    params.time_cost = 2;
    params.parallelism = 1;
    u8 envelope[4096];
    u32 written = 0;
    KASSERT(AuthExportSnapshot("snap-password", params, envelope, sizeof(envelope), &written), "auth/snapshot",
            "self-test: export failed");
    KASSERT(written > 0 && written <= sizeof(envelope), "auth/snapshot", "self-test: export wrote bogus length");

    // Mutate live table: delete snapseed, add a different account.
    KASSERT(AuthDeleteUser("snapseed"), "auth/snapshot", "self-test: failed to delete snapseed");
    KASSERT(AuthAddUser("postsnap", "postsnap-pw", AuthRole::User), "auth/snapshot",
            "self-test: failed to add postsnap");
    AccountView v{};
    KASSERT(AuthAccountByName("postsnap", &v), "auth/snapshot", "self-test: postsnap missing pre-import");
    KASSERT(!AuthAccountByName("snapseed", &v), "auth/snapshot", "self-test: snapseed should be gone pre-import");

    // Import — should restore the pre-mutation state.
    KASSERT(AuthImportSnapshot("snap-password", envelope, written), "auth/snapshot",
            "self-test: import rejected its own envelope");
    KASSERT(AuthAccountByName("snapseed", &v), "auth/snapshot", "self-test: snapseed missing post-import");
    KASSERT(!AuthAccountByName("postsnap", &v), "auth/snapshot",
            "self-test: postsnap survived import (mutation not reverted)");
    KASSERT(AuthVerify("snapseed", "snapseed-pw"), "auth/snapshot",
            "self-test: snapseed Argon2id record didn't round-trip through snapshot");
    KASSERT(AuthVerify("admin", "admin"), "auth/snapshot", "self-test: admin defaults didn't round-trip");

    // Wrong password rejects.
    KASSERT(!AuthImportSnapshot("wrong-password", envelope, written), "auth/snapshot",
            "self-test: wrong password accepted on import");

    // Tampered envelope rejects.
    {
        u8 bad[sizeof(envelope)];
        for (u32 i = 0; i < written; ++i)
            bad[i] = envelope[i];
        bad[written - 1] ^= 0x01;
        KASSERT(!AuthImportSnapshot("snap-password", bad, written), "auth/snapshot",
                "self-test: tampered envelope accepted on import");
    }

    // Cleanup — restore the canonical seed state so subsequent
    // tests see what AuthInit produced.
    KASSERT(AuthDeleteUser("snapseed"), "auth/snapshot", "self-test: cleanup delete failed");

    KLOG_INFO("auth", "snapshot self-test OK");
}

void AuthLazyMigrationSelfTest()
{
    namespace sec = duetos::security;
    // Seed a probe with the default (Argon2id) path so the slot
    // and metadata exist, then surgically replace the record with
    // a PBKDF2-tagged V2 record that hashes the same plaintext
    // password. This simulates a record imported from a legacy
    // V1 / V2-PBKDF2 snapshot.
    const char* pw = "lazy-up-pw";
    const u32 pw_len = StrLen(pw);
    KASSERT(AuthAddUser("lazyprobe", pw, AuthRole::User), "auth/lazy-migrate", "self-test: failed to add lazyprobe");

    Account* a = FindAccount("lazyprobe");
    KASSERT(a != nullptr, "auth/lazy-migrate", "self-test: probe missing post-add");

    // Overwrite with a PBKDF2 V2 record. PasswordHashCreateExplicit
    // / Pbkdf2HmacSha256 isn't directly exposed for V2 records, so
    // we construct it manually: same plaintext + a fresh salt,
    // PBKDF2 with the runtime default iteration count.
    {
        sec::PasswordHashRecordV2 legacy{};
        legacy.version = sec::kPasswordRecordV2Version;
        legacy.algorithm = sec::PasswordAlgorithm::Pbkdf2HmacSha256;
        // Use a deterministic salt for reproducibility in case the
        // self-test ever diffs on output.
        for (u32 i = 0; i < sec::kPasswordSaltBytes; ++i)
            legacy.salt[i] = static_cast<u8>(0xC0 ^ i);
        legacy.params.pbkdf2.iterations = sec::PasswordDefaultIterations();
        for (u32 i = 0; i < 3; ++i)
            legacy.params.pbkdf2.reserved[i] = 0;
        // Re-derive the hash so the record verifies against `pw`.
        // We have access to the V1 PBKDF2 helper via password_hash.h
        // semantics: the V2 PBKDF2 arm of PasswordHashVerifyV2 calls
        // crypto::Pbkdf2HmacSha256 with the same shape. To keep this
        // self-test free of crypto/pbkdf2.h includes we re-use the
        // V2 create path with a temporary record:
        sec::PasswordHashRecord v1{};
        v1.algorithm = sec::PasswordAlgorithm::Pbkdf2HmacSha256;
        v1.iterations = legacy.params.pbkdf2.iterations;
        for (u32 i = 0; i < sec::kPasswordSaltBytes; ++i)
            v1.salt[i] = legacy.salt[i];
        // PasswordHashCreateExplicit derives v1.hash from password +
        // salt + iterations. We then mirror it into the V2 record.
        sec::PasswordHashCreateExplicit(pw, pw_len, legacy.salt, legacy.params.pbkdf2.iterations, &v1);
        for (u32 i = 0; i < sec::kPasswordHashBytes; ++i)
            legacy.hash[i] = v1.hash[i];
        a->record = legacy;
    }
    KASSERT(a->record.algorithm == sec::PasswordAlgorithm::Pbkdf2HmacSha256, "auth/lazy-migrate",
            "self-test: failed to inject PBKDF2 record");

    // Sanity: the injected PBKDF2 record actually verifies against
    // the correct password (so the upgrade trigger fires for the
    // right reason).
    KASSERT(VerifyPasswordOnAccount(a, pw), "auth/lazy-migrate",
            "self-test: injected PBKDF2 record failed direct verify");

    // Drive the upgrade through AuthVerify. AuthVerify on the
    // success branch calls MaybeUpgradeHash, which re-hashes with
    // Argon2id and overwrites a->record.
    KASSERT(AuthVerify("lazyprobe", pw), "auth/lazy-migrate", "self-test: AuthVerify rejected pre-upgrade record");
    KASSERT(a->record.algorithm == sec::PasswordAlgorithm::Argon2id, "auth/lazy-migrate",
            "self-test: record algorithm did NOT flip to Argon2id after successful verify");

    // After the flip, the same password should still verify (now
    // through the Argon2id arm).
    KASSERT(AuthVerify("lazyprobe", pw), "auth/lazy-migrate", "self-test: post-upgrade Argon2id record didn't verify");
    // Wrong password still rejects.
    KASSERT(!AuthVerify("lazyprobe", "wrong"), "auth/lazy-migrate",
            "self-test: post-upgrade record accepted wrong password");

    // Cleanup.
    KASSERT(AuthDeleteUser("lazyprobe"), "auth/lazy-migrate", "self-test: cleanup delete failed");

    KLOG_INFO("auth", "lazy-migration self-test OK");
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
