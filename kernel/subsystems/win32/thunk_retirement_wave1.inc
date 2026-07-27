// kernel32 APIs retired from the legacy kernel thunk table.
//
// The filename is retained because wave 1 introduced the fail-closed
// manifest contract; later retirement waves append to the same source
// of truth instead of creating policy fragments that can drift apart.
//
// This X-macro is the single source of truth for:
//   - the loader's fail-closed policy;
//   - the spawn-time preload contract;
//   - the linked kernel32.dll export verifier; and
//   - fix-journal tooling that must not resurrect retired rows.
//
// Define DUETOS_RETIRED_KERNEL32_IMPORT(name) before including it.
DUETOS_RETIRED_KERNEL32_IMPORT("CreateThread")
DUETOS_RETIRED_KERNEL32_IMPORT("ExitThread")
DUETOS_RETIRED_KERNEL32_IMPORT("FreeLibraryAndExitThread")
DUETOS_RETIRED_KERNEL32_IMPORT("GetExitCodeThread")
DUETOS_RETIRED_KERNEL32_IMPORT("GetCurrentProcess")
DUETOS_RETIRED_KERNEL32_IMPORT("GetCurrentThread")
DUETOS_RETIRED_KERNEL32_IMPORT("GetCurrentProcessId")
DUETOS_RETIRED_KERNEL32_IMPORT("GetCurrentThreadId")
DUETOS_RETIRED_KERNEL32_IMPORT("GetLastError")
DUETOS_RETIRED_KERNEL32_IMPORT("SetLastError")
