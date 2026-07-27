// kernel32 APIs retired from the legacy kernel thunk table in wave 1.
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
