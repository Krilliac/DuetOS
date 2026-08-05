# Native syscall policy inventory

_Generated from `abi/native_syscalls.json`; do not edit by hand._

| # | Symbol | Authorization | Object rights | Trace | Fuzz | Arguments |
| ---: | --- | --- | --- | --- | --- | --- |
| 0 | `SYS_EXIT` | dynamic | none | system | scalar | none |
| 1 | `SYS_GETPID` | dynamic | none | process | scalar | none |
| 2 | `SYS_WRITE` | dynamic | none | filesystem | scalar | none |
| 3 | `SYS_YIELD` | dynamic | none | system | scalar | none |
| 4 | `SYS_STAT` | static: kCapFsRead | none | filesystem | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 5 | `SYS_READ` | static: kCapFsRead | none | filesystem | buffer | `rdi` user_pointer; `rsi` user_buffer; `rdx` user_buffer |
| 6 | `SYS_DROPCAPS` | dynamic | none | system | scalar | `rdi` flags |
| 7 | `SYS_SPAWN` | static: kCapFsRead, kCapSpawnThread | none | process | pointer | `rdi` user_pointer; `rsi` size |
| 8 | `SYS_GETPROCID` | dynamic | none | process | scalar | none |
| 9 | `SYS_GETLASTERROR` | dynamic | none | system | pointer | `rdi` user_pointer |
| 10 | `SYS_SETLASTERROR` | dynamic | none | system | scalar | none |
| 11 | `SYS_HEAP_ALLOC` | dynamic | none | memory | scalar | `rdi` size |
| 12 | `SYS_HEAP_FREE` | dynamic | none | memory | scalar | none |
| 13 | `SYS_PERF_COUNTER` | dynamic | none | time | scalar | none |
| 14 | `SYS_HEAP_SIZE` | dynamic | none | memory | pointer | `rdi` user_pointer |
| 15 | `SYS_HEAP_REALLOC` | dynamic | none | memory | pointer | `rdi` user_pointer; `rsi` size |
| 16 | `SYS_WIN32_MISS_LOG` | dynamic | none | system | pointer | `rdi` user_pointer |
| 17 | `SYS_GETTIME_FT` | dynamic | none | time | scalar | none |
| 18 | `SYS_NOW_NS` | dynamic | none | time | scalar | none |
| 19 | `SYS_SLEEP_MS` | dynamic | none | time | scalar | `rdi` scalar |
| 20 | `SYS_FILE_OPEN` | dynamic | none | filesystem | pointer | `rdi` user_pointer; `rsi` size |
| 21 | `SYS_FILE_READ` | dynamic | dynamic | filesystem | mixed | `rdi` handle; `rsi` user_buffer; `rdx` size |
| 22 | `SYS_FILE_CLOSE` | dynamic | dynamic | filesystem | handle | `rdi` handle |
| 23 | `SYS_FILE_SEEK` | dynamic | dynamic | filesystem | handle | `rdi` handle; `rsi` scalar; `rdx` scalar |
| 24 | `SYS_FILE_FSTAT` | static: kCapFsRead | dynamic | filesystem | mixed | `rdi` handle; `rsi` user_pointer |
| 25 | `SYS_MUTEX_CREATE` | dynamic | none | ipc | scalar | `rdi` scalar |
| 26 | `SYS_MUTEX_WAIT` | dynamic | dynamic | ipc | handle | `rdi` handle; `rsi` scalar |
| 27 | `SYS_MUTEX_RELEASE` | dynamic | dynamic | ipc | handle | `rdi` handle |
| 28 | `SYS_VMAP` | dynamic | none | memory | scalar | `rdi` size |
| 29 | `SYS_VUNMAP` | dynamic | none | memory | scalar | `rdi` scalar; `rsi` size |
| 30 | `SYS_EVENT_CREATE` | dynamic | none | ipc | scalar | `rdi` scalar; `rsi` scalar |
| 31 | `SYS_EVENT_SET` | dynamic | dynamic | ipc | handle | `rdi` handle |
| 32 | `SYS_EVENT_RESET` | dynamic | dynamic | ipc | handle | `rdi` handle |
| 33 | `SYS_EVENT_WAIT` | dynamic | dynamic | ipc | handle | `rdi` handle; `rsi` scalar |
| 34 | `SYS_TLS_ALLOC` | dynamic | none | runtime | scalar | none |
| 35 | `SYS_TLS_FREE` | dynamic | none | runtime | scalar | `rdi` identifier |
| 36 | `SYS_TLS_GET` | dynamic | none | runtime | scalar | `rdi` identifier |
| 37 | `SYS_TLS_SET` | dynamic | none | runtime | scalar | `rdi` identifier; `rsi` scalar |
| 38 | `SYS_BP_INSTALL` | static: kCapDebug | none | diagnostic | scalar | `rdi` scalar; `rsi` flags; `rdx` size |
| 39 | `SYS_BP_REMOVE` | static: kCapDebug | none | diagnostic | scalar | `rdi` scalar |
| 40 | `SYS_GETTIME_ST` | dynamic | none | time | pointer | `rdi` user_pointer |
| 41 | `SYS_ST_TO_FT` | dynamic | none | time | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 42 | `SYS_FT_TO_ST` | dynamic | none | time | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 43 | `SYS_FILE_WRITE` | static: kCapFsWrite | dynamic | filesystem | mixed | `rdi` handle; `rsi` user_pointer; `rdx` size |
| 44 | `SYS_FILE_CREATE` | static: kCapFsWrite | none | filesystem | buffer | `rdi` user_pointer; `rsi` user_buffer; `rdx` user_pointer; `r10` size |
| 45 | `SYS_THREAD_CREATE` | static: kCapSpawnThread | none | process | pointer | `rdi` user_pointer; `rsi` scalar |
| 46 | `SYS_DEBUG_PRINT` | dynamic | none | diagnostic | pointer | `rdi` user_pointer |
| 47 | `SYS_MEM_STATUS` | dynamic | none | system | pointer | `rdi` user_pointer |
| 48 | `SYS_WAIT_MULTI` | dynamic | dynamic | ipc | handle | `rdi` size; `rsi` handle; `rdx` scalar; `r10` scalar |
| 49 | `SYS_SYSTEM_INFO` | dynamic | none | system | pointer | `rdi` user_pointer |
| 50 | `SYS_DEBUG_PRINTW` | dynamic | none | diagnostic | pointer | `rdi` user_pointer |
| 51 | `SYS_SEM_CREATE` | dynamic | none | ipc | scalar | `rdi` size; `rsi` size |
| 52 | `SYS_SEM_RELEASE` | dynamic | dynamic | ipc | handle | `rdi` handle; `rsi` size |
| 53 | `SYS_SEM_WAIT` | dynamic | dynamic | ipc | handle | `rdi` handle; `rsi` scalar |
| 54 | `SYS_THREAD_WAIT` | dynamic | dynamic | process | handle | `rdi` handle; `rsi` scalar |
| 55 | `SYS_THREAD_EXIT_CODE` | dynamic | dynamic | process | handle | `rdi` handle |
| 56 | `SYS_NT_INVOKE` | dynamic | none | system | scalar | `rdi` scalar |
| 57 | `SYS_DLL_PROC_ADDRESS` | dynamic | none | system | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 58 | `SYS_WIN_CREATE` | dynamic | none | graphics | buffer | `rdi` user_buffer; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` user_pointer |
| 59 | `SYS_WIN_DESTROY` | dynamic | none | graphics | scalar | `rdi` scalar |
| 60 | `SYS_WIN_SHOW` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 61 | `SYS_WIN_MSGBOX` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 62 | `SYS_WIN_PEEK_MSG` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` identifier; `rdx` scalar |
| 63 | `SYS_WIN_GET_MSG` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` scalar |
| 64 | `SYS_WIN_POST_MSG` | dynamic | dynamic | graphics | handle | `rdi` scalar; `rsi` identifier; `rdx` scalar; `r10` handle |
| 65 | `SYS_GDI_FILL_RECT` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` scalar; `r9` scalar |
| 66 | `SYS_GDI_TEXT_OUT` | dynamic | none | graphics | pointer | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` user_pointer; `r8` size; `r9` scalar |
| 67 | `SYS_GDI_RECTANGLE` | dynamic | none | graphics | scalar | none |
| 68 | `SYS_GDI_CLEAR` | dynamic | dynamic | graphics | handle | `rdi` handle |
| 69 | `SYS_WIN_MOVE` | dynamic | none | graphics | buffer | `rdi` scalar; `rsi` user_buffer; `rdx` scalar; `r10` scalar; `r8` scalar; `r9` size |
| 70 | `SYS_WIN_GET_RECT` | dynamic | none | graphics | buffer | `rdi` scalar; `rsi` user_buffer; `rdx` user_pointer |
| 71 | `SYS_WIN_SET_TEXT` | dynamic | dynamic | graphics | handle | `rdi` scalar; `rsi` handle |
| 72 | `SYS_WIN_TIMER_SET` | dynamic | dynamic | graphics | handle | `rdi` scalar; `rsi` scalar; `rdx` handle |
| 73 | `SYS_WIN_TIMER_KILL` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 74 | `SYS_GDI_LINE` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` scalar; `r9` scalar |
| 75 | `SYS_GDI_ELLIPSE` | dynamic | none | graphics | scalar | none |
| 76 | `SYS_GDI_SET_PIXEL` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar |
| 77 | `SYS_WIN_GET_KEYSTATE` | static: kCapInput | none | graphics | scalar | `rdi` scalar |
| 78 | `SYS_WIN_GET_CURSOR` | static: kCapInput | none | graphics | pointer | `rdi` user_pointer |
| 79 | `SYS_WIN_SET_CURSOR` | dynamic | none | graphics | buffer | `rdi` scalar; `rsi` user_buffer |
| 80 | `SYS_WIN_SET_CAPTURE` | dynamic | none | graphics | scalar | `rdi` scalar |
| 81 | `SYS_WIN_RELEASE_CAPTURE` | dynamic | none | graphics | scalar | none |
| 82 | `SYS_WIN_GET_CAPTURE` | dynamic | none | graphics | scalar | none |
| 83 | `SYS_WIN_CLIP_SET_TEXT` | dynamic | none | graphics | pointer | `rdi` user_pointer |
| 84 | `SYS_WIN_CLIP_GET_TEXT` | dynamic | none | graphics | buffer | `rdi` user_buffer; `rsi` user_buffer |
| 85 | `SYS_WIN_GET_LONG` | dynamic | dynamic | graphics | handle | `rdi` scalar; `rsi` handle |
| 86 | `SYS_WIN_SET_LONG` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` identifier; `rdx` scalar |
| 87 | `SYS_WIN_INVALIDATE` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 88 | `SYS_WIN_VALIDATE` | dynamic | none | graphics | scalar | `rdi` scalar |
| 89 | `SYS_WIN_GET_ACTIVE` | dynamic | none | graphics | scalar | none |
| 90 | `SYS_WIN_SET_ACTIVE` | dynamic | none | graphics | scalar | `rdi` scalar |
| 91 | `SYS_WIN_GET_METRIC` | dynamic | none | graphics | scalar | `rdi` identifier |
| 92 | `SYS_WIN_ENUM` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` size |
| 93 | `SYS_WIN_FIND` | dynamic | none | graphics | pointer | `rdi` user_pointer |
| 94 | `SYS_WIN_SET_PARENT` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 95 | `SYS_WIN_GET_PARENT` | dynamic | none | graphics | scalar | `rdi` scalar |
| 96 | `SYS_WIN_GET_RELATED` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 97 | `SYS_WIN_SET_FOCUS` | dynamic | none | graphics | scalar | `rdi` scalar |
| 98 | `SYS_WIN_GET_FOCUS` | dynamic | none | graphics | scalar | none |
| 99 | `SYS_WIN_CARET` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar |
| 100 | `SYS_WIN_BEEP` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 101 | `SYS_GFX_D3D_STUB` | dynamic | none | graphics | scalar | `rdi` scalar |
| 102 | `SYS_GDI_BITBLT` | dynamic | dynamic | graphics | handle | `rdi` handle; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` scalar; `r9` handle |
| 103 | `SYS_WIN_BEGIN_PAINT` | dynamic | none | graphics | pointer | `rdi` scalar; `rsi` user_pointer |
| 104 | `SYS_WIN_END_PAINT` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 105 | `SYS_GDI_FILL_RECT_USER` | dynamic | none | graphics | pointer | `rdi` scalar; `rsi` user_pointer; `rdx` scalar |
| 106 | `SYS_GDI_CREATE_COMPAT_DC` | dynamic | none | graphics | scalar | `rdi` scalar |
| 107 | `SYS_GDI_CREATE_COMPAT_BITMAP` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar |
| 108 | `SYS_GDI_CREATE_SOLID_BRUSH` | dynamic | none | graphics | scalar | `rdi` scalar |
| 109 | `SYS_GDI_GET_STOCK_OBJECT` | dynamic | none | graphics | scalar | `rdi` identifier |
| 110 | `SYS_GDI_SELECT_OBJECT` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 111 | `SYS_GDI_DELETE_DC` | dynamic | none | graphics | scalar | `rdi` scalar |
| 112 | `SYS_GDI_DELETE_OBJECT` | dynamic | none | graphics | scalar | `rdi` scalar |
| 113 | `SYS_GDI_BITBLT_DC` | dynamic | none | graphics | scalar | none |
| 114 | `SYS_GDI_SET_TEXT_COLOR` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 115 | `SYS_GDI_SET_BK_COLOR` | dynamic | none | graphics | scalar | none |
| 116 | `SYS_GDI_SET_BK_MODE` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 117 | `SYS_GDI_STRETCH_BLT_DC` | dynamic | none | graphics | scalar | none |
| 118 | `SYS_GDI_CREATE_PEN` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar |
| 119 | `SYS_GDI_MOVE_TO_EX` | dynamic | none | graphics | pointer | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` user_pointer |
| 120 | `SYS_GDI_LINE_TO` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar |
| 121 | `SYS_GDI_DRAW_TEXT_USER` | dynamic | dynamic | graphics | mixed | `rdi` scalar; `rsi` user_pointer; `rdx` size; `r10` user_pointer; `r8` handle |
| 122 | `SYS_GDI_RECTANGLE_FILLED` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` scalar |
| 123 | `SYS_GDI_ELLIPSE_FILLED` | dynamic | none | graphics | scalar | none |
| 124 | `SYS_GDI_PAT_BLT` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` scalar |
| 125 | `SYS_GDI_TEXT_OUT_W` | dynamic | none | graphics | scalar | none |
| 126 | `SYS_GDI_DRAW_TEXT_W` | dynamic | none | graphics | scalar | none |
| 127 | `SYS_GDI_GET_SYS_COLOR` | dynamic | none | graphics | scalar | `rdi` identifier |
| 128 | `SYS_GDI_GET_SYS_COLOR_BRUSH` | dynamic | none | graphics | scalar | `rdi` identifier |
| 129 | `SYS_WIN32_CUSTOM` | dynamic | none | system | scalar | none |
| 130 | `SYS_REGISTRY` | dynamic | none | system | scalar | none |
| 131 | `SYS_PROCESS_OPEN` | dynamic | none | process | scalar | `rdi` identifier |
| 132 | `SYS_PROCESS_VM_READ` | dynamic | dynamic | process | mixed | `rdi` handle; `rsi` user_pointer; `rdx` user_buffer; `r10` size; `r8` user_pointer |
| 133 | `SYS_PROCESS_VM_WRITE` | dynamic | dynamic | process | mixed | `rdi` handle; `rsi` user_pointer; `rdx` user_buffer; `r10` size; `r8` user_pointer |
| 134 | `SYS_PROCESS_VM_QUERY` | dynamic | dynamic | process | mixed | `rdi` handle; `rsi` user_pointer; `rdx` user_pointer |
| 135 | `SYS_THREAD_SUSPEND` | dynamic | dynamic | process | handle | `rdi` handle |
| 136 | `SYS_THREAD_RESUME` | dynamic | none | process | scalar | none |
| 137 | `SYS_THREAD_GET_CONTEXT` | dynamic | dynamic | process | mixed | `rdi` handle; `rsi` user_buffer; `rdx` flags |
| 138 | `SYS_THREAD_SET_CONTEXT` | dynamic | none | process | scalar | none |
| 139 | `SYS_THREAD_OPEN` | dynamic | none | process | scalar | `rdi` identifier |
| 140 | `SYS_SECTION_CREATE` | dynamic | none | system | scalar | `rdi` size; `rsi` scalar; `rdx` scalar; `r10` size; `r8` scalar |
| 141 | `SYS_SECTION_MAP` | dynamic | none | system | scalar | none |
| 142 | `SYS_SECTION_UNMAP` | dynamic | none | system | scalar | none |
| 143 | `SYS_FILE_UNLINK` | dynamic | none | filesystem | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar |
| 144 | `SYS_FILE_RENAME` | static: kCapFsWrite | none | filesystem | scalar | none |
| 145 | `SYS_PROCESS_TERMINATE` | dynamic | dynamic | process | mixed | `rdi` handle; `rsi` scalar; `rdx` user_buffer; `r10` user_buffer; `r8` user_pointer |
| 146 | `SYS_THREAD_TERMINATE` | dynamic | none | process | scalar | none |
| 147 | `SYS_PROCESS_QUERY_INFO` | dynamic | none | process | scalar | none |
| 148 | `SYS_VM_ALLOCATE` | dynamic | dynamic | memory | mixed | `rdi` handle; `rsi` scalar; `rdx` size; `r10` scalar; `r8` flags; `r9` user_pointer |
| 149 | `SYS_VM_FREE` | dynamic | none | memory | scalar | none |
| 150 | `SYS_VM_PROTECT` | dynamic | none | memory | scalar | none |
| 151 | `SYS_FILE_QUERY_ATTRIBUTES` | static: kCapFsRead | none | filesystem | buffer | `rdi` scalar; `rsi` scalar; `rdx` user_buffer; `r10` user_buffer |
| 152 | `SYS_EXECVE` | static: kCapFsRead, kCapSpawnThread | none | process | scalar | `rdi` scalar; `rsi` scalar |
| 153 | `SYS_SOCKET_OP` | static: kCapNet | none | network | pointer | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar; `r8` user_pointer; `r9` scalar |
| 154 | `SYS_DIR_OPEN` | static: kCapFsRead | none | filesystem | scalar | `rdi` scalar; `rsi` size |
| 155 | `SYS_DIR_NEXT` | static: kCapFsRead | none | filesystem | scalar | none |
| 156 | `SYS_DIR_REWIND` | static: kCapFsRead | dynamic | filesystem | handle | `rdi` handle |
| 157 | `SYS_DIR_NOTIFY` | dynamic | dynamic | filesystem | mixed | `rdi` handle; `rsi` scalar; `rdx` scalar; `r10` user_buffer; `r8` user_buffer |
| 158 | `SYS_PROCESS_SPAWN` | static: kCapFsRead, kCapSpawnThread | none | process | scalar | none |
| 159 | `SYS_IOCP_CREATE` | dynamic | none | ipc | scalar | none |
| 160 | `SYS_IOCP_SET` | dynamic | none | ipc | scalar | none |
| 161 | `SYS_IOCP_REMOVE` | dynamic | none | ipc | scalar | none |
| 162 | `SYS_IOCP_CLOSE` | dynamic | none | ipc | scalar | none |
| 163 | `SYS_JOB_CREATE` | dynamic | none | system | scalar | none |
| 164 | `SYS_JOB_ASSIGN` | dynamic | none | system | scalar | none |
| 165 | `SYS_JOB_IS_IN` | dynamic | none | system | scalar | none |
| 166 | `SYS_JOB_TERMINATE` | dynamic | none | system | scalar | none |
| 167 | `SYS_JOB_QUERY` | dynamic | none | system | scalar | none |
| 168 | `SYS_JOB_CLOSE` | dynamic | none | system | scalar | none |
| 169 | `SYS_TOKEN_ADJUST` | dynamic | none | system | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` flags; `r8` scalar |
| 170 | `SYS_WIN_GET_MOUSE_DELTA` | static: kCapInput | none | graphics | buffer | `rdi` user_buffer |
| 171 | `SYS_STDIN_READ` | static: kCapInput | none | system | buffer | `rdi` user_buffer; `rsi` scalar |
| 172 | `SYS_DLL_BASE_BY_NAME` | dynamic | none | system | pointer | `rdi` user_pointer; `rsi` size |
| 173 | `SYS_WIN_TRACK_POPUP` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` size |
| 174 | `SYS_GDI_SET_CURSOR` | dynamic | none | graphics | scalar | `rdi` scalar |
| 175 | `SYS_GDI_CREATE_CURSOR` | dynamic | none | graphics | scalar | `rdi` flags; `rsi` size; `rdx` scalar |
| 180 | `SYS_FILE_MKDIR` | static: kCapFsWrite | none | filesystem | scalar | `rdi` scalar; `rsi` scalar; `rdx` scalar; `r10` scalar |
| 181 | `SYS_FILE_SYMLINK` | static: kCapFsWrite | none | filesystem | scalar | none |
| 182 | `SYS_FILE_LINK` | static: kCapFsWrite | none | filesystem | scalar | none |
| 183 | `SYS_FILE_READLINK` | static: kCapFsRead | none | filesystem | scalar | none |
| 184 | `SYS_SYSTEM_PERFORMANCE_INFO` | dynamic | none | diagnostic | buffer | `rdi` user_pointer; `rsi` user_buffer |
| 185 | `SYS_NAMED_KOBJ_OPEN_OR_CREATE` | dynamic | none | ipc | pointer | `rdi` scalar; `rsi` user_pointer; `rdx` size; `r10` size; `r8` scalar |
| 186 | `SYS_WIN32_CREATE_PIPE` | dynamic | dynamic | system | handle | `rdi` handle; `rsi` handle |
| 187 | `SYS_QUEUE_USER_APC` | dynamic | none | ipc | pointer | `rdi` identifier; `rsi` user_pointer; `rdx` scalar; `r10` scalar; `r8` identifier |
| 188 | `SYS_DRAIN_USER_APC` | dynamic | none | ipc | pointer | `rdi` user_pointer; `rsi` user_pointer; `rdx` user_pointer; `r10` user_pointer |
| 189 | `SYS_PRIORITY_CLASS` | dynamic | none | process | scalar | `rdi` scalar; `rsi` scalar |
| 190 | `SYS_PROCESS_SPAWN_EX` | static: kCapFsRead, kCapSpawnThread | none | process | pointer | `rdi` user_pointer; `rsi` flags; `rdx` scalar |
| 191 | `SYS_GET_INHERITED_STD` | dynamic | dynamic | system | handle | `rdi` handle |
| 192 | `SYS_HEAPEX_CREATE` | dynamic | dynamic | memory | handle | `rdi` handle |
| 193 | `SYS_HEAPEX_DESTROY` | dynamic | dynamic | memory | handle | `rdi` handle |
| 194 | `SYS_HEAPEX_ALLOC` | dynamic | dynamic | memory | mixed | `rdi` handle; `rsi` user_pointer |
| 195 | `SYS_HEAPEX_FREE` | dynamic | dynamic | memory | handle | `rdi` handle; `rsi` scalar |
| 196 | `SYS_HEAPEX_SIZE` | dynamic | dynamic | memory | handle | `rdi` handle; `rsi` scalar |
| 197 | `SYS_HEAPEX_REALLOC` | dynamic | dynamic | memory | mixed | `rdi` handle; `rsi` scalar; `rdx` user_pointer |
| 198 | `SYS_AUDIO_DEVICE_INFO` | dynamic | none | audio | scalar | `rdi` scalar |
| 199 | `SYS_VIRTUAL_ALLOC` | dynamic | none | memory | scalar | `rdi` size; `rsi` scalar; `rdx` scalar; `r10` scalar |
| 200 | `SYS_VIRTUAL_FREE` | dynamic | none | memory | pointer | `rdi` scalar; `rsi` size; `rdx` user_pointer |
| 201 | `SYS_VIRTUAL_PROTECT` | dynamic | none | memory | scalar | `rdi` scalar; `rsi` size; `rdx` scalar; `r10` scalar |
| 202 | `SYS_NAMED_PIPE_CREATE` | dynamic | none | ipc | pointer | `rdi` user_pointer; `rsi` scalar; `rdx` scalar |
| 203 | `SYS_NAMED_PIPE_OPEN` | dynamic | dynamic | ipc | mixed | `rdi` user_pointer; `rsi` handle |
| 204 | `SYS_DIAG_FAULT_INJECT` | static: kCapDiag | none | diagnostic | pointer | `rdi` user_pointer |
| 205 | `SYS_DLL_LOAD_FROM_PATH` | static: kCapFsRead | none | system | pointer | `rdi` user_pointer; `rsi` size |
| 206 | `SYS_COMPAT_QUERY` | dynamic | none | system | scalar | none |
| 207 | `SYS_MODULE_BASE_BY_VA` | dynamic | none | system | scalar | `rdi` scalar |
| 208 | `SYS_WAIT_ON_ADDRESS` | dynamic | none | ipc | pointer | `rdi` user_pointer; `rsi` user_pointer; `rdx` size; `r10` scalar |
| 209 | `SYS_WAKE_BY_ADDRESS` | dynamic | none | ipc | pointer | `rdi` user_pointer; `rsi` user_pointer |
| 210 | `SYS_AUDIO_WRITE` | dynamic | none | audio | buffer | `rdi` user_pointer; `rsi` user_buffer |
| 211 | `SYS_VK_CALL` | dynamic | none | graphics | scalar | none |
| 212 | `SYS_RANDOM_BYTES` | dynamic | none | system | buffer | `rdi` user_buffer; `rsi` size |
| 213 | `SYS_IOCP_POST` | dynamic | dynamic | ipc | mixed | `rdi` handle; `rsi` scalar; `rdx` scalar; `r10` user_pointer |
| 214 | `SYS_GDI_SET_DIBITS` | dynamic | none | graphics | buffer | `rdi` scalar; `rsi` user_buffer; `rdx` scalar; `r10` scalar; `r8` scalar; `r9` user_buffer |
| 215 | `SYS_GDI_GET_DIBITS` | dynamic | none | graphics | scalar | none |
| 216 | `SYS_FIBER_CONVERT` | dynamic | none | runtime | pointer | `rdi` user_pointer |
| 217 | `SYS_FIBER_CREATE` | dynamic | none | runtime | pointer | `rdi` user_pointer; `rsi` user_pointer; `rdx` size |
| 218 | `SYS_FIBER_SWITCH` | dynamic | none | runtime | pointer | `rdi` user_pointer |
| 219 | `SYS_FIBER_DELETE` | dynamic | none | runtime | pointer | `rdi` user_pointer |
| 220 | `SYS_FLS_ALLOC` | dynamic | none | runtime | pointer | `rdi` user_pointer |
| 221 | `SYS_FLS_FREE` | dynamic | none | runtime | scalar | `rdi` identifier |
| 222 | `SYS_FLS_GET` | dynamic | none | runtime | scalar | `rdi` identifier |
| 223 | `SYS_FLS_SET` | dynamic | none | runtime | scalar | `rdi` identifier; `rsi` scalar |
| 224 | `SYS_GDI_CREATE_CURSOR_RGBA` | dynamic | none | graphics | pointer | `rdi` user_pointer; `rsi` scalar; `rdx` identifier |
| 225 | `SYS_GDI_CREATE_FONT` | dynamic | dynamic | graphics | handle | `rdi` handle |
| 226 | `SYS_GDI_GET_TEXT_METRICS` | dynamic | none | graphics | pointer | `rdi` scalar; `rsi` user_pointer |
| 227 | `SYS_SERVICE_ENDPOINT_OP` | dynamic | dynamic | ipc | mixed | `rdi` user_buffer; `rsi` size; `rdx` user_buffer; `r10` size |
| 228 | `SYS_SERVICE_CONTROL` | dynamic | none | process | mixed | `rdi` user_buffer; `rsi` size; `rdx` user_buffer; `r10` size |
| 229 | `SYS_GDI_SET_ROP2` | dynamic | none | graphics | scalar | `rdi` scalar; `rsi` scalar |
| 230 | `SYS_GAMEPAD_STATE` | static: kCapInput | none | graphics | mixed | `rdi` scalar; `rsi` user_buffer; `rdx` size |
| 231 | `SYS_STDIN_PEEK` | static: kCapInput | none | system | buffer | `rdi` user_buffer; `rsi` scalar |
