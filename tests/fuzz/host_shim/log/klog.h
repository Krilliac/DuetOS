#pragma once

// klog macros are no-ops on the fuzz harness — their compile-time
// scope tracking has zero value at fuzz time. Defined variadically
// so a kernel-side arity change can never re-rot this shim and
// silently drop a parser out of fuzz coverage again.
#define KLOG_TRACE_SCOPE(...) ((void)0)
#define KLOG_TRACE(...) ((void)0)
#define KLOG_TRACE_V(...) ((void)0)
#define KLOG_DEBUG(...) ((void)0)
#define KLOG_DEBUG_V(...) ((void)0)
#define KLOG_DEBUG_S(...) ((void)0)
#define KLOG_INFO(...) ((void)0)
#define KLOG_INFO_A(...) ((void)0)
#define KLOG_INFO_V(...) ((void)0)
#define KLOG_INFO_S(...) ((void)0)
#define KLOG_INFO_2V(...) ((void)0)
#define KLOG_WARN(...) ((void)0)
#define KLOG_WARN_V(...) ((void)0)
#define KLOG_WARN_AV(...) ((void)0)
#define KLOG_WARN_2V(...) ((void)0)
#define KLOG_ERROR(...) ((void)0)
#define KLOG_ERROR_V(...) ((void)0)
#define KLOG_ERROR_S(...) ((void)0)
#define KLOG_ERROR_2V(...) ((void)0)
#define KLOG_CRITICAL(...) ((void)0)
