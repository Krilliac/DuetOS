#pragma once

// klog macros are no-ops on the fuzz harness — their compile-time
// scope tracking has zero value at fuzz time.
#define KLOG_TRACE_SCOPE(s, t) ((void)0)
#define KLOG_INFO_V(s, m, v) ((void)0)
#define KLOG_WARN_V(s, m, v) ((void)0)
#define KLOG_WARN_2V(s, m, k1, v1, k2, v2) ((void)0)
#define KLOG_WARN(s, m) ((void)0)
#define KLOG_ERROR_V(s, m, v) ((void)0)
#define KLOG_ERROR_S(s, m, k, v) ((void)0)
#define KLOG_INFO_S(s, m, k, v) ((void)0)
#define KLOG_DEBUG(s, m) ((void)0)
#define KLOG_TRACE_V(s, m, v) ((void)0)
