/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Declarations for KMSAN tracepoints.
 *
 * Copyright (C) 2022, Google LLC.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kmsan

#if !defined(_TRACE_ERROR_REPORT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KMSAN_H

#include <linux/stackdepot.h>
#include <linux/tracepoint.h>

TRACE_EVENT(kmsan_exceed_max_origin_depth,
	    TP_PROTO(depot_stack_handle_t id),
	    TP_ARGS(id),
	    TP_STRUCT__entry(
		__field(depot_stack_handle_t, id)
	    ),
	    TP_fast_assign(__entry->id = id;),
	    TP_printk("origin: %x\n", __entry->id));

#endif /* _TRACE_KMSAN_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
