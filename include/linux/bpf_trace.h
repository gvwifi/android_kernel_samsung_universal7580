#ifndef _LINUX_BPF_TRACE_H
#define _LINUX_BPF_TRACE_H

/* Stubs for BPF tracepoints to avoid backporting massive trace system changes */
/* Use varargs to match any signature */

#define trace_bpf_prog_load(...) do {} while(0)
#define trace_bpf_prog_put_rcu(...) do {} while(0)
#define trace_bpf_prog_get_type(...) do {} while(0)
#define trace_bpf_map_create(...) do {} while(0)
#define trace_bpf_map_lookup_elem(...) do {} while(0)
#define trace_bpf_map_update_elem(...) do {} while(0)
#define trace_bpf_map_delete_elem(...) do {} while(0)
#define trace_bpf_map_next_key(...) do {} while(0)
#define trace_bpf_obj_get_map(...) do {} while(0)
#define trace_bpf_obj_get_prog(...) do {} while(0)
#define trace_bpf_obj_pin_map(...) do {} while(0)
#define trace_bpf_obj_pin_prog(...) do {} while(0)
#define trace_xdp_exception(...) do {} while(0)

#define trace_bpf_obj_pin_prog_enabled() (0)
#define trace_bpf_obj_pin_map_enabled() (0)
#define trace_bpf_obj_get_prog_enabled() (0)
#define trace_bpf_obj_get_map_enabled() (0)

#endif /* _LINUX_BPF_TRACE_H */
