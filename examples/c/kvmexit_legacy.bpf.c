#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kvmexit.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// cat /sys/kernel/tracing/events/kvm/kvm_exit/format
struct kvm_exit_infos
{
	char padding[8];
	int exit_reason;
};

SEC("tp/kvm/kvm_exit")
int handle_tp_kvm_exit(struct kvm_exit_infos *ctx)
{
	struct kvm_exit_event *event;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		return 1;

	int pid = bpf_get_current_pid_tgid() >> 32;
	int cpu_id = bpf_get_smp_processor_id();

	event->pid = pid;
	event->cpu_id = cpu_id;
	event->exit_reason = ctx->exit_reason;

	bpf_ringbuf_submit(event, 0);

	return 0;
}
