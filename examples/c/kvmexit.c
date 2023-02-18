#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kvmexit.skel.h"
#include "kvmexit.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int event_handler(void *_ctx, void *data, size_t size)
{
	struct kvm_exit_event *event = data;

	printf("PID: %d, CPU: %d, EXIT REASON: %d\n", event->pid, event->cpu_id, event->exit_reason);
}

int main(int argc, char **argv)
{
	struct kvmexit_bpf *skel;
	struct ring_buffer *ring_buf = NULL;
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = kvmexit_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = kvmexit_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoint handler */
	err = kvmexit_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
		   "to see output of the BPF programs.\n");

	/* Prepare ring buffer to receive events from the BPF program. */
	ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.rb), event_handler, NULL, NULL);
	if (!ring_buf)
	{
		err = -1;
		goto cleanup;
	}

	/* Wait and receive events */
	while (ring_buffer__poll(ring_buf, -1) >= 0)
	{
	}

cleanup:
	kvmexit_bpf__destroy(skel);
	return -err;
}
