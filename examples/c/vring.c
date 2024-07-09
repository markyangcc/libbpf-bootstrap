#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "vring.skel.h"

int main(int argc, char **argv)
{
	struct vring_bpf *skel;
	int err;

	/* Open load and verify BPF application */
	skel = vring_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = vring_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");


	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}
	
cleanup:
	vring_bpf__destroy(skel);
	return -err;
}