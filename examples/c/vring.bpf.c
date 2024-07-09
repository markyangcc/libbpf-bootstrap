#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "vring.h"

#define to_vvq(_vq) container_of(_vq, struct vring_virtqueue, vq)

SEC("kprobe/vring_interrupt")
void BPF_KPROBE(vring_interrupt, int irq, void *_vq)
{
	struct vring_virtqueue *vq = to_vvq(_vq);
	vring_avail_t *vr_avail = (vring_avail_t*)&vq->split.vring.avail;
	vring_used_t *vr_used = (vring_used_t*)&vq->split.vring.used;

	u16 avail, used, last_used;
	bpf_probe_read(&avail, sizeof(u16), &vr_avail->idx);
	bpf_probe_read(&used, sizeof(u16), &vr_used->idx);
	bpf_probe_read(&last_used, sizeof(u16), &vq->last_used_idx);

	// int avail = vq->split.vring.avail->idx;
	// int used = vq->split.vring.used->idx;
	// int last_used = vq->last_used_idx;
	bpf_printk("%p %d %d %d", vq, avail, used, last_used & 4095);
}

char _license[] SEC("license") = "GPL";