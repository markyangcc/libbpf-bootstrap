#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

// for tx queue
SEC("kprobe/vring_interrupt")
void BPF_KPROBE(vring_interrupt, int irq, void *_vq)
{
	// struct net_device *net_dev = container_of(device, struct net_device, dev);
	// struct virtnet_info *vnet_info = get_virtnet_info(net_dev);
	bpf_printk("%p", _vq);
}




char _license[] SEC("license") = "GPL";