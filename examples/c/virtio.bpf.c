#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "../../vmlinux/vmlinux.h"
#include "virtio.h"

#define ALIGN(x, a)	 __ALIGN(x, (typeof(x))(a)-1)
#define __ALIGN(x, mask) (((x) + (mask)) & ~(mask))

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct vqueue_event);
} imap SEC(".maps");

// struct virtnet_info {
// 	struct virtio_device *vdev;
// 	struct virtqueue *cvq;
// 	struct net_device *dev;
// 	struct send_queue *sq;
// 	struct receive_queue *rq;
// };

// struct send_queue {
// 	struct virtqueue *vq;
// };

// struct receive_queue {
// 	struct virtqueue *vq;
// };

__always_inline struct virtnet_info *get_virtnet_info(struct net_device *dev)
{
	return (struct virtnet_info *)((char *)dev +
				       ALIGN(bpf_core_type_size(struct net_device), NETDEV_ALIGN));
}

// for tx queue
SEC("kprobe/dev_id_show")
int BPF_KPROBE(kprobe_dev_id_show, struct device *device)
{
	struct net_device *net_dev = container_of(device, struct net_device, dev);
	struct virtnet_info *vnet_info = get_virtnet_info(net_dev);
	int key = 0;
	bpf_printk("virtio tx: vnet_info %p", vnet_info);

	struct vqueue_event *qe = bpf_map_lookup_elem(&imap, &key);
	if (!qe)
		return 0;
	bpf_printk("virtio tx: qe %p", qe);

	// int pid = bpf_get_current_pid_tgid() >> 32;
	// if (qe->pid != pid)
	// 	return 0;
	// bpf_printk("virtio tx: pid %d", pid);

	int tx = qe->tx_idx;
	qe->tx_idx++;

	struct send_queue *sq;
	bpf_probe_read(&sq, sizeof(sq), &vnet_info->sq);
	sq = (char *)sq + tx * qe->sq_size;
	struct virtqueue *vq;
	bpf_probe_read(&vq, sizeof(vq), &sq->vq);
	struct vring_virtqueue *vvq = container_of(vq, struct vring_virtqueue, vq);
	struct vring vring;
	bpf_probe_read(&vring, sizeof(vring), &vvq->split.vring);
	struct vring_event *re = &qe->txs[tx & (MAX_QUEUE_NUM - 1)];

	bpf_probe_read(&re->avail_idx, sizeof(u16), &vring.avail->idx);
	bpf_probe_read(&re->used_idx, sizeof(u16), &vring.used->idx);
	bpf_probe_read(&re->last_used_idx, sizeof(u16), &vvq->last_used_idx);
	re->len = vring.num;

	bpf_printk("virtio tx: pkt_in_queue %d,last_used %d", re->avail_idx - re->used_idx,re->last_used_idx);

	return 0;
}

// for rx queue
SEC("kprobe/dev_port_show")
int BPF_KPROBE(kprobe_dev_port_show, struct device *device)
{
	struct receive_queue *rq;
	struct vqueue_event *e;

	struct net_device *dev = container_of(device, struct net_device, dev);
	struct virtnet_info *vi = get_virtnet_info(dev);
	int key = 0;

	bpf_printk("virtio rx: %p", dev);

	e = bpf_map_lookup_elem(&imap, &key);
	if (!e)
		return 0;

	// int pid = bpf_get_current_pid_tgid() >> 32;
	// if (e->pid != pid)
	// 	return 0;

	u64 rx = e->rx_idx;
	e->rx_idx++;
	if (rx >= MAX_QUEUE_NUM)
		return 0;

	bpf_probe_read(&rq, sizeof(rq), &vi->rq);
	rq = (char *)rq + rx * e->rq_size;
	struct virtqueue *vq;
	bpf_probe_read(&vq, sizeof(vq), &rq->vq);
	struct vring_virtqueue *vvq = container_of(vq, struct vring_virtqueue, vq);
	struct vring vring;
	bpf_probe_read(&vring, sizeof(vring), &vvq->split.vring);

	struct vring_event *ring = &e->rxs[rx & (MAX_QUEUE_NUM - 1)];

	bpf_probe_read(&ring->avail_idx, sizeof(u16), &vring.avail->idx);
	bpf_probe_read(&ring->used_idx, sizeof(u16), &vring.used->idx);
	bpf_probe_read(&ring->last_used_idx, sizeof(u16), &vvq->last_used_idx);
	ring->len = vring.num;

	bpf_printk("virtio rx: pkt_in_queue %d,last_used %d", ring->used_idx - ring->last_used_idx,ring->last_used_idx);

	return 0;
}

char _license[] SEC("license") = "GPL";