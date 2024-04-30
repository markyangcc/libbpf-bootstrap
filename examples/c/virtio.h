
#ifndef __VIRTIO_H
#define __VIRTIO_H

#define MAX_QUEUE_NUM 32
#define NETDEV_ALIGN  32

struct vring_event {
	unsigned short len;
	unsigned short last_used_idx;
	unsigned short avail_idx;
	unsigned short used_idx;
};

struct vqueue_event {
	int pid;

	int sq_size;
	int rq_size;

	struct vring_event rxs[MAX_QUEUE_NUM];
	struct vring_event txs[MAX_QUEUE_NUM];

	unsigned int tx_idx;
	unsigned int rx_idx;
};

#endif