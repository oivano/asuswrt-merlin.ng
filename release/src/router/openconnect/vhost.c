/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2021 David Woodhouse.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include "openconnect-internal.h"

#include <linux/if_tun.h>
#include <linux/vhost.h>

#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define debug_vhost 0

#define barrier() __sync_synchronize()

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define vio16(x) ((uint16_t)(x))
#define vio32(x) ((uint32_t)(x))
#define vio64(x) ((uint64_t)(x))
#else
#define vio16(x) ((uint16_t)__builtin_bswap16(x))
#define vio32(x) ((uint32_t)__builtin_bswap32(x))
#define vio64(x) ((uint64_t)__builtin_bswap64(x))
#endif

static int setup_vring(struct openconnect_info *vpninfo, int idx)
{
	struct oc_vring *vring = idx ? &vpninfo->tx_vring : &vpninfo->rx_vring;
	int ret;

	if (getenv("NOVHOST"))
		return -EINVAL;

	vring->desc = calloc(vpninfo->vhost_ring_size, sizeof(*vring->desc));
	vring->avail = calloc(vpninfo->vhost_ring_size + 3, 2);
	vring->used = calloc(1 + (vpninfo->vhost_ring_size * 2), 4);

	if (!vring->desc || !vring->avail || !vring->used)
		return -ENOMEM;

	for (int i = 0; i < vpninfo->vhost_ring_size; i++)
		vring->avail->ring[i] = i;

	struct vhost_vring_state vs = { };
	vs.index = idx;
	vs.num = vpninfo->vhost_ring_size;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_VRING_NUM, &vs) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d size: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	vs.num = 0;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_VRING_BASE, &vs) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d base: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	struct vhost_vring_addr va = { };
	va.index = idx;
	va.desc_user_addr = (unsigned long)vring->desc;
	va.avail_user_addr = (unsigned long)vring->avail;
	va.used_user_addr  = (unsigned long)vring->used;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_VRING_ADDR, &va) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d base: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	struct vhost_vring_file vf = { };
	vf.index = idx;
	vf.fd = vpninfo->tun_fd;
	if (ioctl(vpninfo->vhost_fd, VHOST_NET_SET_BACKEND, &vf) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d RX backend: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	vf.fd = vpninfo->vhost_call_fd;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_VRING_CALL, &vf) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d call eventfd: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	vf.fd = vpninfo->vhost_kick_fd;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_VRING_KICK, &vf) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vring #%d kick eventfd: %s\n"),
			     idx, strerror(-ret));
		return ret;
	}

	return 0;
}

/*
 * This is awful. The kernel doesn't let us just ask for a 1:1 mapping of
 * our virtual address space; we have to *know* the minimum and maximum
 * addresses. We can't test it directly with VHOST_SET_MEM_TABLE because
 * that actually succeeds, and the failure only occurs later when we try
 * to use a buffer at an address that *is* valid, but our memory table
 * *could* point to addresses that aren't. Ewww.
 *
 * So... attempt to work out what TASK_SIZE is for the kernel we happen
 * to be running on right now...
 */

static int testaddr(unsigned long addr)
{
	void *res = mmap((void *)addr, getpagesize(), PROT_NONE,
			 MAP_FIXED|MAP_ANONYMOUS, -1, 0);
	if (res == MAP_FAILED) {
		if (errno == EEXIST || errno == EINVAL)
			return 1;

		/* We get ENOMEM for a bad virtual address */
		return 0;
	}
	/* It shouldn't actually succeed without either MAP_SHARED or
	 * MAP_PRIVATE in the flags, but just in case... */
	munmap((void *)addr, getpagesize());
	return 1;
}

static int find_vmem_range(struct openconnect_info *vpninfo,
			   struct vhost_memory *vmem)
{
	const unsigned long page_size = getpagesize();
	unsigned long top;
	unsigned long bottom;


	top = -page_size;

	if (testaddr(top)) {
		vmem->regions[0].memory_size = top;
		goto out;
	}

	/* 'top' is the lowest address known *not* to work */
	bottom = top;
	while (1) {
		bottom >>= 1;
		bottom &= ~(page_size - 1);
		if (!bottom) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to find virtual task size; search reached zero"));
			return -EINVAL;
		}

		if (testaddr(bottom))
			break;
		top = bottom;
	}

	/* It's often a page or two below the boundary */
	top -= page_size;
	if (testaddr(top)) {
		vmem->regions[0].memory_size = top;
		goto out;
	}
	top -= page_size;
	if (testaddr(top)) {
		vmem->regions[0].memory_size = top;
		goto out;
	}

	/* Now, bottom is the highest address known to work,
	   and we must search between it and 'top' which is
	   the lowest address known not to. */
	while (bottom + page_size != top) {
		unsigned long test = bottom + (top - bottom) / 2;
		test &= ~(page_size - 1);

		if (testaddr(test)) {
			bottom = test;
			continue;
		}
		test -= page_size;
		if (testaddr(test)) {
			vmem->regions[0].memory_size = test;
			goto out;
		}

		test -= page_size;
		if (testaddr(test)) {
			vmem->regions[0].memory_size = test;
			goto out;
		}
		top = test;
	}
	vmem->regions[0].memory_size = bottom;

 out:
	vmem->regions[0].guest_phys_addr = page_size;
	vmem->regions[0].userspace_addr = page_size;
	vpn_progress(vpninfo, PRG_DEBUG, _("Detected virtual address range 0x%lx-0x%lx\n"),
		     page_size,
		     (unsigned long)(page_size + vmem->regions[0].memory_size));
	return 0;
}

#define OC_VHOST_NET_FEATURES ((1ULL << VHOST_NET_F_VIRTIO_NET_HDR) |	\
			       (1ULL << VIRTIO_F_VERSION_1) |		\
			       (1ULL << VIRTIO_RING_F_EVENT_IDX))

int setup_vhost(struct openconnect_info *vpninfo, int tun_fd)
{
	int ret;

	/* If tuned for latency not bandwidth, that isn't vhost-net */
	if (vpninfo->max_qlen < 16) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Not using vhost-net due to low queue length %d\n"),
			     vpninfo->max_qlen);
		return -EINVAL;
	}

	vpninfo->vhost_ring_size = 1 << (32 - __builtin_clz(vpninfo->max_qlen - 1));
	if (vpninfo->vhost_ring_size < 32)
		vpninfo->vhost_ring_size = 32;
	if (vpninfo->vhost_ring_size > 32768)
		vpninfo->vhost_ring_size = 32768;

	vpninfo->vhost_fd = open("/dev/vhost-net", O_RDWR);
	if (vpninfo->vhost_fd == -1) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open /dev/vhost-net: %s\n"),
			     strerror(-ret));
		goto err;
	}

	if (ioctl(vpninfo->vhost_fd, VHOST_SET_OWNER, NULL) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_DEBUG, _("Failed to set vhost ownership: %s\n"),
			     strerror(-ret));
		goto err;
	}

	uint64_t features;

	if (ioctl(vpninfo->vhost_fd, VHOST_GET_FEATURES, &features) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_DEBUG, _("Failed to get vhost features: %s\n"),
			     strerror(-ret));
		goto err;
	}
	if ((features & OC_VHOST_NET_FEATURES) != OC_VHOST_NET_FEATURES) {
		vpn_progress(vpninfo, PRG_DEBUG, _("vhost-net lacks required features: %llx\n"),
			     (unsigned long long)features);
		return -EOPNOTSUPP;
	}

	features = OC_VHOST_NET_FEATURES;
	if (ioctl(vpninfo->vhost_fd, VHOST_SET_FEATURES, &features) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to set vhost features: %s\n"),
			     strerror(-ret));
		goto err;
	}

	vpninfo->vhost_kick_fd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	if (vpninfo->vhost_kick_fd == -1) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open vhost kick eventfd: %s\n"),
			     strerror(-ret));
		goto err;
	}
	vpninfo->vhost_call_fd = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
	if (vpninfo->vhost_call_fd == -1) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open vhost call eventfd: %s\n"),
			     strerror(-ret));
		goto err;
	}

	struct vhost_memory *vmem = alloca(sizeof(*vmem) + sizeof(vmem->regions[0]));

	memset(vmem, 0, sizeof(*vmem) + sizeof(vmem->regions[0]));
	vmem->nregions = 1;

	ret = find_vmem_range(vpninfo, vmem);
	if (ret)
		goto err;

	if (ioctl(vpninfo->vhost_fd, VHOST_SET_MEM_TABLE, vmem) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_DEBUG, _("Failed to set vhost memory map: %s\n"),
			     strerror(-ret));
		goto err;
	}

	ret = setup_vring(vpninfo, 0);
	if (ret)
		goto err;

	ret = setup_vring(vpninfo, 1);
	if (ret)
		goto err;

	/* This isn't just for bufferbloat; there are various issues with the XDP
	 * code path:
	 * https://lore.kernel.org/netdev/2433592d2b26deec33336dd3e83acfd273b0cf30.camel@infradead.org/T/
	 */
	int sndbuf = vpninfo->ip_info.mtu;
	if (!sndbuf)
		sndbuf = 1500;
	sndbuf *= 2 * vpninfo->max_qlen;
	if (ioctl(vpninfo->tun_fd, TUNSETSNDBUF, &sndbuf) < 0) {
		ret = -errno;
		vpn_progress(vpninfo, PRG_INFO, _("Failed to set tun sndbuf: %s\n"),
			     strerror(-ret));
		goto err;
	}

	vpn_progress(vpninfo, PRG_INFO, _("Using vhost-net for tun acceleration, ring size %d\n"),
		     vpninfo->vhost_ring_size);

	monitor_fd_new(vpninfo, vhost_call);
	monitor_read_fd(vpninfo, vhost_call);

	return 0;

 err:
	shutdown_vhost(vpninfo);
	return ret;
}

static void free_vring(struct openconnect_info *vpninfo,
		       struct oc_vring *vring)
{
	if (vring->desc) {
		for (int i = 0; i < vpninfo->vhost_ring_size; i++) {
			if (vring->desc[i].addr)
				free_pkt(vpninfo, pkt_from_hdr(vio64(vring->desc[i].addr), virtio.h));
		}

		free(vring->desc);
		vring->desc = NULL;
	}

	free(vring->avail);
	vring->avail = NULL;
	free(vring->used);
	vring->used = NULL;
}

void shutdown_vhost(struct openconnect_info *vpninfo)
{
	if (vpninfo->vhost_fd != -1)
		close(vpninfo->vhost_fd);
	if (vpninfo->vhost_kick_fd != -1)
		close(vpninfo->vhost_kick_fd);
	if (vpninfo->vhost_call_fd != -1)
		close(vpninfo->vhost_call_fd);

	vpninfo->vhost_fd = vpninfo->vhost_kick_fd = vpninfo->vhost_call_fd = -1;

	free_vring(vpninfo, &vpninfo->rx_vring);
	free_vring(vpninfo, &vpninfo->tx_vring);
}

/* used_event is the uint16_t element after the end of the
 * avail ring:
 *
 *	struct virtq_avail {
 *		le16 flags;
 *		le16 idx;
 *		le16 ring[ Queue Size ];
 *		le16 used_event;
 *	};
 */

#define USED_EVENT(v, r) ((r)->avail->ring[(v)->vhost_ring_size])

/* avail_event is the uint16_t element after the end of the
 * used ring, which is slightly less trivial to reference
 * than the used_event:
 *
 *	struct virtq_used_elem {
 *		le32 id;
 *		le32 len;
 *	};
 *
 *	struct virtq_used {
 *		le16 flags;
 *		le16 idx;
 *		struct virtq_used_elem ring[ Queue Size ];
 *		le16 avail_event;
 *	};
 *
 * So if we thought of it as an array of 16-bit values, 'flags' would
 * be at element [0], 'idx' at [1], the ring would start at [2], the
 * *second* element of the ring would be at [ 2 + 4 ] since each element
 * is as big as four 16-bit values, and thus avail_event would be at
 *  [2 + 4 * RING_SIZE ]
 */
#define AVAIL_EVENT(v, r) ((&(r)->used->flags)[2 + ((v)->vhost_ring_size * 4)])

static void dump_vring(struct openconnect_info *vpninfo, struct oc_vring *ring)
{
	vpn_progress(vpninfo, PRG_ERR,
		     "next_avail 0x%x, used idx 0x%x seen_used 0x%x\n",
		     vio16(ring->avail->idx), vio16(ring->used->idx),
		     ring->seen_used);

	vpn_progress(vpninfo, PRG_ERR, "#   ADDR         AVAIL         USED\n");

	/* Not an off-by-one; it's dumping avail_event and used_event too. */
	for (int i = 0; i < vpninfo->vhost_ring_size + 1; i++)
		vpn_progress(vpninfo, PRG_ERR,
			     "%d %p %x %x\n", i,
			     (void *)(unsigned long)vio64(ring->desc[i].addr),
			     vio16(ring->avail->ring[i]),
			     vio32(ring->used->ring[i].id));
}

/* With thanks to Eugenio Pérez Martin <eperezma@redhat.com> for writing
 * https://www.redhat.com/en/blog/virtqueues-and-virtio-ring-how-data-travels
 * which saved a lot of time and caffeine in getting this to work. */
static inline int process_ring(struct openconnect_info *vpninfo, int tx, uint64_t *kick)
{
	struct oc_vring *ring = tx ? &vpninfo->tx_vring : &vpninfo->rx_vring;
	const unsigned int ring_mask = vpninfo->vhost_ring_size - 1;
	int did_work = 0;

	/* First handle 'used' packets handed back to us from the ring.
	 * For TX packets (incoming from VPN into the tun device) we just
	 * free them now. For RX packets from the tun device we fill in
	 * the length and queue them for sending over the VPN. */
	uint16_t used_idx = vio16(ring->used->idx);
	while (used_idx != ring->seen_used) {
		uint32_t desc = vio32(ring->used->ring[ring->seen_used & ring_mask].id);
		uint32_t len  = vio32(ring->used->ring[ring->seen_used & ring_mask].len);

		if (desc > ring_mask) {
		inval:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error: vhost gave back invalid descriptor %d, len %d\n"),
				     desc, len);
			dump_vring(vpninfo, ring);
			vpninfo->quit_reason = "vhost error";
			return -EIO;
		}

		uint64_t addr = vio64(ring->desc[desc].addr);
		if (!addr) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("vhost gave back empty descriptor %d\n"),
				     desc);
			dump_vring(vpninfo, ring);
			vpninfo->quit_reason = "vhost error";
			return -EIO;
		}

		struct pkt *this = pkt_from_hdr(addr, virtio.h);

		if (tx) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Free TX packet %p [%d] [used %d]\n"),
				     this, ring->seen_used, used_idx);
			vpninfo->stats.rx_pkts++;
			vpninfo->stats.rx_bytes += this->len;

			free_pkt(vpninfo, this);
		} else {
			if (len < sizeof(this->virtio.h))
				goto inval;

			this->len = len - sizeof(this->virtio.h);
			vpn_progress(vpninfo, PRG_TRACE,
				     _("RX packet %p(%d) [%d] [used %d]\n"),
				     this, this->len, ring->seen_used, used_idx);
			if (debug_vhost)
				dump_buf_hex(vpninfo, PRG_TRACE, '<',
					     (void *) &this->virtio.h,
					     this->len + sizeof(this->virtio.h));

			vpninfo->stats.tx_pkts++;
			vpninfo->stats.tx_bytes += this->len;

			/* If the incoming queue fill up, pretend we can't see any more
			 * by contracting our idea of 'used_idx' back to *this* one. */
			if (queue_packet(&vpninfo->outgoing_queue, this) >= vpninfo->max_qlen)
				used_idx = ring->seen_used + 1;

			did_work = 1;
		}

		/* Zero the descriptor and line it up in the next slot in the avail ring. */
		ring->desc[desc].addr = 0;
		ring->avail->ring[ring->seen_used++ & ring_mask] = vio32(desc);
	}

	/* Now handle 'avail' and prime the RX ring full of empty buffers, or
	 * the TX ring with anything we have on the VPN incoming queue. */
	uint16_t next_avail = vio16(ring->avail->idx);
	uint32_t desc = ring->avail->ring[next_avail & ring_mask];
	while (!ring->desc[desc].addr) {
		struct pkt *this;
		if (tx) {
			this = dequeue_packet(&vpninfo->incoming_queue);
			if (!this)
				break;

			/* If only a few packets on the queue, just send them
			 * directly. The latency is much better. We benefit from
			 * vhost-net TX when we're overloaded and want to use all
			 * our CPU on the RX and crypto; there's not a lot of point
			 * otherwise. */
			if (!*kick && vpninfo->incoming_queue.count < vpninfo->max_qlen / 2 &&
			    next_avail == AVAIL_EVENT(vpninfo, ring)) {
				if (!os_write_tun(vpninfo, this)) {
					vpninfo->stats.rx_pkts++;
					vpninfo->stats.rx_bytes += this->len;

					free_pkt(vpninfo, this);
					continue;
				}
				/* Failed! Pretend it never happened; queue for vhost */
			}
			memset(&this->virtio.h, 0, sizeof(this->virtio.h));
		} else {
			int len = vpninfo->ip_info.mtu;
			this = alloc_pkt(vpninfo, len + vpninfo->pkt_trailer);
			if (!this)
				break;
			this->len = len;
		}

		if (!tx)
			ring->desc[desc].flags = vio16(VRING_DESC_F_WRITE);
		ring->desc[desc].addr = vio64((unsigned long)this + pkt_offset(virtio.h));
		ring->desc[desc].len = vio32(this->len + sizeof(this->virtio.h));
		barrier();

		if (debug_vhost) {
			if (tx) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Queue TX packet %p at desc %d avail %d\n"),
					     this, desc, next_avail);
				if (debug_vhost)
					dump_buf_hex(vpninfo, PRG_TRACE, '>',
						     (void *)&this->virtio.h,
						     this->len + sizeof(this->virtio.h));
			} else
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Queue RX packet %p at desc %d avail %d\n"),
					     this, desc, next_avail);
		}


		ring->avail->idx = vio16(++next_avail);
		barrier();
		uint16_t avail_event = AVAIL_EVENT(vpninfo, ring);
		barrier();
		if (avail_event == vio16(next_avail-1))
			*kick = 1;

		desc = ring->avail->ring[next_avail & ring_mask];
	}

	return did_work;
}

static int set_ring_wake(struct openconnect_info *vpninfo, int tx)
{
	/* No wakeup for tun RX if the queue is already full. */
	if (!tx && vpninfo->outgoing_queue.count >= vpninfo->max_qlen)
		return 0;

	struct oc_vring *ring = tx ? &vpninfo->tx_vring : &vpninfo->rx_vring;
	uint16_t wake_idx = vio16(ring->seen_used);

	/* Ask it to wake us if the used idx moves on. */
	USED_EVENT(vpninfo, ring) = wake_idx;
	barrier();

	/* If it already did, loop again immediately */
	if (ring->used->idx != wake_idx) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Immediate wake because vhost ring moved on from 0x%x to 0x%x\n"),
			     ring->used->idx, wake_idx);
		return 1;
	}

	return 0;
}

int vhost_tun_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable, int did_work)
{
	uint64_t kick = 0;

	if (vpninfo->outgoing_queue.count < vpninfo->max_qlen) {
		did_work += process_ring(vpninfo, 0, &kick);
		if (vpninfo->quit_reason)
			return 0;
	}

	did_work += process_ring(vpninfo, 1, &kick);
	if (vpninfo->quit_reason)
		return 0;

	if (kick) {
		barrier();
		if (write(vpninfo->vhost_kick_fd, &kick, sizeof(kick)) != sizeof(kick)) {
			/* Can never happen */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to kick vhost-net eventfd\n"));
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Kick vhost ring\n"));
		did_work = 1;
	}

	/* We only read from the eventfd when we're done with *actual*
	 * work, which is when !did_work. Except in the cases where
	 * we race with setting the ring wakeup and have to go round
	 * again. */
	if (!did_work && readable) {
		uint64_t evt;
		if (read(vpninfo->vhost_call_fd, &evt, sizeof(evt)) != sizeof(evt)) {
			/* Do nothing */
		}
	}

	/* If we aren't going to have one more turn around the mainloop,
	 * set the wake event indices. And if we find the rings have
	 * moved on while we're doing that, take one more turn around
	 * the mainloop... */
	return did_work || set_ring_wake(vpninfo, 1) || set_ring_wake(vpninfo, 0);
}
