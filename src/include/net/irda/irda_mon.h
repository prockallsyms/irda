/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IrDA Monitor Interface - packet capture support
 *
 * Defines the notifier chain and event types used by irda_mon.ko
 * to receive packet and device lifecycle events from the IrDA stack.
 */

#ifndef IRDA_MON_H
#define IRDA_MON_H

#include <linux/notifier.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

/* Notifier event types */
#define IRDA_MON_RX      0x01   /* Frame received (irlap_driver_rcv) */
#define IRDA_MON_TX      0x02   /* Frame transmitted (irlap_queue_xmit) */
#define IRDA_MON_DEV_UP  0x03   /* IrDA device registered (irlap_open) */
#define IRDA_MON_DEV_DOWN 0x04  /* IrDA device removed (irlap_close) */

/* Event data for RX/TX notifications */
struct irda_mon_event {
	struct sk_buff    *skb;
	struct net_device *dev;
};

/* Event data for device lifecycle notifications */
struct irda_mon_dev_event {
	struct net_device *dev;
};

/* Notifier chain declared in irmod.c, exported for irda_mon.ko */
extern struct atomic_notifier_head irda_mon_chain;

#endif /* IRDA_MON_H */
