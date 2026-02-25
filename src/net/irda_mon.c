// SPDX-License-Identifier: GPL-2.0
/*
 * IrDA Monitor Interface (irda_mon)
 *
 * Creates per-device virtual monitor interfaces (irdamon%d) that mirror
 * IrDA traffic for packet capture with Wireshark/tcpdump.
 *
 * Usage:
 *   modprobe irda_mon
 *   wireshark -i irdamon0 -k
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

#include <net/irda/irda.h>
#include <net/irda/irlap.h>
#include <net/irda/irda_mon.h>
#include <net/irda/irqueue.h>

/*
 * Per-device mapping: physical irda device <-> monitor device.
 * Protected by irda_mon_lock for writes, RCU for reads on hot path.
 */
struct irda_mon_pair {
	struct list_head  list;
	struct net_device *phys_dev;   /* physical irda%d device */
	struct net_device *mon_dev;    /* virtual irdamon%d device */
	struct rcu_head   rcu;
};

static LIST_HEAD(irda_mon_pairs);
static DEFINE_SPINLOCK(irda_mon_lock);
static struct workqueue_struct *irda_mon_wq;

/*
 * Work struct for deferring pair creation/destruction out of atomic context.
 */
struct irda_mon_work {
	struct work_struct work;
	struct net_device *dev;
	bool is_up;  /* true = create, false = destroy */
};

static void irda_mon_work_fn(struct work_struct *w);

/* --- Monitor netdev operations --- */

static netdev_tx_t irda_mon_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Monitor interface is receive-only; drop any transmitted frames */
	dev_kfree_skb_any(skb);
	dev->stats.tx_dropped++;
	return NETDEV_TX_OK;
}

static int irda_mon_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int irda_mon_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static const struct net_device_ops irda_mon_netdev_ops = {
	.ndo_open       = irda_mon_open,
	.ndo_stop       = irda_mon_stop,
	.ndo_start_xmit = irda_mon_xmit,
};

static void irda_mon_setup(struct net_device *dev)
{
	dev->netdev_ops      = &irda_mon_netdev_ops;
	dev->type            = ARPHRD_IRDA;
	dev->hard_header_len = 0;
	dev->addr_len        = LAP_ALEN;
	dev->mtu             = 2048;
	dev->flags           = IFF_NOARP;
	dev->needs_free_netdev = true;
	memset(dev->broadcast, 0xff, LAP_ALEN);
}

/* --- Pair management --- */

/*
 * Look up the monitor device for a given physical device.
 * Must be called under rcu_read_lock().
 */
static struct net_device *irda_mon_find_mon_dev(struct net_device *phys_dev)
{
	struct irda_mon_pair *pair;

	list_for_each_entry_rcu(pair, &irda_mon_pairs, list) {
		if (pair->phys_dev == phys_dev)
			return pair->mon_dev;
	}
	return NULL;
}

static void irda_mon_pair_free_rcu(struct rcu_head *head)
{
	struct irda_mon_pair *pair = container_of(head, struct irda_mon_pair, rcu);
	kfree(pair);
}

/*
 * Create a monitor interface for the given physical IrDA device.
 * Must NOT be called from atomic context (calls register_netdev).
 */
static int irda_mon_create_pair(struct net_device *phys_dev)
{
	struct irda_mon_pair *pair, *existing;
	struct net_device *mon_dev;
	int err;

	mon_dev = alloc_netdev(0, "irdamon%d", NET_NAME_UNKNOWN, irda_mon_setup);
	if (!mon_dev)
		return -ENOMEM;

	dev_addr_set(mon_dev, phys_dev->dev_addr);

	err = register_netdev(mon_dev);
	if (err) {
		free_netdev(mon_dev);
		return err;
	}

	pair = kzalloc(sizeof(*pair), GFP_KERNEL);
	if (!pair) {
		unregister_netdev(mon_dev);
		return -ENOMEM;
	}

	pair->phys_dev = phys_dev;
	pair->mon_dev = mon_dev;

	/* Re-check under lock to prevent duplicate creation */
	spin_lock(&irda_mon_lock);
	list_for_each_entry(existing, &irda_mon_pairs, list) {
		if (existing->phys_dev == phys_dev) {
			spin_unlock(&irda_mon_lock);
			unregister_netdev(mon_dev);
			kfree(pair);
			return 0;
		}
	}
	list_add_rcu(&pair->list, &irda_mon_pairs);
	spin_unlock(&irda_mon_lock);

	pr_info("irda_mon: created %s for %s\n", mon_dev->name, phys_dev->name);
	return 0;
}

/*
 * Remove the monitor interface for a given physical device.
 * Must NOT be called from atomic context.
 */
static void irda_mon_destroy_pair(struct net_device *phys_dev)
{
	struct irda_mon_pair *pair, *tmp;

	spin_lock(&irda_mon_lock);
	list_for_each_entry_safe(pair, tmp, &irda_mon_pairs, list) {
		if (pair->phys_dev == phys_dev) {
			list_del_rcu(&pair->list);
			spin_unlock(&irda_mon_lock);

			unregister_netdev(pair->mon_dev);
			call_rcu(&pair->rcu, irda_mon_pair_free_rcu);

			pr_info("irda_mon: removed monitor for %s\n",
				phys_dev->name);
			return;
		}
	}
	spin_unlock(&irda_mon_lock);
}

static void irda_mon_destroy_all(void)
{
	struct irda_mon_pair *pair, *tmp;

	spin_lock(&irda_mon_lock);
	list_for_each_entry_safe(pair, tmp, &irda_mon_pairs, list) {
		list_del_rcu(&pair->list);
		spin_unlock(&irda_mon_lock);

		unregister_netdev(pair->mon_dev);
		call_rcu(&pair->rcu, irda_mon_pair_free_rcu);

		spin_lock(&irda_mon_lock);
	}
	spin_unlock(&irda_mon_lock);
}

static void irda_mon_work_fn(struct work_struct *w)
{
	struct irda_mon_work *mw = container_of(w, struct irda_mon_work, work);

	if (mw->is_up)
		irda_mon_create_pair(mw->dev);
	else
		irda_mon_destroy_pair(mw->dev);

	dev_put(mw->dev);
	kfree(mw);
}

/* --- Notifier callback --- */

static int irda_mon_notify(struct notifier_block *nb, unsigned long event,
			   void *data)
{
	switch (event) {
	case IRDA_MON_RX:
	case IRDA_MON_TX: {
		struct irda_mon_event *ev = data;
		struct sk_buff *clone;
		struct net_device *mon_dev;

		rcu_read_lock();
		mon_dev = irda_mon_find_mon_dev(ev->dev);
		if (!mon_dev || !(mon_dev->flags & IFF_UP)) {
			rcu_read_unlock();
			break;
		}
		dev_hold(mon_dev);
		rcu_read_unlock();

		clone = skb_clone(ev->skb, GFP_ATOMIC);
		if (clone) {
			unsigned int len = clone->len;

			clone->dev = mon_dev;
			clone->protocol = htons(ETH_P_IRDA);
			skb_reset_mac_header(clone);

			if (event == IRDA_MON_TX)
				clone->pkt_type = PACKET_OUTGOING;

			netif_rx(clone);

			mon_dev->stats.rx_packets++;
			mon_dev->stats.rx_bytes += len;
		}
		dev_put(mon_dev);
		break;
	}
	case IRDA_MON_DEV_UP:
	case IRDA_MON_DEV_DOWN: {
		struct irda_mon_dev_event *ev = data;
		struct irda_mon_work *mw;

		mw = kzalloc(sizeof(*mw), GFP_ATOMIC);
		if (mw) {
			INIT_WORK(&mw->work, irda_mon_work_fn);
			dev_hold(ev->dev);
			mw->dev = ev->dev;
			mw->is_up = (event == IRDA_MON_DEV_UP);
			queue_work(irda_mon_wq, &mw->work);
		}
		break;
	}
	}

	return NOTIFY_OK;
}

static struct notifier_block irda_mon_nb = {
	.notifier_call = irda_mon_notify,
};

/* --- Module init/exit --- */

static int __init irda_mon_init(void)
{
	struct net_device *devs[16];
	struct irlap_cb *lap;
	int count = 0;
	int err, i;

	irda_mon_wq = alloc_workqueue("irda_mon", 0, 0);
	if (!irda_mon_wq)
		return -ENOMEM;

	err = atomic_notifier_chain_register(&irda_mon_chain, &irda_mon_nb);
	if (err) {
		destroy_workqueue(irda_mon_wq);
		return err;
	}

	/*
	 * Walk the existing irlap hashbin to pick up IrDA devices
	 * that were registered before this module loaded.
	 * Collect device pointers under lock, then create pairs outside.
	 */
	if (irlap) {
		spin_lock_irq(&irlap->hb_spinlock);
		for (lap = (struct irlap_cb *)hashbin_get_first(irlap);
		     lap;
		     lap = (struct irlap_cb *)hashbin_get_next(irlap)) {
			if (lap->netdev && count < ARRAY_SIZE(devs)) {
				dev_hold(lap->netdev);
				devs[count++] = lap->netdev;
			}
		}
		spin_unlock_irq(&irlap->hb_spinlock);

		for (i = 0; i < count; i++) {
			irda_mon_create_pair(devs[i]);
			dev_put(devs[i]);
		}
	}

	pr_info("irda_mon: IrDA monitor interface loaded\n");
	return 0;
}

static void __exit irda_mon_exit(void)
{
	atomic_notifier_chain_unregister(&irda_mon_chain, &irda_mon_nb);

	/* Wait for any in-flight RCU callbacks */
	synchronize_rcu();

	/* Ensure all deferred work (DEV_UP/DEV_DOWN) has completed */
	drain_workqueue(irda_mon_wq);

	irda_mon_destroy_all();

	/* Final RCU grace period for destroyed pairs */
	rcu_barrier();

	destroy_workqueue(irda_mon_wq);

	pr_info("irda_mon: IrDA monitor interface unloaded\n");
}

module_init(irda_mon_init);
module_exit(irda_mon_exit);

MODULE_AUTHOR("IrDA Project");
MODULE_DESCRIPTION("IrDA monitor interface for packet capture");
MODULE_SOFTDEP("pre: irda");
MODULE_LICENSE("GPL");
