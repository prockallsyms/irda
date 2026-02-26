# IrDA Monitor Interface Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a loadable kernel module (`irda_mon.ko`) that creates per-device virtual monitor interfaces (`irdamon%d`) for Wireshark/tcpdump packet capture of IrDA traffic.

**Architecture:** Atomic notifier chain in `irda.ko` fires at IrLAP TX/RX choke points and device lifecycle events. The separate `irda_mon.ko` module subscribes, clones frames to virtual monitor netdevs with `ARPHRD_IRDA` type so libpcap maps them to `DLT_IRDA` and Wireshark's full IrDA dissector chain fires automatically.

**Tech Stack:** Linux kernel C, Kbuild, atomic notifier chains, net_device API, RCU

**Design doc:** `docs/plans/2026-02-20-irda-monitor-design.md`

---

### Task 1: Create the header — `irda_mon.h`

Defines event types, the event struct, and the extern notifier chain.

**Files:**
- Create: `src/include/net/irda/irda_mon.h`

**Step 1: Write the header**

```c
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
```

**Step 2: Verify it compiles**

Run: `make -C src`
Expected: Compiles successfully (header is not yet included by anything, so no change to build output).

**Step 3: Commit**

```
feat(irda_mon): add irda_mon.h header with notifier event types
```

---

### Task 2: Add the notifier chain to `irda.ko`

Declare the atomic notifier head in `irmod.c` and export it so `irda_mon.ko` can subscribe.

**Files:**
- Modify: `src/net/irmod.c`

**Step 1: Add the notifier chain declaration**

In `src/net/irmod.c`, after the existing includes (line 43), add:

```c
#include <net/irda/irda_mon.h>
```

After the `irda_packet_type` definition (after line 51), add:

```c
/*
 * Monitor notifier chain.
 * Used by irda_mon.ko to receive packet capture and device lifecycle events.
 * Atomic because TX/RX hooks fire in softirq context.
 */
ATOMIC_NOTIFIER_HEAD(irda_mon_chain);
EXPORT_SYMBOL(irda_mon_chain);
```

**Step 2: Verify it compiles**

Run: `make -C src`
Expected: `irda.ko` builds successfully. `irda_mon_chain` appears in the module's exported symbols.

**Step 3: Commit**

```
feat(irda_mon): declare and export irda_mon_chain in irmod.c
```

---

### Task 3: Add TX/RX notifier hooks in `irlap_frame.c`

Fire the notifier at both packet capture points.

**Files:**
- Modify: `src/net/irlap_frame.c`

**Step 1: Add the include**

At the top of `src/net/irlap_frame.c`, after the existing includes, add:

```c
#include <net/irda/irda_mon.h>
```

**Step 2: Add TX hook in `irlap_queue_xmit()`**

In `irlap_queue_xmit()` (line 93), add the notifier call just before
`dev_queue_xmit(skb)` (line 112) but after the monitor-mode check
(after line 110):

```c
	/* Notify monitor subscribers (irda_mon.ko) of outgoing frame */
	{
		struct irda_mon_event ev = { .skb = skb, .dev = self->netdev };
		atomic_notifier_call_chain(&irda_mon_chain, IRDA_MON_TX, &ev);
	}

	dev_queue_xmit(skb);
```

**Step 3: Add RX hook in `irlap_driver_rcv()`**

In `irlap_driver_rcv()` (line 1281), add the notifier call after
`skb_share_check` and `pskb_may_pull` validation (after line 1312),
but before the frame parsing begins (before line 1314):

```c
	/* Notify monitor subscribers (irda_mon.ko) of incoming frame */
	{
		struct irda_mon_event ev = { .skb = skb, .dev = dev };
		atomic_notifier_call_chain(&irda_mon_chain, IRDA_MON_RX, &ev);
	}

```

**Step 4: Verify it compiles**

Run: `make -C src`
Expected: `irda.ko` builds successfully with the two new hook callouts.

**Step 5: Commit**

```
feat(irda_mon): add TX/RX notifier hooks in irlap_frame.c
```

---

### Task 4: Add device lifecycle notifier hooks in `irlap.c`

Fire `IRDA_MON_DEV_UP` from `irlap_open()` and `IRDA_MON_DEV_DOWN` from `irlap_close()`.

**Files:**
- Modify: `src/net/irlap.c`

**Step 1: Add the include**

At the top of `src/net/irlap.c`, after the existing includes (after line 48), add:

```c
#include <net/irda/irda_mon.h>
```

**Step 2: Add DEV_UP hook in `irlap_open()`**

In `irlap_open()`, just before `return self;` (line 172), after
`hashbin_insert` and `irlmp_register_link`, add:

```c
	/* Notify monitor subscribers of new IrDA device */
	{
		struct irda_mon_dev_event ev = { .dev = dev };
		atomic_notifier_call_chain(&irda_mon_chain, IRDA_MON_DEV_UP, &ev);
	}
```

**Step 3: Add DEV_DOWN hook in `irlap_close()`**

In `irlap_close()` (line 210), add the notification at the very top of
the function, before `irlmp_unregister_link` (before line 222), after the
IRDA_ASSERT checks:

```c
	/* Notify monitor subscribers before device teardown */
	{
		struct irda_mon_dev_event ev = { .dev = self->netdev };
		atomic_notifier_call_chain(&irda_mon_chain, IRDA_MON_DEV_DOWN, &ev);
	}
```

**Step 4: Verify it compiles**

Run: `make -C src`
Expected: `irda.ko` builds successfully.

**Step 5: Commit**

```
feat(irda_mon): add device lifecycle notifier hooks in irlap.c
```

---

### Task 5: Export the `irlap` hashbin for device enumeration

The monitor module needs to walk existing devices on init. The `irlap` hashbin
is currently `static` in `irlap.c`.

**Files:**
- Modify: `src/net/irlap.c`
- Modify: `src/include/net/irda/irlap.h`

**Step 1: Export the hashbin**

In `src/net/irlap.c`, line 51, change:

```c
static hashbin_t *irlap = NULL;
```

to:

```c
hashbin_t *irlap = NULL;
EXPORT_SYMBOL(irlap);
```

**Step 2: Add extern declaration**

In `src/include/net/irda/irlap.h`, before the function prototypes
(before line 218 `int irlap_init(void);`), add:

```c
/* IrLAP device hashbin — exported for irda_mon.ko device enumeration */
extern hashbin_t *irlap;
```

**Step 3: Verify it compiles**

Run: `make -C src`
Expected: Builds successfully. No other code is affected since the variable
was already accessed by name within irlap.c.

**Step 4: Commit**

```
feat(irda_mon): export irlap hashbin for device enumeration
```

---

### Task 6: Implement the monitor module — `irda_mon.c`

The core module that creates virtual monitor netdevs and clones packets to them.

**Files:**
- Create: `src/net/irda_mon.c`

**Step 1: Write the module**

```c
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

#include <net/irda/irda.h>
#include <net/irda/irlap.h>
#include <net/irda/irda_mon.h>
#include <net/irda/irqueue.h>

#define IRDA_MON_MAGIC 0x4d4f4e  /* "MON" */

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

/* --- Monitor netdev operations --- */

static netdev_tx_t irda_mon_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* Monitor interface is receive-only; drop any transmitted frames */
	dev_kfree_skb(skb);
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
	struct irda_mon_pair *pair;
	struct net_device *mon_dev;
	int err;

	/* Check if pair already exists */
	rcu_read_lock();
	if (irda_mon_find_mon_dev(phys_dev)) {
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	mon_dev = alloc_netdev(0, "irdamon%d", NET_NAME_UNKNOWN, irda_mon_setup);
	if (!mon_dev)
		return -ENOMEM;

	/* Copy device address from physical device */
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

	spin_lock(&irda_mon_lock);
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
			clone->dev = mon_dev;
			clone->protocol = htons(ETH_P_IRDA);
			skb_reset_mac_header(clone);

			if (event == IRDA_MON_TX)
				clone->pkt_type = PACKET_OUTGOING;

			netif_rx(clone);

			mon_dev->stats.rx_packets++;
			mon_dev->stats.rx_bytes += clone->len;
		}
		dev_put(mon_dev);
		break;
	}
	case IRDA_MON_DEV_UP: {
		struct irda_mon_dev_event *ev = data;
		irda_mon_create_pair(ev->dev);
		break;
	}
	case IRDA_MON_DEV_DOWN: {
		struct irda_mon_dev_event *ev = data;
		irda_mon_destroy_pair(ev->dev);
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
	struct irlap_cb *lap;
	int err;

	err = atomic_notifier_chain_register(&irda_mon_chain, &irda_mon_nb);
	if (err)
		return err;

	/*
	 * Walk the existing irlap hashbin to pick up IrDA devices
	 * that were registered before this module loaded.
	 */
	if (irlap) {
		spin_lock_irq(&irlap->hb_spinlock);
		for (lap = (struct irlap_cb *)hashbin_get_first(irlap);
		     lap;
		     lap = (struct irlap_cb *)hashbin_get_next(irlap)) {
			if (lap->netdev) {
				spin_unlock_irq(&irlap->hb_spinlock);
				irda_mon_create_pair(lap->netdev);
				spin_lock_irq(&irlap->hb_spinlock);
			}
		}
		spin_unlock_irq(&irlap->hb_spinlock);
	}

	pr_info("irda_mon: IrDA monitor interface loaded\n");
	return 0;
}

static void __exit irda_mon_exit(void)
{
	atomic_notifier_chain_unregister(&irda_mon_chain, &irda_mon_nb);

	/* Wait for any in-flight RCU callbacks */
	synchronize_rcu();

	irda_mon_destroy_all();

	/* Final RCU grace period for destroyed pairs */
	rcu_barrier();

	pr_info("irda_mon: IrDA monitor interface unloaded\n");
}

module_init(irda_mon_init);
module_exit(irda_mon_exit);

MODULE_AUTHOR("IrDA Project");
MODULE_DESCRIPTION("IrDA monitor interface for packet capture");
MODULE_LICENSE("GPL");
```

**Step 2: Verify it compiles**

Run: `make -C src`
Expected: Will fail — `irda_mon.c` is not yet added to Kbuild. That's Task 7.

**Step 3: Commit**

```
feat(irda_mon): implement monitor module irda_mon.c
```

---

### Task 7: Wire up Kbuild and DKMS

Add the new module to the build system.

**Files:**
- Modify: `src/net/Kbuild`
- Modify: `src/dkms.conf.in`

**Step 1: Add to Kbuild**

In `src/net/Kbuild`, after line 7 (`obj-m += irda.o`), add:

```
obj-m += irda_mon.o
```

**Step 2: Add to DKMS config**

In `src/dkms.conf.in`, find the last `BUILT_MODULE_NAME` entry and add a
new entry at the next index. The current last index should be checked, then
append:

```
BUILT_MODULE_NAME[N]=irda_mon
BUILT_MODULE_LOCATION[N]=net
DEST_MODULE_LOCATION[N]=/kernel/net/irda
```

(Where `N` is the next sequential index.)

**Step 3: Verify it compiles**

Run: `make -C src`
Expected: Both `irda.ko` and `irda_mon.ko` build successfully. Verify:

```bash
ls -la src/net/irda.ko src/net/irda_mon.ko
```

**Step 4: Verify module info**

Run: `modinfo src/net/irda_mon.ko`
Expected: Shows description "IrDA monitor interface for packet capture", license GPL.

**Step 5: Commit**

```
feat(irda_mon): add irda_mon to Kbuild and DKMS config
```

---

### Task 8: Smoke test — load modules and verify interface creation

Manual verification that the module loads and behaves correctly.

**Step 1: Load the IrDA stack**

```bash
sudo insmod src/net/irda.ko
```

Expected: Module loads, `dmesg` shows no errors.

**Step 2: Load the monitor module**

```bash
sudo insmod src/net/irda_mon.ko
```

Expected: Module loads, `dmesg` shows "irda_mon: IrDA monitor interface loaded".
No `irdamon` interfaces yet (no physical IrDA devices present).

**Step 3: Verify the monitor module is loaded**

```bash
lsmod | grep irda_mon
```

Expected: `irda_mon` appears, depends on `irda`.

**Step 4: Unload in reverse order**

```bash
sudo rmmod irda_mon
sudo rmmod irda
```

Expected: Clean unload, `dmesg` shows "irda_mon: IrDA monitor interface unloaded".

**Step 5: Commit**

No code changes — this is a manual verification step only.

---

### Task 9: Update CLAUDE.md

Document the new module.

**Files:**
- Modify: `CLAUDE.md`

**Step 1: Add irda_mon section**

Under the **Architecture** section, after the device drivers paragraph, add:

```markdown
**Monitor interface** (`src/net/irda_mon.c`) — builds `irda_mon.ko`:
- Creates per-device virtual `irdamon%d` interfaces for Wireshark/tcpdump capture
- Subscribes to atomic notifier chain (`irda_mon_chain`) in `irda.ko`
- Hook points: `irlap_queue_xmit()` (TX), `irlap_driver_rcv()` (RX), `irlap_open()`/`irlap_close()` (device lifecycle)
- Clones IrLAP frames to monitor netdev with `ARPHRD_IRDA` → Wireshark sees `DLT_IRDA` and decodes full stack (IrLAP/IrLMP/IrTTP/OBEX)
```

**Step 2: Commit**

```
docs: document irda_mon module in CLAUDE.md
```
