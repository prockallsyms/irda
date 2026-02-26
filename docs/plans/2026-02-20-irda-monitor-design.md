# IrDA Monitor Interface Design

Packet capture abstraction layer for the IrDA kernel stack, enabling
Wireshark/tcpdump traffic analysis via per-device virtual monitor interfaces.

## Goals

- Capture all IrDA traffic (TX and RX) at the IrLAP layer as raw frames
- Deliver frames to userspace via standard libpcap/Wireshark workflow
- Support full protocol dissection: IrLAP, IrLMP, IrTTP, IrCOMM, OBEX, IAS
- Per-physical-device monitor interfaces (irdamon0 pairs with irda0, etc.)
- Zero overhead when the monitor module is not loaded

## Architecture

### Module Structure

**`irda_mon.ko`** — separate loadable module (`src/net/irda_mon.c`).

**Changes to `irda.ko`**:
- `irmod.c`: declare and export `ATOMIC_NOTIFIER_HEAD(irda_mon_chain)`
- `irlap_frame.c`: fire notifier in `irlap_queue_xmit()` (TX) and
  `irlap_driver_rcv()` (RX)
- `irlap.c`: fire notifier in `irlap_open()` / `irlap_close()` for
  device lifecycle

**New files**:
- `src/include/net/irda/irda_mon.h` — event types, notifier chain extern
- `src/net/irda_mon.c` — monitor module

### Hook Mechanism: Atomic Notifier Chain

Both TX and RX hook points run in softirq context (packet path), so the
chain must be `ATOMIC_NOTIFIER` (no sleeping in callbacks).

Three event types on `irda_mon_chain`:

| Event           | Fired from            | Data                           |
|-----------------|-----------------------|--------------------------------|
| `IRDA_MON_RX`  | `irlap_driver_rcv()`  | skb + originating net_device   |
| `IRDA_MON_TX`  | `irlap_queue_xmit()`  | skb + originating net_device   |
| `IRDA_MON_DEV` | `irlap_open/close()`  | net_device + up/down flag      |

Event data passed via:

```c
struct irda_mon_event {
    struct sk_buff    *skb;
    struct net_device *dev;
    int                direction;  /* IRDA_MON_RX or IRDA_MON_TX */
};
```

### Monitor Callback (RX/TX)

1. Look up paired `irdamon%d` for the given physical device
2. `skb_clone()` — cheap copy, shares data buffer
3. Set `clone->dev` to the monitor netdev
4. Set `clone->pkt_type` to `PACKET_OUTGOING` for TX (Wireshark shows direction)
5. `netif_rx(clone)` — delivers to any libpcap listener

If no pcap socket is open, `netif_rx` drops the clone cheaply. If the
monitor module isn't loaded, the notifier chain has no subscribers and
returns immediately.

### Monitor Netdev Properties

```c
dev->type            = ARPHRD_IRDA;   /* libpcap maps to DLT_IRDA (144) */
dev->hard_header_len = 0;
dev->addr_len        = LAP_ALEN;      /* 4 bytes */
dev->mtu             = 2048;
dev->flags           = IFF_NOARP | IFF_RUNNING;
```

- `ndo_start_xmit`: no-op, drops packets (receive-only interface)
- `ndo_open`/`ndo_stop`: minimal, just toggle IFF_UP
- Net namespace: `init_net` (matches physical IrDA devices)

### Device Lifecycle

**Module init:**
1. Register on `irda_mon_chain` for RX/TX/DEV events
2. Walk existing `irlap` hashbin to find current IrDA devices
3. Create paired `irdamon%d` for each

**`IRDA_MON_DEV` (device up):**
- `irlap_open()` fires notifier after device is initialized
- Monitor creates `irdamon%d`, copies device address, `register_netdev()`

**`IRDA_MON_DEV` (device down):**
- `irlap_close()` fires notifier before teardown
- Monitor calls `unregister_netdev()`, frees monitor netdev, removes mapping

**Module exit:**
1. Unregister from notifier chain
2. Destroy all remaining monitor netdevs
3. Clean up mapping table

**Race protection:** Atomic notifier serialization plus `rtnl_lock()` for
netdev creation/destruction. RX/TX callbacks use RCU-style lookup of the
device mapping — if a monitor netdev is being torn down, lookup returns
NULL and the callback is a no-op.

### Frame Content

Captured frames are raw IrLAP (what DLT_IRDA expects):

```
[CADDR 1B] [Control 1B] [IrLMP header 2B] [IrTTP header 1B] [Payload...]
```

- RX: hooked after `skb_share_check()`, before frame parsing
- TX: hooked after headers are pushed, before `dev_queue_xmit()`

Wireshark decodes the full stack automatically:
IrLAP -> IrLMP -> IrTTP -> IrCOMM / IAS / OBEX

## Usage

```bash
modprobe irda_mon
wireshark -i irdamon0 -k
# or
tcpdump -i irdamon0 -w capture.pcap
```
