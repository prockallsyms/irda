# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Out-of-tree Linux kernel module project maintaining the IrDA (Infrared Data Association) subsystem and device drivers, removed from mainline Linux in v4.17. Builds 30 loadable kernel modules covering the full IrDA protocol stack, hardware drivers, and packet capture.

Minimum supported kernel: Linux 6.6 (older versions via kernel-* git tags).

## Build Commands

```bash
# Build all modules against the running kernel
make -C src

# Build a specific module
make -C "/lib/modules/$(uname -r)/build" M="$(pwd)/src" net/irda.ko

# Install modules
make -C src install

# Clean build artifacts
make -C src clean

# DKMS install
autoconf -f && ./configure
dkms add src
dkms install "irda/$(git show --pretty=format:'%cd~%h' --date='format:%Y%m%d' | head -1)"
```

Build requires: `build-essential libelf-dev libssl-dev flex bison bc`

CI builds against both mainline and stable kernels using `defconfig` plus `.extraconfig` overrides (`CONFIG_ATALK=m`, `CONFIG_PPP=m`).

## Architecture

The IrDA stack is layered, all under `src/`:

**Core protocol stack** (`src/net/`) — builds `irda.ko`:
- `irmod.c` — module entry point; init order: irlmp → irlap → irda_device → iriap → irttp → irsock → packet handler → proc/sysctl/netlink
- `irlap*.c` — Link Access Protocol (framing, connection management)
- `irlmp*.c` — Link Management Protocol (multiplexing, discovery)
- `irttp.c` — TinyTP transport (segmentation/reassembly, flow control)
- `iriap*.c` — Information Access Protocol (service discovery)
- `af_irda.c` — Socket interface (SOCK_STREAM, SOCK_SEQPACKET, SOCK_DGRAM)

**Protocol layer modules** (`src/net/irlan/`, `src/net/irnet/`, `src/net/ircomm/`):
- IrLAN — LAN access over IrDA
- IrNET — PPP over IrDA (conditional on CONFIG_PPP)
- IrCOMM — serial port emulation (conditional on CONFIG_TTY)

**Monitor interface** (`src/net/irda_mon.c`) — builds `irda_mon.ko`:
- Creates per-device virtual `irdamon%d` interfaces for Wireshark/tcpdump capture
- Subscribes to atomic notifier chain (`irda_mon_chain`) in `irda.ko`
- Hook points: `irlap_queue_xmit()` (TX), `irlap_driver_rcv()` (RX), `irlap_open()`/`irlap_close()` (device lifecycle)
- Clones IrLAP frames to monitor netdev with `ARPHRD_IRDA` → Wireshark sees `DLT_IRDA` and decodes full stack (IrLAP/IrLMP/IrTTP/OBEX)

**Device drivers** (`src/drivers/`) — FIR (4 Mbps), SIR (115.2 kbps), and dongle drivers for USB, PCI, ISA, and platform-specific hardware.

**Headers** (`src/include/net/irda/`) — internal kernel API shared across modules.

## Build System

Uses Linux kernel Kbuild. `src/Kbuild` defines compile-time feature flags:
- `CONFIG_IRDA_ULTRA`, `CONFIG_IRDA_CACHE_LAST_LSAP`, `CONFIG_IRDA_FAST_RR`, `CONFIG_IRDA_DEBUG`

Driver compilation is conditional on kernel config (CONFIG_USB, CONFIG_PCI, CONFIG_ISA_DMA_API, CONFIG_TTY, arch-specific flags). See `src/drivers/Kbuild` for details.

## Development Patterns

Commits primarily track Linux kernel API changes (new rc releases) and fix compiler warnings/errors from evolving kernel internals. When updating for a new kernel version, check for changed function signatures, deprecated APIs, and struct field modifications across the entire driver and protocol codebase.

Commit messages use short imperative sentences without conventional commit prefixes (no `feat:`, `fix:`, etc.). Examples: "Update for Linux 6.19-rc1", "Fix sysctl registration", "Export irlap hashbin for device enumeration".

Feature design documents live in `docs/plans/`.
