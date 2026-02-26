# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Out-of-tree Linux kernel module project maintaining the IrDA (Infrared Data Association) subsystem and device drivers, removed from mainline Linux in v4.17. Builds 30 loadable kernel modules covering the full IrDA protocol stack, hardware drivers, and packet capture.

Minimum supported kernel: Linux 6.6 (older versions via kernel-* git tags).

## Build Commands

Module compilation, installation, and loading use DKMS. The `./irda` CLI wraps these operations:

```bash
# First-time setup (installs deps, builds, installs via DKMS)
sudo ./irda init

# Rebuild after code changes (removes old DKMS, reconfigures, reinstalls)
sudo ./irda rebuild

# Manual DKMS workflow (equivalent to what the CLI does)
autoconf -f && ./configure           # Generate dkms.conf with current version
sudo dkms add src                    # Register source tree
sudo dkms install irda/<version>     # Build + install + depmod

# Build a specific module (for development iteration)
make -C "/lib/modules/$(uname -r)/build" M="$(pwd)/src" net/irda.ko
```

Build requires: `build-essential libelf-dev libssl-dev flex bison bc dkms autoconf`

CI builds against both mainline and stable kernels using `defconfig` plus `.extraconfig` overrides (`CONFIG_ATALK=m`, `CONFIG_PPP=m`).

## CLI Tool

All management scripts live in `custom/scripts/` and are accessed via a single `./irda` entry point (symlink at project root):

```bash
sudo ./irda init                   # First-time setup after cloning (firmware, blacklist, headers, build, load)
sudo ./irda setup start           # Load modules, bring up interfaces, enable discovery
sudo ./irda setup start --capture  # ... and start tcpdump on each irdamon interface
sudo ./irda setup stop             # Kill captures, tear down interfaces, unload modules
./irda setup status                # Show USB devices, modules, interfaces, discovery (no root)
sudo ./irda test server            # Start echo server on first dongle
sudo ./irda test client            # Discover remote device, run echo tests
sudo ./irda rebuild                # Rebuild and reinstall all modules via DKMS
```

The `init` command handles first-time setup: installs STIr421x firmware from the bundled archive, creates the ir_usb blacklist, installs kernel headers and build dependencies (including `dkms` and `autoconf`) via apt, builds and installs modules via DKMS, and loads them with `modprobe`. Only tested on Kali with kernel 6.18.9+kali-amd64.

The `setup start` command handles: checking DKMS install status, blacklisting the in-kernel `ir_usb` driver, loading modules via `modprobe` in dependency order (`irda` → `irda_mon` → USB drivers), waiting for interfaces, bringing them up, and enabling discovery.

## Hardware Notes

**Tested hardware:**
- Actisys ACT-IR2002UL — MCS7780 chipset (USB `9710:7780`) → `mcs7780.ko`
- Actisys ACT-IR2012UL — STIr4210 chipset (USB `066f:4210`) → `irda-usb.ko`

**ir_usb blacklist:** The in-kernel `ir_usb` USB-serial driver has a wildcard USB class alias (`0xFE/0x02` = IrDA Bridge) that auto-loads and claims IrDA USB devices before our drivers can. Must be blacklisted in `/etc/modprobe.d/irda-blacklist.conf`. The setup script handles this automatically.

**STIr4200 vs STIr4210:** Despite similar names, these are completely different chips. STIr4200 (`066f:4200`) uses `stir4200.ko` with vendor-specific register I/O. STIr4210/4220/4116 (`066f:4210`, `066f:4220`, `066f:4116`) use `irda-usb.ko` with firmware upload. Loading the wrong driver will freeze the system.

**STIr421x firmware:** The `irda-usb.ko` driver requires firmware files in `/lib/firmware/`. Files are named `4210XXXX.sb` where `XXXX` is the USB bcdDevice value (typically `42101001.sb` and `42101002.sb`). Firmware is available from archived SigmaTel/linux-IrDA sources.

**Monitor interface lifecycle:** `irdamon%d` interfaces are created when the corresponding `irda%d` interface is brought up (`ip link set irda0 up`), not at USB probe time. This is because `irda-usb.c` calls `irlap_open()` from `ndo_open`, not during probe.

**IrDA discovery:** Enable with `echo 1 > /proc/sys/net/irda/discovery`. Results appear in `/proc/net/irda/discovery` after a few seconds. The setup script enables this automatically.

**MCS7780 speed change bug:** The MCS7780 driver (`mcs7780.ko`) fails to change the IR link speed after IrLAP connection negotiation — `mcs_speed_change()` polls `MCS_IRINTX` in `MCS_RESV_REG` but the transmitter doesn't clear in time. Workaround: cap the negotiated speed at 9600 baud so no speed change is needed: `echo 9600 > /proc/sys/net/irda/max_baud_rate`. The setup script applies this automatically. Root cause: the 100-iteration busy-wait poll in `mcs7780.c:597-599` doesn't account for USB transfer latency.

## Scapy Dissector

`custom/scripts/scapy/contrib/irda.py` implements the full IrDA protocol stack as scapy layers, structured for upstream contribution to scapy. Requires a `usercustomize.py` import hook (see `~/.local/lib/python3.13/site-packages/usercustomize.py`) to resolve the local contrib path.

**Layers:** IrLAP (address/control dispatch, I/S/U frames), IrLAP_XID (discovery), IrLAP_SNRM/UA (connection setup with QoS negotiation), IrLMP (LSAP multiplexing), IrTTP (credit-based flow control), IrIAS (service discovery queries), IrOBEX (object exchange with typed headers).

**DLT integration:** Overrides scapy's built-in `layers/ir.py` bindings. Registers `CookedLinux(proto=23) → IrLAP` for `DLT_LINUX_IRDA` (144) pcap files from irdamon captures.

```bash
# Read a capture
python3 -c "from scapy.contrib.irda import *; rdpcap('/tmp/irda.pcap').summary()"

# Interactive dissection
sudo tshark -i irdamon0 -w /tmp/irda.pcap
python3 -c "from scapy.contrib.irda import *; rdpcap('/tmp/irda.pcap')[0].show()"

# Run tests
python3 -m scapy.tools.UTscapy -f text custom/scripts/tests/irda_scapy.uts
```

## Test Tool

`./irda test` generates real multi-layer IrDA traffic between two dongles using `AF_IRDA` sockets:

```bash
# Terminal 1: echo server on one dongle
sudo ./irda test server

# Terminal 2: client discovers and connects, sends test patterns
sudo ./irda test client
```

Generates IrLAP (SNRM/UA/I-frames/DISC), IrLMP (connect/data), TTP (credit flow, SAR for large transfers), and IAS (service name resolution) — all visible in tshark or scapy on the irdamon interfaces.

**AF_IRDA socket workaround:** Python's socket module was compiled without `linux/irda.h` (removed from mainline in v4.17), so `bind()`/`connect()`/`accept()` fail with "bad family". The test tool works around this using ctypes to call libc directly with manually-packed `sockaddr_irda` structs (36 bytes: family + lsap_sel + padding + addr + name[25] + trailing padding). The `sir_lsap_sel` field must be `LSAP_ANY` (0xFF) for service-name binding/connecting, not 0 (which is reserved for IAS and rejected by `irttp_open_tsap`).

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
