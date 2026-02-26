"""IrDA setup subcommand: module loading, interface bringup, packet capture."""

import os
import re
import signal
import subprocess
import sys
import time

from irda_common import (
    UNLOAD_ORDER, CORE_MODULE_NAMES, USB_DRIVER_MODULE_NAMES,
    DKMS_PACKAGE,
    BLACKLIST_CONF, BLACKLIST_LINE, DISCOVERY_SYSCTL, MAX_BAUD_RATE_SYSCTL,
    DISCOVERY_LOG, STIR421X_PRODUCTS, FIRMWARE_DIR,
    header, ok, warn, fail, info,
    run, is_module_loaded, check_root, get_dkms_status,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_interfaces(pattern):
    """Return list of network interfaces matching a regex pattern."""
    try:
        names = os.listdir("/sys/class/net")
    except OSError:
        return []
    return sorted(n for n in names if re.match(pattern, n))


def get_interface_state(iface):
    """Return operstate of an interface."""
    path = f"/sys/class/net/{iface}/operstate"
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return "unknown"


def find_usb_irda_devices():
    """Find USB devices that match known IrDA hardware.

    Returns list of dicts with keys: bus, dev, vendor, product, description.
    """
    r = run("lsusb")
    if r.returncode != 0:
        return []
    devices = []
    for line in r.stdout.splitlines():
        m = re.match(
            r"Bus (\d+) Device (\d+): ID ([0-9a-f]{4}):([0-9a-f]{4})\s+(.*)",
            line, re.IGNORECASE,
        )
        if not m:
            continue
        vendor, product = m.group(3).lower(), m.group(4).lower()
        # MCS7780
        if vendor == "9710" and product == "7780":
            devices.append({
                "bus": m.group(1), "dev": m.group(2),
                "vendor": vendor, "product": product,
                "description": m.group(5), "chip": "MCS7780",
                "driver": "mcs7780.ko",
            })
        # STIr421x family
        elif vendor == "066f" and product in STIR421X_PRODUCTS:
            devices.append({
                "bus": m.group(1), "dev": m.group(2),
                "vendor": vendor, "product": product,
                "description": m.group(5), "chip": f"STIr{product}",
                "driver": "irda-usb.ko",
            })
        # STIr4200
        elif vendor == "066f" and product == "4200":
            devices.append({
                "bus": m.group(1), "dev": m.group(2),
                "vendor": vendor, "product": product,
                "description": m.group(5), "chip": "STIr4200",
                "driver": "stir4200.ko",
            })
    return devices


def find_stir421x_firmware_needed(devices):
    """Check if STIr421x firmware files exist for detected devices.

    Returns (present, missing) lists of firmware filenames.
    """
    present = []
    missing = []
    for dev in devices:
        if not dev["chip"].startswith("STIr42") or dev["chip"] == "STIr4200":
            continue
        for bcd in ["1001", "1002"]:
            fw_name = f"4210{bcd}.sb"
            fw_path = os.path.join(FIRMWARE_DIR, fw_name)
            if os.path.isfile(fw_path):
                present.append(fw_name)
            else:
                missing.append(fw_name)
    return present, missing


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

def check_dkms_installed():
    """Verify IrDA modules are installed via DKMS."""
    kernel = os.uname().release
    entries = get_dkms_status()
    for version, kern, status in entries:
        if kern == kernel and status == "installed":
            ok(f"DKMS {DKMS_PACKAGE}/{version} installed for {kernel}")
            return True
    fail(f"No DKMS-installed IrDA modules for kernel {kernel} — run 'irda init' or 'irda rebuild'")
    return False


def ensure_blacklist():
    """Blacklist the in-kernel ir_usb driver."""
    if os.path.isfile(BLACKLIST_CONF):
        with open(BLACKLIST_CONF) as f:
            if BLACKLIST_LINE in f.read():
                ok(f"ir_usb already blacklisted in {BLACKLIST_CONF}")
                _remove_ir_usb()
                return True

    try:
        os.makedirs(os.path.dirname(BLACKLIST_CONF), exist_ok=True)
        with open(BLACKLIST_CONF, "w") as f:
            f.write(BLACKLIST_LINE + "\n")
        ok(f"Created {BLACKLIST_CONF}")
    except OSError as e:
        fail(f"Could not create {BLACKLIST_CONF}: {e}")
        return False

    _remove_ir_usb()
    return True


def _remove_ir_usb():
    """Remove ir_usb if loaded."""
    if is_module_loaded("ir_usb"):
        run("rmmod ir_usb")
        if is_module_loaded("ir_usb"):
            warn("Could not unload ir_usb — USB IrDA devices may not bind correctly")
        else:
            ok("Unloaded in-kernel ir_usb driver")


def check_firmware(devices):
    """Check STIr421x firmware availability."""
    present, missing = find_stir421x_firmware_needed(devices)
    if not present and not missing:
        return True
    for fw in present:
        ok(f"Firmware {fw} found in {FIRMWARE_DIR}/")
    for fw in missing:
        warn(f"Firmware {fw} not found in {FIRMWARE_DIR}/ — "
             "STIr421x devices will fail to initialize")
    return len(missing) == 0


def unload_modules():
    """Unload all IrDA modules in dependency order."""
    any_removed = False
    for mod in UNLOAD_ORDER:
        if is_module_loaded(mod):
            r = run(f"rmmod {mod}")
            if r.returncode == 0:
                ok(f"Unloaded {mod}")
                any_removed = True
            else:
                warn(f"Could not unload {mod}: {r.stderr.strip()}")
    if not any_removed:
        info("No IrDA modules were loaded")


def load_modules():
    """Load core + USB driver modules via modprobe."""
    for mod in CORE_MODULE_NAMES:
        normalized = mod.replace("-", "_")
        if is_module_loaded(normalized):
            ok(f"{mod} already loaded")
            continue
        r = run(f"modprobe {mod}")
        if r.returncode != 0:
            fail(f"Failed to load {mod}: {r.stderr.strip()}")
            return False
        ok(f"Loaded {mod}")

    for mod in USB_DRIVER_MODULE_NAMES:
        normalized = mod.replace("-", "_")
        if is_module_loaded(normalized):
            ok(f"{mod} already loaded")
            continue
        r = run(f"modprobe {mod}")
        if r.returncode != 0:
            # Non-fatal for USB drivers — device may not be present
            warn(f"Could not load {mod}: {r.stderr.strip()}")
        else:
            ok(f"Loaded {mod}")
    return True


def wait_for_interfaces(pattern, label, timeout=5):
    """Wait for interfaces matching pattern to appear, return list."""
    for _ in range(timeout * 10):
        ifaces = get_interfaces(pattern)
        if ifaces:
            return ifaces
        time.sleep(0.1)
    return get_interfaces(pattern)


def bring_up_interfaces(ifaces):
    """Bring up a list of network interfaces."""
    for iface in ifaces:
        r = run(f"ip link set {iface} up")
        if r.returncode == 0:
            ok(f"Brought up {iface}")
        else:
            warn(f"Could not bring up {iface}: {r.stderr.strip()}")


def enable_discovery():
    """Enable IrDA discovery via sysctl."""
    if not os.path.exists(DISCOVERY_SYSCTL):
        warn("Discovery sysctl not available (irda.ko not loaded?)")
        return
    try:
        with open(DISCOVERY_SYSCTL, "w") as f:
            f.write("1\n")
        ok("Enabled IrDA discovery")
    except OSError as e:
        warn(f"Could not enable discovery: {e}")


def cap_baud_rate():
    """Cap max baud rate to 9600 to work around MCS7780 speed change bug."""
    if not os.path.exists(MAX_BAUD_RATE_SYSCTL):
        return
    try:
        with open(MAX_BAUD_RATE_SYSCTL, "w") as f:
            f.write("9600\n")
        ok("Set max_baud_rate=9600 (MCS7780 speed change workaround)")
    except OSError as e:
        warn(f"Could not set max_baud_rate: {e}")


def show_discovery():
    """Print discovery results."""
    if not os.path.exists(DISCOVERY_LOG):
        info("Discovery log not available")
        return
    with open(DISCOVERY_LOG) as f:
        content = f.read().strip()
    if not content or "Discovery log:" in content and content.count("\n") <= 2:
        lines = [l.strip() for l in content.splitlines() if l.strip()]
        entries = [l for l in lines if l.startswith("nickname:")]
        if not entries:
            info("No devices discovered (yet — discovery may take a few seconds)")
            return
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("nickname:"):
            ok(f"Discovered: {line}")


def start_capture(ifaces, capture_dir="/tmp"):
    """Start tcpdump on each irdamon interface, return list of PIDs."""
    pids = []
    for iface in ifaces:
        pcap = os.path.join(capture_dir, f"irda_{iface}.pcap")
        proc = subprocess.Popen(
            ["tcpdump", "-i", iface, "-w", pcap],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        pids.append(proc.pid)
        ok(f"Capturing on {iface} → {pcap} (pid {proc.pid})")
    return pids


def stop_captures():
    """Kill any tcpdump processes on irdamon interfaces."""
    r = run("pgrep -a tcpdump")
    if r.returncode != 0:
        return
    for line in r.stdout.splitlines():
        if "irdamon" in line:
            pid = int(line.split()[0])
            try:
                os.kill(pid, signal.SIGTERM)
                ok(f"Stopped tcpdump pid {pid}")
            except ProcessLookupError:
                pass


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_start(args):
    check_root()

    header("Preflight checks")
    if not check_dkms_installed():
        sys.exit(1)
    ensure_blacklist()

    usb_devices = find_usb_irda_devices()
    if usb_devices:
        for dev in usb_devices:
            ok(f"USB: {dev['chip']} ({dev['vendor']}:{dev['product']}) → {dev['driver']}")
    else:
        warn("No known IrDA USB devices detected")

    check_firmware(usb_devices)

    header("Loading modules")
    unload_modules()
    if not load_modules():
        sys.exit(1)

    header("Bringing up IrDA interfaces")
    irda_ifaces = wait_for_interfaces(r"^irda\d+$", "IrDA")
    if irda_ifaces:
        for iface in irda_ifaces:
            ok(f"Found {iface}")
        bring_up_interfaces(irda_ifaces)
    else:
        warn("No irda interfaces appeared — are USB dongles plugged in?")

    header("Bringing up monitor interfaces")
    irdamon_ifaces = wait_for_interfaces(r"^irdamon\d+$", "irdamon")
    if irdamon_ifaces:
        for iface in irdamon_ifaces:
            ok(f"Found {iface}")
        bring_up_interfaces(irdamon_ifaces)
    else:
        warn("No irdamon interfaces appeared — is irda_mon.ko loaded?")

    header("Discovery")
    enable_discovery()
    cap_baud_rate()
    time.sleep(2)
    show_discovery()

    if args.capture:
        header("Packet capture")
        if irdamon_ifaces:
            start_capture(irdamon_ifaces)
            info("Capture running in background — use 'irda setup stop' to end")
        else:
            warn("No irdamon interfaces available for capture")

    header("Summary")
    irda_count = len(get_interfaces(r"^irda\d+$"))
    irdamon_count = len(get_interfaces(r"^irdamon\d+$"))
    ok(f"{irda_count} IrDA interface(s), {irdamon_count} monitor interface(s)")


def cmd_stop(args):
    check_root()

    header("Stopping captures")
    stop_captures()

    header("Bringing down interfaces")
    for iface in reversed(get_interfaces(r"^irdamon\d+$")):
        run(f"ip link set {iface} down")
        ok(f"Brought down {iface}")
    for iface in reversed(get_interfaces(r"^irda\d+$")):
        run(f"ip link set {iface} down")
        ok(f"Brought down {iface}")

    header("Unloading modules")
    unload_modules()

    ok("IrDA stack stopped")


def cmd_status(args):
    header("USB devices")
    usb_devices = find_usb_irda_devices()
    if usb_devices:
        for dev in usb_devices:
            ok(f"{dev['chip']} ({dev['vendor']}:{dev['product']}) — {dev['description']}")
    else:
        info("No known IrDA USB devices detected")

    present, missing = find_stir421x_firmware_needed(usb_devices)
    if present or missing:
        header("STIr421x firmware")
        for fw in present:
            ok(f"{fw} found")
        for fw in missing:
            warn(f"{fw} missing from {FIRMWARE_DIR}/")

    header("DKMS")
    entries = get_dkms_status()
    kernel = os.uname().release
    if entries:
        for version, kern, status in entries:
            if kern == kernel and status == "installed":
                ok(f"{DKMS_PACKAGE}/{version} ({kern}): {status}")
            elif status == "installed":
                info(f"{DKMS_PACKAGE}/{version} ({kern}): {status}")
            else:
                warn(f"{DKMS_PACKAGE}/{version} ({kern}): {status}")
    else:
        warn(f"No DKMS entries for {DKMS_PACKAGE} — run 'irda init' or 'irda rebuild'")

    header("Loaded modules")
    irda_mods = []
    for mod in UNLOAD_ORDER:
        if is_module_loaded(mod):
            irda_mods.append(mod)
    if irda_mods:
        for mod in irda_mods:
            ok(mod)
    else:
        info("No IrDA modules loaded")

    header("Interfaces")
    for iface in get_interfaces(r"^irda\d+$") + get_interfaces(r"^irdamon\d+$"):
        state = get_interface_state(iface)
        if state == "up" or state == "unknown":
            ok(f"{iface}: {state}")
        elif state == "down":
            warn(f"{iface}: {state}")
        else:
            info(f"{iface}: {state}")

    header("ir_usb blacklist")
    if os.path.isfile(BLACKLIST_CONF):
        with open(BLACKLIST_CONF) as f:
            if BLACKLIST_LINE in f.read():
                ok(f"ir_usb blacklisted in {BLACKLIST_CONF}")
            else:
                warn(f"{BLACKLIST_CONF} exists but does not blacklist ir_usb")
    else:
        warn(f"No blacklist file at {BLACKLIST_CONF}")
    if is_module_loaded("ir_usb"):
        warn("ir_usb is currently loaded — it will claim USB IrDA devices")

    header("Discovery")
    if os.path.exists(DISCOVERY_SYSCTL):
        with open(DISCOVERY_SYSCTL) as f:
            val = f.read().strip()
        if val == "1":
            ok("Discovery enabled")
        else:
            info("Discovery disabled (echo 1 > /proc/sys/net/irda/discovery)")
        show_discovery()
    else:
        info("Discovery sysctl not available (irda.ko not loaded)")

    header("Captures")
    r = run("pgrep -a tcpdump")
    found = False
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if "irdamon" in line:
                ok(f"tcpdump: {line}")
                found = True
    if not found:
        info("No active tcpdump captures on irdamon interfaces")


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

def register_parser(subparsers):
    parser = subparsers.add_parser(
        "setup", help="Manage IrDA modules and interfaces",
    )
    sub = parser.add_subparsers(dest="setup_command")
    sub.required = True

    p_start = sub.add_parser("start", help="Load modules and bring up interfaces")
    p_start.add_argument(
        "--capture", action="store_true",
        help="Start tcpdump on each irdamon interface",
    )
    p_start.set_defaults(func=cmd_start)

    p_stop = sub.add_parser("stop", help="Tear down interfaces and unload modules")
    p_stop.set_defaults(func=cmd_stop)

    p_status = sub.add_parser("status", help="Show current IrDA state")
    p_status.set_defaults(func=cmd_status)
