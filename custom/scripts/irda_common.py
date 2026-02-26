"""Shared helpers for the irda CLI tools.

Provides output formatting, path resolution, system helpers, and constants
used across irda_setup, irda_test, and irda_rebuild.
"""

import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Path resolution
# ---------------------------------------------------------------------------

def get_project_root():
    """Return the project root (two levels up from custom/scripts/)."""
    return os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))

PROJECT_ROOT = get_project_root()
SRC_DIR = os.path.join(PROJECT_ROOT, "src")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Module unload order: upper layers -> drivers -> monitor -> core
UNLOAD_ORDER = [
    "irlan", "irnet", "ircomm_tty", "ircomm",
    "mcs7780", "stir4200", "vlsi_ir", "nsc_ircc", "smsc_ircc2",
    "ali_ircc", "w83977af_ir", "irda_usb", "irtty_sir", "sir_dev",
    "act200l_sir", "actisys_sir", "esi_sir", "girbil_sir", "litelink_sir",
    "ma600_sir", "mcp2120_sir", "old_belkin_sir", "tekram_sir",
    "toim3232_sir", "kingsun_sir", "ks959_sir", "ksdazzle_sir",
    "irda_mon", "irda",
]

# Module load order: core -> monitor -> USB drivers (names for modprobe)
CORE_MODULE_NAMES = ["irda", "irda_mon"]
USB_DRIVER_MODULE_NAMES = ["mcs7780", "stir4200", "irda-usb"]

DKMS_PACKAGE = "irda"

BLACKLIST_CONF = "/etc/modprobe.d/irda-blacklist.conf"
BLACKLIST_LINE = "blacklist ir_usb"

DISCOVERY_SYSCTL = "/proc/sys/net/irda/discovery"
MAX_BAUD_RATE_SYSCTL = "/proc/sys/net/irda/max_baud_rate"
DISCOVERY_LOG = "/proc/net/irda/discovery"

# STIr421x USB product IDs (vendor 066f)
STIR421X_PRODUCTS = {"4210", "4220", "4116"}

FIRMWARE_DIR = "/lib/firmware"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

COLORS = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "cyan": "\033[36m",
}

# Disable colors when not a terminal
if not sys.stdout.isatty():
    COLORS = {k: "" for k in COLORS}


def _c(color, text):
    return f"{COLORS[color]}{text}{COLORS['reset']}"


def header(text):
    print(f"\n{_c('bold', _c('cyan', f'==> {text}'))}")


def ok(text):
    print(f"  {_c('green', '[OK]')}   {text}")


def warn(text):
    print(f"  {_c('yellow', '[WARN]')} {text}")


def fail(text):
    print(f"  {_c('red', '[FAIL]')} {text}")


def info(text):
    print(f"  {_c('bold', '[INFO]')} {text}")


def hexdump(data, max_bytes=64):
    """Return a compact hex dump string of the first max_bytes of data."""
    show = data[:max_bytes]
    hex_part = " ".join(f"{b:02x}" for b in show)
    if len(data) > max_bytes:
        hex_part += " ..."
    return hex_part


# ---------------------------------------------------------------------------
# System helpers
# ---------------------------------------------------------------------------

def run(cmd, check=False, capture=True):
    """Run a shell command, return CompletedProcess."""
    return subprocess.run(
        cmd, shell=isinstance(cmd, str),
        capture_output=capture, text=True,
        check=check,
    )


def is_module_loaded(name):
    """Check if a kernel module is loaded (handles - and _ equivalence)."""
    normalized = name.replace("-", "_")
    r = run("cat /proc/modules")
    if r.returncode != 0:
        return False
    for line in r.stdout.splitlines():
        mod = line.split()[0]
        if mod.replace("-", "_") == normalized:
            return True
    return False


def check_root():
    if os.geteuid() != 0:
        fail("This command must be run as root (use sudo)")
        sys.exit(1)


# ---------------------------------------------------------------------------
# DKMS helpers
# ---------------------------------------------------------------------------

def get_dkms_version():
    """Read PACKAGE_VERSION from src/dkms.conf."""
    conf = os.path.join(SRC_DIR, "dkms.conf")
    if not os.path.isfile(conf):
        return None
    with open(conf) as f:
        for line in f:
            if line.startswith("PACKAGE_VERSION="):
                return line.split("=", 1)[1].strip().strip('"')
    return None


def get_dkms_status():
    """Return list of (version, kernel, status) tuples for the irda package."""
    r = run("dkms status")
    if r.returncode != 0 or not r.stdout.strip():
        return []
    entries = []
    for line in r.stdout.strip().splitlines():
        # Format: "PACKAGE/VERSION, KERNEL, ARCH: STATUS"
        parts = line.split(":")
        if len(parts) < 2:
            continue
        status = parts[-1].strip()
        fields = parts[0].split(",")
        if "/" not in fields[0]:
            continue
        pkg, version = fields[0].split("/", 1)
        pkg = pkg.strip()
        version = version.strip()
        if pkg != DKMS_PACKAGE:
            continue
        kernel = fields[1].strip() if len(fields) > 1 else ""
        entries.append((version, kernel, status))
    return entries


def dkms_remove_all():
    """Remove all installed DKMS versions of the irda package."""
    entries = get_dkms_status()
    for version, kernel, status in entries:
        r = run(f"dkms remove {DKMS_PACKAGE}/{version} --all")
        if r.returncode == 0:
            ok(f"Removed DKMS {DKMS_PACKAGE}/{version}")
        else:
            warn(f"Could not remove DKMS {DKMS_PACKAGE}/{version}: {r.stderr.strip()}")


def dkms_configure():
    """Run autoconf/configure to regenerate dkms.conf with current version."""
    r = subprocess.run(
        ["autoconf", "-f"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    if r.returncode != 0:
        fail(f"autoconf failed: {r.stderr.strip()}")
        return False
    r = subprocess.run(
        ["./configure"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
    )
    if r.returncode != 0:
        fail(f"configure failed: {r.stderr.strip()}")
        return False
    version = get_dkms_version()
    ok(f"Configured DKMS version: {version}")
    return True


def dkms_install():
    """Add and install the irda package via DKMS. Returns True on success."""
    version = get_dkms_version()
    if not version:
        fail("Cannot determine DKMS version — run 'irda rebuild' or 'irda init'")
        return False

    r = run(f"dkms add {SRC_DIR}")
    if r.returncode != 0:
        # "already added" is not a real error
        if "already added" not in r.stderr:
            fail(f"dkms add failed: {r.stderr.strip()}")
            return False

    ok(f"DKMS source registered: {DKMS_PACKAGE}/{version}")

    info(f"Building and installing {DKMS_PACKAGE}/{version} (this may take a moment)...")
    r = subprocess.run(
        ["dkms", "install", f"{DKMS_PACKAGE}/{version}"],
        text=True,
    )
    if r.returncode != 0:
        fail("dkms install failed")
        return False

    ok(f"DKMS install complete: {DKMS_PACKAGE}/{version}")
    return True
