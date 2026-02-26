"""IrDA initialize subcommand: first-time setup after cloning the repo.

WARNING: This initialization has only been tested on:
    Linux FishingHamlet 6.18.9+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.18.9-1kali1 (2026-02-10) x86_64 GNU/Linux
"""

import os
import subprocess
import sys
import tarfile

from irda_common import (
    PROJECT_ROOT, FIRMWARE_DIR,
    BLACKLIST_CONF, BLACKLIST_LINE,
    CORE_MODULE_NAMES, USB_DRIVER_MODULE_NAMES, UNLOAD_ORDER,
    header, ok, warn, fail, info,
    run, is_module_loaded, check_root,
    dkms_configure, dkms_install,
)

FIRMWARE_ARCHIVE = os.path.join(
    PROJECT_ROOT, "custom", "firmware",
    "stir4210_4220_4116_patch_files.tar.gz",
)

BUILD_DEPS = [
    "build-essential", "libelf-dev", "libssl-dev", "flex", "bison", "bc",
    "dkms", "autoconf",
]

TESTED_SYSTEM = (
    "Linux FishingHamlet 6.18.9+kali-amd64 #1 SMP PREEMPT_DYNAMIC "
    "Kali 6.18.9-1kali1 (2026-02-10) x86_64 GNU/Linux"
)


def _get_kernel_headers_pkg():
    """Return the linux-headers package name for the running kernel."""
    return f"linux-headers-{os.uname().release}"


def _is_pkg_installed(pkg):
    """Check if a dpkg package is installed."""
    r = run(f"dpkg -s {pkg}")
    return r.returncode == 0


def _apt_install(packages):
    """Install packages via apt-get."""
    r = subprocess.run(
        ["apt-get", "install", "-y"] + packages,
        text=True,
    )
    return r.returncode == 0


def cmd_init(args):
    check_root()

    warn(f"This initialization has only been tested on:")
    warn(f"  {TESTED_SYSTEM}")
    print()

    # -- Step 1: Firmware ---------------------------------------------------
    header("STIr421x firmware")
    firmware_files = ["42101001.sb", "42101002.sb"]
    all_present = True
    for fw in firmware_files:
        if os.path.isfile(os.path.join(FIRMWARE_DIR, fw)):
            ok(f"{fw} already in {FIRMWARE_DIR}/")
        else:
            all_present = False

    if not all_present:
        if not os.path.isfile(FIRMWARE_ARCHIVE):
            fail(f"Firmware archive not found: {FIRMWARE_ARCHIVE}")
            fail("Cannot install STIr421x firmware")
        else:
            info(f"Extracting firmware to {FIRMWARE_DIR}/")
            with tarfile.open(FIRMWARE_ARCHIVE, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name in firmware_files:
                        member.name = os.path.basename(member.name)
                        tar.extract(member, FIRMWARE_DIR)
                        ok(f"Installed {member.name}")

    # -- Step 2: ir_usb blacklist -------------------------------------------
    header("ir_usb blacklist")
    if os.path.isfile(BLACKLIST_CONF):
        with open(BLACKLIST_CONF) as f:
            if BLACKLIST_LINE in f.read():
                ok(f"ir_usb already blacklisted in {BLACKLIST_CONF}")
            else:
                with open(BLACKLIST_CONF, "a") as f2:
                    f2.write(BLACKLIST_LINE + "\n")
                ok(f"Added blacklist to existing {BLACKLIST_CONF}")
    else:
        os.makedirs(os.path.dirname(BLACKLIST_CONF), exist_ok=True)
        with open(BLACKLIST_CONF, "w") as f:
            f.write(BLACKLIST_LINE + "\n")
        ok(f"Created {BLACKLIST_CONF}")

    if is_module_loaded("ir_usb"):
        run("rmmod ir_usb")
        if is_module_loaded("ir_usb"):
            warn("Could not unload ir_usb — unplug USB devices and retry")
        else:
            ok("Unloaded in-kernel ir_usb driver")

    # -- Step 3: Kernel headers and build deps ------------------------------
    header("Build dependencies")
    headers_pkg = _get_kernel_headers_pkg()
    all_pkgs = BUILD_DEPS + [headers_pkg]
    missing = [pkg for pkg in all_pkgs if not _is_pkg_installed(pkg)]

    if not missing:
        ok("All build dependencies installed")
    else:
        for pkg in missing:
            info(f"Missing: {pkg}")
        info("Installing via apt-get...")
        if _apt_install(missing):
            ok("Build dependencies installed")
        else:
            fail("apt-get install failed")
            sys.exit(1)

    # -- Step 4: Build and install via DKMS ---------------------------------
    header("Configuring")
    if not dkms_configure():
        sys.exit(1)

    # Unload any stale modules before DKMS install
    for mod in UNLOAD_ORDER:
        if is_module_loaded(mod):
            run(f"rmmod {mod}")

    header("Building and installing via DKMS")
    if not dkms_install():
        sys.exit(1)

    # -- Step 5: Load modules -----------------------------------------------
    header("Loading modules")
    for mod in CORE_MODULE_NAMES:
        r = run(f"modprobe {mod}")
        if r.returncode != 0:
            fail(f"Failed to load {mod}: {r.stderr.strip()}")
            sys.exit(1)
        ok(f"Loaded {mod}")

    for mod in USB_DRIVER_MODULE_NAMES:
        r = run(f"modprobe {mod}")
        if r.returncode != 0:
            warn(f"Could not load {mod}: {r.stderr.strip()}")
        else:
            ok(f"Loaded {mod}")

    # -- Done ---------------------------------------------------------------
    header("Initialization complete")
    ok("Run './irda setup start' to bring up interfaces and enable discovery")


def register_parser(subparsers):
    parser = subparsers.add_parser(
        "init",
        help="First-time setup (firmware, blacklist, headers, build, load)",
    )
    parser.set_defaults(func=cmd_init)
