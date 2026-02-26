"""IrDA rebuild subcommand: rebuild and install all modules via DKMS."""

import sys

from irda_common import (
    UNLOAD_ORDER,
    header, ok, warn, fail, info,
    run, is_module_loaded, check_root,
    dkms_remove_all, dkms_configure, dkms_install, get_dkms_status,
)


def cmd_rebuild(args):
    check_root()

    # Unload modules if any are loaded
    loaded = [mod for mod in UNLOAD_ORDER if is_module_loaded(mod)]
    if loaded:
        header("Unloading modules")
        for mod in loaded:
            r = run(f"rmmod {mod}")
            if r.returncode == 0:
                ok(f"Unloaded {mod}")
            else:
                warn(f"Could not unload {mod}: {r.stderr.strip()}")

    # Remove old DKMS registrations
    if get_dkms_status():
        header("Removing old DKMS install")
        dkms_remove_all()

    # Regenerate dkms.conf with current version
    header("Configuring")
    if not dkms_configure():
        sys.exit(1)

    # Build and install via DKMS
    header("Building and installing via DKMS")
    if not dkms_install():
        sys.exit(1)


def register_parser(subparsers):
    parser = subparsers.add_parser(
        "rebuild", help="Rebuild and install all IrDA modules via DKMS",
    )
    parser.set_defaults(func=cmd_rebuild)
