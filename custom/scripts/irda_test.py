"""IrDA test subcommand: AF_IRDA socket echo server and client."""

import ctypes
import ctypes.util
import os
import socket
import struct
import sys
import time

from irda_common import header, ok, warn, fail, info, hexdump

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AF_IRDA is 23 on Linux; Python exposes it when built with IrDA support.
AF_IRDA = getattr(socket, "AF_IRDA", 23)

# Socket option level for IrLMP options (linux/irda.h).
SOL_IRLMP = getattr(socket, "SOL_IRLMP", 266)

# getsockopt option to enumerate discovered devices.
IRLMP_ENUMDEVICES = 1

# LSAP selector: 0xFF = let the kernel assign one (LSAP_ANY).
LSAP_ANY = 0xFF

# Service name used for the echo test (25-byte limit in sockaddr_irda).
SERVICE_NAME = b"IrDATest:IrDA:TinyTP"

# Test patterns sent by the client.
PATTERNS = [
    ("short",  16,   "Short message (16 B)"),
    ("medium", 512,  "Medium block (512 B)"),
    ("large",  4096, "Large transfer (4096 B, SAR)"),
]

# sizeof(struct irda_device_info) on Linux — see include/linux/irda.h.
SIZEOF_IRDA_DEVICE_INFO = 36

# Offset of the dev[] array inside the getsockopt return buffer.
DEVICE_LIST_OFFSET = 4

# Receive buffer size.
RECV_BUF = 8192

# ---------------------------------------------------------------------------
# Raw sockaddr_irda helpers
# ---------------------------------------------------------------------------

SIZEOF_SOCKADDR_IRDA = 36  # includes alignment padding
SIR_NAME_LEN = 25

_libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6",
                     use_errno=True)

_libc.bind.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
_libc.bind.restype = ctypes.c_int
_libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
_libc.connect.restype = ctypes.c_int
_libc.accept.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
_libc.accept.restype = ctypes.c_int


def _pack_sockaddr_irda(addr, lsap_sel, name):
    """Pack a sockaddr_irda struct for bind/connect."""
    padded = name[:SIR_NAME_LEN].ljust(SIR_NAME_LEN, b"\x00")
    return struct.pack("<HBxI25s3x", AF_IRDA, lsap_sel, addr, padded)


def _unpack_sockaddr_irda(buf):
    """Unpack a sockaddr_irda buffer. Returns (family, lsap_sel, addr, name)."""
    family, lsap_sel, addr = struct.unpack_from("<HBxI", buf, 0)
    raw_name = buf[8:33]
    name = raw_name.split(b"\x00", 1)[0]
    return family, lsap_sel, addr, name


def _raw_bind(sock, addr, lsap_sel, name):
    """Bind an AF_IRDA socket using raw libc call."""
    sa = ctypes.create_string_buffer(_pack_sockaddr_irda(addr, lsap_sel, name),
                                     SIZEOF_SOCKADDR_IRDA)
    ret = _libc.bind(sock.fileno(), sa, SIZEOF_SOCKADDR_IRDA)
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _raw_connect(sock, addr, lsap_sel, name):
    """Connect an AF_IRDA socket using raw libc call."""
    sa = ctypes.create_string_buffer(_pack_sockaddr_irda(addr, lsap_sel, name),
                                     SIZEOF_SOCKADDR_IRDA)
    ret = _libc.connect(sock.fileno(), sa, SIZEOF_SOCKADDR_IRDA)
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))


def _raw_accept(sock):
    """Accept on an AF_IRDA socket using raw libc call."""
    sa_buf = ctypes.create_string_buffer(SIZEOF_SOCKADDR_IRDA)
    addrlen = ctypes.c_uint(SIZEOF_SOCKADDR_IRDA)
    fd = _libc.accept(sock.fileno(), sa_buf, ctypes.byref(addrlen))
    if fd < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    new_sock = socket.socket(fileno=fd)
    family, lsap_sel, addr, name = _unpack_sockaddr_irda(sa_buf.raw)
    return new_sock, (addr, lsap_sel, name)


# ---------------------------------------------------------------------------
# Device discovery
# ---------------------------------------------------------------------------

def discover_devices(sock):
    """Query IRLMP_ENUMDEVICES and return a list of (saddr, daddr, name) tuples."""
    try:
        buf = sock.getsockopt(SOL_IRLMP, IRLMP_ENUMDEVICES, 1024)
    except OSError as e:
        return [], e

    if len(buf) < DEVICE_LIST_OFFSET:
        return [], None

    count = struct.unpack_from("<I", buf, 0)[0]
    devices = []
    for i in range(count):
        base = DEVICE_LIST_OFFSET + i * SIZEOF_IRDA_DEVICE_INFO
        if base + SIZEOF_IRDA_DEVICE_INFO > len(buf):
            break
        saddr = struct.unpack_from("<I", buf, base)[0]
        daddr = struct.unpack_from("<I", buf, base + 4)[0]
        raw_info = buf[base + 8 : base + 8 + 22]
        name = raw_info.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        charset = buf[base + 30] if base + 30 < len(buf) else 0
        hints_b = buf[base + 31 : base + 33] if base + 33 <= len(buf) else b"\x00\x00"
        devices.append({
            "saddr": saddr,
            "daddr": daddr,
            "name": name,
            "charset": charset,
            "hints": hints_b,
        })
    return devices, None


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

def cmd_server(args):
    """Echo server: bind, accept one connection, echo back everything."""
    header("IrDA Echo Server")

    try:
        srv = socket.socket(AF_IRDA, socket.SOCK_STREAM)
    except OSError as e:
        fail(f"Cannot create AF_IRDA socket: {e}")
        fail("Is the irda.ko module loaded? (sudo irda setup start)")
        sys.exit(1)

    try:
        _raw_bind(srv, 0, LSAP_ANY, SERVICE_NAME)
    except OSError as e:
        fail(f"bind() failed: {e}")
        srv.close()
        sys.exit(1)

    ok(f"Bound to service \"{SERVICE_NAME.decode()}\"")

    srv.listen(1)
    ok("Listening for incoming connections (Ctrl-C to stop)")

    try:
        conn, (peer_addr, peer_lsap, peer_name) = _raw_accept(srv)
    except KeyboardInterrupt:
        info("Interrupted — shutting down")
        srv.close()
        return

    ok(f"Accepted connection from 0x{peer_addr:08x}")

    total_bytes = 0
    total_msgs = 0
    try:
        while True:
            data = conn.recv(RECV_BUF)
            if not data:
                info("Peer closed connection")
                break
            total_bytes += len(data)
            total_msgs += 1
            info(f"Received {len(data)} bytes (msg #{total_msgs}): {hexdump(data)}")
            conn.sendall(data)
            ok(f"Echoed {len(data)} bytes back")
    except KeyboardInterrupt:
        info("Interrupted — shutting down")
    except OSError as e:
        warn(f"Connection error: {e}")
    finally:
        conn.close()
        srv.close()

    header("Summary")
    ok(f"Echoed {total_msgs} message(s), {total_bytes} bytes total")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

def cmd_client(args):
    """Test client: discover, connect, send patterns, verify echo."""
    header("IrDA Echo Client")

    try:
        sock = socket.socket(AF_IRDA, socket.SOCK_STREAM)
    except OSError as e:
        fail(f"Cannot create AF_IRDA socket: {e}")
        fail("Is the irda.ko module loaded? (sudo irda setup start)")
        sys.exit(1)

    # -- Discovery ----------------------------------------------------------
    header("Discovery")
    info("Querying IRLMP_ENUMDEVICES (ensure discovery is enabled)...")

    devices = []
    for attempt in range(1, 6):
        devices, err = discover_devices(sock)
        if devices:
            break
        if attempt < 5:
            info(f"No devices yet (attempt {attempt}/5, retrying in 2 s)...")
            time.sleep(2)

    if not devices:
        fail("No IrDA devices discovered")
        if err:
            fail(f"Last error: {err}")
        fail("Make sure the server dongle is in range and discovery is enabled:")
        fail("  echo 1 > /proc/sys/net/irda/discovery")
        sock.close()
        sys.exit(1)

    for dev in devices:
        ok(f"Found device: \"{dev['name']}\" "
           f"daddr=0x{dev['daddr']:08x} saddr=0x{dev['saddr']:08x}")

    target = devices[0]
    daddr = target["daddr"]
    info(f"Connecting to daddr=0x{daddr:08x} service \"{SERVICE_NAME.decode()}\"")

    # -- Connect ------------------------------------------------------------
    header("Connect")
    try:
        _raw_connect(sock, daddr, LSAP_ANY, SERVICE_NAME)
    except OSError as e:
        fail(f"connect() failed: {e}")
        sock.close()
        sys.exit(1)
    ok(f"Connected to 0x{daddr:08x}")

    # -- Test patterns ------------------------------------------------------
    header("Test Patterns")
    passed = 0
    failed = 0

    for label, size, description in PATTERNS:
        pattern = bytes(b % 256 for b in range(size))

        info(f"Sending {description}...")
        t0 = time.monotonic()
        try:
            sock.sendall(pattern)
        except OSError as e:
            fail(f"  send failed: {e}")
            failed += 1
            continue

        received = b""
        sock.settimeout(10.0)
        try:
            while len(received) < size:
                chunk = sock.recv(RECV_BUF)
                if not chunk:
                    break
                received += chunk
        except socket.timeout:
            fail(f"  Timed out waiting for echo (got {len(received)}/{size} bytes)")
            failed += 1
            continue
        except OSError as e:
            fail(f"  recv failed: {e}")
            failed += 1
            continue
        finally:
            sock.settimeout(None)

        t1 = time.monotonic()
        rtt_ms = (t1 - t0) * 1000.0

        if received == pattern:
            ok(f"  {label}: {size} bytes echoed correctly "
               f"({rtt_ms:.1f} ms round-trip)")
            passed += 1
        else:
            fail(f"  {label}: DATA MISMATCH "
                 f"(sent {size}, received {len(received)} bytes, "
                 f"{rtt_ms:.1f} ms)")
            if received[:16] != pattern[:16]:
                fail(f"    Expected: {hexdump(pattern[:16], 16)}")
                fail(f"    Got:      {hexdump(received[:16], 16)}")
            failed += 1

    sock.close()

    # -- Summary ------------------------------------------------------------
    header("Summary")
    total = passed + failed
    if failed == 0:
        ok(f"All {total} test(s) passed")
    else:
        fail(f"{failed}/{total} test(s) failed")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Parser registration
# ---------------------------------------------------------------------------

def register_parser(subparsers):
    parser = subparsers.add_parser(
        "test", help="IrDA AF_IRDA socket echo tests",
    )
    sub = parser.add_subparsers(dest="test_command")
    sub.required = True

    p_server = sub.add_parser("server", help="Start IrDA echo server")
    p_server.set_defaults(func=cmd_server)

    p_client = sub.add_parser("client", help="Run echo client tests")
    p_client.set_defaults(func=cmd_client)
