# IrDA Scapy Dissector Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement full IrDA protocol stack as scapy layers (IrLAP, IrLMP, TTP, IAS, OBEX) for dissection and crafting, suitable for contribution to scapy upstream. Also build an AF_IRDA socket test tool for generating real multi-layer traffic.

**Architecture:** A single scapy contrib module (`scapy/contrib/irda.py`) replaces the existing minimal `layers/ir.py` dissector. The IrLAP layer parses address + control bytes and dispatches to frame-type-specific payload classes via `guess_payload_class()`. Upper layers (IrLMP → TTP → IAS/OBEX) bind conventionally. A separate `irda-test.py` uses kernel `AF_IRDA` sockets to generate traffic.

**Tech Stack:** Python 3, scapy (no external deps beyond scapy itself), UTScapy for tests

**Reference:** Design doc at `docs/plans/2026-02-25-irda-scapy-dissector-design.md`. Protocol constants extracted from `src/include/net/irda/irlap_frame.h`, `src/net/irlap_frame.c`, `src/include/net/irda/irlmp.h`, `src/include/net/irda/irttp.h`, `src/include/net/irda/iriap.h`, `src/include/linux/irda.h`.

**Existing scapy code:** `/usr/lib/python3/dist-packages/scapy/layers/ir.py` has minimal `IrLAPHead` + `IrLAPCommand` (XID-only) + `IrLMP` (actually discovery info). Bound via `CookedLinux(proto=23) → IrLAPHead`. Our module overrides these bindings.

---

### Task 1: Module skeleton and IrLAP base layer

**Files:**
- Create: `scapy/contrib/irda.py`
- Create: `tests/irda_scapy.uts`

**Step 1: Write the initial test**

In `tests/irda_scapy.uts`:

```
% IrDA protocol layer tests

+ IrLAP base layer
= Import IrDA contrib module
from scapy.contrib.irda import *

= IrLAP frame type detection - I-frame
p = IrLAP(bytes.fromhex("fe00"))
assert p.addr == 0x7f
assert p.cr == 0
assert p.control == 0x00
assert p.frame_type == "I"

= IrLAP frame type detection - S-frame (RR)
p = IrLAP(bytes.fromhex("ff11"))
assert p.addr == 0x7f
assert p.cr == 1
assert p.control == 0x11
assert p.frame_type == "S"

= IrLAP frame type detection - U-frame (XID cmd)
p = IrLAP(bytes.fromhex("ff3f"))
assert p.addr == 0x7f
assert p.cr == 1
assert p.control == 0x3f
assert p.frame_type == "U"

= IrLAP build roundtrip
p = IrLAP(addr=0x7f, cr=1, control=0x3f)
assert raw(p) == bytes.fromhex("ff3f")
```

**Step 2: Run test to verify it fails**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: FAIL (module doesn't exist)

**Step 3: Write the IrLAP base class**

Create `scapy/contrib/irda.py`:

```python
# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = IrDA (Infrared Data Association)
# scapy.contrib.status = loads

"""
IrDA protocol stack: IrLAP, IrLMP, TTP, IAS, OBEX

Dissects and crafts IrDA frames captured from Linux irdamon interfaces
(DLT_LINUX_IRDA / ARPHRD_IRDA).

References:
- IrDA IrLAP 1.1 specification
- IrDA IrLMP 1.1 specification
- IrDA Tiny TP 1.1 specification
- IrDA IrIAP 1.0 specification
- IrDA OBEX 1.3 specification
- Linux kernel IrDA implementation (net/irda/)
"""

from scapy.config import conf
from scapy.data import DLT_LINUX_IRDA
from scapy.fields import (
    BitEnumField, BitField, ByteEnumField, ByteField,
    ConditionalField, FieldLenField, IntField, LEIntField,
    PacketListField, ShortField, StrField, StrFixedLenField,
    StrLenField, XBitField, XByteField, XIntField, XShortField,
)
from scapy.layers.l2 import CookedLinux
from scapy.packet import Packet, Raw, bind_layers

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# IrLAP address field
CMD_FRAME = 0x01
RSP_FRAME = 0x00
CBROADCAST = 0xFE  # 7-bit broadcast addr = 0x7F, C/R = 0

# IrLAP control field — P/F bit
PF_BIT = 0x10

# IrLAP S-frame types (low nibble with bit 0 = 1, bit 1 = 0)
S_RR   = 0x01
S_RNR  = 0x05
S_REJ  = 0x09
S_SREJ = 0x0D

# IrLAP U-frame control values (with P/F = 0)
SNRM_CMD = 0x83
DISC_CMD = 0x43
XID_CMD  = 0x2F
XID_RSP  = 0x9F  # 0xAF & ~PF_BIT
TEST_CMD = 0xE3
UI_FRAME = 0x03
UA_RSP   = 0x63
DM_RSP   = 0x0F
FRMR_RSP = 0x87
RD_RSP   = 0x43
RNRM_RSP = 0x83

# XID
XID_FORMAT = 0x01

# IrLAP broadcast
BROADCAST = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# IrLAP
# ---------------------------------------------------------------------------

class IrLAP(Packet):
    name = "IrLAP"
    fields_desc = [
        XBitField("addr", 0x7f, 7),
        BitEnumField("cr", 1, 1, {0: "rsp", 1: "cmd"}),
        XByteField("control", 0),
    ]

    @property
    def frame_type(self):
        """Return 'I', 'S', or 'U' based on control field low bits."""
        if not (self.control & 0x01):
            return "I"
        elif not (self.control & 0x02):
            return "S"
        else:
            return "U"

    @property
    def pf(self):
        """Poll/Final bit."""
        return bool(self.control & PF_BIT)

    @property
    def ns(self):
        """Send sequence number (I-frames only)."""
        return (self.control >> 1) & 0x07

    @property
    def nr(self):
        """Receive sequence number (I-frames and S-frames)."""
        return (self.control >> 5) & 0x07

    @property
    def s_type(self):
        """S-frame type code (low nibble)."""
        return self.control & 0x0F

    @property
    def u_type(self):
        """U-frame type (control with P/F masked out)."""
        return self.control & ~PF_BIT & 0xFF

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        ft = self.frame_type
        if ft == "I":
            return IrLMP
        elif ft == "U":
            ut = self.u_type
            if ut == XID_CMD or ut == XID_RSP:
                return IrLAP_XID
            elif ut == SNRM_CMD:
                return IrLAP_SNRM
            elif ut == UA_RSP:
                return IrLAP_UA
            elif ut == FRMR_RSP:
                return IrLAP_FRMR
        return Packet.guess_payload_class(self, payload)
```

**Step 4: Run tests to verify they pass**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add IrLAP base layer with frame type detection"
```

---

### Task 2: XID discovery frames

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write XID tests**

Append to `tests/irda_scapy.uts`:

```
+ XID discovery frames
= Dissect XID command (non-final slot)
# Real capture: addr=0xFF(bcast,cmd), ctrl=0x3F(XID,P=1), slot 5
p = IrLAP(bytes.fromhex("ff3f01 8b85c7da ffffffff 01 05 00"))
assert p.addr == 0x7f
assert p.cr == 1
assert p.control == 0x3f
x = p[IrLAP_XID]
assert x.format_id == 0x01
assert x.saddr == 0xdac7858b
assert x.daddr == 0xffffffff
assert x.flags == 0x01
assert x.slotnr == 0x05
assert x.version == 0x00

= Dissect XID command (final slot with discovery info)
# Final slot with nickname "Linux": hints=0x04 (Computer), charset=0, name="Linux"
p = IrLAP(bytes.fromhex("ff3f01 8b85c7da ffffffff 01 ff 00 0400 00 4c696e7578"))
x = p[IrLAP_XID]
assert x.slotnr == 0xff
d = x[IrLAP_XID_DiscInfo]
assert d.hints1 == 0x04
assert d.charset == 0x00
assert d.nickname == b"Linux"

= XID slot count decoding
# flags bits 1..0: 00=1slot, 01=6slots, 10=8slots, 11=16slots
p = IrLAP(bytes.fromhex("ff3f01 00000000 ffffffff 02 00 00"))
assert p[IrLAP_XID].slot_count == 8

= XID build roundtrip
x = IrLAP(addr=0x7f, cr=1, control=0x3f) / IrLAP_XID(
    format_id=0x01, saddr=0xdac7858b, daddr=0xffffffff,
    flags=0x01, slotnr=5, version=0)
assert bytes(x) == bytes.fromhex("ff3f01 8b85c7da ffffffff 01 05 00")
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: XID tests FAIL (classes don't exist yet)

**Step 3: Implement XID classes**

Add to `scapy/contrib/irda.py`:

```python
# Hint bit definitions
_hint1_flags = {
    0x01: "PnP", 0x02: "PDA", 0x04: "Computer", 0x08: "Printer",
    0x10: "Modem", 0x20: "Fax", 0x40: "LAN", 0x80: "Extension",
}
_hint2_flags = {
    0x01: "Telephony", 0x02: "FileServer", 0x04: "IrCOMM",
    0x08: "Message", 0x10: "HTTP", 0x20: "OBEX",
}
_charset_names = {
    0x00: "ASCII", 0x01: "ISO-8859-1", 0x02: "ISO-8859-2",
    0x03: "ISO-8859-3", 0x04: "ISO-8859-4", 0x05: "ISO-8859-5",
    0x06: "ISO-8859-6", 0x07: "ISO-8859-7", 0x08: "ISO-8859-8",
    0x09: "ISO-8859-9", 0xFF: "Unicode",
}
_slot_counts = {0x00: 1, 0x01: 6, 0x02: 8, 0x03: 16}


class IrLAP_XID_DiscInfo(Packet):
    """Discovery information appended to XID final-slot frames."""
    name = "IrLAP XID Discovery Info"
    fields_desc = [
        ByteField("hints1", 0),
        ConditionalField(ByteField("hints2", 0),
                         lambda p: p.hints1 & 0x80),
        ByteEnumField("charset", 0, _charset_names),
        StrField("nickname", b""),
    ]


class IrLAP_XID(Packet):
    """XID (Exchange Station Identification) frame info field."""
    name = "IrLAP XID"
    fields_desc = [
        XByteField("format_id", XID_FORMAT),
        LEIntField("saddr", 0),
        LEIntField("daddr", BROADCAST),
        ByteField("flags", 0x01),
        ByteField("slotnr", 0xFF),
        ByteField("version", 0x00),
    ]

    @property
    def slot_count(self):
        return _slot_counts.get(self.flags & 0x03, 0)

    def guess_payload_class(self, payload):
        if payload and self.slotnr == 0xFF:
            return IrLAP_XID_DiscInfo
        return Packet.guess_payload_class(self, payload)
```

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add IrLAP XID discovery frame dissection"
```

---

### Task 3: SNRM, UA, and negotiation parameters

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write SNRM/UA tests**

Append to `tests/irda_scapy.uts`:

```
+ SNRM and UA frames
= Dissect SNRM command
# addr=0xFF(bcast,cmd), ctrl=0x93(SNRM|PF), saddr, daddr, new_caddr=0x42
p = IrLAP(bytes.fromhex("ff93 8b85c7da d9c32895 42"))
assert p.control == 0x93
assert p.u_type == SNRM_CMD
s = p[IrLAP_SNRM]
assert s.saddr == 0xdac7858b
assert s.daddr == 0x9528c3d9
assert s.new_caddr == 0x42

= Dissect UA response
# addr=0x42(caddr,rsp), ctrl=0x73(UA|PF), saddr, daddr
p = IrLAP(bytes.fromhex("4273 d9c32895 8b85c7da"))
assert p.addr == 0x21
assert p.cr == 0
assert p.u_type == UA_RSP
u = p[IrLAP_UA]
assert u.saddr == 0x9528c3d9
assert u.daddr == 0xdac7858b

= Dissect SNRM with QoS negotiation parameters
# SNRM + baud rate param (PI=0x01, PL=0x01, PV=0x20 = 115200)
p = IrLAP(bytes.fromhex("ff93 8b85c7da d9c32895 42 010120"))
s = p[IrLAP_SNRM]
assert len(s.params) >= 1
assert s.params[0].pi == 0x01
assert s.params[0].pv == bytes.fromhex("20")

= QoS parameter roundtrip
param = IrLAP_NegParam(pi=0x01, pl=1, pv=b"\x20")
assert raw(param) == bytes.fromhex("010120")
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: SNRM/UA tests FAIL

**Step 3: Implement SNRM, UA, and negotiation parameter classes**

Add to `scapy/contrib/irda.py`:

```python
# QoS negotiation parameter identifiers
_qos_pi_names = {
    0x01: "BaudRate", 0x08: "LinkDisconnect",
    0x82: "MaxTurnTime", 0x83: "DataSize", 0x84: "WindowSize",
    0x85: "AdditionalBOFs", 0x86: "MinTurnTime",
}


class IrLAP_NegParam(Packet):
    """QoS negotiation parameter (PI/PL/PV triplet)."""
    name = "IrLAP Negotiation Parameter"
    fields_desc = [
        ByteEnumField("pi", 0, _qos_pi_names),
        FieldLenField("pl", None, length_of="pv", fmt="B"),
        StrLenField("pv", b"", length_from=lambda p: p.pl),
    ]

    def extract_padding(self, s):
        return b"", s


class IrLAP_SNRM(Packet):
    """SNRM (Set Normal Response Mode) frame info field."""
    name = "IrLAP SNRM"
    fields_desc = [
        LEIntField("saddr", 0),
        LEIntField("daddr", 0),
        XByteField("new_caddr", 0),
        PacketListField("params", [], IrLAP_NegParam),
    ]


class IrLAP_UA(Packet):
    """UA (Unnumbered Acknowledgement) frame info field."""
    name = "IrLAP UA"
    fields_desc = [
        LEIntField("saddr", 0),
        LEIntField("daddr", 0),
        PacketListField("params", [], IrLAP_NegParam),
    ]


class IrLAP_FRMR(Packet):
    """FRMR (Frame Reject) info field."""
    name = "IrLAP FRMR"
    fields_desc = [
        XByteField("rej_control", 0),
        XByteField("rej_info", 0),
        XByteField("rej_flags", 0),
    ]
```

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add IrLAP SNRM/UA with negotiation parameters"
```

---

### Task 4: I-frames, S-frames, and remaining U-frames

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write I-frame and S-frame tests**

Append to `tests/irda_scapy.uts`:

```
+ I-frames and S-frames
= IrLAP I-frame properties
# addr=0x42(caddr=0x21,cmd), ctrl=0x30 (Ns=0, Nr=1, P=1, bit0=0 → I-frame)
p = IrLAP(bytes.fromhex("4330"))
assert p.frame_type == "I"
assert p.ns == 0
assert p.nr == 1
assert p.pf == True

= IrLAP S-frame RR
# addr=0x42(caddr,rsp), ctrl=0x31 (Nr=1, P=1, RR)
p = IrLAP(bytes.fromhex("4231"))
assert p.frame_type == "S"
assert p.s_type == S_RR
assert p.nr == 1
assert p.pf == True

= IrLAP S-frame RNR
p = IrLAP(bytes.fromhex("4235"))
assert p.s_type == S_RNR

= IrLAP DISC command
# addr=0x43(caddr=0x21,cmd), ctrl=0x53(DISC|PF)
p = IrLAP(bytes.fromhex("4353"))
assert p.u_type == DISC_CMD
assert p.pf == True

= IrLAP DM response
p = IrLAP(bytes.fromhex("421f"))
assert p.u_type == DM_RSP

= IrLAP UI frame
p = IrLAP(bytes.fromhex("ff13") + b"hello")
assert p.u_type == UI_FRAME
assert p.payload.load == b"hello"
```

**Step 2: Run tests to verify they pass** (these use existing IrLAP properties, should mostly pass already)

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: Mostly PASS; fix any issues

**Step 3: Add S-frame type enum and any missing U-frame constants**

Ensure `irda.py` exports all constants and that `guess_payload_class` handles DISC/DM/UI correctly (returning `Raw` for payload-less frames).

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add I-frame/S-frame properties and remaining U-frame types"
```

---

### Task 5: IrLMP layer

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write IrLMP tests**

Append to `tests/irda_scapy.uts`:

```
+ IrLMP layer
= IrLMP data frame dissection
# DLSAP=0x12 (control=0), SLSAP=0x34
p = IrLMP(bytes.fromhex("1234") + b"\x05data")
assert p.dlsap == 0x12
assert p.control_bit == 0
assert p.slsap == 0x34

= IrLMP control frame dissection
# DLSAP=0x12|CONTROL(0x80)=0x92, SLSAP=0x34, opcode=CONNECT_CMD(0x01), reason=0
p = IrLMP(bytes.fromhex("92340100"))
assert p.dlsap == 0x12
assert p.control_bit == 1
assert p.slsap == 0x34
c = p[IrLMP_Control]
assert c.opcode == 0x01
assert c.reason == 0x00

= IrLMP disconnect
p = IrLMP(bytes.fromhex("92340201"))
c = p[IrLMP_Control]
assert c.opcode == 0x02
assert c.reason == 0x01

= IrLMP IAS LSAP detection
# DLSAP=0x00 (IAS), SLSAP=0x05 → payload is TTP then IAS
p = IrLMP(bytes.fromhex("0005"))
assert p.dlsap == 0x00

= IrLMP build roundtrip
p = IrLMP(dlsap=0x12, control_bit=0, slsap=0x34, rsvd=0)
assert raw(p) == bytes.fromhex("1234")
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: IrLMP tests FAIL

**Step 3: Implement IrLMP**

Add to `scapy/contrib/irda.py`:

```python
# IrLMP constants
LSAP_IAS = 0x00
LSAP_ANY = 0xFF
LSAP_CONNLESS = 0x70
LSAP_MASK = 0x7F
CONTROL_BIT = 0x80

_irlmp_opcodes = {
    0x01: "CONNECT_CMD", 0x81: "CONNECT_CNF",
    0x02: "DISCONNECT", 0x03: "ACCESSMODE_CMD", 0x83: "ACCESSMODE_CNF",
}


class IrLMP_Control(Packet):
    """IrLMP control frame (connect/disconnect/access mode)."""
    name = "IrLMP Control"
    fields_desc = [
        ByteEnumField("opcode", 0, _irlmp_opcodes),
        ByteField("reason", 0),
    ]


class IrLMP(Packet):
    """IrDA Link Management Protocol."""
    name = "IrLMP"
    fields_desc = [
        XBitField("dlsap", 0, 7),
        BitField("control_bit", 0, 1),
        XBitField("slsap", 0, 7),
        BitField("rsvd", 0, 1),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        if self.control_bit:
            return IrLMP_Control
        # Data frame → TTP
        return IrTTP
```

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add IrLMP layer with control frame dispatch"
```

---

### Task 6: TTP layer

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write TTP tests**

Append to `tests/irda_scapy.uts`:

```
+ TTP layer
= TTP data frame
# credit=5, more=0
p = IrTTP(bytes.fromhex("05") + b"hello")
assert p.more == 0
assert p.credit == 5
assert p.payload.load == b"hello"

= TTP SAR fragment
# more=1, credit=3
p = IrTTP(bytes.fromhex("83") + b"partial")
assert p.more == 1
assert p.credit == 3

= TTP connect with SAR parameters
# params=1, credit=10, total_len=4, PI=0x01(MaxSduSize), PL=2, PV=0x0400(1024)
p = IrTTP(bytes.fromhex("8a 04 01 02 0400"))
assert p.more == 1  # params bit
assert p.credit == 10

= TTP build roundtrip
p = IrTTP(more=0, credit=5)
assert raw(p) == bytes.fromhex("05")
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: TTP tests FAIL

**Step 3: Implement TTP**

Add to `scapy/contrib/irda.py`:

```python
# TTP constants
TTP_MORE = 0x80
TTP_PARAMETERS = 0x80
TTP_MAX_SDU_SIZE = 0x01


class IrTTP(Packet):
    """IrDA Tiny Transport Protocol."""
    name = "IrTTP"
    fields_desc = [
        BitField("more", 0, 1),
        BitField("credit", 0, 7),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        return Packet.guess_payload_class(self, payload)
```

Note: The SAR connect parameter parsing is deferred — the `more` bit in a connect context means "parameters follow" but distinguishing connect vs data requires IrLMP state. For stateless dissection, the raw payload after the TTP header is sufficient and can be decoded manually or with `IrIAS`/`IrOBEX` binding.

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add TTP layer with credit-based flow control"
```

---

### Task 7: IAS layer

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write IAS tests**

Append to `tests/irda_scapy.uts`:

```
+ IAS layer
= IAS GetValueByClass request
# lst=1, ack=0, opcode=0x04, class="IrDA:IrCOMM"(12), attr="IrDA:TinyTP:LsapSel"(20)
class_name = b"IrDA:IrCOMM"
attr_name = b"IrDA:TinyTP:LsapSel"
data = bytes([0x84, len(class_name)]) + class_name + bytes([len(attr_name)]) + attr_name
p = IrIAS(data)
assert p.lst == 1
assert p.ack == 0
assert p.opcode == 0x04
r = p[IrIAS_GetValueByClass_Req]
assert r.class_name == class_name
assert r.attr_name == attr_name

= IAS GetValueByClass response (integer)
# lst=1, ack=0, opcode=0x04, return=SUCCESS(0), list_len=1, obj_id=1,
# type=INTEGER(1), value=10 (LSAP selector)
data = bytes.fromhex("84 0000 0001 0001 01 0000000a")
p = IrIAS(data)
assert p.opcode == 0x04
r = p[IrIAS_GetValueByClass_Rsp]
assert r.return_code == 0
assert r.attr_type == 1
assert r.integer_value == 10

= IAS GetValueByClass response (string)
# type=STRING(3), charset=0(ASCII), len=5, "Hello"
data = bytes.fromhex("84 0000 0001 0001 03 00 0005 48656c6c6f")
p = IrIAS(data)
r = p[IrIAS_GetValueByClass_Rsp]
assert r.attr_type == 3
assert r.string_value == b"Hello"
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: IAS tests FAIL

**Step 3: Implement IAS**

Add to `scapy/contrib/irda.py`:

```python
# IAS constants
IAS_SUCCESS = 0
IAS_CLASS_UNKNOWN = 1
IAS_ATTRIB_UNKNOWN = 2

_ias_opcodes = {
    0x01: "GetInfoBaseDetails", 0x02: "GetObjects", 0x03: "GetValue",
    0x04: "GetValueByClass", 0x05: "GetObjectInfo", 0x06: "GetAttribNames",
}
_ias_attr_types = {
    0: "MISSING", 1: "INTEGER", 2: "OCT_SEQ", 3: "STRING",
}
_ias_return_codes = {
    0: "SUCCESS", 1: "CLASS_UNKNOWN", 2: "ATTRIB_UNKNOWN",
}


class IrIAS_GetValueByClass_Req(Packet):
    name = "IrIAS GetValueByClass Request"
    fields_desc = [
        FieldLenField("class_name_len", None, length_of="class_name", fmt="B"),
        StrLenField("class_name", b"", length_from=lambda p: p.class_name_len),
        FieldLenField("attr_name_len", None, length_of="attr_name", fmt="B"),
        StrLenField("attr_name", b"", length_from=lambda p: p.attr_name_len),
    ]


class IrIAS_GetValueByClass_Rsp(Packet):
    name = "IrIAS GetValueByClass Response"
    fields_desc = [
        ShortField("return_code", 0),
        ShortField("list_len", 1),
        ShortField("obj_id", 0),
        ByteEnumField("attr_type", 0, _ias_attr_types),
        # Type-dependent value fields
        ConditionalField(IntField("integer_value", 0),
                         lambda p: p.attr_type == 1),
        ConditionalField(ByteEnumField("string_charset", 0, _charset_names),
                         lambda p: p.attr_type == 3),
        ConditionalField(
            FieldLenField("string_len", None, length_of="string_value", fmt="!H"),
            lambda p: p.attr_type == 3),
        ConditionalField(
            StrLenField("string_value", b"", length_from=lambda p: p.string_len),
            lambda p: p.attr_type == 3),
        ConditionalField(
            FieldLenField("octseq_len", None, length_of="octseq_value", fmt="!H"),
            lambda p: p.attr_type == 2),
        ConditionalField(
            StrLenField("octseq_value", b"", length_from=lambda p: p.octseq_len),
            lambda p: p.attr_type == 2),
    ]


class IrIAS(Packet):
    """IrDA Information Access Service."""
    name = "IrIAS"
    fields_desc = [
        BitField("lst", 1, 1),
        BitField("ack", 0, 1),
        BitField("opcode", 0, 6),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        if self.opcode == 0x04:
            # Distinguish request vs response by checking the data:
            # Requests start with class_name_len (1 byte string length)
            # Responses start with return_code (2 bytes)
            # Heuristic: if the frame is from a command (lst=1), check
            # if the ack bit distinguishes direction
            # Actually, IAS uses lst+ack for framing; the direction is
            # determined by SLSAP/DLSAP at the IrLMP layer.
            # For stateless dissection: if first 2 bytes look like a
            # return code (0x0000-0x000A), it's likely a response.
            if len(payload) >= 2:
                rc = (payload[0] << 8) | payload[1]
                if rc <= 10:
                    return IrIAS_GetValueByClass_Rsp
            return IrIAS_GetValueByClass_Req
        return Packet.guess_payload_class(self, payload)
```

Note: The request vs response heuristic is imperfect for stateless dissection. A more robust approach would use IrLMP SLSAP/DLSAP context (IAS server is always LSAP 0). This is documented as a known limitation.

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add IAS layer with GetValueByClass request/response"
```

---

### Task 8: OBEX layer

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write OBEX tests**

Append to `tests/irda_scapy.uts`:

```
+ OBEX layer
= OBEX Connect request
# opcode=0x80(Connect), length=7, version=0x10, flags=0, max_pkt=1024
p = IrOBEX(bytes.fromhex("80 0007 10 00 0400"))
assert p.opcode == 0x80
assert p.length == 7
assert p.version == 0x10
assert p.max_pkt_len == 0x0400

= OBEX Put with Name and Body headers
# opcode=0x02(Put), length=..., headers: Name(0x01)+"test.txt", Body(0x48)+data
name_hdr = bytes.fromhex("01") + b"\x00\x15" + "test.txt".encode("utf-16-be") + b"\x00\x00"
body_hdr = bytes.fromhex("48") + b"\x00\x07" + b"data"
data = bytes([0x02]) + (3 + len(name_hdr) + len(body_hdr)).to_bytes(2, "big") + name_hdr + body_hdr
p = IrOBEX(data)
assert p.opcode == 0x02
assert len(p.headers) >= 2

= OBEX Success response
p = IrOBEX(bytes.fromhex("a0 0003"))
assert p.opcode == 0xa0
assert p.length == 3

= OBEX build roundtrip
p = IrOBEX(opcode=0xa0, length=3)
assert raw(p) == bytes.fromhex("a00003")
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: OBEX tests FAIL

**Step 3: Implement OBEX**

Add to `scapy/contrib/irda.py`:

```python
# OBEX opcodes
_obex_opcodes = {
    0x00: "Connect", 0x01: "Disconnect", 0x02: "Put", 0x03: "Get",
    0x05: "SetPath", 0x06: "Action", 0x07: "Session",
    0x80: "Connect", 0x81: "Disconnect", 0x82: "Put-Final",
    0x83: "Get-Final", 0x85: "SetPath", 0xFF: "Abort",
    # Responses
    0x10: "Continue", 0x20: "Success", 0x40: "Bad Request",
    0x41: "Unauthorized", 0x43: "Forbidden", 0x44: "Not Found",
    0x4D: "Not Acceptable", 0x60: "Internal Server Error",
    0x61: "Not Implemented", 0x63: "Service Unavailable",
    0x90: "Continue", 0xA0: "Success",
    0xC0: "Bad Request", 0xC1: "Unauthorized", 0xC3: "Forbidden",
    0xC4: "Not Found",
}

# OBEX header IDs — high 2 bits encode type
_obex_header_ids = {
    0x01: "Name", 0x05: "Description", 0x42: "Type", 0x44: "TimeISO",
    0x46: "Target", 0x48: "Body", 0x49: "EndOfBody", 0x4A: "Who",
    0x4B: "AppParameters", 0x4F: "ObjectClass",
    0xC0: "Count", 0xC3: "Length", 0xC4: "TimeCompat",
    0xCB: "ConnectionID",
}


class IrOBEX_Header(Packet):
    """Single OBEX header."""
    name = "OBEX Header"
    fields_desc = [
        ByteEnumField("hid", 0, _obex_header_ids),
        # Type depends on high 2 bits of hid:
        # 00 = unicode string (2-byte length prefix, includes header+length)
        # 01 = byte sequence (2-byte length prefix)
        # 10 = 1-byte value
        # 11 = 4-byte value
        ConditionalField(
            FieldLenField("hlen", None, length_of="hval", fmt="!H",
                          adjust=lambda pkt, x: x + 3),
            lambda p: (p.hid >> 6) in (0, 1)),
        ConditionalField(
            StrLenField("hval", b"", length_from=lambda p: max(0, p.hlen - 3)),
            lambda p: (p.hid >> 6) in (0, 1)),
        ConditionalField(ByteField("hval_1b", 0),
                         lambda p: (p.hid >> 6) == 2),
        ConditionalField(IntField("hval_4b", 0),
                         lambda p: (p.hid >> 6) == 3),
    ]

    def extract_padding(self, s):
        return b"", s


class IrOBEX(Packet):
    """IrDA Object Exchange Protocol."""
    name = "IrOBEX"
    fields_desc = [
        ByteEnumField("opcode", 0, _obex_opcodes),
        ShortField("length", None),
        # Connect request/response has extra fields
        ConditionalField(ByteField("version", 0x10),
                         lambda p: (p.opcode & 0x7F) == 0x00),
        ConditionalField(ByteField("flags", 0),
                         lambda p: (p.opcode & 0x7F) == 0x00),
        ConditionalField(ShortField("max_pkt_len", 1024),
                         lambda p: (p.opcode & 0x7F) == 0x00),
        PacketListField("headers", [], IrOBEX_Header,
                         length_from=lambda p: _obex_headers_len(p)),
    ]

    def post_build(self, p, pay):
        if self.length is None:
            p = p[:1] + len(p).to_bytes(2, "big") + p[3:]
        return p + pay


def _obex_headers_len(pkt):
    """Calculate remaining bytes available for headers."""
    base = 3  # opcode + length
    if (pkt.opcode & 0x7F) == 0x00:
        base += 4  # version + flags + max_pkt_len
    total = pkt.length if pkt.length else 0
    return max(0, total - base)
```

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add OBEX layer with header dissection"
```

---

### Task 9: DLT registration, layer bindings, and CookedLinux integration

**Files:**
- Modify: `scapy/contrib/irda.py`
- Modify: `tests/irda_scapy.uts`

**Step 1: Write integration tests**

Append to `tests/irda_scapy.uts`:

```
+ Layer bindings and DLT registration
= CookedLinux to IrLAP binding
from scapy.layers.l2 import CookedLinux
# SLL header: pkttype=0(host), lladdrtype=783(IRDA), lladdrlen=0, src=0, proto=23(IRDA)
sll = bytes.fromhex("0000 030f 0000 0000000000000000 0017")
irlap = bytes.fromhex("ff3f01 8b85c7da ffffffff 01 05 00")
p = CookedLinux(sll + irlap)
assert IrLAP in p
assert p[IrLAP].addr == 0x7f
assert p[IrLAP_XID].saddr == 0xdac7858b

= Full stack: IrLAP I-frame → IrLMP → TTP
# addr=0x43(caddr=0x21,cmd), ctrl=0x10(I-frame, Ns=0, Nr=0, P=1)
# IrLMP: dlsap=0x12, ctl=0, slsap=0x34
# TTP: credit=5, more=0
# Payload: "test"
p = IrLAP(bytes.fromhex("4310 1234 05") + b"test")
assert p.frame_type == "I"
assert IrLMP in p
assert p[IrLMP].dlsap == 0x12
assert IrTTP in p
assert p[IrTTP].credit == 5
assert p[IrTTP].payload.load == b"test"

= DLT_LINUX_IRDA registration
assert conf.l2types.get(144) is not None
```

**Step 2: Run tests to verify failures**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: Binding tests may fail

**Step 3: Add DLT registration and override existing bindings**

Add to the end of `scapy/contrib/irda.py`:

```python
# ---------------------------------------------------------------------------
# Layer bindings
# ---------------------------------------------------------------------------

# Override the existing minimal ir.py bindings
# Remove old IrLAPHead binding from CookedLinux
from scapy.layers import ir as _ir_module
CookedLinux.payload_guess = [
    (cond, cls) for cond, cls in CookedLinux.payload_guess
    if cls is not _ir_module.IrLAPHead
]

# Register our layers
bind_layers(CookedLinux, IrLAP, proto=23)

# DLT_LINUX_IRDA (144) → CookedLinux (which then dispatches to IrLAP via proto=23)
# The existing registration in l2.py already maps 144 → CookedLinux, which is correct.
# Verify it's registered:
if conf.l2types.num2layer.get(DLT_LINUX_IRDA) is None:
    conf.l2types.register_num2layer(DLT_LINUX_IRDA, CookedLinux)
```

**Step 4: Run tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add scapy/contrib/irda.py tests/irda_scapy.uts
git commit -m "Add DLT registration and CookedLinux layer bindings"
```

---

### Task 10: IrDA AF_IRDA socket test tool

**Files:**
- Create: `irda-test.py`

**Step 1: Write the test tool**

Create `irda-test.py` at project root:

```python
#!/usr/bin/env python3
"""IrDA socket test tool for generating real IrDA traffic.

Generates multi-layer traffic visible in tshark/scapy captures:
IrLAP SNRM/UA, IrLMP connect, TTP flow control, IAS queries.

Usage:
    # Terminal 1 (receiving dongle):
    sudo ./irda-test.py server

    # Terminal 2 (sending dongle):
    sudo ./irda-test.py client

    # Capture traffic:
    tshark -i irdamon0
"""

import argparse
import ctypes
import ctypes.util
import socket
import struct
import sys
import time

AF_IRDA = socket.AF_IRDA
SERVICE_NAME = b"IrDATest:IrDA:TinyTP"

# ioctl / sockopt constants from linux/irda.h
IRLMP_ENUMDEVICES = 0x02
IRLMP_IAS_SET = 0x03
IRLMP_HINTS_SET = 0x06


def discover_devices(sock, timeout=5):
    """Discover IrDA devices, return list of (daddr, info) tuples."""
    # IRLMP_ENUMDEVICES returns an irda_device_list struct
    # Give discovery time to run
    print(f"  Discovering devices ({timeout}s)...")
    time.sleep(timeout)

    buf = sock.getsockopt(socket.SOL_IRLMP, IRLMP_ENUMDEVICES, 1024)
    if len(buf) < 4:
        return []

    count = struct.unpack_from("<I", buf, 0)[0]
    devices = []
    offset = 4
    # Each irda_device_info: saddr(4) + daddr(4) + info(22) + charset(1) + hints(2) = 33 bytes
    for _ in range(count):
        if offset + 33 > len(buf):
            break
        saddr, daddr = struct.unpack_from("<II", buf, offset)
        info = buf[offset + 8:offset + 30].split(b"\x00", 1)[0].decode("ascii", errors="replace")
        devices.append((daddr, info))
        offset += 33
    return devices


def cmd_server(args):
    """Run IrDA echo server."""
    print("==> Starting IrDA echo server")
    print(f"  Service: {SERVICE_NAME.decode()}")

    sock = socket.socket(AF_IRDA, socket.SOCK_STREAM)
    sock.bind((0, SERVICE_NAME))
    sock.listen(1)

    print("  Listening for connections...")
    try:
        conn, addr = sock.accept()
        print(f"  Connected: {addr}")

        total = 0
        while True:
            data = conn.recv(4096)
            if not data:
                break
            total += len(data)
            print(f"  Received {len(data)} bytes (total: {total})")
            # Echo back
            conn.sendall(data)

        print(f"  Connection closed. Total bytes: {total}")
        conn.close()
    except KeyboardInterrupt:
        print("\n  Interrupted")
    finally:
        sock.close()


def cmd_client(args):
    """Run IrDA test client."""
    print("==> Starting IrDA test client")

    sock = socket.socket(AF_IRDA, socket.SOCK_STREAM)

    # Discover devices
    devices = discover_devices(sock)
    if not devices:
        print("  No devices found. Is discovery enabled?")
        print("  echo 1 > /proc/sys/net/irda/discovery")
        sock.close()
        sys.exit(1)

    for daddr, info in devices:
        print(f"  Found: {info} (0x{daddr:08x})")

    # Connect to first device
    daddr = devices[0][0]
    print(f"\n  Connecting to 0x{daddr:08x}...")
    sock.connect((daddr, SERVICE_NAME))
    print("  Connected!")

    # Send test patterns
    patterns = [
        ("Short message", b"Hello IrDA!"),
        ("Medium block", b"X" * 512),
        ("Large transfer (SAR)", b"Y" * 4096),
    ]

    for name, data in patterns:
        print(f"\n  Sending: {name} ({len(data)} bytes)")
        start = time.monotonic()
        sock.sendall(data)

        # Read echo
        received = b""
        while len(received) < len(data):
            chunk = sock.recv(4096)
            if not chunk:
                break
            received += chunk

        elapsed = time.monotonic() - start
        ok = received == data
        status = "OK" if ok else f"MISMATCH (got {len(received)} bytes)"
        rate = len(data) / elapsed if elapsed > 0 else 0
        print(f"  Echo: {status} ({elapsed:.3f}s, {rate:.0f} B/s)")

    sock.close()
    print("\n  Done.")


def main():
    parser = argparse.ArgumentParser(description="IrDA socket test tool")
    sub = parser.add_subparsers(dest="command")
    sub.required = True

    p_server = sub.add_parser("server", help="Echo server (binds to first dongle)")
    p_server.set_defaults(func=cmd_server)

    p_client = sub.add_parser("client", help="Test client (connects to remote device)")
    p_client.set_defaults(func=cmd_client)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
```

**Step 2: Test help output**

Run: `python3 irda-test.py --help`
Expected: Shows server/client subcommands

**Step 3: Integration test (requires two dongles)**

In terminal 1: `sudo python3 irda-test.py server`
In terminal 2: `sudo python3 irda-test.py client`
In terminal 3: `sudo tshark -i irdamon0` — should show SNRM, UA, I-frames, RR, DISC

**Step 4: Commit**

```bash
git add irda-test.py
git commit -m "Add IrDA AF_IRDA socket test tool"
```

---

### Task 11: End-to-end validation with real captures

**Files:**
- Modify: `tests/irda_scapy.uts` (add pcap-based tests if captures available)

**Step 1: Capture real traffic**

```bash
sudo tshark -i irdamon0 -w /tmp/irda_test.pcap &
sudo python3 irda-test.py server &
sudo python3 irda-test.py client
kill %1
```

**Step 2: Validate scapy can read the capture**

```bash
python3 -c "
from scapy.contrib.irda import *
from scapy.utils import rdpcap
pkts = rdpcap('/tmp/irda_test.pcap')
pkts.summary()
# Should show IrLAP / IrLMP / IrTTP layers
for p in pkts[:5]:
    p.show()
"
```

**Step 3: Compare scapy output with tshark**

```bash
tshark -r /tmp/irda_test.pcap
```

Both should decode the same frame types. Document any discrepancies.

**Step 4: Fix any issues found, re-run UTScapy tests**

Run: `cd /home/f0rk/Tools/irda && python3 -m scapy.tools.UTscapy -f text tests/irda_scapy.uts`
Expected: All PASS

**Step 5: Commit**

```bash
git add tests/irda_scapy.uts
git commit -m "Validate scapy dissector against real captures"
```
