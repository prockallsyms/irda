# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information

# scapy.contrib.description = IrDA (Infrared Data Association)
# scapy.contrib.status = loads

"""
IrDA (Infrared Data Association) protocol stack.

Implements the IrDA protocol layers: IrLAP, IrLMP, TinyTP, IAS, and OBEX.

References:
    IrDA IrLAP specification v1.1
    IrDA IrLMP specification v1.1
    IrDA Tiny TP specification v1.1
    IrDA IrOBEX specification v1.3
"""

from scapy.packet import Packet, Raw, bind_layers, split_bottom_up
from scapy.fields import (XBitField, BitField, BitEnumField, XByteField,
                          ByteField, LEIntField, StrField, ByteEnumField,
                          ConditionalField, FieldLenField, StrLenField,
                          PacketListField, ShortField, IntField)

# ---------------------------------------------------------------------------
# IrLAP constants
# ---------------------------------------------------------------------------

# Command/Response bit values
CMD_FRAME = 0x01
RSP_FRAME = 0x00

# Connection address for broadcast (7-bit)
CBROADCAST = 0x7F

# Poll/Final bit in the control byte
PF_BIT = 0x10

# S-frame supervisory function codes (bits 3..2 of control byte)
S_RR = 0x01      # Receive Ready
S_RNR = 0x05     # Receive Not Ready
S_REJ = 0x09     # Reject
S_SREJ = 0x0D    # Selective Reject

# U-frame control values (with P/F = 0)
SNRM_CMD = 0x83   # Set Normal Response Mode
DISC_CMD = 0x43   # Disconnect
XID_CMD = 0x2F    # Exchange Station Identification (command)
XID_RSP = 0xAF    # Exchange Station Identification (response)
TEST_CMD = 0xE3   # Test
UI_FRAME = 0x03   # Unnumbered Information
UA_RSP = 0x63     # Unnumbered Acknowledgement
DM_RSP = 0x0F     # Disconnected Mode
FRMR_RSP = 0x87   # Frame Reject
RD_RSP = 0x43     # Request Disconnect (same encoding as DISC)
RNRM_RSP = 0x83   # Request Normal Response Mode (same encoding as SNRM)

# XID format identifier
XID_FORMAT = 0x01

# Broadcast device address (32-bit)
BROADCAST = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# IrLAP packet
# ---------------------------------------------------------------------------

class IrLAP(Packet):
    """IrDA Link Access Protocol frame.

    The IrLAP address field is one byte:
        - bits 7..1: 7-bit connection address
        - bit 0: C/R (command/response) bit

    The control field is one byte encoding the frame type:
        - I-frame:  bit 0 = 0;  Nr(7..5), P/F(4), Ns(3..1), 0
        - S-frame:  bits 1..0 = 01;  Nr(7..5), P/F(4), type(3..2), 01
        - U-frame:  bits 1..0 = 11;  modifier(7..5), P/F(4), modifier(3..2), 11
    """
    name = "IrLAP"
    fields_desc = [
        XBitField("addr", 0x7f, 7),
        BitEnumField("cr", 1, 1, {0: "rsp", 1: "cmd"}),
        XByteField("control", 0),
    ]

    @property
    def frame_type(self):
        """Return the frame type as a string: 'I', 'S', or 'U'."""
        c = self.control
        if (c & 0x01) == 0:
            return "I"
        elif (c & 0x03) == 0x01:
            return "S"
        else:
            return "U"

    @property
    def pf(self):
        """Return the Poll/Final bit value (0 or 1)."""
        return (self.control >> 4) & 0x01

    @property
    def ns(self):
        """Return the send sequence number Ns (I-frames only)."""
        return (self.control >> 1) & 0x07

    @property
    def nr(self):
        """Return the receive sequence number Nr (I-frames and S-frames)."""
        return (self.control >> 5) & 0x07

    @property
    def s_type(self):
        """Return the S-frame supervisory function code (S-frames only).

        Returns the full nibble (bits 3..0) matching the S_RR/S_RNR/etc.
        constants, e.g. 0x01 for RR, 0x05 for RNR.
        """
        return self.control & 0x0F

    @property
    def u_type(self):
        """Return the U-frame modifier bits (U-frames only).

        Returns the control byte with P/F bit cleared, matching the
        U-frame constants (SNRM_CMD, XID_CMD, etc.).
        """
        return self.control & ~PF_BIT & 0xFF

    def guess_payload_class(self, payload):
        """Dispatch to the appropriate payload class based on frame type.

        U-frames are dispatched by modifier:
            - XID_CMD / XID_RSP  -> IrLAP_XID
            - SNRM_CMD           -> IrLAP_SNRM
            - UA_RSP             -> IrLAP_UA
            - FRMR_RSP           -> IrLAP_FRMR

        I-frames will be dispatched to IrLMP (Task 5).
        """
        if not payload:
            return Raw
        ft = self.frame_type
        if ft == "U":
            ut = self.u_type
            if ut == XID_CMD or ut == XID_RSP:
                return IrLAP_XID
            elif ut == SNRM_CMD:
                return IrLAP_SNRM
            elif ut == UA_RSP:
                return IrLAP_UA
            elif ut == FRMR_RSP:
                return IrLAP_FRMR
        elif ft == "I":
            return IrLMP
        return Packet.guess_payload_class(self, payload)


# ---------------------------------------------------------------------------
# XID Discovery Frames (Task 2)
# ---------------------------------------------------------------------------

# Hint byte 1 flags
XID_HINT1_FLAGS = {
    0x01: "PnP",
    0x02: "PDA",
    0x04: "Computer",
    0x08: "Printer",
    0x10: "Modem",
    0x20: "Fax",
    0x40: "LAN",
    0x80: "Extension",
}

# Hint byte 2 flags
XID_HINT2_FLAGS = {
    0x01: "Telephony",
    0x02: "FileServer",
    0x04: "IrCOMM",
    0x08: "Message",
    0x10: "HTTP",
    0x20: "OBEX",
}

# Charset names
XID_CHARSETS = {
    0x00: "ASCII",
    0x01: "ISO-8859-1",
    0x02: "ISO-8859-2",
    0x03: "ISO-8859-3",
    0x04: "ISO-8859-4",
    0x05: "ISO-8859-5",
    0x06: "ISO-8859-6",
    0x07: "ISO-8859-7",
    0x08: "ISO-8859-8",
    0x09: "ISO-8859-9",
    0xFF: "Unicode",
}


class IrLAP_XID(Packet):
    """IrLAP XID (Exchange Station Identification) frame info field."""
    name = "IrLAP_XID"
    fields_desc = [
        XByteField("format_id", XID_FORMAT),
        LEIntField("saddr", 0),
        LEIntField("daddr", BROADCAST),
        ByteField("flags", 0),
        ByteField("slotnr", 0xFF),
        ByteField("version", 0),
    ]

    @property
    def slot_count(self):
        """Decode flags bits 1..0 to slot count."""
        slot_bits = self.flags & 0x03
        return {0x00: 1, 0x01: 6, 0x02: 8, 0x03: 16}[slot_bits]

    def guess_payload_class(self, payload):
        if self.slotnr == 0xFF and payload:
            return IrLAP_XID_DiscInfo
        return Packet.guess_payload_class(self, payload)


class IrLAP_XID_DiscInfo(Packet):
    """IrLAP XID Discovery Information appended to final-slot XID frames."""
    name = "IrLAP_XID_DiscInfo"
    fields_desc = [
        ByteField("hints1", 0),
        ConditionalField(ByteField("hints2", 0),
                         lambda pkt: pkt.hints1 & 0x80),
        ByteEnumField("charset", 0, XID_CHARSETS),
        StrField("nickname", b""),
    ]


# ---------------------------------------------------------------------------
# Negotiation Parameters and SNRM/UA/FRMR (Task 3)
# ---------------------------------------------------------------------------

# PI (Parameter Identifier) names
PI_NAMES = {
    0x01: "BaudRate",
    0x08: "LinkDisconnect",
    0x82: "MaxTurnTime",
    0x83: "DataSize",
    0x84: "WindowSize",
    0x85: "AdditionalBOFs",
    0x86: "MinTurnTime",
}


class IrLAP_NegParam(Packet):
    """IrLAP QoS negotiation parameter (PI/PL/PV triplet)."""
    name = "IrLAP_NegParam"
    fields_desc = [
        ByteEnumField("pi", 0, PI_NAMES),
        FieldLenField("pl", None, length_of="pv", fmt="B"),
        StrLenField("pv", b"", length_from=lambda pkt: pkt.pl),
    ]

    def extract_padding(self, s):
        return b"", s


class IrLAP_SNRM(Packet):
    """IrLAP SNRM (Set Normal Response Mode) info field."""
    name = "IrLAP_SNRM"
    fields_desc = [
        LEIntField("saddr", 0),
        LEIntField("daddr", 0),
        XByteField("new_caddr", 0),
        PacketListField("params", [], IrLAP_NegParam),
    ]


class IrLAP_UA(Packet):
    """IrLAP UA (Unnumbered Acknowledgement) info field."""
    name = "IrLAP_UA"
    fields_desc = [
        LEIntField("saddr", 0),
        LEIntField("daddr", 0),
        PacketListField("params", [], IrLAP_NegParam),
    ]


class IrLAP_FRMR(Packet):
    """IrLAP FRMR (Frame Reject) info field."""
    name = "IrLAP_FRMR"
    fields_desc = [
        XByteField("rej_control", 0),
        XByteField("rej_info", 0),
        XByteField("rej_flags", 0),
    ]


# ---------------------------------------------------------------------------
# IrLMP — Link Management Protocol (Task 5)
# ---------------------------------------------------------------------------

# Well-known LSAP selectors
LSAP_IAS = 0x00
LSAP_ANY = 0xFF
LSAP_CONNLESS = 0x70
LSAP_MASK = 0x7F
CONTROL_BIT = 0x80

# IrLMP control opcodes
_irlmp_opcodes = {
    0x01: "CONNECT_CMD", 0x81: "CONNECT_CNF",
    0x02: "DISCONNECT", 0x03: "ACCESSMODE_CMD", 0x83: "ACCESSMODE_CNF",
}


class IrLMP_Control(Packet):
    """IrLMP control frame payload (opcode + reason)."""
    name = "IrLMP_Control"
    fields_desc = [
        ByteEnumField("opcode", 0, _irlmp_opcodes),
        ByteField("reason", 0),
    ]


class IrLMP(Packet):
    """IrDA Link Management Protocol frame.

    The first two bytes encode DLSAP/SLSAP selectors (7 bits each) plus
    a control bit and a reserved bit:
        byte 0: C(7) | DLSAP(6..0)
        byte 1: rsvd(7) | SLSAP(6..0)

    When C=1 the payload is an IrLMP control frame; otherwise it is data
    passed up to TinyTP.
    """
    name = "IrLMP"
    fields_desc = [
        BitField("control_bit", 0, 1),
        XBitField("dlsap", 0, 7),
        BitField("rsvd", 0, 1),
        XBitField("slsap", 0, 7),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        if self.control_bit:
            return IrLMP_Control
        return IrTTP


# ---------------------------------------------------------------------------
# IrTTP — Tiny Transport Protocol (Task 6)
# ---------------------------------------------------------------------------

class IrTTP(Packet):
    """IrDA Tiny Transport Protocol frame.

    The single-byte TTP header encodes:
        bit 7: M (more fragments)
        bits 6..0: delta-credit
    """
    name = "IrTTP"
    fields_desc = [
        BitField("more", 0, 1),
        BitField("credit", 0, 7),
    ]


# ---------------------------------------------------------------------------
# IrIAS — Information Access Service (Task 7)
# ---------------------------------------------------------------------------

_ias_opcodes = {
    0x01: "GetInfoBaseDetails", 0x02: "GetObjects", 0x03: "GetValue",
    0x04: "GetValueByClass", 0x05: "GetObjectInfo", 0x06: "GetAttribNames",
}

_ias_attr_types = {0: "MISSING", 1: "INTEGER", 2: "OCT_SEQ", 3: "STRING"}

_ias_return_codes = {0: "SUCCESS", 1: "CLASS_UNKNOWN", 2: "ATTRIB_UNKNOWN"}


class IrIAS_GetValueByClass_Req(Packet):
    """IAS GetValueByClass request payload."""
    name = "IrIAS_GetValueByClass_Req"
    fields_desc = [
        FieldLenField("class_name_len", None, length_of="class_name", fmt="B"),
        StrLenField("class_name", b"", length_from=lambda pkt: pkt.class_name_len),
        FieldLenField("attr_name_len", None, length_of="attr_name", fmt="B"),
        StrLenField("attr_name", b"", length_from=lambda pkt: pkt.attr_name_len),
    ]


class IrIAS_GetValueByClass_Rsp(Packet):
    """IAS GetValueByClass response payload."""
    name = "IrIAS_GetValueByClass_Rsp"
    fields_desc = [
        ShortField("return_code", 0),
        ShortField("list_len", 0),
        ShortField("obj_id", 0),
        ByteEnumField("attr_type", 0, _ias_attr_types),
        # INTEGER (type == 1)
        ConditionalField(IntField("integer_value", 0),
                         lambda pkt: pkt.attr_type == 1),
        # STRING (type == 3)
        ConditionalField(ByteEnumField("string_charset", 0, XID_CHARSETS),
                         lambda pkt: pkt.attr_type == 3),
        ConditionalField(FieldLenField("string_len", None,
                                       length_of="string_value", fmt="!H"),
                         lambda pkt: pkt.attr_type == 3),
        ConditionalField(StrLenField("string_value", b"",
                                     length_from=lambda pkt: pkt.string_len),
                         lambda pkt: pkt.attr_type == 3),
        # OCT_SEQ (type == 2)
        ConditionalField(FieldLenField("octseq_len", None,
                                       length_of="octseq_value", fmt="!H"),
                         lambda pkt: pkt.attr_type == 2),
        ConditionalField(StrLenField("octseq_value", b"",
                                     length_from=lambda pkt: pkt.octseq_len),
                         lambda pkt: pkt.attr_type == 2),
    ]


class IrIAS(Packet):
    """IrDA Information Access Service frame.

    The first byte encodes:
        bit 7: Lst (last frame)
        bit 6: Ack
        bits 5..0: opcode
    """
    name = "IrIAS"
    fields_desc = [
        BitField("lst", 0, 1),
        BitField("ack", 0, 1),
        BitField("opcode", 0, 6),
    ]

    def guess_payload_class(self, payload):
        if not payload:
            return Raw
        if self.opcode == 0x04:
            # Heuristic: if first 2 bytes look like a small return code
            # (0-10), it is a response; otherwise it is a request.
            if len(payload) >= 2:
                val = (payload[0] << 8) | payload[1]
                if val <= 10:
                    return IrIAS_GetValueByClass_Rsp
            return IrIAS_GetValueByClass_Req
        return Packet.guess_payload_class(self, payload)


# ---------------------------------------------------------------------------
# IrOBEX — Object Exchange Protocol (Task 8)
# ---------------------------------------------------------------------------

_obex_opcodes = {
    0x00: "Connect", 0x01: "Disconnect", 0x02: "Put", 0x03: "Get",
    0x05: "SetPath", 0xFF: "Abort",
    0x80: "Connect-Final", 0x81: "Disconnect-Final", 0x82: "Put-Final",
    0x83: "Get-Final", 0x85: "SetPath-Final",
    0x10: "Continue", 0x20: "Success", 0xA0: "Success-Final",
    0x40: "Bad Request", 0xC0: "Bad Request-Final",
    0x44: "Not Found", 0xC4: "Not Found-Final",
}

_obex_header_ids = {
    0x01: "Name", 0x05: "Description", 0x42: "Type", 0x46: "Target",
    0x48: "Body", 0x49: "EndOfBody", 0x4A: "Who", 0x4B: "AppParameters",
    0xC0: "Count", 0xC3: "Length", 0xCB: "ConnectionID",
}


class IrOBEX_Header(Packet):
    """OBEX header (TLV-style, type determined by high 2 bits of hid)."""
    name = "IrOBEX_Header"
    fields_desc = [
        ByteEnumField("hid", 0, _obex_header_ids),
        # 0b00 or 0b01: variable length (hlen includes hid + hlen = 3 bytes)
        ConditionalField(ShortField("hlen", 3),
                         lambda pkt: (pkt.hid >> 6) in (0, 1)),
        ConditionalField(StrLenField("hval", b"",
                                     length_from=lambda pkt: max(pkt.hlen - 3, 0)),
                         lambda pkt: (pkt.hid >> 6) in (0, 1)),
        # 0b10: 1-byte value
        ConditionalField(ByteField("hval_1b", 0),
                         lambda pkt: (pkt.hid >> 6) == 2),
        # 0b11: 4-byte value
        ConditionalField(IntField("hval_4b", 0),
                         lambda pkt: (pkt.hid >> 6) == 3),
    ]

    def extract_padding(self, s):
        return b"", s


def _obex_headers_len(pkt):
    """Compute the remaining length available for OBEX headers."""
    base = 3  # opcode(1) + length(2)
    if (pkt.opcode & 0x7F) == 0x00:
        base += 4  # version(1) + flags(1) + max_pkt_len(2)
    return max(pkt.length - base, 0) if pkt.length is not None else 0


class IrOBEX(Packet):
    """IrDA Object Exchange (OBEX) protocol frame."""
    name = "IrOBEX"
    fields_desc = [
        ByteEnumField("opcode", 0, _obex_opcodes),
        ShortField("length", None),
        # Connect-specific fields (opcode & 0x7F == 0x00)
        ConditionalField(ByteField("version", 0x10),
                         lambda pkt: (pkt.opcode & 0x7F) == 0x00),
        ConditionalField(ByteField("flags", 0),
                         lambda pkt: (pkt.opcode & 0x7F) == 0x00),
        ConditionalField(ShortField("max_pkt_len", 0),
                         lambda pkt: (pkt.opcode & 0x7F) == 0x00),
        PacketListField("headers", [], IrOBEX_Header,
                         length_from=_obex_headers_len),
    ]

    def post_build(self, pkt, pay):
        if self.length is None:
            total = len(pkt) + len(pay)
            pkt = pkt[:1] + total.to_bytes(2, "big") + pkt[3:]
        return pkt + pay


# ---------------------------------------------------------------------------
# DLT registration and CookedLinux binding (Task 9)
# ---------------------------------------------------------------------------

from scapy.config import conf
from scapy.data import DLT_LINUX_IRDA
from scapy.layers.l2 import CookedLinux
from scapy.layers import ir as _ir_module

# Remove the existing ir.py IrLAPHead binding for proto=23
split_bottom_up(CookedLinux, _ir_module.IrLAPHead, proto=23)

# Register our IrLAP as payload for CookedLinux with proto=23 (ETH_P_IRDA)
bind_layers(CookedLinux, IrLAP, proto=23)

# Ensure DLT_LINUX_IRDA -> CookedLinux mapping exists
if conf.l2types.num2layer.get(DLT_LINUX_IRDA) is None:
    conf.l2types.register_num2layer(DLT_LINUX_IRDA, CookedLinux)
