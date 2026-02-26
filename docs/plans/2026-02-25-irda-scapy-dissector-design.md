# IrDA Scapy Dissector and Test Tool Design

## Context

The irda_mon kernel module captures raw IrLAP frames on virtual `irdamon%d` interfaces. tshark/Wireshark already decode IrLAP natively from these captures. However, scapy has no IrDA support at all, and we need a way to generate multi-layer IrDA traffic beyond discovery for analysis.

This design covers two deliverables: a scapy contrib module implementing the full IrDA protocol stack as scapy layers (suitable for upstream contribution), and a test tool that generates real IrDA traffic between two dongles.

## Deliverable 1: Scapy IrDA Contrib Module

### File: `scapy/contrib/irda.py`

Single-file scapy contrib module, structured to match scapy's existing `contrib/` conventions for upstream PR.

### Protocol Layers

#### IrLAP (Link Access Protocol)

Base layer — all IrDA frames start here.

**Address field** (1 byte):
- Connection address (7 bits): 0x7F = broadcast, otherwise negotiated at SNRM/UA
- C/R bit (1 bit): command vs response

**Control field** (1 byte): Three frame types distinguished by low bits:
- **I-frames** (bit 0 = 0): `N(R):3 | P/F:1 | N(S):3 | 0`. Carry sequenced data.
- **S-frames** (bits 0-1 = 01): `N(R):3 | P/F:1 | type:2 | 01`. Types: RR (00), RNR (01), REJ (10), SREJ (11).
- **U-frames** (bits 0-1 = 11): `M:3 | P/F:1 | M:2 | 11`. Types: SNRM, DISC, UA, DM, FRMR, UI, XID.

Control field decoding uses `ConditionalField` or a custom multi-dispatch field to select the right sub-fields based on frame type bits.

**U-frame subtypes with info fields**:
- **XID**: Format ID (1B) + source addr (4B LE) + dest addr (4B LE) + flags (1B) + version (1B, optional) + discovery info (variable: hint bytes + charset + nickname). The flags byte encodes slot number and final-slot indicator.
- **SNRM**: Source addr (4B) + dest addr (4B) + new connection address (1B) + negotiation parameters (variable TLV).
- **UA**: Source addr (4B) + dest addr (4B) + negotiation parameters (variable TLV).
- **FRMR**: Rejected control field (1B) + N(S)/N(R)/C/R (1B) + flags (1B).

**Negotiation parameters** (used in SNRM/UA): TLV format — PI (1B parameter identifier) + PL (1B length) + PV (variable). Parameters include baud rate, max turnaround time, data size, window size, additional BOFs, min turnaround time, link disconnect time.

#### IrLMP (Link Management Protocol)

Multiplexes multiple logical connections over a single IrLAP link.

**Header** (2 bytes, carried in IrLAP I-frame payloads):
- DLSAP selector (7 bits) + control bit (1 bit)
- SLSAP selector (7 bits) + reserved (1 bit)

When control bit = 1, the frame is an LMP control frame (connect, disconnect, access mode). When control bit = 0, it's data passed up to TTP or directly to a client.

**Connect PDU**: DLSAP + SLSAP + reason/status byte + optional connect userdata (passed to TTP/IAS).

**Disconnect PDU**: DLSAP + SLSAP + reason byte.

Binding: IrLMP is the payload of IrLAP I-frames. Bind `IrLAP_I` -> `IrLMP`.

#### TTP (Tiny Transport Protocol)

Adds credit-based flow control and optional segmentation/reassembly (SAR).

**Header** (1 byte, carried in IrLMP data frames):
- M bit (1 bit): more fragments follow (SAR)
- Initial delta credit (7 bits): credits granted to peer

During IrLMP connect, TTP prepends a connect header with initial credit and optional MaxSduSize parameter (for SAR-enabled connections).

Binding: TTP is the payload of IrLMP data frames (control bit = 0).

#### IAS (Information Access Protocol)

Service discovery — clients query remote IAS databases to find LSAP selectors for named services.

**Opcodes**: GetInfoBaseDetails (0x01), GetObjects (0x02), GetValue (0x03), GetValueByClass (0x04), GetObjectInfo (0x05), GetAttribNames (0x06).

**GetValueByClass request**: Control byte (opcode + last-frame flag) + class name length (1B) + class name + attribute name length (1B) + attribute name.

**GetValueByClass response**: Control byte + return code (2B) + object ID (2B) + attribute type (1B) + value (type-dependent: integer 4B BE, octet sequence with 2B length prefix, string with 1B charset + 2B length prefix).

IAS uses LSAP selector 0 (well-known). Binding: when DLSAP/SLSAP = 0, payload is IAS.

#### OBEX (Object Exchange)

Application-layer protocol for object transfer. Runs over TTP with SAR.

**Packet format**: Opcode (1B) + length (2B BE) + headers (variable).

**Opcodes**: Connect (0x80), Disconnect (0x81), Put (0x02), Get (0x03), SetPath (0x05), Abort (0xFF). Response codes: Continue (0x90), Success (0xA0), various errors.

**Headers**: TLV-like. Header ID (1B) encodes type in high 2 bits:
- 00: Unicode text (2B length prefix)
- 01: Byte sequence (2B length prefix)
- 10: 1-byte value
- 11: 4-byte value

Common headers: Name (0x01), Type (0x42), Body (0x48), End-of-Body (0x49), Length (0xC3), Connection-ID (0xCB), Target (0x46).

Binding: OBEX is the payload of TTP data frames on non-IAS LSAPs.

### DLT and Layer Bindings

```python
# Register for pcap reading
conf.l2types.register(144, IrLAP)        # DLT_LINUX_IRDA

# Bind to Linux cooked capture
bind_layers(LinuxSLL, IrLAP, type=0x0017) # ETH_P_IRDA

# Internal bindings
# IrLAP I-frame payload → IrLMP
# IrLMP data (control=0) → TTP (for connected LSAPs) or IAS (LSAP 0)
# TTP data → OBEX (for OBEX services)
```

### Scapy Conventions

- Module docstring with `scapy.contrib.description` and `scapy.contrib.status` markers
- Use `Packet`, `bind_layers()`, `ConditionalField`, `PacketListField` per scapy conventions
- Include `__all__` export list
- Unit tests using scapy's `UTScapy` format (`.uts` file)

## Deliverable 2: IrDA Test Tool

### File: `irda-test.py`

Python script using `AF_IRDA` sockets (kernel manages all protocol state machines). Two modes:

**Server mode** (`irda-test.py server`):
- Creates `AF_IRDA` / `SOCK_STREAM` socket
- Binds service name (e.g. `IrDATest:IrDA:TinyTP`)
- Accepts one connection, echoes received data back, prints hex dump
- Ctrl-C to stop

**Client mode** (`irda-test.py client`):
- Discovers remote devices via `IRLMP_ENUMDEVICES` socket option
- Connects to server's service name
- Sends configurable test patterns (short message, repeated blocks, large transfer for SAR)
- Prints round-trip results

**Traffic generated** (visible in tshark/scapy):
- IrLAP: SNRM → UA (connection setup), I-frames (data), RR (ack), DISC → UA (teardown)
- IrLMP: Connect → Data → Disconnect
- TTP: Credit flow control, SAR segmentation for large transfers
- IAS: GetValueByClass queries (kernel does this automatically during connect to resolve service name → LSAP)

No scapy dependency — uses only stdlib `socket` module with `AF_IRDA`.

## Verification

1. `python3 -c "from scapy.contrib.irda import *"` — import succeeds
2. `scapy -c "rdpcap('/tmp/irda_capture.pcap').show()"` — decodes captured IrDA frames
3. Run `irda-test.py server` on one dongle, `irda-test.py client` on the other
4. Capture with `tshark -i irdamon0` during test — see SNRM/UA/I-frames/DISC
5. Read same capture with scapy — layers decode identically to tshark
6. Scapy UTScapy tests pass
