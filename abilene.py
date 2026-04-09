import json
import time

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

# ── Load topology from Abilene.json ──────────────────────────────────────────

with open('Abilene.json') as f:
    _TOPO = json.load(f)

# NODES sorted by id: each entry has 'id', 'name', 'lon', 'lat'
NODES = [
    {
        'id':   int(n['id']),
        'name': n['name'],
        'lon':  n['pos'][0],   # pos = [lon, lat]
        'lat':  n['pos'][1],
    }
    for n in sorted(_TOPO['nodes'], key=lambda n: int(n['id']))
]

# LINKS: each entry has 'src', 'dst' (0-indexed ints), 'dist_km'
LINKS = [
    {
        'src':     int(e['source']),
        'dst':     int(e['target']),
        'dist_km': e['dist'],
    }
    for e in _TOPO['edges']
]


# ── Extra hosts ───────────────────────────────────────────────────────────────
# Add entries here to attach additional hosts to any switch.
# Format: (node_idx, host_name, mac, ip)
# node_idx is 0-based (0=New York, 1=Chicago, 2=Washington DC, 3=Seattle,
#   4=Sunnyvale, 5=Los Angeles, 6=Denver, 7=Kansas City,
#   8=Houston, 9=Atlanta, 10=Indianapolis)
# Example:
#   EXTRA_HOSTS = [
#       (0, 'ha', '00:00:00:00:ff:01', '10.1.0.1/16'),  # New York s1
#       (3, 'hb', '00:00:00:00:ff:02', '10.1.0.2/16'),  # Seattle  s4
#   ]
EXTRA_HOSTS = [
    (3, 'ha', '00:00:00:00:ff:02', '10.1.0.1/16'),  
    (7, 'hb', '00:00:00:00:ff:03', '10.1.0.2/16'),  
    (6, 'relay', '00:00:00:00:00:0c', '10.1.0.3/16'),
]


def _delay_ms(src: int, dst: int) -> str:
    """One-way fiber propagation delay from JSON dist field."""
    for lnk in LINKS:
        if (lnk['src'] == src and lnk['dst'] == dst) or \
           (lnk['src'] == dst and lnk['dst'] == src):
            ms = lnk['dist_km'] / 200_000 * 1000   # fiber ~200,000 km/s
            return f'{ms:.2f}ms'
    return '1ms'


# ── Topology ──────────────────────────────────────────────────────────────────

class AbileneTopoMismatch(Topo):
    """
    Abilene 11-node topology loaded from Abilene.json.
    One host per switch (h1…h11), 14 backbone links with realistic delays.
    Switch naming: s1…s11  (node id + 1)
    DPID:          0000000000000001 … 000000000000000b
    """

    def build(self):
        switches = []
        for node in NODES:
            idx = node['id']
            sw  = self.addSwitch(
                f's{idx + 1}',
                dpid=f'{idx + 1:016x}',
                protocols='OpenFlow15',
            )
            switches.append(sw)
            print(f'  s{idx + 1:2d} = {node["name"]}')

        # Inter-switch links
        for lnk in LINKS:
            a, b = lnk['src'], lnk['dst']
            self.addLink(
                switches[a], switches[b],
                cls=TCLink,
                delay=_delay_ms(a, b),
                bw=10000,
                loss=0,
            )

        # One host per switch — skip nodes whose hnum conflicts with EXTRA_HOSTS names
        extra_names = {hname for (_, hname, _, _) in EXTRA_HOSTS}
        for node in NODES:
            idx  = node['id']
            hnum = idx + 1
            if f'h{hnum}' in extra_names:
                continue          # this name is reserved for EXTRA_HOSTS
            ip   = f'10.0.{(hnum >> 8) & 0xFF}.{hnum & 0xFF}/16'
            mac  = f'00:00:00:00:{(hnum >> 8) & 0xFF:02x}:{hnum & 0xFF:02x}'
            h    = self.addHost(f'h{hnum}', ip=ip, mac=mac)
            self.addLink(h, switches[idx])

        # ── Extra hosts (add more hosts to any switch) ─────────────────────
        # Format: (node_idx, host_name, mac, ip)
        # node_idx matches the JSON id (0-based): 0=New York, 1=Chicago, etc.
        # Example:
        #   EXTRA_HOSTS = [
        #       (0, 'ha', '00:00:00:00:ff:01', '10.1.0.1/16'),  # extra host on s1 (New York)
        #       (3, 'hb', '00:00:00:00:ff:02', '10.1.0.2/16'),  # extra host on s4 (Seattle)
        #   ]
        for (node_idx, hname, mac, ip) in EXTRA_HOSTS:
            eh = self.addHost(hname, mac=mac, ip=ip)
            self.addLink(eh, switches[node_idx])


# ── Runner ────────────────────────────────────────────────────────────────────

def run():
    print(f'Abilene topology — {len(NODES)} nodes, {len(LINKS)} links')
    print()

    topo = AbileneTopoMismatch()

    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,
        autoSetMacs=False,
        link=TCLink,
    )

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653,
    )

    net.start()

    print('\n[*] Waiting for switches to connect to controller...')
    net.waitConnected()

    print('[*] Waiting for LLDP link discovery (10s)...')
    time.sleep(10)

    print('\n[*] Inter-switch link delays:')
    for lnk in LINKS:
        a, b = lnk['src'], lnk['dst']
        print(f'    s{a+1:2d}({NODES[a]["name"]:>15s}) ↔ s{b+1:2d}({NODES[b]["name"]:<15s})  {_delay_ms(a, b)}')

    print('\n[*] Topology ready. Controller: 127.0.0.1:6653')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
