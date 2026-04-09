from collections import defaultdict
import json
import subprocess
import time

from pox.core import core
import pox.openflow.libopenflow_01 as of

log = core.getLogger()

THRESHOLD = 8
WINDOW = 3
BLOCK_TIME = 45
LOG_FILE = "/home/vageesh/Downloads/SDN_DYNAMIC_HOST/events.json"
WHITELIST = {"10.0.0.2"}

packet_log = defaultdict(list)
blocked_hosts = {}
mac_to_port = {}


def log_event(event):
    event["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as handle:
        handle.write(json.dumps(event) + "\n")


def is_blocked(ip):
    result = subprocess.run(
        ["sudo", "ovs-ofctl", "-O", "OpenFlow10", "dump-flows", "s1"],
        capture_output=True,
        text=True,
    )
    output = result.stdout
    return f"nw_src={ip}" in output and "actions=drop" in output


def detect_suspicious(ip):
    now = time.time()
    packet_log[ip] = [t for t in packet_log[ip] if now - t <= WINDOW]
    return len(packet_log[ip]) >= THRESHOLD


def unblock_host(connection, ip):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    msg.match.dl_type = 0x0800
    msg.match.nw_src = ip
    connection.send(msg)
    log.info("[+] OpenFlow unblock rule removed for %s", ip)


def cleanup_expired_blocks(connection):
    now = time.time()
    expired_hosts = []

    for ip, block_start in blocked_hosts.items():
        if now - block_start > BLOCK_TIME:
            unblock_host(connection, ip)
            log_event({
                "ip": ip,
                "event": "unblocked",
                "action": "removed",
            })
            expired_hosts.append(ip)

    for ip in expired_hosts:
        del blocked_hosts[ip]


def block_host(connection, ip, packet_count):
    msg = of.ofp_flow_mod()
    msg.priority = 100
    msg.match.dl_type = 0x0800
    msg.match.nw_src = ip
    connection.send(msg)

    blocked_hosts[ip] = time.time()
    verified = is_blocked(ip)

    log.info("[!] Suspicious activity detected from %s", ip)
    log.info("[+] OpenFlow BLOCK rule installed for %s", ip)

    log_event({
        "ip": ip,
        "event": "suspicious_traffic",
        "count": packet_count,
        "threshold": THRESHOLD,
        "window_sec": WINDOW,
        "action": "blocked",
        "verified": verified,
    })


class DynamicBlockController(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        log.info("[*] Dynamic Host Blocking Controller connected")

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        cleanup_expired_blocks(self.connection)

        mac_to_port[packet.src] = event.port
        ip_packet = packet.find("ipv4")

        if ip_packet:
            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)

            if src_ip in blocked_hosts:
                log.debug("[DEBUG] Already blocked: %s", src_ip)
                return

            if src_ip not in WHITELIST:
                packet_log[src_ip].append(time.time())
                current_count = len(
                    [t for t in packet_log[src_ip] if time.time() - t <= WINDOW]
                )

                log.debug("[DEBUG] Packet seen: %s -> %s", src_ip, dst_ip)
                log.debug(
                    "[DEBUG] %s packet count in %ss window = %s",
                    src_ip,
                    WINDOW,
                    current_count,
                )

                if detect_suspicious(src_ip):
                    block_host(self.connection, src_ip, current_count)
                    return

        if packet.dst.is_multicast:
            self.flood(event)
            return

        if packet.dst in mac_to_port:
            out_port = mac_to_port[packet.dst]

            if ip_packet:
                src_ip = str(ip_packet.srcip)
                if src_ip not in WHITELIST and src_ip not in blocked_hosts:
                    self.forward_packet(event, out_port)
                    return

            self.install_flow(event, packet, out_port)
            return

        self.flood(event)

    def flood(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port
        self.connection.send(msg)

    def forward_packet(self, event, out_port):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = event.port
        self.connection.send(msg)

    def install_flow(self, event, packet, out_port):
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, event.port)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.data = event.ofp
        self.connection.send(msg)


def launch():
    def start_switch(event):
        log.info("[*] Controlling %s", event.connection)
        DynamicBlockController(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("[*] Dynamic Host Blocking POX module loaded")
