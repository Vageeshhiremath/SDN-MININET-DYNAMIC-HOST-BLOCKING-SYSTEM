from pox.core import core
import pox.openflow.libopenflow_01 as of
import time
from collections import defaultdict

log = core.getLogger()

# ----------------------------
# Detection settings
# ----------------------------
THRESHOLD = 8      # packets
WINDOW = 3          # seconds
BLOCK_TIME = 45    # seconds

# Trusted hosts that should not be blocked
WHITELIST = {"10.0.0.2"}

# State tables
packet_log = defaultdict(list)     # src_ip -> timestamps
blocked_hosts = {}                 # src_ip -> block start time
mac_to_port = {}                   # MAC learning table


def cleanup_expired_blocks(connection):
    """
    Remove expired OpenFlow drop rules after BLOCK_TIME seconds.
    """
    now = time.time()
    expired = []

    for ip, block_start in blocked_hosts.items():
        if now - block_start > BLOCK_TIME:
            log.info("[+] Unblocking host %s", ip)

            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.match.dl_type = 0x0800
            msg.match.nw_src = ip
            connection.send(msg)

            expired.append(ip)

    for ip in expired:
        del blocked_hosts[ip]


def detect_suspicious(ip):
    """
    Detect if host exceeds traffic threshold within the sliding window.
    """
    now = time.time()
    packet_log[ip] = [t for t in packet_log[ip] if now - t <= WINDOW]
    return len(packet_log[ip]) >= THRESHOLD


def block_host(connection, ip):
    """
    Install a high-priority OpenFlow drop rule for suspicious host.
    """
    msg = of.ofp_flow_mod()
    msg.priority = 100
    msg.match.dl_type = 0x0800
    msg.match.nw_src = ip
    # No actions = DROP
    connection.send(msg)

    blocked_hosts[ip] = time.time()
    log.info("[!] Suspicious activity detected from %s", ip)
    log.info("[+] OpenFlow BLOCK rule installed for %s", ip)


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

        in_port = event.port
        mac_to_port[packet.src] = in_port

        ip_packet = packet.find('ipv4')

        # ----------------------------
        # SECURITY / DETECTION LOGIC
        # ----------------------------
        if ip_packet:
            src_ip = str(ip_packet.srcip)
            dst_ip = str(ip_packet.dstip)

            if src_ip not in WHITELIST:
                if src_ip in blocked_hosts:
                    log.debug("[DEBUG] Already blocked: %s", src_ip)
                    return

                packet_log[src_ip].append(time.time())
                current_count = len([t for t in packet_log[src_ip]
                                     if time.time() - t <= WINDOW])

                log.debug("[DEBUG] Packet seen: %s -> %s", src_ip, dst_ip)
                log.debug("[DEBUG] %s packet count in %ss window = %s",
                          src_ip, WINDOW, current_count)

                if detect_suspicious(src_ip):
                    block_host(self.connection, src_ip)
                    return

        # ----------------------------
        # NORMAL L2 SWITCHING LOGIC
        # ----------------------------
        if packet.dst.is_multicast:
            self.flood(event)
            return

        if packet.dst in mac_to_port:
            out_port = mac_to_port[packet.dst]

            # Keep monitored suspicious traffic visible to controller
            if ip_packet:
                src_ip = str(ip_packet.srcip)
                if src_ip not in WHITELIST and src_ip not in blocked_hosts:
                    self.forward_packet(event, out_port)
                    return

            # Trusted / learned traffic gets normal flow rule
            self.install_flow(event, packet, out_port)
        else:
            self.flood(event)

    def flood(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = event.port
        self.connection.send(msg)

    def forward_packet(self, event, out_port):
        """
        Forward packet without installing flow rule so future packets
        still reach the controller for monitoring.
        """
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=out_port))
        msg.in_port = event.port
        self.connection.send(msg)

    def install_flow(self, event, packet, out_port):
        """
        Install normal OpenFlow forwarding rule.
        """
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
