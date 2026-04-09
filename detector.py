from scapy.all import sniff, IP
from collections import defaultdict
import time

from blocker import block_ip, unblock_ip
from verifier import is_blocked
from logger import log_event

THRESHOLD = 5       # packets
WINDOW = 5          # seconds
BLOCK_TIME = 60     # seconds

WHITELIST = {"10.0.0.1", "10.0.0.2"}
INTERFACES = ["s1-eth1", "s1-eth2", "s1-eth3"]

packet_log = defaultdict(list)
blocked_hosts = {}

def cleanup_expired_blocks():
    now = time.time()
    expired = []

    for ip, block_start in blocked_hosts.items():
        if now - block_start > BLOCK_TIME:
            unblock_ip(ip)
            log_event({
                "ip": ip,
                "event": "unblocked",
                "action": "removed"
            })
            print(f"[+] Unblocked {ip}")
            expired.append(ip)

    for ip in expired:
        del blocked_hosts[ip]

def detect_suspicious(ip):
    now = time.time()
    packet_log[ip] = [t for t in packet_log[ip] if now - t <= WINDOW]
    return len(packet_log[ip]) >= THRESHOLD

def process_packet(packet):
    cleanup_expired_blocks()

    if IP in packet:
        src_ip = packet[IP].src

        if src_ip in WHITELIST or src_ip in blocked_hosts:
            return

        packet_log[src_ip].append(time.time())

        if detect_suspicious(src_ip):
            print(f"[!] Suspicious activity detected from {src_ip}")

            success, err = block_ip(src_ip)
            verified = is_blocked(src_ip)

            if success and verified:
                blocked_hosts[src_ip] = time.time()
                log_event({
                    "ip": src_ip,
                    "event": "suspicious_traffic",
                    "count": len(packet_log[src_ip]),
                    "threshold": THRESHOLD,
                    "window_sec": WINDOW,
                    "action": "blocked",
                    "verified": verified
                })
                print(f"[+] POX/OpenFlow BLOCK applied to {src_ip}")
            else:
                print(f"[-] Failed to block {src_ip}: {err}")

print(f"[*] Monitoring traffic on {INTERFACES} ...")
sniff(iface=INTERFACES, filter="ip", prn=process_packet, store=False)
