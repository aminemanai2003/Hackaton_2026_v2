import sqlite3
import random
from datetime import datetime, timedelta, timezone

DB_PATH = "sentinel.db"

MITRE_MAP = {
    "phishing":          ("Initial Access",      "T1566"),
    "brute_force":       ("Credential Access",   "T1110"),
    "lateral_movement":  ("Lateral Movement",    "T1021"),
    "data_exfiltration": ("Exfiltration",        "T1048"),
    "c2":                ("Command and Control", "T1071"),
    "ransomware":        ("Impact",              "T1486"),
    "port_scan":         ("Discovery",           "T1046"),
    "sql_injection":     ("Initial Access",      "T1190"),
    "malware":           ("Execution",           "T1204"),
    "persistence":       ("Persistence",         "T1053"),
}

MALICIOUS_IP_PREFIXES = [
    "185.220.101", "194.165.16", "45.142.212",
    "91.108.4", "77.73.133", "193.32.162",
]

MALICIOUS_DOMAINS = [
    "evil-c2.ru", "malware-host.tk", "darkweb-shop.onion",
    "apt-c2.xyz", "botnet-ctrl.ru", "phish-kit.top",
    "exfil-gate.net", "ransomware-c2.tk", "dropper-cdn.xyz",
]

MALICIOUS_HASHES = [
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5",
    "c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
    "deadbeefdeadbeefdeadbeefdeadbeef",
    "cafebabecafebabecafebabecafebabe",
    "0badf00d0badf00d0badf00d0badf00d",
]

COUNTRIES = ["RU", "CN", "KP", "IR", "UA", "US", "DE", "FR"]
COUNTRY_WEIGHTS = [20, 18, 10, 12, 10, 8, 6, 6]
SOURCES = ["abuseipdb", "otx_feed", "seeded", "manual"]

SECTOR_CONFIG = {
    "banking":    {"attack_types": ["phishing", "c2", "brute_force", "malware"],           "risk_min": 65},
    "telecom":    {"attack_types": ["port_scan", "lateral_movement", "brute_force"],        "risk_min": 50},
    "healthcare": {"attack_types": ["ransomware", "data_exfiltration", "malware"],          "risk_min": 68},
    "government": {"attack_types": ["phishing", "c2", "lateral_movement", "persistence",
                                    "data_exfiltration", "ransomware"],                     "risk_min": 72},
    "generic":    {"attack_types": list(MITRE_MAP.keys()),                                  "risk_min": 45},
}

# Network architecture IPs
ATTACKER_IPS  = [f"10.0.0.{i}" for i in range(10, 20)]   # Public/WAN attackers
DMZ_IPS       = ["192.168.50.10", "192.168.50.20", "192.168.50.30"]
INTERNAL_IPS  = [f"192.168.100.{i}" for i in range(10, 15)]
PFSENSE_WAN   = "10.0.0.1"

ATTACK_EVENTS = [
    # (event_type, zone_src, zone_dst, protocol, dst_port, action, rule, packets_range)
    ("dos",       "public",   "dmz",      "TCP",  80,   "blocked",  "BLOCK_DOS_FLOOD",      (800,  5000)),
    ("dos",       "public",   "dmz",      "TCP",  443,  "blocked",  "BLOCK_DOS_FLOOD",      (600,  3000)),
    ("ddos",      "public",   "dmz",      "TCP",  80,   "blocked",  "BLOCK_DDOS_RATE_LIMIT",(2000, 15000)),
    ("ddos",      "public",   "dmz",      "UDP",  53,   "blocked",  "BLOCK_DDOS_RATE_LIMIT",(1000, 8000)),
    ("sql_injection","public","dmz",      "TCP",  80,   "blocked",  "BLOCK_SQLI_WAF",       (5,    50)),
    ("sql_injection","dmz",   "internal", "TCP",  5432, "blocked",  "BLOCK_DMZ_TO_LAN",     (3,    20)),
    ("port_scan", "public",   "dmz",      "TCP",  0,    "detected", "DETECT_PORT_SCAN",     (1024, 65535)),
    ("port_scan", "public",   "internal", "TCP",  0,    "blocked",  "BLOCK_WAN_TO_LAN",     (1024, 65535)),
    ("brute_force","public",  "dmz",      "TCP",  22,   "blocked",  "BLOCK_SSH_BRUTE",      (50,   500)),
    ("brute_force","public",  "dmz",      "TCP",  21,   "blocked",  "BLOCK_FTP_BRUTE",      (30,   200)),
]


def random_risk(min_val: int) -> int:
    pool = list(range(min_val, 99))
    weights = [1 + (i / len(pool)) * 3 for i in range(len(pool))]
    return random.choices(pool, weights=weights, k=1)[0]


def random_ioc(sector: str) -> tuple:
    ioc_type = random.choices(["ip", "domain", "md5"], weights=[50, 35, 15])[0]
    if ioc_type == "ip":
        prefix = random.choice(MALICIOUS_IP_PREFIXES)
        ip = f"{prefix}.{random.randint(1, 254)}"
        return ip, ip, "ip"
    elif ioc_type == "domain":
        return None, random.choice(MALICIOUS_DOMAINS), "domain"
    else:
        return None, random.choice(MALICIOUS_HASHES), "md5"


def random_ts(max_hours_ago: int = 168) -> str:
    seconds_ago = random.uniform(0, max_hours_ago * 3600)
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def create_tables(conn: sqlite3.Connection):
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            ioc_value TEXT NOT NULL,
            ioc_type TEXT,
            risk_score INTEGER,
            attack_type TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            sector TEXT,
            country TEXT,
            source TEXT,
            confidence REAL,
            first_seen TEXT,
            last_seen TEXT,
            summary TEXT,
            raw_json TEXT
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_id INTEGER,
            severity TEXT,
            message TEXT,
            timestamp TEXT
        );

        CREATE TABLE IF NOT EXISTS network_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            dst_port INTEGER,
            zone_src TEXT,
            zone_dst TEXT,
            protocol TEXT,
            packets_count INTEGER,
            action TEXT,
            rule_matched TEXT,
            timestamp TEXT,
            raw_log TEXT
        );
    """)
    conn.commit()


def seed_threats(conn: sqlite3.Connection) -> list:
    threat_ids = []
    for sector, cfg in SECTOR_CONFIG.items():
        for _ in range(12):
            attack_type = random.choice(cfg["attack_types"])
            tactic, technique = MITRE_MAP.get(attack_type, ("Defense Evasion", "T1027"))
            ip, ioc_value, ioc_type = random_ioc(sector)
            risk_score = random_risk(cfg["risk_min"])
            first_seen = random_ts()
            country = random.choices(COUNTRIES, weights=COUNTRY_WEIGHTS, k=1)[0]
            confidence = round(random.uniform(0.70, 0.99), 2)
            source = random.choice(SOURCES)

            cur = conn.execute("""
                INSERT INTO threats
                (ip, ioc_value, ioc_type, risk_score, attack_type, mitre_tactic,
                 mitre_technique, sector, country, source, confidence, first_seen,
                 last_seen, summary, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ip, ioc_value, ioc_type, risk_score, attack_type, tactic,
                technique, sector, country, source, confidence, first_seen,
                first_seen, None, None
            ))
            threat_ids.append(cur.lastrowid)

    conn.commit()
    return threat_ids


def seed_alerts(conn: sqlite3.Connection, threat_ids: list):
    severity_plan = [("critical", 5), ("high", 8), ("medium", 7)]
    alert_messages = {
        "critical": [
            "Critical IOC detected - immediate containment required",
            "Active C2 communication detected from flagged IP",
            "Ransomware staging detected - endpoint isolation recommended",
            "Nation-state APT pattern matched - escalate to Tier 3",
            "Credential dump in progress - accounts at risk",
        ],
        "high": [
            "Suspicious lateral movement detected",
            "Brute-force campaign targeting authentication endpoints",
            "Data exfiltration attempt blocked",
            "Phishing domain resolved by internal DNS",
            "Known malware hash executed on endpoint",
            "Port scan from threat actor IP range",
            "Anomalous outbound traffic volume",
            "New IOC matched to threat intel feed",
        ],
        "medium": [
            "Reconnaissance activity detected",
            "Unusual login pattern flagged",
            "IOC added to watchlist",
            "Low-confidence indicator requires review",
            "Geo-anomalous access from flagged country",
            "Repeated failed authentication attempts",
            "DNS query to suspicious TLD",
        ],
    }
    now = datetime.now(timezone.utc)
    for severity, count in severity_plan:
        msgs = alert_messages[severity]
        for i in range(count):
            threat_id = random.choice(threat_ids)
            msg = msgs[i % len(msgs)]
            minutes_ago = random.randint(0, 120)
            ts = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")
            conn.execute(
                "INSERT INTO alerts (threat_id, severity, message, timestamp) VALUES (?,?,?,?)",
                (threat_id, severity, msg, ts)
            )
    conn.commit()


def seed_network_events(conn: sqlite3.Connection):
    now = datetime.now(timezone.utc)
    count = 0
    # 3 events per attack scenario = 30 total
    for event_type, zone_src, zone_dst, protocol, dst_port, action, rule, pkt_range in ATTACK_EVENTS:
        for _ in range(3):
            if zone_src == "public":
                src_ip = random.choice(ATTACKER_IPS)
            elif zone_src == "dmz":
                src_ip = random.choice(DMZ_IPS)
            else:
                src_ip = random.choice(INTERNAL_IPS)

            if zone_dst == "dmz":
                dst_ip = random.choice(DMZ_IPS)
            elif zone_dst == "internal":
                dst_ip = random.choice(INTERNAL_IPS)
            else:
                dst_ip = PFSENSE_WAN

            minutes_ago = random.randint(0, 180)
            ts = (now - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S")
            packets = random.randint(*pkt_range)

            raw_log = (
                f"{ts} pfsense filterlog: {action.upper()} {protocol} "
                f"{src_ip} -> {dst_ip}:{dst_port} pkts={packets} rule={rule}"
            )

            conn.execute("""
                INSERT INTO network_events
                (event_type, src_ip, dst_ip, dst_port, zone_src, zone_dst,
                 protocol, packets_count, action, rule_matched, timestamp, raw_log)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                event_type, src_ip, dst_ip, dst_port, zone_src, zone_dst,
                protocol, packets, action, rule, ts, raw_log
            ))
            count += 1

    conn.commit()
    return count


def main():
    conn = sqlite3.connect(DB_PATH)
    create_tables(conn)

    row = conn.execute("SELECT COUNT(*) FROM threats").fetchone()
    if row[0] > 0:
        print(f"Already seeded ({row[0]} threats in DB). Skipping.")
        conn.close()
        return

    threat_ids = seed_threats(conn)
    seed_alerts(conn, threat_ids)
    net_count = seed_network_events(conn)

    t_count = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    a_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print(f"Seeded: {t_count} threats, {a_count} alerts, {net_count} network events")
    conn.close()


if __name__ == "__main__":
    main()
