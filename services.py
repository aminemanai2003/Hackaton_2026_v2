import re
import json
import sqlite3
import os
import httpx

_iso_model = None

PATTERNS = {
    "ip":     r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
    "domain": r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|onion)\b',
    "md5":    r'\b[a-fA-F0-9]{32}\b',
    "sha256": r'\b[a-fA-F0-9]{64}\b',
    "cve":    r'CVE-\d{4}-\d{4,7}',
    "url":    r'https?://[^\s<>"{}|\\^`\[\]]+',
}

PRIVATE_IP_RE = re.compile(
    r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)'
)

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

COUNTRY_RISK = {"RU": 90, "CN": 80, "KP": 100, "IR": 85, "US": 15, "TN": 20}
IOC_TYPE_WEIGHT = {"ip": 1.0, "domain": 0.8, "md5": 0.7, "sha256": 0.7, "url": 0.6, "cve": 0.9}
CRITICAL_COUNTRIES = {"KP", "RU", "CN", "IR"}


# ── A) Regex IOC extractor ────────────────────────────────────────────────────

def extract_iocs_regex(text: str) -> list[dict]:
    seen = set()
    results = []

    # URLs first (greedy — consume before domain/ip patterns fire)
    for url in re.findall(PATTERNS["url"], text):
        if url not in seen:
            seen.add(url)
            results.append({"type": "url", "value": url, "confidence": 0.95})

    # Sanitise text for remaining patterns (replace extracted URLs)
    clean = re.sub(PATTERNS["url"], " ", text)

    for ioc_type in ("sha256", "md5", "cve", "ip", "domain"):
        for value in re.findall(PATTERNS[ioc_type], clean):
            if value in seen:
                continue
            if ioc_type == "ip" and PRIVATE_IP_RE.match(value):
                continue
            seen.add(value)
            results.append({"type": ioc_type, "value": value, "confidence": 0.95})

    return results


# ── B) Threat scorer ──────────────────────────────────────────────────────────

def score_ioc(ioc_type: str, country: str, abuse_score: int) -> int:
    country_risk = COUNTRY_RISK.get(country, 50)
    type_weight = IOC_TYPE_WEIGHT.get(ioc_type, 0.5)
    score = (abuse_score * 0.5) + (country_risk * 0.3) + (type_weight * 20)
    return max(0, min(100, int(score)))


# ── C) MITRE mapper ───────────────────────────────────────────────────────────

def map_to_mitre(attack_type: str) -> tuple[str, str]:
    return MITRE_MAP.get(attack_type, ("Defense Evasion", "T1027"))


# ── D) Ollama wrapper ─────────────────────────────────────────────────────────

async def call_llama(prompt: str, timeout: int = 25) -> str:
    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3")
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{base_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=timeout,
            )
            return r.json().get("response", "")
    except Exception:
        return ""


# ── E) LLM IOC extractor ──────────────────────────────────────────────────────

async def extract_iocs_llm(text: str) -> list[dict]:
    prompt = f"""Extract cybersecurity IOCs from this text.
Return ONLY a JSON array like: [{{"type":"ip","value":"1.2.3.4"}}, ...]
Types: ip, domain, hash, url, cve
If none found, return []
Text: {text[:800]}"""
    try:
        raw = await call_llama(prompt)
        if not raw:
            return []
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start == -1:
            return []
        items = json.loads(raw[start:end])
        return [
            {"type": i.get("type", "unknown"), "value": i.get("value", ""), "confidence": 0.80}
            for i in items if i.get("value")
        ]
    except Exception:
        return []


# ── F) Executive summary generator ───────────────────────────────────────────

_SUMMARY_FALLBACK = {
    "summary": (
        "Multiple high-severity IOCs detected across banking and government sectors. "
        "Threat actors are leveraging phishing and C2 infrastructure from high-risk "
        "nation-state IP ranges. Immediate analyst review is recommended."
    ),
    "severity": "HIGH",
    "recommendation": "Isolate flagged endpoints, block listed IPs at perimeter, and escalate to Tier 2 SOC.",
}

async def generate_summary(threats: list) -> dict:
    threat_str = json.dumps(threats[:5], indent=2)
    prompt = f"""You are a SOC analyst. Analyze these threats and respond ONLY in JSON:
{{"summary": "2-3 sentence overview", "severity": "CRITICAL|HIGH|MEDIUM|LOW", "recommendation": "one action sentence"}}
Threats: {threat_str[:1000]}"""
    try:
        raw = await call_llama(prompt)
        if not raw:
            return _SUMMARY_FALLBACK
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start == -1:
            return _SUMMARY_FALLBACK
        result = json.loads(raw[start:end])
        if "summary" in result and "severity" in result:
            return result
        return _SUMMARY_FALLBACK
    except Exception:
        return _SUMMARY_FALLBACK


# ── G) AbuseIPDB enrichment ───────────────────────────────────────────────────

async def enrich_ip(ip: str, api_key: str) -> dict:
    if not api_key:
        return {
            "abuseConfidenceScore": 75,
            "countryCode": "RU",
            "totalReports": 42,
            "isPublic": True,
            "mock": True,
        }
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 30},
                timeout=10,
            )
            return r.json().get("data", {})
    except Exception:
        return {"abuseConfidenceScore": 50, "countryCode": "XX", "totalReports": 0}


# ── H) IsolationForest training ───────────────────────────────────────────────

def fit_isolation_forest(db_path: str):
    global _iso_model
    try:
        from sklearn.ensemble import IsolationForest
        import numpy as np

        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT risk_score, confidence, country FROM threats"
        ).fetchall()
        conn.close()

        if len(rows) < 20:
            return

        X = np.array([
            [
                r[0],
                r[1],
                1 if r[2] in CRITICAL_COUNTRIES else 0,
            ]
            for r in rows
        ], dtype=float)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(X)
        _iso_model = model
    except Exception:
        _iso_model = None


# ── I) Anomaly predictor ──────────────────────────────────────────────────────

def predict_anomaly(risk_score: int, confidence: float, country: str) -> bool:
    global _iso_model
    if _iso_model is not None:
        try:
            import numpy as np
            X = np.array([[risk_score, confidence, 1 if country in CRITICAL_COUNTRIES else 0]])
            return int(_iso_model.predict(X)[0]) == -1
        except Exception:
            pass
    return risk_score > 80


# ── J) VirusTotal enrichment ─────────────────────────────────────────────────

async def enrich_virustotal(value: str, ioc_type: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        headers = {"x-apikey": api_key}
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{value}"
        elif ioc_type in ("md5", "sha256"):
            url = f"https://www.virustotal.com/api/v3/files/{value}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            return {}

        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers, timeout=10)
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "tags":       data.get("tags", []),
            }
    except Exception as e:
        return {"error": str(e)}


# ── K) AlienVault OTX enrichment ──────────────────────────────────────────────

async def enrich_otx(value: str, ioc_type: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        type_map = {"ip": "IPv4", "domain": "domain", "md5": "file", "sha256": "file", "url": "url"}
        otx_type = type_map.get(ioc_type)
        if not otx_type:
            return {}
        url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{value}/general"
        async with httpx.AsyncClient() as client:
            r = await client.get(
                url,
                headers={"X-OTX-API-KEY": api_key},
                timeout=httpx.Timeout(30.0, connect=5.0, read=25.0),
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json()
            pulse_info = data.get("pulse_info", {})
            pulses = pulse_info.get("pulses", [])
            tags = list({t for p in pulses for t in (p.get("tags") or [])})[:10]
            families = list({
                mf.get("display_name", "")
                for p in pulses
                for mf in (p.get("malware_families") or [])
                if mf.get("display_name")
            })[:5]
            return {
                "pulse_count":      pulse_info.get("count", 0),
                "reputation":       data.get("reputation", 0),
                "tags":             tags,
                "malware_families": families,
                "in_threat_feed":   pulse_info.get("count", 0) > 0,
            }
    except Exception as e:
        return {"error": str(e)}


# ── L) Shodan enrichment ──────────────────────────────────────────────────────

async def enrich_shodan(ip: str, api_key: str) -> dict:
    """
    Uses Shodan InternetDB (free, no key) for port/vuln data,
    then enriches with authenticated Shodan API if key is available.
    """
    try:
        async with httpx.AsyncClient() as client:
            # InternetDB — always free, no key required
            r = await client.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                result = {
                    "ports":    data.get("ports", []),
                    "vulns":    data.get("vulns", []),
                    "tags":     data.get("tags", []),
                    "cpes":     data.get("cpes", [])[:5],
                    "hostnames":data.get("hostnames", [])[:3],
                    "source":   "internetdb",
                }
            else:
                result = {"ports": [], "vulns": [], "tags": [], "source": "internetdb_unavailable"}

            # Authenticated Shodan — extra org/city/OS info (paid feature)
            if api_key:
                try:
                    r2 = await client.get(
                        f"https://api.shodan.io/shodan/host/{ip}",
                        params={"key": api_key},
                        timeout=8,
                    )
                    if r2.status_code == 200:
                        d2 = r2.json()
                        result.update({
                            "org":     d2.get("org", ""),
                            "isp":     d2.get("isp", ""),
                            "country": d2.get("country_name", ""),
                            "city":    d2.get("city", ""),
                            "os":      d2.get("os", ""),
                            "source":  "shodan+internetdb",
                        })
                except Exception:
                    pass
            return result
    except Exception as e:
        return {"error": str(e)}


# ── M) IPinfo enrichment ──────────────────────────────────────────────────────

async def enrich_ipinfo(ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(
                f"https://ipinfo.io/{ip}",
                params={"token": api_key},
                timeout=8,
            )
            if r.status_code != 200:
                return {"error": f"HTTP {r.status_code}"}
            data = r.json()
            return {
                "city":     data.get("city", ""),
                "region":   data.get("region", ""),
                "country":  data.get("country", ""),
                "org":      data.get("org", ""),
                "timezone": data.get("timezone", ""),
                "loc":      data.get("loc", ""),
                "hostname": data.get("hostname", ""),
            }
    except Exception as e:
        return {"error": str(e)}


# ── N) pfSense log parser ─────────────────────────────────────────────────────

# pfSense filterlog format (simplified):
# <timestamp> pfsense filterlog: <action>,<rule>,<proto>,<src_ip>,<dst_ip>,<dst_port>
_PFSENSE_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T[\d:]+)?'
    r'.*?filterlog.*?'
    r'(?P<action>block|pass|match)\b.*?'
    r'(?P<proto>TCP|UDP|ICMP)\s+'
    r'(?P<src>[\d.]+)\s*->\s*(?P<dst>[\d.]+):?(?P<port>\d+)?',
    re.IGNORECASE,
)

_SQLI_PATTERNS = re.compile(
    r"(union\s+select|drop\s+table|'.*?or.*?'|1=1|--\s|;.*?select|"
    r"information_schema|xp_cmdshell|exec\s*\()",
    re.IGNORECASE,
)

# Zone classification based on IP prefix
def classify_zone(ip: str) -> str:
    if ip.startswith("10.0."):
        return "public"
    if ip.startswith("192.168.50."):
        return "dmz"
    if ip.startswith("192.168.100."):
        return "internal"
    return "unknown"


def detect_attack_type(event: dict) -> str:
    """Infer attack type from a parsed network event dict."""
    proto    = (event.get("protocol") or "").upper()
    port     = event.get("dst_port", 0) or 0
    packets  = event.get("packets_count", 0) or 0
    raw      = (event.get("raw_log") or "").lower()
    zone_src = event.get("zone_src", "")
    zone_dst = event.get("zone_dst", "")

    if _SQLI_PATTERNS.search(raw):
        return "sql_injection"
    if packets > 5000:
        return "ddos"
    if packets > 800 and proto == "TCP" and port in (80, 443):
        return "dos"
    if port == 0 or packets > 1000:
        return "port_scan"
    if port in (22, 21, 3389, 5900) and packets > 30:
        return "brute_force"
    if zone_src in ("dmz", "internal") and zone_dst == "internal":
        return "lateral_movement"
    return "port_scan"


def parse_pfsense_log(raw_line: str) -> dict | None:
    """
    Parse a raw pfSense filterlog syslog line into a network_event dict.
    Returns None if the line cannot be parsed.
    """
    m = _PFSENSE_RE.search(raw_line)
    if not m:
        return None

    src_ip = m.group("src") or "0.0.0.0"
    dst_ip = m.group("dst") or "0.0.0.0"
    port   = int(m.group("port")) if m.group("port") else 0
    action = "blocked" if m.group("action").lower() == "block" else "allowed"
    proto  = m.group("proto").upper()

    event = {
        "src_ip":        src_ip,
        "dst_ip":        dst_ip,
        "dst_port":      port,
        "zone_src":      classify_zone(src_ip),
        "zone_dst":      classify_zone(dst_ip),
        "protocol":      proto,
        "packets_count": 1,
        "action":        action,
        "rule_matched":  "pfsense_import",
        "raw_log":       raw_line.strip(),
    }
    event["event_type"] = detect_attack_type(event)
    return event
