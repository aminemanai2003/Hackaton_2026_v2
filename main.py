import sqlite3
import json
import csv
import io
import os
import time
from typing import Optional

from fastapi import FastAPI, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

import asyncio

from services import (
    extract_iocs_regex,
    extract_iocs_llm,
    score_ioc,
    map_to_mitre,
    enrich_ip,
    enrich_virustotal,
    enrich_otx,
    enrich_shodan,
    enrich_ipinfo,
    generate_summary,
    fit_isolation_forest,
    predict_anomaly,
    compute_fpr,
    parse_pfsense_log,
    detect_attack_type,
    classify_zone,
)

load_dotenv()

app = FastAPI(title="SENTINEL SOC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")


# ── DB helper ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect("sentinel.db", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


def derive_severity(risk_score: int) -> str:
    if risk_score > 80:
        return "critical"
    if risk_score > 60:
        return "high"
    if risk_score > 40:
        return "medium"
    return "low"


# ── Startup ───────────────────────────────────────────────────────────────────

@app.on_event("startup")
def on_startup():
    fit_isolation_forest("sentinel.db")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    return FileResponse("static/index.html")


@app.get("/api/threats")
def list_threats(
    limit: int = Query(50, ge=1, le=500),
    sector: Optional[str] = None,
    severity: Optional[str] = None,
):
    try:
        conn = get_db()
        conditions = []
        params: list = []

        if sector:
            conditions.append("sector = ?")
            params.append(sector)

        if severity:
            ranges = {
                "critical": "risk_score > 80",
                "high":     "risk_score > 60 AND risk_score <= 80",
                "medium":   "risk_score > 40 AND risk_score <= 60",
                "low":      "risk_score <= 40",
            }
            if severity in ranges:
                conditions.append(ranges[severity])

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        rows = conn.execute(
            f"SELECT * FROM threats {where} ORDER BY risk_score DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        conn.close()

        result = []
        for r in rows:
            d = row_to_dict(r)
            d["severity"] = derive_severity(d.get("risk_score", 0))
            result.append(d)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/threats/stats")
def threat_stats():
    try:
        conn = get_db()

        total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM threats").fetchone()[0] or 0

        by_sector = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT sector, COUNT(*) FROM threats GROUP BY sector"
            ).fetchall()
        }

        by_attack = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT attack_type, COUNT(*) FROM threats GROUP BY attack_type"
            ).fetchall()
        }

        by_mitre = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT mitre_tactic, COUNT(*) FROM threats WHERE mitre_tactic IS NOT NULL GROUP BY mitre_tactic"
            ).fetchall()
        }

        by_severity = {
            "critical": conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score > 80").fetchone()[0],
            "high":     conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score > 60 AND risk_score <= 80").fetchone()[0],
            "medium":   conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score > 40 AND risk_score <= 60").fetchone()[0],
            "low":      conn.execute("SELECT COUNT(*) FROM threats WHERE risk_score <= 40").fetchone()[0],
        }

        conn.close()
        return {
            "total": total,
            "by_sector": by_sector,
            "by_attack_type": by_attack,
            "by_mitre_tactic": by_mitre,
            "by_severity": by_severity,
            "avg_risk": round(avg_risk, 1),
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/threats/top")
def top_threats():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM threats ORDER BY risk_score DESC LIMIT 10"
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = row_to_dict(r)
            d["severity"] = derive_severity(d.get("risk_score", 0))
            result.append(d)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/kpis")
def kpis():
    try:
        conn = get_db()
        iocs_processed = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
        threats_detected = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE risk_score > 60"
        ).fetchone()[0]
        critical_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE severity = 'critical'"
        ).fetchone()[0]
        anomaly_count = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE risk_score > 80"
        ).fetchone()[0]

        # Real MTTA: average extraction duration from perf_log (in milliseconds)
        mtta_row = conn.execute(
            "SELECT AVG(duration_ms) FROM perf_log WHERE operation = 'ioc_extract'"
        ).fetchone()[0]
        mtta_ms = round(mtta_row or 0, 2)

        conn.close()

        # Real FPR: computed from IsolationForest predictions on live DB
        fpr = compute_fpr("sentinel.db")

        return {
            "iocs_processed": iocs_processed,
            "threats_detected": threats_detected,
            "critical_count": critical_count,
            "anomaly_count": anomaly_count,
            "mtta_ms": mtta_ms,
            "sources": ["AbuseIPDB", "AlienVault OTX", "Local ML Engine"],
            "false_positive_rate": fpr,
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── IOC extraction ────────────────────────────────────────────────────────────

class TextBody(BaseModel):
    text: str


@app.post("/api/ioc/extract")
async def ioc_extract(body: TextBody):
    try:
        t_start = time.perf_counter()
        regex_iocs = extract_iocs_regex(body.text)
        llm_iocs = await extract_iocs_llm(body.text)

        # Merge & deduplicate
        seen_values = {i["value"] for i in regex_iocs}
        merged = list(regex_iocs)
        for ioc in llm_iocs:
            if ioc.get("value") and ioc["value"] not in seen_values:
                seen_values.add(ioc["value"])
                merged.append(ioc)

        enriched = []
        conn = get_db()
        for ioc in merged:
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "")
            risk = score_ioc(ioc_type, "XX", 50)
            tactic, technique = map_to_mitre("malware")
            is_anomaly = predict_anomaly(risk, ioc.get("confidence", 0.95), "XX")

            try:
                conn.execute("""
                    INSERT INTO threats
                    (ip, ioc_value, ioc_type, risk_score, attack_type, mitre_tactic,
                     mitre_technique, sector, country, source, confidence, first_seen,
                     last_seen, summary, raw_json)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'),datetime('now'),?,?)
                """, (
                    value if ioc_type == "ip" else None,
                    value, ioc_type, risk, "malware", tactic, technique,
                    "generic", "XX", "manual", ioc.get("confidence", 0.95),
                    None, None,
                ))
            except Exception:
                pass

            enriched.append({
                **ioc,
                "risk_score": risk,
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "is_anomaly": is_anomaly,
            })

        duration_ms = round((time.perf_counter() - t_start) * 1000, 3)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        conn.execute(
            "INSERT INTO perf_log (operation, duration_ms, ioc_count, timestamp) VALUES (?,?,?,?)",
            ("ioc_extract", duration_ms, len(enriched), ts)
        )
        conn.commit()
        conn.close()
        return enriched
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── IP enrichment ─────────────────────────────────────────────────────────────

class IPBody(BaseModel):
    ip: str


@app.post("/api/ioc/enrich")
async def ioc_enrich(body: IPBody):
    try:
        ip = body.ip
        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "")
        vt_key    = os.getenv("VIRUSTOTAL_API_KEY", "")
        otx_key   = os.getenv("OTX_API_KEY", "")
        shodan_key= os.getenv("SHODAN_API_KEY", "")
        ipinfo_key= os.getenv("IPINFO_API_KEY", "")

        # Call all 5 sources in parallel; OTX gets extra time for large payloads
        async def _otx_safe():
            try:
                return await asyncio.wait_for(
                    enrich_otx(ip, "ip", otx_key), timeout=28
                )
            except Exception as e:
                return {"error": type(e).__name__}

        abuse_data, vt_data, otx_data, shodan_data, ipinfo_data = await asyncio.gather(
            enrich_ip(ip, abuse_key),
            enrich_virustotal(ip, "ip", vt_key),
            _otx_safe(),
            enrich_shodan(ip, shodan_key),
            enrich_ipinfo(ip, ipinfo_key),
            return_exceptions=True,
        )

        # Normalize exceptions to empty dicts
        def safe(x):
            return x if isinstance(x, dict) else {}

        abuse_data  = safe(abuse_data)
        vt_data     = safe(vt_data)
        otx_data    = safe(otx_data)
        shodan_data = safe(shodan_data)
        ipinfo_data = safe(ipinfo_data)

        country     = abuse_data.get("countryCode") or ipinfo_data.get("country") or "XX"
        abuse_score = abuse_data.get("abuseConfidenceScore", 50)
        risk        = score_ioc("ip", country, abuse_score)
        tactic, technique = map_to_mitre("c2")
        is_anomaly  = predict_anomaly(risk, 0.90, country)

        return {
            "ip":             ip,
            "risk_score":     risk,
            "severity":       derive_severity(risk),
            "mitre_tactic":   tactic,
            "mitre_technique":technique,
            "is_anomaly":     is_anomaly,
            "sources": {
                "abuseipdb":  abuse_data,
                "virustotal": vt_data,
                "otx":        otx_data,
                "shodan":     shodan_data,
                "ipinfo":     ipinfo_data,
            },
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Executive summary ─────────────────────────────────────────────────────────

@app.post("/api/analysis/summary")
async def analysis_summary():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM threats ORDER BY risk_score DESC LIMIT 5"
        ).fetchall()
        conn.close()
        threats = [row_to_dict(r) for r in rows]
        result = await generate_summary(threats)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Forecast ─────────────────────────────────────────────────────────────────

@app.post("/api/analysis/forecast")
async def analysis_forecast():
    try:
        conn = get_db()

        by_sector = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT sector, COUNT(*) FROM threats GROUP BY sector ORDER BY COUNT(*) DESC"
            ).fetchall()
        }
        by_attack = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT attack_type, COUNT(*) FROM threats GROUP BY attack_type ORDER BY COUNT(*) DESC"
            ).fetchall()
        }
        recent = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE first_seen >= datetime('now', '-3 days')"
        ).fetchone()[0]
        previous = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE first_seen >= datetime('now', '-6 days') AND first_seen < datetime('now', '-3 days')"
        ).fetchone()[0]
        avg_risk = conn.execute("SELECT AVG(risk_score) FROM threats").fetchone()[0] or 0
        top_country = conn.execute(
            "SELECT country, COUNT(*) FROM threats GROUP BY country ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        conn.close()

        trend_pct = round(((recent - previous) / max(previous, 1)) * 100)
        trend_dir = "increasing" if trend_pct > 0 else ("stable" if trend_pct == 0 else "decreasing")

        context = {
            "threat_volume_trend": f"{trend_dir} ({abs(trend_pct)}% vs previous 3 days)",
            "top_targeted_sector": list(by_sector.keys())[0] if by_sector else "unknown",
            "dominant_attack_type": list(by_attack.keys())[0] if by_attack else "unknown",
            "avg_risk_score": round(avg_risk, 1),
            "top_origin_country": top_country[0] if top_country else "XX",
            "threat_distribution": by_sector,
            "attack_distribution": by_attack,
        }

        prompt = (
            "You are a senior SOC analyst. Based on this threat data, predict what happens next. "
            "Respond ONLY with JSON, no markdown, no explanation:\n"
            '{"predicted_next_attack":"...","predicted_target_sector":"...",'
            '"confidence":"HIGH or MEDIUM or LOW","trend_summary":"one sentence",'
            '"emerging_threat":"one sentence","recommended_action":"one sentence"}\n\n'
            f"Top sector: {context['top_targeted_sector']}. "
            f"Top attack: {context['dominant_attack_type']}. "
            f"Trend: {context['threat_volume_trend']}. "
            f"Avg risk: {context['avg_risk_score']}. "
            f"Top origin: {context['top_origin_country']}. "
            f"Attack counts: {json.dumps(context['attack_distribution'])}."
        )

        from services import call_llama
        raw = await call_llama(prompt, timeout=30)
        if raw:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start != -1:
                try:
                    parsed = json.loads(raw[start:end])
                    if "predicted_next_attack" in parsed:
                        parsed["context"] = context
                        parsed["generated_at"] = __import__('datetime').datetime.utcnow().isoformat()
                        return parsed
                except Exception:
                    pass

        top_sector = list(by_sector.keys())[0] if by_sector else "banking"
        top_attack = list(by_attack.keys())[0] if by_attack else "phishing"
        return {
            "predicted_next_attack": top_attack,
            "predicted_target_sector": top_sector,
            "confidence": "MEDIUM",
            "trend_summary": f"Threat volume is {trend_dir} ({abs(trend_pct)}% change over last 3 days).",
            "emerging_threat": f"Continued {top_attack} campaigns from {top_country[0] if top_country else 'RU'} targeting {top_sector} infrastructure.",
            "recommended_action": f"Strengthen monitoring on {top_sector} sector assets and block known {top_attack} indicators at perimeter.",
            "context": context,
            "generated_at": __import__('datetime').datetime.utcnow().isoformat(),
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
def list_alerts(limit: int = Query(20, ge=1, le=100)):
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [row_to_dict(r) for r in rows]
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


# ── Exports ───────────────────────────────────────────────────────────────────

# ── Network events ────────────────────────────────────────────────────────────

@app.get("/api/network/events")
def network_events(limit: int = Query(50, ge=1, le=500), event_type: Optional[str] = None):
    try:
        conn = get_db()
        where = "WHERE event_type = ?" if event_type else ""
        params = [event_type] if event_type else []
        rows = conn.execute(
            f"SELECT * FROM network_events {where} ORDER BY timestamp DESC LIMIT ?",
            params + [limit],
        ).fetchall()
        conn.close()
        return [row_to_dict(r) for r in rows]
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/network/stats")
def network_stats():
    try:
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) FROM network_events").fetchone()[0]

        by_type = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT event_type, COUNT(*) FROM network_events GROUP BY event_type"
            ).fetchall()
        }
        by_action = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT action, COUNT(*) FROM network_events GROUP BY action"
            ).fetchall()
        }
        by_zone_src = {
            row[0]: row[1]
            for row in conn.execute(
                "SELECT zone_src, COUNT(*) FROM network_events GROUP BY zone_src"
            ).fetchall()
        }
        total_packets = conn.execute(
            "SELECT SUM(packets_count) FROM network_events"
        ).fetchone()[0] or 0
        blocked = conn.execute(
            "SELECT COUNT(*) FROM network_events WHERE action='blocked'"
        ).fetchone()[0]
        conn.close()

        return {
            "total_events": total,
            "total_packets": total_packets,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_rate": round((blocked / total * 100) if total else 0, 1),
            "by_type": by_type,
            "by_action": by_action,
            "by_zone_src": by_zone_src,
        }
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


class AttackIngestBody(BaseModel):
    event_type: str
    src_ip: str
    dst_ip: str
    dst_port: int = 0
    zone_src: str = ""
    zone_dst: str = ""
    protocol: str = "TCP"
    packets_count: int = 1
    action: str = "blocked"
    rule_matched: str = "manual"
    raw_log: str = ""


@app.post("/api/attack/ingest")
def attack_ingest(body: AttackIngestBody):
    """Receive a network event from attack_sim.py or pfSense syslog forwarder."""
    try:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        zone_src = body.zone_src or classify_zone(body.src_ip)
        zone_dst = body.zone_dst or classify_zone(body.dst_ip)
        conn = get_db()
        cur = conn.execute("""
            INSERT INTO network_events
            (event_type, src_ip, dst_ip, dst_port, zone_src, zone_dst,
             protocol, packets_count, action, rule_matched, timestamp, raw_log)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            body.event_type, body.src_ip, body.dst_ip, body.dst_port,
            zone_src, zone_dst, body.protocol, body.packets_count,
            body.action, body.rule_matched, ts, body.raw_log,
        ))
        conn.commit()
        event_id = cur.lastrowid
        conn.close()
        return {"status": "ok", "id": event_id, "timestamp": ts}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


class PfSenseLogBody(BaseModel):
    log: str


@app.post("/api/attack/pfsense")
def attack_pfsense(body: PfSenseLogBody):
    """Accept a raw pfSense filterlog line, parse it, and store it."""
    try:
        event = parse_pfsense_log(body.log)
        if not event:
            return JSONResponse({"error": "unparseable log line"}, status_code=422)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        conn = get_db()
        cur = conn.execute("""
            INSERT INTO network_events
            (event_type, src_ip, dst_ip, dst_port, zone_src, zone_dst,
             protocol, packets_count, action, rule_matched, timestamp, raw_log)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            event["event_type"], event["src_ip"], event["dst_ip"],
            event["dst_port"], event["zone_src"], event["zone_dst"],
            event["protocol"], event["packets_count"], event["action"],
            event["rule_matched"], ts, event["raw_log"],
        ))
        conn.commit()
        conn.close()
        return {"status": "ok", "id": cur.lastrowid, "parsed": event}
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/export/json")
def export_json():
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM threats ORDER BY risk_score DESC").fetchall()
        conn.close()
        data = [row_to_dict(r) for r in rows]
        content = json.dumps(data, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=threats.json"},
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/export/csv")
def export_csv():
    try:
        conn = get_db()
        rows = conn.execute("SELECT * FROM threats ORDER BY risk_score DESC").fetchall()
        conn.close()

        if not rows:
            return JSONResponse({"error": "no data"}, status_code=404)

        buf = io.StringIO()
        fieldnames = list(row_to_dict(rows[0]).keys())
        writer = csv.DictWriter(buf, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(row_to_dict(r))

        buf.seek(0)
        return StreamingResponse(
            iter([buf.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=threats.csv"},
        )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
