import json
import os
from datetime import datetime, timedelta

def clean_anchor_val(val):
    """Sanitizes anchor strings, ignoring nulls, sentinels, and generic system defaults."""
    if not val:
        return None
    cleaned = str(val).strip()
    if cleaned in ("", "-", "None", "null", "127.0.0.1", "0.0.0.0", "localhost", "unknown", "/", "/index.php", "/about.html"):
        return None
    return cleaned

def parse_iso_ts(ts_str):
    """Parses ISO 8601 UTC timestamp string into datetime object."""
    if not ts_str:
        return None
    try:
        cleaned = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None

def extract_multi_axis_anchors(seed_logs, max_path_frequency=5):
    """
    Extracts high-signal forensic pivot keys from seeds:
    1. Attacker IPs
    2. Compromised User Accounts
    3. Low-frequency or Signature-flagged File/Endpoint Paths
    4. User-Agent Fingerprints
    """
    anchor_ips = set()
    anchor_users = set()
    anchor_files = set()
    anchor_user_agents = set()
    anchor_timestamps = []

    for log in seed_logs:
        # Collect seed timestamps for strict time-window bounding
        ts = parse_iso_ts(log.get("timestamp"))
        if ts:
            anchor_timestamps.append(ts)

        # 1. IPs
        ip = clean_anchor_val(log.get("ip"))
        if ip:
            anchor_ips.add(ip)

        details = log.get("details", {})
        for ip_key in ["srcip", "ip", "forwarded_for"]:
            nested_ip = clean_anchor_val(details.get(ip_key))
            if nested_ip:
                anchor_ips.add(nested_ip)

        # 2. Users
        for user_key in ["user", "user_id"]:
            u = clean_anchor_val(details.get(user_key))
            if u:
                anchor_users.add(u)

        # 3. File / Endpoint Paths (Only low-frequency or signature-flagged!)
        cluster_size = log.get("template_cluster_size", 1)
        has_signature = any(log.get(k) for k in ["sig_libinjection", "sig_owasp_crs", "sig_cyfirma_ioc"])
        for path_key in ["path", "file_path", "stealer_path", "url"]:
            p = clean_anchor_val(details.get(path_key))
            if p:
                if cluster_size <= max_path_frequency or has_signature or "shell" in p.lower():
                    anchor_files.add(p)

        # 4. User-Agents
        ua = clean_anchor_val(details.get("user_agent"))
        if ua and len(ua) > 5 and ua not in ("Mozilla/5.0", "curl/7.68.0"):
            anchor_user_agents.add(ua)

    return {
        "ips": anchor_ips,
        "users": anchor_users,
        "files": anchor_files,
        "user_agents": anchor_user_agents,
        "timestamps": anchor_timestamps
    }

def log_matches_multi_axis_anchors(log, anchors, time_window_minutes=30):
    """
    Evaluates candidate logs across IP, User, Path, and User-Agent.
    CRITICAL FIX: STRICT TIME-WINDOW BOUNDING ENFORCED ACROSS ALL AXES!
    """
    log_ts = parse_iso_ts(log.get("timestamp"))
    
    # 1. STRICT TIME-WINDOW CHECK (Applies to ALL axes)
    if log_ts and anchors["timestamps"]:
        min_ts = min(anchors["timestamps"]) - timedelta(minutes=time_window_minutes)
        max_ts = max(anchors["timestamps"]) + timedelta(minutes=15)
        if not (min_ts <= log_ts <= max_ts):
            return False, None  # Outside attack time window -> IGNORE!

    ip = clean_anchor_val(log.get("ip"))
    details = log.get("details", {})

    # 2. Axis 1: IP Match
    if ip and ip in anchors["ips"]:
        return True, f"IP_MATCH ({ip})"

    for ip_key in ["srcip", "ip", "forwarded_for"]:
        nested_ip = clean_anchor_val(details.get(ip_key))
        if nested_ip and nested_ip in anchors["ips"]:
            return True, f"IP_MATCH ({nested_ip})"

    # 3. Axis 2: User Account Match
    for user_key in ["user", "user_id"]:
        u = clean_anchor_val(details.get(user_key))
        if u and u in anchors["users"]:
            return True, f"USER_ACCOUNT_MATCH ({u})"

    # 4. Axis 3: File / Endpoint Path Match
    for path_key in ["path", "file_path", "stealer_path", "url"]:
        p = clean_anchor_val(details.get(path_key))
        if p and p in anchors["files"]:
            return True, f"ENDPOINT_PATH_MATCH ({p})"

    # 5. Axis 4: User-Agent Match
    ua = clean_anchor_val(details.get("user_agent"))
    if ua and ua in anchors["user_agents"]:
        return True, f"USER_AGENT_FINGERPRINT_MATCH ({ua[:30]}...)"

    return False, None

def run_stage3_anchor_hunter_v2(
    master_ledger_path="output/normalized_logs.json",
    path2_candidates_path="output/path2_candidate_logs.json",
    path1_wazuh_path="output/path1_wazuh_alerts.json",
    output_timeline_path="output/stage3_incident_timeline.json",
    time_window_minutes=30
):
    print("=================================================================")
    print("[*] STARTING STAGE 3: BOUNDED MULTI-AXIS ANCHOR HUNTER V2")
    print("=================================================================")

    os.makedirs(os.path.dirname(output_timeline_path) if os.path.dirname(output_timeline_path) else "output", exist_ok=True)

    if not os.path.exists(master_ledger_path):
        print(f"[!] Master ledger {master_ledger_path} not found. Creating synthetic master dataset...")
        synthetic_master = [
            {"timestamp": "2026-05-09T13:10:00Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/index.php", "status": 200, "user": "-"}},
            {"timestamp": "2026-05-09T13:12:15Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/wp-login.php", "status": 404, "user": "-"}},
            {"timestamp": "2026-05-09T13:14:02Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/wp-content/shell.php", "status": 404, "user": "-"}},
            {"timestamp": "2026-05-09T13:16:22Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "POST", "path": "/wp-content/shell.php", "status": 200, "user": "-"}},
            {"timestamp": "2026-05-09T13:16:24Z", "source_type": "fim", "ip": None, "details": {"file_path": "/var/www/html/wp-content/shell.php", "action": "ADDED", "rule_id": 550, "agent_name": "web-server-prod"}},
            {"timestamp": "2026-05-09T13:16:25Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/wp-content/shell.php?id=102' UNION SELECT 1,2,3--", "status": 200, "user": "admin"}},
            {"timestamp": "2026-05-07T00:00:00Z", "source_type": "cti_cyfirma", "ip": None, "details": {"user_id": "admin", "stealer_name": "RedLine"}},
            {"timestamp": "2026-05-09T13:20:00Z", "source_type": "web_server", "ip": "192.168.1.105", "details": {"method": "GET", "path": "/about.html", "status": 200, "user": "-"}}
        ]
        with open(master_ledger_path, "w", encoding="utf-8") as f:
            json.dump(synthetic_master, f, indent=2)

    with open(master_ledger_path, "r", encoding="utf-8") as f:
        master_ledger = json.load(f)

    # Ingest seeds
    seed_logs = []
    if os.path.exists(path1_wazuh_path):
        with open(path1_wazuh_path, "r", encoding="utf-8") as f:
            wazuh_seeds = json.load(f)
            for w in wazuh_seeds:
                w["seed_source"] = "PATH_1_WAZUH_ALERT"
            seed_logs.extend(wazuh_seeds)

    if os.path.exists(path2_candidates_path):
        with open(path2_candidates_path, "r", encoding="utf-8") as f:
            path2_candidates = json.load(f)
            for p in path2_candidates:
                p["seed_source"] = "PATH_2_RAW_CANDIDATE"
            seed_logs.extend(path2_candidates)

    if not seed_logs:
        seed_logs = [log for log in master_ledger if log.get("source_type") in ("fim", "cti_cyfirma") or log.get("details", {}).get("method") == "POST"]
        for s in seed_logs:
            s["seed_source"] = "SEED_FALLBACK"

    anchors = extract_multi_axis_anchors(seed_logs, max_path_frequency=5)

    timeline_dict = {}
    for seed in seed_logs:
        fp = f"{seed.get('timestamp')}_{seed.get('source_type')}_{seed.get('ip')}_{seed.get('details', {}).get('path') or seed.get('details', {}).get('file_path')}"
        seed["pivot_reason"] = f"SEED_EVENT ({seed.get('seed_source')})"
        timeline_dict[fp] = seed

    pivoted_count = 0
    for log in master_ledger:
        fp = f"{log.get('timestamp')}_{log.get('source_type')}_{log.get('ip')}_{log.get('details', {}).get('path') or log.get('details', {}).get('file_path')}"
        if fp in timeline_dict:
            continue

        matched, match_reason = log_matches_multi_axis_anchors(log, anchors, time_window_minutes=time_window_minutes)
        if matched:
            log["seed_source"] = "PIVOTED_CONTEXT"
            log["pivot_reason"] = f"BACKWARD_PIVOT_MATCH -> {match_reason}"
            timeline_dict[fp] = log
            pivoted_count += 1

    final_timeline = list(timeline_dict.values())
    final_timeline.sort(key=lambda x: x.get("timestamp") or "9999-12-31")

    evidence_table = []
    for idx, event in enumerate(final_timeline, 1):
        evidence_table.append({
            "event_id": idx,
            "timestamp": event.get("timestamp"),
            "source_type": event.get("source_type"),
            "ip": event.get("ip") or "-",
            "pivot_reason": event.get("pivot_reason"),
            "summary": event.get("semantic_text") or str(event.get("details"))
        })

    output_data = {
        "summary": {
            "total_master_logs": len(master_ledger),
            "seed_events_count": len(seed_logs),
            "anchors_used": {
                "ips": list(anchors["ips"]),
                "users": list(anchors["users"]),
                "files": list(anchors["files"]),
                "user_agents": list(anchors["user_agents"])
            },
            "pivoted_events_count": pivoted_count,
            "final_timeline_events": len(final_timeline),
            "reduction_percentage": round((1 - len(final_timeline) / len(master_ledger)) * 100, 2) if len(master_ledger) > 0 else 0
        },
        "evidence_verification_table": evidence_table,
        "chronological_incident_timeline": final_timeline
    }

    with open(output_timeline_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print("=================================================================")
    print("[✓] STAGE 3 V2 STRICT BOUNDED TIMELINE COMPLETE!")
    print(f"  ├─ Final Timeline Length  : {len(final_timeline)} events")
    print(f"  ├─ Volume Reduction       : {output_data['summary']['reduction_percentage']}%")
    print(f"  └─ Timeline Saved To      : {output_timeline_path}")
    print("=================================================================")

if __name__ == "__main__":
    run_stage3_anchor_hunter_v2()
