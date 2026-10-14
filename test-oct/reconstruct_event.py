import json
from datetime import datetime, timezone
from pathlib import Path
from collections import defaultdict, Counter

BASE_DIR = Path(__file__).resolve().parent
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"
RELATIONSHIPS = BASE_DIR / "data" / "output" / "event_relationships.json"
INCIDENT = BASE_DIR / "data" / "output" / "incident.json"

SCOPE_FILE = BASE_DIR / "data" /"input" / "incident_scope.json"


def load_jsonl(path):
    rows = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def parse_ts(ts):
    if not ts:
        return None
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def real_client(ev):
    fwd = ev["entities"].get("http_forwarded_for") or []
    return fwd[0] if fwd else ev["entities"].get("source_ip")


def summarize(ev):
    si = ev["security_interpretation"]
    dec = ev["source"].get("decoder") or "?"
    target = ev["entities"].get("file") or ev["entities"].get("url") or ""
    return f"[{dec}] {si.get('rule_description') or ''} {target}".strip()


def build_timeline(events):
    timeline = []
    for ev in sorted(events, key=lambda e: parse_ts(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)):
        timeline.append({
            "time": ev["timestamp"],
            "event_id": ev["event_id"],
            "actor": real_client(ev),
            "action": ev["source"].get("decoder"),
            "summary": summarize(ev),
        })
    return timeline


def extract_actors(events):
    actors = {}
    for ev in events:
        for ip in filter(None, [real_client(ev)]):
            a = actors.setdefault(ip, {"ip": ip, "role": "source", "events": [], "first": None, "last": None})
            a["events"].append(ev["event_id"])
            a["first"] = min(filter(None, [a["first"], ev["timestamp"]]))
            a["last"] = max(filter(None, [a["last"], ev["timestamp"]]))
    return sorted(actors.values(), key=lambda a: len(a["events"]), reverse=True)


def extract_targets(events):
    files, urls, hosts = set(), set(), set()
    for ev in events:
        e = ev["entities"]
        if e.get("file"):
            files.add(e["file"])
        if e.get("url"):
            urls.add(e["url"])
        if e.get("host"):
            hosts.add(e["host"])
    return {"hosts": sorted(hosts), "files": sorted(files), "urls": sorted(urls)}


def extract_techniques(events):
    techniques = {}
    for ev in events:
        for m in ev["attack_mapping"].get("mitre", []):
            tid = m.get("technique")
            if not tid:
                continue
            t = techniques.setdefault(tid, {
                "technique": tid,
                "name": m.get("name"),
                "source": "wazuh_rule",
                "evidence": [],
            })
            t["evidence"].append(ev["event_id"])
    return list(techniques.values())


def extract_observed(events):
    observed = []
    for ev in events:
        si = ev["security_interpretation"]
        groups = set(si.get("groups") or [])
        status = ev["entities"].get("http_status")
        dec = ev["source"].get("decoder") or ""

        if status == 200 and "attack" in groups:
            observed.append({
                "statement": f"web attack request returned HTTP 200: {ev['entities'].get('url')}",
                "event_id": ev["event_id"],
            })
        elif dec.startswith("syscheck") and ev["entities"].get("file"):
            observed.append({
                "statement": f"file system change: {ev['entities']['file']} ({si.get('rule_description')})",
                "event_id": ev["event_id"],
            })
    return observed


def extract_inferred(events, relationships):
    # heuristic: one target touched by >1 distinct actor -> possible shared campaign
    target_actors = defaultdict(set)
    for ev in events:
        actor = real_client(ev)
        target = ev["entities"].get("file") or ev["entities"].get("url")
        if actor and target:
            target_actors[target].add(actor)

    inferred = []
    for target, actors in target_actors.items():
        if len(actors) > 1:
            inferred.append({
                "statement": f"multiple actors touched the same target: {target}",
                "actors": sorted(actors),
                "note": "linkage inferred, not directly observed",
            })
    return inferred


def extract_unknown_and_missing(events):
    # these are curated per case; seed with sensible gaps for this incident
    unknown = [
        "whether commands were executed through the dropped shells",
        "whether data was exfiltrated",
        "whether the server was fully compromised",
    ]
    missing = [
        "process execution telemetry (e.g. Sysmon/auditd) after shell drop",
        "outbound network connections following the shell",
        "web server logs beyond the ingested window",
    ]
    return unknown, missing


def build_incident(scope, events, relationships):
    timeline = build_timeline(events)
    observed = extract_observed(events)
    inferred = extract_inferred(events, relationships)
    unknown, missing = extract_unknown_and_missing(events)

    return {
        "incident_id": scope["incident_id"],
        "actors": extract_actors(events),
        "targets": extract_targets(events),
        "timeline": timeline,
        "actions": [{"event_id": t["event_id"], "action": t["action"]} for t in timeline],
        "attack_techniques": extract_techniques(events),
        "relationships": relationships,
        "observed": observed,
        "inferred": inferred,
        "unknown": unknown,
        "missing_evidence": missing,
        "impact": {
            "observed_file_changes": len([o for o in observed if "file system" in o["statement"]]),
            "successful_web_attacks": len([o for o in observed if "HTTP 200" in o["statement"]]),
        },
    }


def main():
    scope = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    events = load_jsonl(CANDIDATES)
    relationships = json.loads(RELATIONSHIPS.read_text(encoding="utf-8")) if RELATIONSHIPS.exists() else []

    incident = build_incident(scope, events, relationships)

    INCIDENT.parent.mkdir(parents=True, exist_ok=True)
    INCIDENT.write_text(json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"incident     : {incident['incident_id']}")
    print(f"timeline     : {len(incident['timeline'])} entries")
    print(f"actors       : {[a['ip'] for a in incident['actors'][:5]]}")
    print(f"observed     : {len(incident['observed'])}")
    print(f"inferred     : {len(incident['inferred'])}")
    print(f"techniques   : {[t['technique'] for t in incident['attack_techniques']]}")
    print(f"wrote        : {INCIDENT}")


if __name__ == "__main__":
    main()

