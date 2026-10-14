import json
from datetime import datetime, timezone
from pathlib import Path
from helpers import load_jsonl, parse_ts, real_client
import logging
log = logging.getLogger(__name__)


BASE_DIR = Path(__file__).resolve().parent
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"
CORRELATIONS = BASE_DIR / "data" / "output" / "correlated_events.json"
INCIDENT = BASE_DIR / "data" / "output" / "incident.json"

SCOPE_FILE = BASE_DIR / "data" /"input" / "incident_scope.json"


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
                "kind": "attack_success",
            })
        elif dec.startswith("syscheck") and ev["entities"].get("file"):
            observed.append({
                "statement": f"file system change: {ev['entities']['file']} ({si.get('rule_description')})",
                "event_id": ev["event_id"],
                "kind": "file_change",
            })
    return observed

def extract_inferred(events, relationships):
    return []

def extract_unknown_and_missing(scope):
    return scope.get("unknown", []), scope.get("missing_evidence", [])

def build_incident(scope, events, relationships):
    timeline = build_timeline(events)
    observed = extract_observed(events)
    inferred = extract_inferred(events, relationships)
    unknown, missing = extract_unknown_and_missing(scope)

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
            "observed_file_changes": sum(1 for o in observed if o.get("kind") == "file_change"),
            "successful_web_attacks": sum(1 for o in observed if o.get("kind") == "attack_success"),
        },
    }


def run():
    scope = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    events = load_jsonl(CANDIDATES)
    correlations = json.loads(CORRELATIONS.read_text(encoding="utf-8")) if CORRELATIONS.exists() else []

    incident = build_incident(scope, events, correlations)

    INCIDENT.parent.mkdir(parents=True, exist_ok=True)
    INCIDENT.write_text(json.dumps(incident, ensure_ascii=False, indent=2), encoding="utf-8")

    log.info(f"incident     : {incident['incident_id']}")
    log.info(f"timeline     : {len(incident['timeline'])} entries")
    log.info(f"actors       : {[a['ip'] for a in incident['actors'][:5]]}")
    log.info(f"observed     : {len(incident['observed'])}")
    log.info(f"inferred     : {len(incident['inferred'])}")
    log.info(f"techniques   : {[t['technique'] for t in incident['attack_techniques']]}")
    log.info(f"wrote        : {INCIDENT}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()