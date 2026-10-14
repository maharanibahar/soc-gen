import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict
from helpers import parse_ts, real_client, load_jsonl
import logging
log = logging.getLogger(__name__)


BASE_DIR = Path(__file__).resolve().parent
INCIDENT = BASE_DIR / "data" / "output" / "incident.json"
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"
SCOPE_FILE = BASE_DIR / "data" / "input" / "incident_scope.json"
CONTEXT = BASE_DIR / "data" / "output" / "incident_context.json"

WEB_ROOT = "/var/www/html"
EXAMPLES_PER_PHASE = 5

def groups_of(ev):
    return set(ev["security_interpretation"].get("groups") or [])


def is_attack_indicator(ev):
    g = groups_of(ev)
    dec = ev["source"].get("decoder") or ""
    status = ev["entities"].get("http_status")
    level = ev["security_interpretation"].get("rule_level") or 0

    if status == 200 and "attack" in g:
        return True
    if "webshell" in g:
        return True
    if dec.startswith("syscheck") and (ev["entities"].get("file") or "").startswith(WEB_ROOT):
        return True
    return level >= 10 and "attack" in g


def classify_phase(ev):
    g = groups_of(ev)
    dec = ev["source"].get("decoder") or ""
    status = ev["entities"].get("http_status")
    if "webshell" in g:
        return "webshell"
    if status == 200 and "attack" in g:
        return "initial_access"
    if "web_scan" in g or "recon" in g:
        return "recon"
    if dec.startswith("syscheck"):
        return "file_change"
    if "attack" in g:
        return "attack"
    return "other"


def build_timeline(candidates):
    phases = defaultdict(list)
    for ev in sorted(candidates, key=lambda e: parse_ts(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc)):
        phases[classify_phase(ev)].append(ev)

    timeline = []
    for phase, evs in phases.items():
        timeline.append({
            "phase": phase,
            "count": len(evs),
            "first": evs[0]["timestamp"],
            "last": evs[-1]["timestamp"],
            "examples": [
                {
                    "time": e["timestamp"],
                    "event_id": e["event_id"],
                    "actor": real_client(e),
                    "summary": (e["security_interpretation"].get("rule_description") or "")[:120],
                }
                for e in evs[:EXAMPLES_PER_PHASE]
            ],
        })
    return timeline


def technique_names(ev):
    rule = (ev.get("raw") or {}).get("rule") or {}   # <- raw IS the original record
    mitre = rule.get("mitre") or {}
    ids = mitre.get("id") or []
    names = mitre.get("technique") or []
    tactics = mitre.get("tactic") or []
    out = {}
    for i, tid in enumerate(ids):
        out[tid] = {
            "name": names[i] if i < len(names) else None,
            "tactic": tactics[i] if i < len(tactics) else None,
        }
    return out


def build_techniques(candidates):
    tech = {}
    for ev in candidates:
        for tid, meta in technique_names(ev).items():
            t = tech.setdefault(tid, {"technique": tid, "name": meta["name"], "tactic": meta["tactic"],
                                      "source": "wazuh_rule", "evidence": []})
            if not t["name"]:
                t["name"] = meta["name"]
            t["evidence"].append(ev["event_id"])
    return list(tech.values())


def attack_actors(candidates):
    actors = {}
    for ev in candidates:
        if not is_attack_indicator(ev):
            continue
        ip = real_client(ev)
        if not ip:
            continue
        a = actors.setdefault(ip, {"ip": ip, "events": [], "phases": set()})
        a["events"].append(ev["event_id"])
        a["phases"].add(classify_phase(ev))
    return sorted(
        [{"ip": a["ip"], "events": a["events"], "phases": sorted(a["phases"])} for a in actors.values()],
        key=lambda a: len(a["events"]), reverse=True,
    )


def build_supporting(candidates):
    out = []
    seen = set()
    for ev in candidates:
        if not is_attack_indicator(ev):
            continue
        if ev["event_id"] in seen:
            continue
        seen.add(ev["event_id"])
        si = ev["security_interpretation"]
        target = ev["entities"].get("file") or ev["entities"].get("url") or ""
        out.append({
            "statement": f"{si.get('rule_description')} -> {target}".strip(),
            "event_id": ev["event_id"],
        })
    return out[:100]  # cap; the LLM doesn't need hundreds


def build_weakening(candidates, attack_actor_ips):
    g = Counter(classify_phase(e) for e in candidates)
    actors = {real_client(e) for e in candidates if is_attack_indicator(e) and real_client(e)}
    items = []
    if g.get("initial_access") and g.get("file_change"):
        items.append("initial access and file changes are not directly linked in telemetry (no shared actor/session observed)")
    items.append(f"candidate set includes {g.get('other', 0)} routine/other events that may be background traffic")
    items.append(f"attack indicators span {len(actors)} distinct client IP(s); campaign linkage between them is not proven")
    return items


def build_context(scope, incident, candidates):
    actor_ips = {a["ip"] for a in attack_actors(candidates)}
    return {
        "investigation": {
            "incident_id": scope["incident_id"],
            "scope": {"host": scope["seed_host"], "start": scope["start_time"], "end": scope["end_time"]},
            "seed_events": scope.get("seed_events", []),
            "seed_selection": scope.get("seed_selection", {}),
        },
        "actors": attack_actors(candidates),
        "targets": incident.get("targets", {}),
        "timeline": build_timeline(candidates),
        "linkage_summary": dict(Counter(r["relationship"] for r in incident.get("relationships", []))),
        "attack_techniques": build_techniques(candidates),
        "supporting_evidence": build_supporting(candidates),
        "weakening_evidence": build_weakening(candidates, actor_ips),
       
    }


def run():
    scope = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    incident = json.loads(INCIDENT.read_text(encoding="utf-8"))
    candidates = load_jsonl(CANDIDATES)

    context = build_context(scope, incident, candidates)
    CONTEXT.write_text(json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8")

    log.info("phases: %s", [(t["phase"], t["count"]) for t in context["timeline"]])
    log.info("actors: %s", [a["ip"] for a in context["actors"]])
    log.info("supporting: %s", len(context["supporting_evidence"]))
    log.info("techniques: %s", [(t["technique"], t["name"]) for t in context["attack_techniques"]])
    log.info("wrote: %s", CONTEXT)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
