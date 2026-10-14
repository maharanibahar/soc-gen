import json
import logging

from helpers import load_jsonl, write_jsonl, parse_ts

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent          # (from pathlib import Path)
NORMALIZED = BASE_DIR / "data" / "output" / "normalized_events.jsonl"
SCOPE_FILE = BASE_DIR / "data" / "input" / "incident_scope.json"
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"

TEMPORAL_WINDOW_HOURS = 48
LEVEL_THRESHOLD = 7


def real_client(ev):
    fwd = ev["entities"].get("http_forwarded_for") or []
    return fwd[0] if fwd else ev["entities"].get("source_ip")


def build_seed_profile(seed_events):
    actors, rules, urls, times = set(), set(), set(), []
    for ev in seed_events:
        rc = real_client(ev)                 # real client only (bug fix)
        if rc:
            actors.add(rc)
        si = ev["security_interpretation"]
        if si.get("rule_id"):
            rules.add(si["rule_id"])
        url = ev["entities"].get("url")
        if url:
            urls.add(url)
        t = parse_ts(ev["timestamp"])
        if t:
            times.append(t)
    return {"actors": actors, "rules": rules, "urls": urls, "times": times}


def in_scope(ev, scope):
    if ev["entities"].get("host") != scope["seed_host"]:
        return False
    t = parse_ts(ev["timestamp"])
    return t is not None and parse_ts(scope["start_time"]) <= t <= parse_ts(scope["end_time"])


def same_seed_event(ev, scope):
    return ev["event_id"] in scope.get("seed_events", [])


def same_actor(ev, profile):
    return real_client(ev) in profile["actors"]


def same_rule(ev, profile):
    return ev["security_interpretation"].get("rule_id") in profile["rules"]


def same_url(ev, profile):
    url = ev["entities"].get("url")
    return bool(url and url in profile["urls"])


def temporal_bridge(ev, profile):
    t = parse_ts(ev["timestamp"])
    if t is None:
        return False
    near = any(abs((t - st).total_seconds()) <= TEMPORAL_WINDOW_HOURS * 3600 for st in profile["times"])
    if not near:
        return False
    decoder = ev["source"].get("decoder") or ""
    level = ev["security_interpretation"].get("rule_level") or 0
    return decoder.startswith("syscheck") or level >= LEVEL_THRESHOLD


def retrieve(events, scope):
    seed_ids = set(scope.get("seed_events", []))
    seed_events = [ev for ev in events if ev["event_id"] in seed_ids]
    if not seed_events:
        raise ValueError(f"seed events not found: {seed_ids}")
    profile = build_seed_profile(seed_events)

    kept = []
    for ev in events:
        if not in_scope(ev, scope):
            continue
        if (same_seed_event(ev, scope) or same_actor(ev, profile)
                or same_rule(ev, profile) or same_url(ev, profile)
                or temporal_bridge(ev, profile)):
            kept.append(ev)
    return kept


def run():
    scope = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    events = load_jsonl(NORMALIZED)
    log.info("loaded %d normalized events", len(events))

    candidates = retrieve(events, scope)
    write_jsonl(candidates, CANDIDATES)
    log.info("kept %d candidates -> %s", len(candidates), CANDIDATES)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    run()
