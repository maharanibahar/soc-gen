import json
from pathlib import Path
from collections import Counter
from helpers import load_jsonl, write_jsonl, parse_ts, real_client, path_prefix
import logging
log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
NORMALIZED = BASE_DIR/"data"/"output"/"normalized_events.jsonl"
SCOPE_FILE = BASE_DIR/"data"/"input"/"incident_scope.json"
CANDIDATES = BASE_DIR/"data"/"output"/"candidate_events.jsonl"

TEMPORAL_WINDOW_HOURS = 48
LEVEL_THRESHOLD = 7


def build_seed_profile(seed_events):
    actors, rules, urls, times = set(), set(), set(), []
    for ev in seed_events:
        e = ev["entities"]

        rc = real_client(ev)
        if rc:
            actors.add(rc)

        si = ev["security_interpretation"]
        if si.get("rule_id"):
            rules.add(si["rule_id"])
        
        if e.get("url"):
            urls.add(e["url"])
        t = parse_ts(ev["timestamp"])
        if t:
            times.append(t)
    return {"actors": actors, "rules": rules, "urls": urls, "times": times}


def in_scope(ev,scope):
    if ev["entities"].get("host") != scope["seed_host"]:
        return False
    t = parse_ts(ev["timestamp"])
    start = parse_ts(scope["start_time"])
    end = parse_ts(scope["end_time"])
    return t is not None and start <= t <= end

def same_seed_event(ev, scope):
    return ev["event_id"] in scope.get("seed_events", [])

def same_actor(ev, profile):
    return real_client(ev) in profile["actors"]

def same_rule(ev, profile):
    return ev["security_interpretation"].get("rule_id") in profile["rules"]

def same_url(ev, profile):
    url = ev["entities"].get("url")
    if not url:
        return False
    for su in profile["urls"]:
        if url == su:
            return True
        pref = path_prefix(su)
        if pref and url.startswith(pref):
            return True
    return False


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
        raise ValueError(f"Seed events not found in normalized data: {seed_ids}")
    profile = build_seed_profile(seed_events)

    kept = []
    for ev in events:
        if not in_scope(ev, scope):
            continue
        if (
            same_seed_event(ev, scope)
            or same_actor(ev, profile)
            or same_rule(ev, profile)
            or same_url(ev, profile)
            or temporal_bridge(ev, profile)
        ):
            kept.append(ev)
    return kept


def run():
    scope = json.loads(SCOPE_FILE.read_text(encoding="utf-8"))
    events = load_jsonl(NORMALIZED)

    candidates = retrieve(events, scope)
    write_jsonl(candidates, CANDIDATES)

    total = len(events)
    kept = len(candidates)
    log.info(f"Input events : {total}")
    log.info(f"Candidates   : {kept}")
    log.info(f"Reduction   : {kept / total:.1%}")
    log.info("by decoder: %s", Counter(c["source"].get("decoder") for c in candidates).most_common(10))
    log.info("seed inside: %s", all(any(c["event_id"] == s for c in candidates) for s in scope["seed_events"]))


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
