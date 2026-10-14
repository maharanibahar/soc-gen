import json
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter
from helpers import load_jsonl, parse_ts, real_client, path_prefix
import logging
log = logging.getLogger(__name__)


BASE_DIR = Path(__file__).resolve().parent
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"
CORRELATIONS = BASE_DIR / "data" / "output" / "correlated_events.json"

BUCKET_CAP = 50

#key extractors 
def key_file(ev):
    return ev["entities"].get("file")

def key_actor(ev):
    return real_client(ev)

def key_url_path(ev):
    return path_prefix(ev["entities"].get("url"))

def key_rule(ev):
    return ev["security_interpretation"].get("rule_id")

def key_technique(ev):
    return [m.get("technique") for m in ev["attack_mapping"].get("mitre", []) if m.get("technique")]

def key_user(ev):
    return ev["entities"].get("user")

def key_process(ev):
    return ev["entities"].get("process")


SIGNALS = [
    ("SAME_FILE", key_file, "entities.file"),
    ("SAME_ACTOR", key_actor, "entities.http_forwarded_for"),
    ("SAME_URL_PATH", key_url_path, "entities.url"),
    ("SAME_RULE", key_rule, "security_interpretation.rule_id"),
    ("SHARED_TECHNIQUE", key_technique, "attack_mapping.mitre.technique"),
    ("SAME_USER", key_user, "entities.user"),
    ("SAME_PROCESS", key_process, "entities.process"),
]


def bucket_by(events, key_fn):
    buckets = {}
    for ev in events:
        values = key_fn(ev)
        if values is None:
            continue
        if isinstance(values, str):
            values = [values]
        for value in values:
            if value is None:
                continue
            buckets.setdefault(value, []).append(ev)
    return buckets


def correlate(events):
    correlations = []
    seen = set()

    def emit(a, b, name, field, value):
        if a["event_id"] == b["event_id"]:
            return
        sig = (a["event_id"], b["event_id"], name)
        if sig in seen:
            return
        seen.add(sig)
        correlations.append({
            "source_event": a["event_id"],
            "target_event": b["event_id"],
            "relationship": name,
            "evidence": {"field": field, "value": value},
        })

    for name, key_fn, field in SIGNALS:
        buckets = bucket_by(events, key_fn)
        for value, group in buckets.items():
            if len(group) < 2:
                continue
            group.sort(key=lambda e: parse_ts(e["timestamp"]) or datetime.min.replace(tzinfo=timezone.utc))

            if len(group) > BUCKET_CAP:
                pairs = list(zip(group, group[1:]))          # linear chain, not all pairs
            else:
                pairs = [(group[i], group[j])
                         for i in range(len(group))
                         for j in range(i + 1, len(group))]

            for a, b in pairs:
                emit(a, b, name, field, value)

            # temporal ordering between consecutive events sharing this key
            for a, b in zip(group, group[1:]):
                emit(a, b, "PRECEDES", field, value)

    return correlations


def run():
    events = load_jsonl(CANDIDATES)
    correlations = correlate(events)

    CORRELATIONS.parent.mkdir(parents=True, exist_ok=True)
    with CORRELATIONS.open("w", encoding="utf-8") as f:
        json.dump(correlations, f, ensure_ascii=False, indent=2)

    kinds = Counter(r["relationship"] for r in correlations)
    connected = {r["source_event"] for r in correlations} | {r["target_event"] for r in correlations}

    log.info(f"candidate events : {len(events)}")
    log.info(f"correlations    : {len(correlations)}")
    log.info(f"events connected : {len(connected)}")
    log.info("by type           : %s", kinds.most_common())


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
