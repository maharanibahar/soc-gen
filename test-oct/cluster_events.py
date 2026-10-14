import json
from pathlib import Path
from collections import Counter
from helpers import load_jsonl, parse_ts, real_client
import networkx as nx
import logging
log = logging.getLogger(__name__)


BASE_DIR = Path(__file__).resolve().parent
CANDIDATES = BASE_DIR / "data" / "output" / "candidate_events.jsonl"
CORRELATIONS = BASE_DIR / "data" / "output" / "correlated_events.json"
CLUSTERS = BASE_DIR / "data" / "output" / "incident_clusters.json"

WEB_ROOT = "/var/www/html"
ALLOWED = {"SAME_FILE", "SAME_ACTOR", "PRECEDES"}          # SAME_URL_PATH dropped
STRONG_PRECEDES = {"entities.file", "entities.http_forwarded_for"}
MAX_GAP_HOURS = 12
EXAMPLES = 5

def groups_of(ev):
    return set(ev["security_interpretation"].get("groups") or [])


def url_path(ev):
    url = ev["entities"].get("url")
    if not url:
        return None
    path = url.split("?", 1)[0]
    return path if path.startswith("/") else None


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


def build_graph(by_id, relationships):
    g = nx.Graph()
    g.add_nodes_from(by_id)

    # 1) correlation links: SAME_FILE / SAME_ACTOR, and only strong PRECEDES
    for r in relationships:
        rel = r["relationship"]
        if rel not in ALLOWED:
            continue
        if rel == "PRECEDES" and r.get("evidence", {}).get("field") not in STRONG_PRECEDES:
            continue
        a, b = r["source_event"], r["target_event"]
        if a not in by_id or b not in by_id:
            continue
        ta, tb = parse_ts(by_id[a]["timestamp"]), parse_ts(by_id[b]["timestamp"])
        if ta and tb and abs((ta - tb).total_seconds()) > MAX_GAP_HOURS * 3600:
            continue
        g.add_edge(a, b)

    # 2) bridge: web URL path <-> syscheck file path (same target, different fields)
    file_events = [
        (ev["entities"]["file"], ev["event_id"])
        for ev in by_id.values()
        if ev["entities"].get("file")
    ]
    for ev in by_id.values():
        p = url_path(ev)
        if not p or p.count("/") < 2:
            continue
        te = parse_ts(ev["timestamp"])
        for f, fid in file_events:
            if f == p or f.endswith(p):
                tf = parse_ts(by_id[fid]["timestamp"])
                if te and tf and abs((te - tf).total_seconds()) > MAX_GAP_HOURS * 3600:
                    continue
                g.add_edge(ev["event_id"], fid)

    return g


def summarize(events):
    evs = sorted(events, key=lambda e: parse_ts(e["timestamp"]))
    if len(evs) <= EXAMPLES:
        example_evs = evs
    else:
        example_evs = evs[:2] + evs[len(evs) // 2: len(evs) // 2 + 1] + evs[-2:]

    return {
        "size": len(evs),
        "first": evs[0]["timestamp"],
        "last": evs[-1]["timestamp"],
        "actors": sorted({real_client(e) for e in evs if real_client(e)}),
        "phases": dict(Counter(classify_phase(e) for e in evs)),
        "decoders": dict(Counter(e["source"].get("decoder") for e in evs)),
        "has_attack": any(is_attack_indicator(e) for e in evs),
        "examples": [
            {
                "time": e["timestamp"],
                "event_id": e["event_id"],
                "summary": (e["security_interpretation"].get("rule_description") or "")[:100],
            }
            for e in example_evs
        ],
    }


def run():
    candidates = load_jsonl(CANDIDATES)
    by_id = {e["event_id"]: e for e in candidates}
    correlations = json.loads(CORRELATIONS.read_text(encoding="utf-8"))

    graph = build_graph(by_id, correlations)

    clusters = []
    for i, comp in enumerate(nx.connected_components(graph), start=1):
        summary = summarize([by_id[eid] for eid in comp])
        summary["cluster_id"] = f"c{i}"
        clusters.append(summary)

    clusters.sort(key=lambda c: c["size"], reverse=True)

    CLUSTERS.write_text(json.dumps(clusters, ensure_ascii=False, indent=2), encoding="utf-8")

    log.info(f"events: {len(by_id)} | clusters: {len(clusters)}")
    for c in clusters[:15]:
        log.info(f"  {c['cluster_id']:>4}  size={c['size']:5d}  attack={c['has_attack']}  "
                 f"{c['first'][:19]}..{c['last'][:19]}  actors={c['actors'][:2]}")
    log.info(f"wrote: {CLUSTERS}")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()