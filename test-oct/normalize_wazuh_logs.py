import re
import json
from helpers import  parse_ts, to_utc, write_jsonl
from collections import Counter
from pathlib import Path
import logging

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
INPUT_DIR = BASE_DIR / "data" / "input"
OUTPUT_DIR = BASE_DIR / "data" / "output"

web_logs = re.compile(
    r'(?P<ip>[^\s"]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)\s+'
    r'"(?P<referer>[^"]*)"\s*'
    r'"(?P<user_agent>[^"]*)"\s*'
    r'"(?P<forwarded_for>[^"]*)"\s*'
    r'"?(?P<extra>[^"]*)"?'
)

def read_wazuh_records(path):
    text = Path(path).read_text(encoding="utf-8-sig")

    decoder = json.JSONDecoder()
    records = []
    pos = 0
    length = len(text)

    while pos < length:
        while pos < length and text[pos].isspace():
            pos += 1
        if pos >= length:
            break

        obj, end = decoder.raw_decode(text, pos)
        if isinstance(obj, list):
            records.extend(obj)
        else:
            records.append(obj)

        pos = end

    return records


def report(records):
    log.info(f"records: {len(records)}")

    decoders = Counter()
    missing = Counter()
    earliest = latest = None

    for rec in records:
        decoders[(rec.get("decoder") or {}).get("name")] += 1

        for field in ("id", "timestamp", "rule", "agent"):
            if not rec.get(field):
                missing[field] += 1

        dt = parse_ts(rec.get("timestamp"))
        if dt:
            if earliest is None or dt < earliest:
                earliest = dt
            if latest is None or dt > latest:
                latest = dt

    if earliest:
        log.info(f"\nTimeline of logs:      {earliest.isoformat()} -> {latest.isoformat()}")
        log.info(
            "Timeline of logs (UTC):  "
            f"{to_utc(earliest.isoformat())} -> {to_utc(latest.isoformat())}"
        )

    log.info(f"\ntop decoders: {decoders.most_common(10)}")
    log.info(f"missing: {dict(missing)}")

def extract_entities(rec):
    decoder = (rec.get("decoder") or {}).get("name")

    if decoder == "web-accesslog":
        m = web_logs.match(rec.get("full_log") or "")
        if not m:
            return {}
        g = m.groupdict()
        fwd = [x.strip() for x in g["forwarded_for"].split(",") if x.strip() not in ("", "-")]
        return {
            "http_status": int(g["status"]),
            "user_agent": g["user_agent"] if g["user_agent"] != "-" else None,
            "http_forwarded_for": fwd,
        }

    return {}


def normalize_record(rec):
    agent = rec.get("agent") or {}
    data = rec.get("data") or {}
    rule = rec.get("rule") or {}
    mitre = rule.get("mitre") or {}

    entities = {
        "host": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "source_ip": data.get("srcip"),
        "destination_ip": data.get("dstip"),
        "file": (rec.get("syscheck") or {}).get("path"),
        "url": data.get("url"),
        "user": data.get("dstuser") or data.get("srcuser"),
        "process": (rec.get("predecoder") or {}).get("program_name"),
    }
    entities.update(extract_entities(rec))

    return {
        "event_id": rec.get("id"),
        "timestamp": to_utc(rec.get("timestamp")),
        "timestamp_raw": rec.get("timestamp"),
        "source": {
            "platform": "wazuh",
            "decoder": (rec.get("decoder") or {}).get("name"),
            "location": rec.get("location"),
        },
        "entities": entities,
        "security_interpretation": {
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_description": rule.get("description"),
            "groups": rule.get("groups") or [],
        },
       "action": {"decoder": (rec.get("decoder") or {}).get("name")},
        "attack_mapping": {
            "mitre": [
                {"technique": tid, "source": "wazuh_rule"}
                for tid in (mitre.get("id") or [])
            ]
        },
        "raw": rec,  
    }


def run ():
    files = sorted(INPUT_DIR.glob("*.json"))
    if not files:
        raise FileNotFoundError(f"No JSON files found in {INPUT_DIR}")
    input_path = files[0]
    log.info(f"Reading File: {input_path}")

    records = read_wazuh_records(input_path)
    report(records)

    #Save Raw Events
    write_jsonl(records, OUTPUT_DIR / "raw_events.jsonl")

    #Save Normalized Events
    normalized = [normalize_record(r) for r in records]
    write_jsonl(normalized, OUTPUT_DIR / "normalized_events.jsonl")

    log.info(f"Wrote {len(records)} raw and {len(normalized)} normalized events")

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()