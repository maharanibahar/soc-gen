import json
import re
from pathlib import Path
import logging
log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
CTX = BASE_DIR / "data" / "output" / "incident_context.json"
PSEUDO = BASE_DIR / "data" / "output" / "incident_context_pseudo.json"
MAP_FILE = BASE_DIR / "data" / "output" / "pseudonym_map.json"

# --- 1) structured fields: harvest by key name (catches usernames/short hosts) ---
IDENTITY_KEYS = {
    "ip": "IP", "source_ip": "IP", "destination_ip": "IP", "agent_ip": "IP",
    "host": "HOST", "hosts": "HOST", "hostname": "HOST",
    "file": "FILE", "files": "FILE",
    "url": "URL", "urls": "URL",
    "user": "USER", "username": "USER", "srcuser": "USER", "dstuser": "USER",
}

# --- 2) regex patterns: longest/most-specific first ---
PATTERNS = [
    ("EMAIL", re.compile(r'[\w.\-+]+@[\w.\-]+\.\w+')),
    ("URL",   re.compile(r'https?://[^\s"\'<>)\]]+')),
    ("WINPATH", re.compile(r'[A-Za-z]:\\(?:[^\\\s"<>|]+\\)*[^\\\s"<>|]+')),
    ("FILE",  re.compile(r'/(?:[\w.\-@]+/)+[\w.\-@]+')),
    ("MAC",   re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')),
    ("IP",    re.compile(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}')),
    ("FQDN",  re.compile(r'\b(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,}\b')),
]


def iter_nodes(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from iter_nodes(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from iter_nodes(item)


def harvest_structured(obj, mapping, counters):
    for key, value in iter_nodes(obj):
        kind = IDENTITY_KEYS.get(key if isinstance(key, str) else "")
        if not kind:
            continue
        values = value if isinstance(value, list) else [value]
        for v in values:
            if isinstance(v, str) and v.strip() and v not in mapping:
                counters[kind] = counters.get(kind, 0) + 1
                mapping[v] = f"{kind}_{counters[kind]}"


def harvest_patterns(text, mapping, counters):
    for kind, pattern in PATTERNS:
        for match in pattern.findall(text):
            if match in mapping:
                continue
            counters[kind] = counters.get(kind, 0) + 1
            mapping[match] = f"{kind}_{counters[kind]}"


def build_map(context):
    mapping, counters = {}, {}
    harvest_structured(context, mapping, counters)
    harvest_patterns(json.dumps(context, ensure_ascii=False), mapping, counters)
    return mapping


def apply_map(text, mapping):
    for real, label in sorted(mapping.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, label)
    return text


def verify(pseudo_text):
    """Fail-closed: warn about any identifier-looking leftovers."""
    leftovers = []
    for kind, pattern in PATTERNS:
        hits = set(pattern.findall(pseudo_text))
        if hits:
            leftovers.append((kind, list(hits)[:5]))
    return leftovers


def run():
    context = json.loads(CTX.read_text(encoding="utf-8"))
    text = json.dumps(context, ensure_ascii=False, indent=2)

    mapping = build_map(context)
    pseudo = apply_map(text, mapping)

    PSEUDO.write_text(pseudo, encoding="utf-8")
    MAP_FILE.write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")
    MAP_FILE.chmod(0o600)

    logging.info(f"replaced {len(mapping)} identifiers")
    leftovers = verify(pseudo)
    if leftovers:
        logging.warning("!! WARNING - identifier-looking text still present:")
        for kind, hits in leftovers:
            logging.warning(f"   {kind}: {hits}")
        logging.info("   -> add a pattern or harvest rule before sending.")
    else:
        logging.info("OK: no identifier-looking text remains")
    logging.info("send to API : %s", PSEUDO)
    logging.info("keep secret : %s", MAP_FILE)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
