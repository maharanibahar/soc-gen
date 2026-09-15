import json
import hashlib
import ipaddress
import math
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_HTTP_RULES_PATH = BASE_DIR / "detection" / "http-signatures.json"
DEFAULT_THREAT_INTEL_PATH = BASE_DIR / "detection" / "threat-intel.json"
DEFAULT_TRUSTED_PROXIES_PATH = BASE_DIR / "detection" / "trusted-proxies.json"
DEFAULT_CRS_REPLAY_DIR = BASE_DIR / "crs-replay"

# Optional ML libraries with offline fallbacks for sandbox environment
try:
    from sentence_transformers import SentenceTransformer
    HAS_SBERT = True
except ImportError:
    HAS_SBERT = False

try:
    from drain3.template_miner import TemplateMiner
    from drain3.template_miner_config import TemplateMinerConfig
    HAS_DRAIN = True
except ImportError:
    HAS_DRAIN = False

try:
    import hdbscan
    HAS_HDBSCAN = True
except ImportError:
    HAS_HDBSCAN = False


# =====================================================================
# OFFLINE FALLBACK CLASSES
# =====================================================================

class LexicalFallbackEncoder:
    """Builds deterministic lexical vectors when SBERT is unavailable."""
    def encode(self, sentences, **kwargs):
        embeddings = []
        for sentence in sentences:
            vector = [0.0] * 256
            tokens = re.findall(r"[a-z0-9_]+|[^\w\s]", sentence.casefold())
            for token in tokens:
                digest = hashlib.blake2s(token.encode("utf-8"), digest_size=4).digest()
                bucket = int.from_bytes(digest, "big") % len(vector)
                vector[bucket] += 1.0 if digest[0] & 1 else -1.0
            norm = math.sqrt(sum(value * value for value in vector))
            embeddings.append([value / norm for value in vector] if norm else vector)
        return embeddings


class LexicalFallbackClusterer:
    """Groups nearly identical fallback vectors and marks the rest as outliers."""
    def fit_predict(self, embeddings):
        labels = [-1] * len(embeddings)
        for i in range(len(embeddings)):
            for j in range(i + 1, len(embeddings)):
                sim = sum(left * right for left, right in zip(embeddings[i], embeddings[j]))
                if sim > 0.99:
                    labels[i] = 0
                    labels[j] = 0
        return labels


class LexicalFallbackDrain:
    """Simulates Partitioned Drain3 template mining when offline."""
    def __init__(self):
        self.templates = {}
        self.cluster_counts = {}
        self.next_id = 1

    def add_log_message(self, text):
        masked = mask_leaf_path(text)
        masked = re.sub(r'((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)', '<IP>', masked)
        masked = re.sub(r'\b\d+\b', '<NUM>', masked)
        
        if masked not in self.templates:
            self.templates[masked] = self.next_id
            self.cluster_counts[self.next_id] = 1
            self.next_id += 1
        else:
            cid = self.templates[masked]
            self.cluster_counts[cid] += 1
            
        cid = self.templates[masked]
        return {
            "cluster_id": cid,
            "template_mined": masked,
            "cluster_size": self.cluster_counts[cid]
        }


# =====================================================================
# FIX 1: LEAF-LEVEL PATH MASKING & TEMPLATE_TEXT GENERATION
# =====================================================================

def mask_leaf_path(raw_path):
    """
    FIX 1: Leaf-level path masking.
    Preserves static directory structure (e.g., /wp-content/plugins/revslider/)
    while masking dynamic leaf filenames, numeric IDs, hex hashes, and query parameters.
    """
    if not raw_path:
        return "/"
    
    # 1. Separate Query String if present
    if "?" in raw_path:
        base_path, query_str = raw_path.split("?", 1)
        # Mask numbers, hex, and parameter values in query
        query_masked = re.sub(r'=[^&]+', '=<VAL>', query_str)
        query_masked = re.sub(r'0x[a-fA-F0-9]+', '<HEX>', query_masked)
        query_masked = re.sub(r'\b\d+\b', '<NUM>', query_masked)
        formatted_query = "?" + query_masked
    else:
        base_path = raw_path
        formatted_query = ""

    # 2. Mask leaf file name / dynamic tokens while keeping directory structure
    parts = base_path.rsplit("/", 1)
    if len(parts) == 2:
        dirname, leaf = parts[0], parts[1]
        # Mask numbers and hex inside leaf filename
        masked_leaf = re.sub(r'0x[a-fA-F0-9]+', '<HEX>', leaf)
        masked_leaf = re.sub(r'\b\d+\b', '<NUM>', masked_leaf)
        return f"{dirname}/{masked_leaf}{formatted_query}"
    
    return f"{base_path}{formatted_query}"


def build_template_text(event):
    """
    STEP 1: Builds source-specific low-entropy template_text.
    Applies leaf-level masking to retain structural web directory hierarchy.
    """
    source_type = event.get("source_type", "")
    details = event.get("details", {})
    
    if source_type == "web_server":
        method = details.get("method", "GET")
        raw_path = details.get("path", "/")
        masked_path = mask_leaf_path(raw_path)
        protocol = details.get("protocol", "HTTP/1.1")
        status = details.get("status", 200)
        return f"{method} {masked_path} {protocol} {status}"
        
    elif source_type in ("fim", "wazuh_fim"):
        rule_id = details.get("rule_id", 0)
        action = details.get("action", "MODIFY").upper()
        raw_file = details.get("file_path", "")
        masked_file = mask_leaf_path(raw_file)
        return f"Wazuh_FIM_Rule_{rule_id} {action} on {masked_file}"
        
    elif source_type == "cti_cyfirma":
        stealer_name = details.get("stealer_name", "Unknown")
        return f"CYFIRMA_CTI_ALERT Account <USER_ID> linked to {stealer_name} stealer"
        
    else:
        return mask_leaf_path(str(details))


def build_semantic_text(event):
    """
    STEP 3: Builds high-entropy, neutral semantic_text across all sources.
    States only facts present in data without causal overclaims or false facts.
    """
    source_type = event.get("source_type", "")
    details = event.get("details", {})
    
    # Strictly validate user field to avoid "-" truthy bug
    raw_user = details.get("user") or details.get("user_id")
    clean_user = str(raw_user).strip() if raw_user and str(raw_user).strip() not in ("-", "None", "") else None
    user_str = f"authenticated as {clean_user}" if clean_user else "anonymous"

    if source_type == "web_server":
        status_num = int(details.get("status", 200)) if str(details.get("status", 200)).isdigit() else 200
        status_desc = "successful" if status_num < 400 else "failed"
        method = details.get("method", "GET")
        path = details.get("path", "/")
        
        # Neutral referer handling without causal overclaim
        raw_referer = details.get("referer")
        clean_referer = str(raw_referer).strip() if raw_referer and str(raw_referer).strip() not in ("-", "None", "") else None
        referer_str = f"with referer '{clean_referer}'" if clean_referer else "without referer header"
        
        return f"Web server recorded a {status_desc} {method} request to path {path} ({user_str}) {referer_str} returning status code {status_num}."

    elif source_type in ("fim", "wazuh_fim"):
        action = str(details.get("action", "modified")).lower()
        file_path = details.get("file_path", "unknown_path")
        agent = details.get("agent_name") or "host"
        return f"Host integrity monitor on {agent} detected file {file_path} was {action} on system."

    elif source_type == "cti_cyfirma":
        stealer = details.get("stealer_name") or "unknown malware"
        user_id = details.get("user_id") or "unspecified user"
        return f"Threat intelligence flagged credential exposure: user account {user_id}'s data was linked to {stealer} stealer activity."

    else:
        return f"Generic security telemetry event recorded for source type {source_type}."


@lru_cache(maxsize=None)
def load_detection_data(path, expected_key):
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as source:
            data = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not load detection data from {path}: {exc}") from exc

    if not isinstance(data, dict) or expected_key not in data:
        raise ValueError(f"Detection data {path} must contain '{expected_key}'.")
    return data


def normalize_http_fields(event):
    details = event.get("details") or {}
    raw_target = str(details.get("path") or details.get("file_path") or "")
    decoded_once = unquote(raw_target)
    decoded_twice = unquote(decoded_once)
    parsed = urlsplit(raw_target)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)

    return {
        "raw_target": raw_target,
        "decoded_target_once": decoded_once,
        "decoded_target_twice": decoded_twice,
        "route": unquote(parsed.path),
        "query_keys": " ".join(key for key, _ in query_pairs),
        "query_values": " ".join(value for _, value in query_pairs),
        "user_agent": str(details.get("user_agent") or ""),
    }


def load_trusted_networks(path):
    data = load_detection_data(path, "networks")
    networks = []
    for value in data["networks"]:
        try:
            networks.append(ipaddress.ip_network(value))
        except ValueError as exc:
            raise ValueError(f"Invalid trusted proxy network '{value}' in {path}.") from exc
    return networks, data.get("version", "unknown")


def is_trusted_address(value, trusted_networks):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in trusted_networks)


def resolve_effective_client_ip(event, trusted_networks):
    details = event.get("details") or {}
    peer = str(event.get("ip") or details.get("srcip") or "").strip()
    forwarded = [part.strip() for part in str(details.get("forwarded_for") or "").split(",") if part.strip()]

    if not peer or not forwarded or not is_trusted_address(peer, trusted_networks):
        return peer or None, "immediate_peer"

    for candidate in reversed(forwarded):
        if not is_trusted_address(candidate, trusted_networks):
            return candidate, "trusted_forwarded_chain"
    return forwarded[0], "trusted_forwarded_chain"


def inspect_custom_http_rules(normalized_fields, rule_data):
    metadata = rule_data["rule_set"]
    hits = []

    for rule in rule_data["rules"]:
        try:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)
        except (KeyError, re.error) as exc:
            raise ValueError(f"Invalid HTTP rule {rule.get('id', '<missing id>')}: {exc}") from exc

        for field in rule.get("fields", []):
            value = normalized_fields.get(field, "")
            match = pattern.search(value)
            if not match:
                continue
            hits.append({
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "rule_source": metadata["name"],
                "rule_version": metadata["version"],
                "category": rule["category"],
                "severity": rule["severity"],
                "confidence": rule["confidence"],
                "matched_field": field,
                "matched_value": match.group(0),
            })
            break
    return hits


def values_from_event(event, normalized_fields):
    details = event.get("details") or {}
    source_url = str(details.get("source_url") or "")
    source_domain = urlsplit(source_url).hostname or ""
    return {
        "ips": [str(event.get("effective_client_ip") or ""), str(event.get("ip") or "")],
        "domains": [source_domain],
        "urls": [source_url],
        "file_names": [Path(str(details.get("file_path") or "")).name, normalized_fields["raw_target"]],
        "file_hashes": [str(details.get(key) or "") for key in ("sha256", "sha1", "md5", "hash")],
        "users": [str(details.get("user_id") or details.get("user") or "")],
    }


def inspect_threat_intel(event, normalized_fields, intel_data):
    metadata = intel_data["feed"]
    observed = values_from_event(event, normalized_fields)
    hits = []

    for indicator_type, indicators in intel_data["indicators"].items():
        candidates = [value.casefold() for value in observed.get(indicator_type, []) if value]
        for indicator in indicators:
            value = str(indicator["value"])
            expected = value.casefold()
            matched = any(
                expected in candidate if indicator_type == "file_names" else expected == candidate
                for candidate in candidates
            )
            if matched:
                hits.append({
                    "rule_id": indicator.get("id", f"IOC-{indicator_type}-{value}"),
                    "rule_name": f"Threat intelligence {indicator_type} match",
                    "rule_source": metadata["name"],
                    "rule_version": metadata["version"],
                    "category": "threat_intelligence",
                    "severity": indicator.get("severity", "high"),
                    "confidence": indicator.get("confidence", 1.0),
                    "matched_field": indicator_type,
                    "matched_value": value,
                })
    return hits


def inspect_upstream_crs(event):
    details = event.get("details") or {}
    rule_ids = []
    for key in ("owasp_crs_rule_ids", "modsecurity_rule_ids", "crs_rule_ids"):
        value = details.get(key)
        if isinstance(value, list):
            rule_ids.extend(value)
        elif value:
            rule_ids.extend(part.strip() for part in str(value).split(",") if part.strip())

    return [{
        "rule_id": str(rule_id),
        "rule_name": "Upstream OWASP CRS match",
        "rule_source": "owasp-crs-upstream",
        "rule_version": str(details.get("owasp_crs_version") or "unknown"),
        "category": "upstream_waf",
        "severity": "high",
        "confidence": 1.0,
        "matched_field": "details.crs_rule_ids",
        "matched_value": str(rule_id),
    } for rule_id in rule_ids]


def inspect_offline_crs(event):
    replay = event.get("crs_replay") or {}
    hits = []
    for rule in replay.get("matched_rules", []):
        if not rule.get("is_attack"):
            continue
        matched_variables = rule.get("matched_variables") or []
        first_match = matched_variables[0] if matched_variables else {}
        variable = first_match.get("variable", "unknown")
        key = first_match.get("key")
        hits.append({
            "rule_id": str(rule["id"]),
            "rule_name": rule.get("message") or "Offline OWASP CRS match",
            "rule_source": "owasp-crs-offline-coraza",
            "rule_version": replay.get("crs_version", "unknown"),
            "engine": replay.get("engine", "coraza"),
            "engine_version": replay.get("engine_version", "unknown"),
            "category": next(
                (tag for tag in rule.get("tags", []) if tag.startswith("attack-")),
                "owasp_crs",
            ),
            "severity": rule.get("severity", "unknown"),
            "confidence": 1.0,
            "matched_field": f"{variable}:{key}" if key else variable,
            "matched_value": first_match.get("value", ""),
            "coverage": replay.get("coverage", {}),
        })
    return hits


def run_offline_crs_replay(events, command=None, replay_dir=DEFAULT_CRS_REPLAY_DIR):
    if not events:
        return []
    if command is None:
        command = ["mise", "exec", "--", "go", "run", "."]

    payload = "\n".join(json.dumps(event, ensure_ascii=False) for event in events) + "\n"
    try:
        completed = subprocess.run(
            command,
            cwd=replay_dir,
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not start offline CRS replay: {exc}") from exc

    if completed.returncode != 0:
        error = completed.stderr.strip() or "unknown runner error"
        raise RuntimeError(f"Offline CRS replay failed: {error}")

    results = []
    for line_number, line in enumerate(completed.stdout.splitlines(), 1):
        if not line.strip():
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Offline CRS replay returned invalid JSON on line {line_number}.") from exc
        results.append(result)

    if len(results) != len(events):
        raise RuntimeError(
            f"Offline CRS replay returned {len(results)} results for {len(events)} events."
        )
    return results


def run_signature_inspection(
    event,
    http_rules_path=DEFAULT_HTTP_RULES_PATH,
    threat_intel_path=DEFAULT_THREAT_INTEL_PATH,
    trusted_proxies_path=DEFAULT_TRUSTED_PROXIES_PATH,
):
    rule_data = load_detection_data(http_rules_path, "rules")
    intel_data = load_detection_data(threat_intel_path, "indicators")
    trusted_networks, trusted_proxy_version = load_trusted_networks(trusted_proxies_path)
    normalized_fields = normalize_http_fields(event)
    effective_client_ip, client_ip_source = resolve_effective_client_ip(event, trusted_networks)

    event["effective_client_ip"] = effective_client_ip
    normalized_fields["effective_client_ip"] = effective_client_ip
    custom_hits = inspect_custom_http_rules(normalized_fields, rule_data)
    threat_intel_hits = inspect_threat_intel(event, normalized_fields, intel_data)
    offline_crs_hits = inspect_offline_crs(event)
    upstream_crs_hits = inspect_upstream_crs(event)
    detection_hits = custom_hits + threat_intel_hits + offline_crs_hits + upstream_crs_hits

    return {
        "signature_custom_http": bool(custom_hits),
        "signature_threat_intel": bool(threat_intel_hits),
        "signature_offline_owasp_crs": bool(offline_crs_hits),
        "signature_upstream_owasp_crs": bool(upstream_crs_hits),
        "signature_reasons": [hit["rule_id"] for hit in detection_hits],
        "detection_hits": detection_hits,
        "http_normalization": normalized_fields,
        "effective_client_ip": effective_client_ip,
        "client_ip_source": client_ip_source,
        "trusted_proxy_config_version": trusted_proxy_version,
    }


# =====================================================================
# MAIN PIPELINE EXECUTION (STEPS 1 TO 8)
# =====================================================================

def run_path2_triage_pipeline(
    input_path="output/normalized_multiple_logs.json",
    all_output_path="output/engineered_logs_all.json",
    candidate_output_path="output/path2_candidate_logs.json",
    http_rules_path=DEFAULT_HTTP_RULES_PATH,
    threat_intel_path=DEFAULT_THREAT_INTEL_PATH,
    trusted_proxies_path=DEFAULT_TRUSTED_PROXIES_PATH,
    crs_replay_command=None,
    crs_replay_dir=DEFAULT_CRS_REPLAY_DIR,
    rare_template_threshold=3,
    min_cluster_size=5,
    min_samples=2
):
    print("=================================================================")
    print("[*] STARTING PATH 2: FEATURE ENGINEERING & TRIAGE REDUCTION V2")
    print("=================================================================")

    os.makedirs(os.path.dirname(all_output_path) if os.path.dirname(all_output_path) else "output", exist_ok=True)

    # Load normalized logs
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file {input_path} not found.")

    with open(input_path, "r", encoding="utf-8") as f:
        logs = json.load(f)
    print(f"[+] Step 0: Ingested {len(logs)} raw normalized event cards.")

    print("[*] Replaying normalized HTTP events through Coraza and OWASP CRS...")
    crs_events = [
        event for event in logs
        if event.get("source_type") in ("web", "web_server")
    ]
    crs_results = run_offline_crs_replay(
        crs_events,
        command=crs_replay_command,
        replay_dir=crs_replay_dir,
    )
    for event, result in zip(crs_events, crs_results):
        event["crs_replay"] = result
    print(f"[+] Offline CRS replay complete for {len(crs_results)} HTTP events.")

    # -----------------------------------------------------------------
    # STEP 1 & 2: PARTITIONED DRAIN3 MINING WITH LEAF-MASKED PATHS
    # -----------------------------------------------------------------
    print("[*] Step 1 & 2: Building leaf-masked template_text and mining Partitioned Drain3...")
    
    if HAS_DRAIN:
        drain_config = TemplateMinerConfig()
        if os.path.exists("drain3.ini"):
            drain_config.load("drain3.ini")
        miners = {
            "web_server": TemplateMiner(config=drain_config),
            "fim": TemplateMiner(config=drain_config),
            "wazuh_fim": TemplateMiner(config=drain_config),
            "cti_cyfirma": TemplateMiner(config=drain_config)
        }
    else:
        miners = {
            "web_server": LexicalFallbackDrain(),
            "fim": LexicalFallbackDrain(),
            "wazuh_fim": LexicalFallbackDrain(),
            "cti_cyfirma": LexicalFallbackDrain()
        }

    for event in logs:
        stype = event.get("source_type", "unknown")
        t_text = build_template_text(event)
        event["template_text"] = t_text
        
        miner = miners.get(stype, miners["web_server"])
        res = miner.add_log_message(t_text)
        
        if HAS_DRAIN:
            event["template_id"] = f"{stype}_{res['cluster_id']}"
            event["masked_template"] = res["template_mined"]
            cluster_obj = miner.drain.id_to_cluster.get(res['cluster_id'])
            event["template_cluster_size"] = cluster_obj.size if cluster_obj else 1
        else:
            event["template_id"] = f"{stype}_{res['cluster_id']}"
            event["masked_template"] = res["template_mined"]
            event["template_cluster_size"] = res["cluster_size"]

    print("[+] Step 2 Complete: Partitioned Drain3 templates assigned with preserved directory structure.")

    # -----------------------------------------------------------------
    # STEP 3: FACTUAL SEMANTIC TEXT GENERATION
    # -----------------------------------------------------------------
    print("[*] Step 3: Generating neutral, factual semantic_text across all events...")
    semantic_sentences = []
    for event in logs:
        s_text = build_semantic_text(event)
        event["semantic_text"] = s_text
        semantic_sentences.append(s_text)
    print(f"[+] Step 3 Complete: Compiled {len(semantic_sentences)} semantic sentences.")

    # -----------------------------------------------------------------
    # STEP 4: SHARED SBERT EMBEDDING
    # -----------------------------------------------------------------
    print("[*] Step 4: Embedding semantic_text with SBERT or the lexical fallback...")
    if HAS_SBERT:
        encoder = SentenceTransformer("all-MiniLM-L6-v2")
        embeddings = encoder.encode(semantic_sentences, show_progress_bar=False, convert_to_numpy=True)
    else:
        encoder = LexicalFallbackEncoder()
        embeddings = encoder.encode(semantic_sentences)
    embedding_width = len(embeddings[0]) if len(embeddings) else 0
    print(f"[+] Step 4 Complete: Embeddings generated shape = ({len(embeddings)}, {embedding_width}).")

    # -----------------------------------------------------------------
    # STEP 5 & 6: HDBSCAN CLUSTERING & PARALLEL SIGNATURE ENGINE
    # -----------------------------------------------------------------
    print("[*] Step 5 & 6: Running HDBSCAN clustering & Parallel Signature/IOC Engine...")
    if HAS_HDBSCAN and len(embeddings) >= min_cluster_size:
        clusterer = hdbscan.HDBSCAN(min_cluster_size=min_cluster_size, min_samples=min_samples, metric="euclidean")
        cluster_labels = clusterer.fit_predict(embeddings)
    else:
        clusterer = LexicalFallbackClusterer()
        cluster_labels = clusterer.fit_predict(embeddings)

    for i, event in enumerate(logs):
        event["embedding"] = embeddings[i].tolist() if hasattr(embeddings[i], "tolist") else embeddings[i]
        event["cluster_label"] = int(cluster_labels[i])
        event["is_outlier"] = bool(cluster_labels[i] == -1)
        
        sig_results = run_signature_inspection(
            event,
            http_rules_path=http_rules_path,
            threat_intel_path=threat_intel_path,
            trusted_proxies_path=trusted_proxies_path,
        )
        event.update(sig_results)

    print("[+] Step 5 & 6 Complete: HDBSCAN outliers & Signature/IOC flags assigned.")

    # -----------------------------------------------------------------
    # FIX 3: MULTI-TAG CANDIDATE ATTRIBUTION & UNION SAFETY NET
    # -----------------------------------------------------------------
    print(f"[*] Step 7: Merging Candidate Pool with Multi-Tag Attribution...")
    candidate_logs = []
    
    for event in logs:
        is_hdbscan_outlier = event["is_outlier"]
        is_rare_template = event["template_cluster_size"] <= rare_template_threshold
        is_sig_hit = (
            event["signature_custom_http"]
            or event["signature_threat_intel"]
            or event["signature_offline_owasp_crs"]
            or event["signature_upstream_owasp_crs"]
        )

        event["anomaly_hdbscan_outlier"] = is_hdbscan_outlier
        event["anomaly_rare_drain3_template"] = is_rare_template
        
        tags = []
        if event["signature_custom_http"]:
            tags.append("SIG_CUSTOM_HTTP")
        if event["signature_threat_intel"]:
            tags.append("SIG_THREAT_INTEL")
        if event["signature_offline_owasp_crs"]:
            tags.append("SIG_OFFLINE_OWASP_CRS")
        if event["signature_upstream_owasp_crs"]:
            tags.append("SIG_UPSTREAM_OWASP_CRS")
        if is_hdbscan_outlier:
            tags.append("ANOMALY_HDBSCAN")
        if is_rare_template:
            tags.append("ANOMALY_RARE_DRAIN3")

        event["attribution_tags"] = tags
        event["passed_triage"] = bool(is_sig_hit or is_hdbscan_outlier or is_rare_template)

        if event["passed_triage"]:
            candidate_logs.append(event)

    # -----------------------------------------------------------------
    # STEP 8: SAVE ENRICHED MASTER LOGS & CANDIDATE POOL
    # -----------------------------------------------------------------
    print(f"[*] Step 8: Saving candidate pool for Stage 3 Anchor Hunter...")
    
    with open(all_output_path, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2)
        
    with open(candidate_output_path, "w", encoding="utf-8") as f:
        json.dump(candidate_logs, f, indent=2)

    total_count = len(logs)
    candidate_count = len(candidate_logs)
    reduction_pct = ((total_count - candidate_count) / total_count * 100) if total_count > 0 else 0.0

    print("=================================================================")
    print(f"[✓] PATH 2 TRIAGE V2 COMPLETE!")
    print(f"  ├─ Total Raw Logs Ingested    : {total_count}")
    print(f"  ├─ Candidate Pool Selected    : {candidate_count}")
    print(f"  ├─ Data Reduction Rate        : {reduction_pct:.2f}%")
    print(f"  ├─ Full Enriched Dataset      : {all_output_path}")
    print(f"  └─ Candidate Pool (for Stage3): {candidate_output_path}")
    print("=================================================================")

    return candidate_logs


if __name__ == "__main__":
    run_path2_triage_pipeline()
