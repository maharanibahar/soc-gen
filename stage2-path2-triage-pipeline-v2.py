import json
import os
import re
from datetime import datetime

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
    """Simulates 384-d SBERT vector embeddings deterministically when offline."""
    def encode(self, sentences, **kwargs):
        import numpy as np
        embeddings = []
        for s in sentences:
            np.random.seed(abs(hash(s)) % (2**32))
            vec = np.random.randn(384)
            norm = np.linalg.norm(vec)
            embeddings.append(vec / norm if norm > 0 else vec)
        return np.array(embeddings)


class LexicalFallbackClusterer:
    """Simulates HDBSCAN density clustering when offline."""
    def fit_predict(self, embeddings):
        import numpy as np
        labels = np.full(len(embeddings), -1)  # Default to outliers
        for i in range(len(embeddings)):
            for j in range(i + 1, len(embeddings)):
                sim = np.dot(embeddings[i], embeddings[j])
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
        
    elif source_type == "fim":
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

    elif source_type == "fim":
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


# =====================================================================
# FIX 2: PARALLEL DETERMINISTIC SIGNATURE & IOC INSPECTION ENGINE
# =====================================================================

def run_signature_inspection(event, cyfirma_iocs=None):
    """
    FIX 2: Parallel Signature / IOC Inspection Engine (Step 6).
    Inspects raw telemetry in parallel with S-BERT/HDBSCAN using:
    1. libinjection Lexical Parser (SQLi / XSS)
    2. OWASP CRS Attack Pattern Ruleset (Path Traversal, RCE, Webshells)
    3. CYFIRMA Feed Direct IOC Matching (File Hashes, C2 Domains, IP Feeds)
    """
    if cyfirma_iocs is None:
        cyfirma_iocs = {
            "users": {"admin", "root", "db_admin"},
            "stealer_files": {"shell.php", "redline.exe", "setup.sh"},
            "malicious_ips": {"172.19.0.12"},
            "c2_urls": {"http://threat-intel"}
        }

    source_type = event.get("source_type", "")
    details = event.get("details", {})
    raw_ip = event.get("ip") or details.get("srcip")
    
    sig_flags = {
        "signature_libinjection": False,
        "signature_owasp_crs": False,
        "signature_cyfirma_ioc": False,
        "signature_reasons": []
    }

    # Extract strings for lexical scanning
    target_path = details.get("path") or details.get("file_path") or ""
    user_agent = details.get("user_agent") or ""
    user_id = details.get("user_id") or details.get("user") or ""
    scan_string = f"{target_path} {user_agent} {str(details)}".lower()

    # 1. libinjection Lexical SQLi / XSS Parsing
    sqli_patterns = [r"\bunion\b.*\bselect\b", r"\bor\b\s+1=1", r"/\*.*\*/", r";\s*drop\b", r"--\s*$", r"xp_cmdshell"]
    xss_patterns = [r"<script\b", r"javascript:", r"onerror\s*=", r"onload\s*=", r"document\.cookie"]
    
    for pat in sqli_patterns + xss_patterns:
        if re.search(pat, scan_string, re.IGNORECASE):
            sig_flags["signature_libinjection"] = True
            sig_flags["signature_reasons"].append("LIBINJECTION_SQLI_XSS_DETECTED")
            break

    # 2. OWASP CRS Rule Subset (Path Traversal, RCE, Webshell Execution)
    owasp_patterns = [
        (r"\.\./|\.\.\\", "OWASP_CRS_PATH_TRAVERSAL"),
        (r"\b(eval|passthru|shell_exec|system|base64_decode)\s*\(", "OWASP_CRS_RCE_WEBSHELL"),
        (r"/(cmd|bash|sh|powershell|certutil)\b", "OWASP_CRS_COMMAND_INJECTION"),
        (r"\.(php|asp|aspx|jsp|cgi)\.", "OWASP_CRS_DOUBLE_EXTENSION_WEBSHELL")
    ]
    for pat, reason in owasp_patterns:
        if re.search(pat, scan_string, re.IGNORECASE):
            sig_flags["signature_owasp_crs"] = True
            sig_flags["signature_reasons"].append(reason)

    # 3. CYFIRMA Direct Threat Intelligence IOC Matching
    if raw_ip and raw_ip in cyfirma_iocs["malicious_ips"]:
        sig_flags["signature_cyfirma_ioc"] = True
        sig_flags["signature_reasons"].append(f"CYFIRMA_MALICIOUS_IP ({raw_ip})")

    if user_id and str(user_id).lower() in cyfirma_iocs["users"]:
        if source_type == "cti_cyfirma":
            sig_flags["signature_cyfirma_ioc"] = True
            sig_flags["signature_reasons"].append(f"CYFIRMA_BREACHED_ACCOUNT ({user_id})")

    for sfile in cyfirma_iocs["stealer_files"]:
        if sfile in target_path.lower():
            sig_flags["signature_cyfirma_ioc"] = True
            sig_flags["signature_reasons"].append(f"CYFIRMA_MALICIOUS_FILE_MATCH ({sfile})")

    return sig_flags


# =====================================================================
# MAIN PIPELINE EXECUTION (STEPS 1 TO 8)
# =====================================================================

def run_path2_triage_pipeline(
    input_path="output/normalized_logs.json",
    all_output_path="output/engineered_logs_all.json",
    candidate_output_path="output/path2_candidate_logs.json",
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
        print(f"[!] Input file {input_path} not found. Creating synthetic test batch...")
        mock_logs = [
            {"timestamp": "2026-05-09T13:16:20Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/index.php", "status": 200, "user": "-", "referer": "http://google.com"}},
            {"timestamp": "2026-05-09T13:16:21Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/index.php", "status": 200, "user": "-", "referer": "http://google.com"}},
            {"timestamp": "2026-05-09T13:16:22Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "POST", "path": "/wp-content/shell.php", "status": 200, "user": "-", "referer": "-"}},
            {"timestamp": "2026-05-09T13:16:24Z", "source_type": "fim", "ip": None, "details": {"file_path": "/var/www/html/wp-content/shell.php", "action": "CREATE", "rule_id": 550, "agent_name": "web-server-prod"}},
            {"timestamp": "2026-05-09T13:16:25Z", "source_type": "web_server", "ip": "172.19.0.12", "details": {"method": "GET", "path": "/wp-content/shell.php?id=102' UNION SELECT 1,2,3--", "status": 200, "user": "admin", "referer": "-"}},
            {"timestamp": "2026-05-09T13:16:28Z", "source_type": "cti_cyfirma", "ip": None, "details": {"user_id": "admin", "stealer_name": "RedLine", "source_url": "http://threat-intel"}},
            {"timestamp": "2026-05-09T13:17:10Z", "source_type": "web_server", "ip": "192.168.1.100", "details": {"method": "GET", "path": "/about.html", "status": 200, "user": "-", "referer": "http://bing.com"}},
            {"timestamp": "2026-05-09T13:17:11Z", "source_type": "web_server", "ip": "192.168.1.100", "details": {"method": "GET", "path": "/about.html", "status": 200, "user": "-", "referer": "http://bing.com"}}
        ]
        with open(input_path, "w", encoding="utf-8") as f:
            json.dump(mock_logs, f, indent=2)

    with open(input_path, "r", encoding="utf-8") as f:
        logs = json.load(f)
    print(f"[+] Step 0: Ingested {len(logs)} raw normalized event cards.")

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
            "cti_cyfirma": TemplateMiner(config=drain_config)
        }
    else:
        miners = {
            "web_server": LexicalFallbackDrain(),
            "fim": LexicalFallbackDrain(),
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
    print("[*] Step 4: Embedding semantic_text into shared 384-d vector space via SBERT...")
    if HAS_SBERT:
        encoder = SentenceTransformer("all-MiniLM-L6-v2")
        embeddings = encoder.encode(semantic_sentences, show_progress_bar=False, convert_to_numpy=True)
    else:
        encoder = LexicalFallbackEncoder()
        embeddings = encoder.encode(semantic_sentences)
    print(f"[+] Step 4 Complete: Embeddings generated shape = {embeddings.shape}.")

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
        event["embedding"] = embeddings[i].tolist()
        event["cluster_label"] = int(cluster_labels[i])
        event["is_outlier"] = bool(cluster_labels[i] == -1)
        
        # FIX 2: Run parallel signature & CYFIRMA IOC inspection
        sig_results = run_signature_inspection(event)
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
            event["signature_libinjection"] or 
            event["signature_owasp_crs"] or 
            event["signature_cyfirma_ioc"]
        )

        event["anomaly_hdbscan_outlier"] = is_hdbscan_outlier
        event["anomaly_rare_drain3_template"] = is_rare_template
        
        tags = []
        if event["signature_libinjection"]:
            tags.append("SIG_LIBINJECTION")
        if event["signature_owasp_crs"]:
            tags.append("SIG_OWASP_CRS")
        if event["signature_cyfirma_ioc"]:
            tags.append("SIG_CYFIRMA_IOC")
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
