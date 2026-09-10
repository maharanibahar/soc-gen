import json
import numpy as np
from pathlib import Path
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from sentence_transformers import SentenceTransformer
import hdbscan


BASE_DIR = Path(__file__).resolve().parent
INPUT_FILE = BASE_DIR / "output" / "normalized_multiple_logs.json"
OUTPUT_FILE = BASE_DIR / "output" / "feature_engineering.json"


if not INPUT_FILE.exists():
    print(f"Error: Could not find normalized multiple logs at {INPUT_FILE}.")
    exit()

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    logs = json.load(f)

print(f"Loaded {len(logs)} normalized multiple logs.")

config = TemplateMinerConfig()
config.load("drain3.ini")
template_miner = TemplateMiner(config=config)

template_to_raw_logs = {}

#Template Mining
def web_template_text(event):
    details = event.get("details") or {}
    
    method = details.get("method").upper()
    path = details.get("path") or "/"
    status = details.get("status")
    
    return f"{method} {path} {status}"


def fim_template_text(event):
    details = event.get("details") or {}

    action = details.get("action").upper()
    file_path = details.get("file_path")

    return f"{action} {file_path}"


def cti_template_text(event):
    details = event.get("details") or {}

    stealer_name = details.get("stealer_name") or "unknown"

    return f"CTI_ALERT {stealer_name}"


BUILDERS = {
    "web": web_template_text,
    "web_server": web_template_text,
    "fim": fim_template_text,
    "cti_cyfirma": cti_template_text,
}


def generic_template_text(event):
    source_type = event.get("source_type") or "unknown"

    return f"UNKNOWN_SOURCE {source_type}"


def build_template_text(event):
    source_type = event.get("source_type", "unknown")

    builder = BUILDERS.get(
        source_type,
        generic_template_text
    )

    event["template_text"] = builder(event)

    return event

print("Running Drain3 template mining...")


for log in logs:
    drain_input = f"{log['details'].get('method', '?')} {log['details'].get('path', '?')} {log['details'].get('status', '?')}"
    result = template_miner.add_log_message(drain_input)
    template_str = result["template_mined"]
    
    if template_str not in template_to_raw_logs:
        template_to_raw_logs[template_str] = []
    template_to_raw_logs[template_str].append(log)

unique_templates = list(template_to_raw_logs.keys())
print(f"✓ Done mapping normalized logs into {len(unique_templates)} templates.")

#Semantic Encoding with S-BERT
print("Generating semantic embeddings for unique templates...")
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(unique_templates, show_progress_bar=True)
embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)

#Density Clustering with HDBSCAN
print("Running HDBSCAN spatial anomaly detection...")
clusterer = hdbscan.HDBSCAN(
    min_cluster_size=2,
    min_samples=1,
    cluster_selection_epsilon=0.15,
    metric='euclidean'
)
cluster_labels = clusterer.fit_predict(embeddings)

#
flagged_anomalies = []
spatial_anomaly_count = 0

for idx, label in enumerate(cluster_labels):
    template_str = unique_templates[idx]
    matching_logs = template_to_raw_logs[template_str]
    
    if label == -1:  
        for raw_log in matching_logs:
            raw_log["anomaly_reason"] = "Spatial Outlier (HDBSCAN Noise)"
            flagged_anomalies.append(raw_log)
            spatial_anomaly_count += 1


#Anchor Point Hunter
print("\n Initializing Anchor Point Hunter for successful (200) stealth exploits...")
anchor_point_count = 0

# Define specific indicators from your threat scenario
wp_db_indicators = ["wp_users", "wp-config", "db-table", "db_", "users", "admin_user", "select", "union"]
github_indicators = ["github", "raw.githubusercontent", "malicious", ".sh", "wget", "curl", "setup.sh", "backdoor"]

for log in logs:
    path = log["path"].lower()
    status = log["status"]
    
    # We only inspect successful requests (status 200) to find hidden vectors
    if status == 200:
        is_db_backdoor = any(ind in path for ind in wp_db_indicators)
        is_github_download = any(ind in path for ind in github_indicators)
        
        if is_db_backdoor or is_github_download:
            reasons = []
            if is_db_backdoor:
                reasons.append("Stealth DB/WP-User Backdoor Transaction")
            if is_github_download:
                reasons.append("Malicious GitHub Payload Fetch (Payload Delivery)")
            
            # Label the log and add it to our triage stream
            log["anomaly_reason"] = " | ".join(reasons)
            flagged_anomalies.append(log)
            anchor_point_count += 1
            print(f"   ↳ [Success 200 Caught] IP: {log['ip']} | Payload: {log['path'][:60]}... | Reason: {log['anomaly_reason']}")

print(f"✓ Isolated {spatial_anomaly_count} spatial outliers and {anchor_point_count} stealth anchor points.")


# 8. Save the merged results (HDBSCAN outliers + Anchor Points)
# We deduplicate the list in case a log falls into both categories
unique_flagged = {f"{l['ip']}_{l['timestamp']}_{l['path']}": l for l in flagged_anomalies}.values()

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    json.dump(list(unique_flagged), out, ensure_ascii=False, indent=2)

print(f"✓ Enriched triage complete. Saved {len(unique_flagged)} true anomalies to '{OUTPUT_FILE}'.")


