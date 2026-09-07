import json
import numpy as np
from pathlib import Path
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from sentence_transformers import SentenceTransformer
import hdbscan

# 1. Setup paths
BASE_DIR = Path(__file__).resolve().parent
INPUT_JSON = BASE_DIR / "normalized_logs.json"
OUTPUT_ANOMALIES = BASE_DIR / "output" / "flagged_anomalies.json"

if not INPUT_JSON.exists():
    print(f"❌ Error: Could not find normalized logs at {INPUT_JSON}.")
    print("Please run your 'normalie_logs.py' script first to generate this file!")
    exit()

# 2. Load normalized logs
with open(INPUT_JSON, "r", encoding="utf-8") as f:
    logs = json.load(f)

print(f"Loaded {len(logs)} normalized logs.")

# 3. Step 1: Syntactic Masking & Template Mining with Drain3
config = TemplateMinerConfig()
# Load from your drain3.ini file using the correct .load() method
config.load("drain3.ini")
template_miner = TemplateMiner(config=config)

# This dictionary maps: "Clean Template String" -> [List of original raw log dictionaries]
# This is our Parallel Metadata Tracker!
template_to_raw_logs = {}

print("Running Drain3 template mining...")
for log in logs:
    # Reconstruct the structural signature
    drain_input = f"{log['method']} {log['path']} {log['protocol']} {log['status']} {log['response_size']}"
    
    # Mine template
    result = template_miner.add_log_message(drain_input)
    
    # FIXED: Reverted back to the correct official key "template_mined"
    template_str = result["template_mined"]
    
    # Store the original log dict under its structural template group
    if template_str not in template_to_raw_logs:
        template_to_raw_logs[template_str] = []
    template_to_raw_logs[template_str].append(log)

unique_templates = list(template_to_raw_logs.keys())
print(f"✓ Compression complete! {len(logs)} raw logs collapsed into {len(unique_templates)} unique templates.")

# 4. Step 2: Semantic Encoding with S-BERT
print(f"Generating semantic embeddings for {len(unique_templates)} templates...")
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(unique_templates, show_progress_bar=True)

# L2-normalize embeddings so Euclidean distance behaves like Cosine distance
embeddings = embeddings / np.linalg.norm(embeddings, axis=1, keepdims=True)

# 5. Step 3: Density Clustering with HDBSCAN
print("Running HDBSCAN anomaly detection...")
clusterer = hdbscan.HDBSCAN(
    min_cluster_size=2,
    min_samples=1,
    cluster_selection_epsilon=0.15,
    metric='euclidean'
)
cluster_labels = clusterer.fit_predict(embeddings)

# 6. Step 4: Metadata Callback (Retrieving the original Attacker IPs!)
flagged_anomalies = []
print("\n===== ANALYSIS RESULTS =====")

for idx, label in enumerate(cluster_labels):
    template_str = unique_templates[idx]
    matching_logs = template_to_raw_logs[template_str]
    
    # HDBSCAN assigns '-1' to points that sit in low-density space (anomalies!)
    if label == -1:
        print(f"🚨 ANOMALOUS TEMPLATE IDENTIFIED (Size: {len(matching_logs)} logs):")
        print(f"   Template: {template_str}")
        
        # Pull the matching raw logs out of our dictionary
        for raw_log in matching_logs:
            raw_log["anomaly_reason"] = f"Matches semantically anomalous template: {template_str}"
            flagged_anomalies.append(raw_log)
            print(f"   ↳ Attacker IP: {raw_log['ip']} | Timestamp: {raw_log['timestamp']} | Original Path: {raw_log['path']}")
        print()

# Save the true anomalies with unmasked metadata to JSON
OUTPUT_ANOMALIES.parent.mkdir(exist_ok=True)
with open(OUTPUT_ANOMALIES, "w", encoding="utf-8") as out:
    json.dump(flagged_anomalies, out, ensure_ascii=False, indent=2)

print(f"✓ Triage complete. Saved {len(flagged_anomalies)} true anomalous logs to '{OUTPUT_ANOMALIES}'.")
