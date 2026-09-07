import json
import numpy as np
from sentence_transformers import SentenceTransformer
import hdbscan

# 1. Load your normalized logs
with open("normalized_logs.json", "r") as f:
    logs = json.load(f)

# Reconstruct a slightly detailed string representing the event context
# We include Method, Path, Status, and Response Size for semantic analysis
log_strings = [
    f"{log['method']} {log['path']} {log['protocol']} {log['status']} {log['response_size']}"
    for log in logs
]

print(f"Generating semantic embeddings for {len(logs)} logs...")
# 2. Use a lightweight, fast, security-optimized Sentence-BERT model
model = SentenceTransformer("all-MiniLM-L6-v2")
embeddings = model.encode(log_strings, show_progress_bar=True)

print("Running HDBSCAN density clustering...")
# 3. Configure HDBSCAN
# min_cluster_size: Minimum size of a cluster of "normal" behavior (e.g., at least 15 logs)
# min_samples: Controls how conservative the noise selection is
clusterer = hdbscan.HDBSCAN(min_cluster_size=15, min_samples=5, gen_min_span_tree=True)
cluster_labels = clusterer.fit_predict(embeddings)

# 4. Extract the Noise (Cluster ID -1 is isolated by HDBSCAN as outliers)
anomalies = []
for idx, label in enumerate(cluster_labels):
    if label == -1:  # -1 represents HDBSCAN noise
        logs[idx]["anomaly_reason"] = "Semantic density outlier (HDBSCAN Noise)"
        anomalies.append(logs[idx])

print(f"\n=== SEMANTIC TRIAGE COMPLETE ===")
print(f"Successfully grouped routine traffic into {len(set(cluster_labels)) - 1} dense benign clusters.")
print(f"Isolated {len(anomalies)} semantic outliers (Noise points) from your dataset.")

# Save the isolated anomalies directly for Llama 3.1 analysis!
with open("flagged_anomalies.json", "w") as out:
    json.dump(anomalies, out, indent=2)

print("Outliers saved to 'flagged_anomalies.json'.")
