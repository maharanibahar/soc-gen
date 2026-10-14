import time
import traceback
import normalize_wazuh_logs
import retrieve_events
import correlate_events
import reconstruct_event
import cluster_events
import incident_context
import pseudomyze
import llm_gen
import demap_report
import logging


logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STAGES = [
    ("normalize", normalize_wazuh_logs.run),
    ("retrieve", retrieve_events.run),
    ("correlate", correlate_events.run),
    ("reconstruct", reconstruct_event.run),
    ("cluster", cluster_events.run),
    ("context", incident_context.run),
    ("pseudonymize", pseudomyze.run),
    ("generate report", llm_gen.run),
    ("de-map report", demap_report.run),
]

def run():
    for name, stages in STAGES:
        print(f"\n{'=' * 60}\n▶ {name}\n{'=' * 60}")
        start = time.time()
        try:
            stages()
        except Exception:
            print(f"✖ stage failed: {name}")
            traceback.print_exc()
            raise
        print(f"✓ {name}  ({time.time() - start:.1f}s)")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
