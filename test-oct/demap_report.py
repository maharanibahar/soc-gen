import json
from pathlib import Path
import logging
log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
MAP_FILE = BASE_DIR / "data" / "output" / "pseudonym_map.json"
REPORT_MD = BASE_DIR / "data" / "output" / "generated_report.md"
OUT_MD = BASE_DIR / "data" / "output" / "generated_report_demapped_2.md"


def run():
    real_to_label = json.loads(MAP_FILE.read_text(encoding="utf-8"))
    label_to_real = {label: real for real, label in real_to_label.items()}
    text = REPORT_MD.read_text(encoding="utf-8")
    
    for label, real in sorted(label_to_real.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(label, real)
    
    OUT_MD.write_text(text, encoding="utf-8")
    logging.info("wrote: %s", OUT_MD)

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    run()
