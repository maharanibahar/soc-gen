import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MAP_FILE = BASE_DIR / "data" / "output" / "pseudonym_map.json"
REPORT_MD = BASE_DIR / "data" / "output" / "generated_report.md"
OUT_MD = BASE_DIR / "data" / "output" / "generated_report_demapped.md"

# map is stored as {real: label}; we need {label: real}
real_to_label = json.loads(MAP_FILE.read_text(encoding="utf-8"))
label_to_real = {label: real for real, label in real_to_label.items()}

text = REPORT_MD.read_text(encoding="utf-8")

# replace the LONGEST labels first so IP_10 isn't clobbered by IP_1
for label, real in sorted(label_to_real.items(), key=lambda kv: -len(kv[0])):
    text = text.replace(label, real)

OUT_MD.write_text(text, encoding="utf-8")
print("wrote:", OUT_MD)
