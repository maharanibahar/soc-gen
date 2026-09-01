import os
import re
import csv
import glob
import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_LOG = BASE_DIR / "output"
OUTPUT_LOG.mkdir(exist_ok=True)

csv_files = glob.glob("dataset/*.csv")
csv_file = csv_files[0]

print(f"Reading : {csv_file}")
total_lines = sum(1 for _ in open(csv_file))
print(f"Total logs: {total_lines}")


normalize = re.compile(
    r'(?P<ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'-\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s*'
    r'"(?P<user_agent>[^"]*)"\s*'
    r'"(?P<forwarded_for>[^"]*)"\s*'
    r'"?(?P<extra>[^"]*)"?'
)

with open(csv_file, newline="", encoding="utf-8") as f:
    reader = csv.reader(f)
    output = []
    matched = 0
    failed = 0

    for i, row in enumerate(reader):
        line = " ".join(row).strip()

        match = normalize.match(line)

        if match:
            data = match.groupdict()
            data["status"] = int(data["status"])
            data["response_size"] = int(data.pop("size"))
            output.append(data)
            matched += 1

        else:
            failed += 1
            if failed <=5:
                print(f"failed normalize logs {i}: {line[:100]}")

print(f"Matched logs : {matched}")
print(f"Failed logs : {failed}")

output_file = OUTPUT_LOG / "normalized_logs.json"

with open(output_file, "w", encoding="utf-8") as f:
    json.dump(output, f, ensure_ascii=False, indent=2)