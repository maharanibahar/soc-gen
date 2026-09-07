import os
import re
import csv
import glob
import json
from datetime import datetime, timezone
from pathlib import Path

# Setup BASE_DIR and output folder
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_LOG = BASE_DIR / "output"
OUTPUT_LOG.mkdir(exist_ok=True)

csv_files = glob.glob("input/*.csv")

#webserver log regex pattern
regex = re.compile(
    r'(?P<ip>[\d.]+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s*'
    r'"(?P<user_agent>[^"]*)"\s*'
    r'"(?P<forwarded_for>[^"]*)"\s*'
    r'"?(?P<extra>[^"]*)"?'
)

#timestamp to UTC format
def to_utc(original_timestamp: str):
    if not original_timestamp:
        return None
    original_timestamp = original_timestamp.strip()
    if not original_timestamp:
        return None

    #from ISO 8601 format
    try:
        dt = datetime.fromisoformat(original_timestamp.replace("+00:00", "Z"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec='seconds').replace("+00:00", "Z")
    except ValueError:
        pass
    

    # from @ style
   if "@" in original_timestamp:
        cleaned = original_timestamp.replace("@", "").replace("  ", " ").strip()
        for fmt in ("%b %d, %Y %H:%M:%S.%f", "%b %d, %Y %H:%M:%S"):
            try:
                dt = datetime.strptime(cleaned, fmt).replace(tzinfo=timezone.utc)
                return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
            except ValueError:
                continue
    try:
        dt = datetime.strptime(original_timestamp, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except ValueError:
        pass

    #from bare date
    try:
        dt = datetime.strptime(original_timestamp, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt.isoformat(timespec="seconds").replace("+00:00", "Z")
    except ValueError:
        pass
 
    return None 
output = []

for csv_file in csv_files:
    filename = os.path.basename(csv_file).lower()
    print(f"Reading : {csv_file}")
    
    with open(csv_file, newline="", encoding="utf-8") as f:
        first_line = f.readline()
        f.seek(0)
        
        reader = csv.reader(f)
        
        # Wazuh File Integrity Monitoring (FIM) Log
        if "syscheck.path" in first_line or "rule.id" in first_line:
            print("→ Detected Schema: Wazuh File Integrity Monitoring (FIM)")
            next(reader) 
            
            for row in reader:
                if not row or len(row) < 7:
                    continue

                row_timestamp, agent_name, file_path, event_action, rule_desc, rule_level, rule_id = row[:7]
                row_timestamp = row_timestamp.strip()
                if not row_timestamp:
                    continue
 
                timestamp_utc = to_utc(row_timestamp)
 
                output.append({
                    "timestamp": timestamp_utc,
                    "source_log": "wazuh_fim",
                    "ip": None,  
                    "signature": f"Wazuh_FIM_Rule_{rule_id} {event_action} on {file_path} ({rule_desc})",
                    "details": {
                        "agent_name": agent_name,
                        "file_path": file_path,
                        "action": event_action,
                        "description": rule_desc,
                        "rule_level": int(rule_level) if rule_level.isdigit() else 0,
                        "rule_id": int(rule_id) if rule_id.isdigit() else 0
                    }
                })
                
        #CYFIRMA Cyber Threat Intelligence (CTI) Log
       
        elif "User ID" in first_line or "Stealer Name" in first_line:
            print("→ Detected Schema: CYFIRMA Cyber Threat Intelligence (CTI)")
            next(reader)
            
            for row in reader:
                if not row or len(row) < 8: 
                    continue
                
                user_id, source_url, row_timestamp, breach_date, antivirus, stealer, stealer_name, stealer_path = row[:8]
                row_timestamp = row_timestamp.strip()
                if not row_timestamp:
                    continue
 
                timestamp_utc = to_utc(row_timestamp)
 
                output.append({
                    "timestamp": timestamp_utc,
                    "source_log": "cti_cyfirma",
                    "ip": None,  
                    "signature": f"CYFIRMA_CTI_ALERT Account {user_id} exfiltrated via {stealer_name} malware",
                    "details": {
                        "user_id": user_id,
                        "source_url": source_url,
                        "breach_date": breach_date,
                        "antivirus": antivirus,
                        "stealer": stealer,
                        "stealer_name": stealer_name,
                        "stealer_path": stealer_path,
                        "timestamp_raw": row_timestamp,
                    }
                })

        # Web server Logs
        else:
            print("→ Detected Schema: Web Server Logs")
            matched = 0
            failed = 0
            
            for i, row_list in enumerate(reader):
                line = " ".join(row_list).strip()
                if not line:
                    continue  

                match = regex.match(line)

              if match:
                    data = match.groupdict()
 
                    timestamp_utc = to_utc(data["timestamp"])
                    data["timestamp"] = timestamp_utc
 
                    data["status"] = int(data["status"])
                    size_raw = data.pop("size")
                    data["response_size"] = None if size_raw == "-" else int(size_raw)
 
                    output.append({
                        "timestamp": timestamp_utc,
                        "source_log": "web_server",
                        "ip": data["ip"],
                        "signature": f"{data['method']} {data['path']} {data['protocol']} "
                                     f"{data['status']} {data['response_size']}",
                        "details": data
                    })
                    matched += 1
                else:
                    failed += 1
                    if failed <= 5:
                        print(f"failed normalize logs {i}: {line[:100]}")
 
            print(f"Matched logs : {matched}")
            print(f"Failed logs  : {failed}")

#sort all logs by timestamp
output.sort(key=lambda x: x["timestamp"])

output_file = OUTPUT_LOG / "normalized__multiple_logs.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(output, f, ensure_ascii=False, indent=2)

print(f"\n✓ Completed! Successfully saved {len(output)} clean events to {output_file}")