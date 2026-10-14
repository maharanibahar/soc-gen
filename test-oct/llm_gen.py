from openai import OpenAI
import json
import re
import os
from datetime import datetime, timezone
from pathlib import Path
from collections import Counter, defaultdict
import networkx as nx
import yaml
import json
from pathlib import Path
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import uuid
from dotenv import load_dotenv
import subprocess




BASE_DIR = Path(__file__).resolve().parent

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / "api_key.env")

CONTEXT = BASE_DIR / "data" / "output" / "incident_context_pseudo.json"
REPORT_MD = BASE_DIR / "data" / "output" / "generated_report.md"
REPORT_JSON = BASE_DIR / "data" / "output" / "generated_report.json"

MODEL = os.environ.get(
    "OPENAI_MODEL",
    "opencode-go/deepseek-v4.1-flash",
)

client = OpenAI(
    api_key=os.environ["OPENAI_API_KEY"],
    base_url=os.environ.get(
        "OPENAI_BASE_URL",
        "https://opencode.ai/zen/go/v1",
    ),
    default_headers={
        "x-opencode-session": str(uuid.uuid4()),
        "User-Agent": "my-python-agent/1.0",
    },
)

SYSTEM = """You are a SOC analyst writing an evidence-grounded incident report.
Rules:
- Use ONLY the incident context below. Never invent facts.
- Cite event_id(s) for every factual claim, inline like [evt <event_id>].
- Keep observed, inferred, and unknown strictly separate.
- All times are UTC.
- Never turn an attempt, a Wazuh ATT&CK classification, or a file creation
  into a confirmed compromise."""

SECTIONS = [
    "Executive Summary", "Investigation Scope", "Timeline", "Observed Activity",
    "Entities", "ATT&CK Techniques", "Supporting Evidence",
    "Weakening/Missing Evidence", "Uncertainty", "Impact", "Conclusion",
]

# tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
# model = AutoModelForCausalLM.from_pretrained(MODEL_NAME, torch_dtype="auto", device_map="auto")


def build_user_prompt(context):
    return (
        "Write the report with exactly these sections: " + ", ".join(SECTIONS) + ".\n\n"
        "INCIDENT CONTEXT:\n" + json.dumps(context, ensure_ascii=False, indent=2)
    )



def call_llm(system, user):
    prompt = (
        f"SYSTEM INSTRUCTIONS:\n{system}\n\n"
        f"USER REQUEST:\n{user}"
    )

    try:
        result = subprocess.run(
            [
                "opencode",
                "run",
                "--model", MODEL,
                "--format", "default",
                prompt,
            ],
            capture_output=True,
            text=True,
            timeout=900,  # 15 minutes
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        partial_output = exc.stdout or ""
        if isinstance(partial_output, bytes):
            partial_output = partial_output.decode(
                "utf-8", errors="replace"
            )

        raise RuntimeError(
            "OpenCode timed out after 15 minutes.\n"
            f"Partial output:\n{partial_output}"
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"OpenCode exited with code {result.returncode}.\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    return result.stdout.strip()


def main():
    context = json.loads(CONTEXT.read_text(encoding="utf-8"))
    user_prompt = build_user_prompt(context)
    report = call_llm(SYSTEM, user_prompt)

    REPORT_MD.write_text(report, encoding="utf-8")
    REPORT_JSON.write_text(
        json.dumps(
            {"model": MODEL, "system": SYSTEM, "user_prompt": user_prompt, "report": report},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    print("wrote:", REPORT_MD)


if __name__ == "__main__":
    main()

# def load_jsonl(path):
#     rows = []
#     with Path(path).open(encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()
#             if line:
#                 rows.append(json.loads(line))
#     return rows


# def parse_ts(ts):
#     if not ts:
#         return None
#     dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
#     return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# def call_llm(system_prompt, user_prompt):
#     try:
#         response = client.chat.completions.create(
#             model = MODEL,
#             max_tokens=4000,
#             messages=[
#                 {"role": "system", 
#                  "content": system_prompt},
#                  {
#                     "role": "user",
#                     "content": user_prompt}
#             ]
#         )
        
#         print(f"[Debug] Response type: {type(response)}")
        
#         output = response.choices[0].message.content
        
#         if not output:
#             print("LLM Error: Empty response from LLM")
#             return None
        
#         report_match = re.search(r'<post_mortem>(.*?)</post_mortem>', output, re.DOTALL)
#         if report_match:
#             report_text = report_match.group(1).strip()
#         else:
#             report_text = output.strip()

#         date_match = re.search(r'<attack_date>(.*?)</attack_date>', output)
#         if date_match:
#             raw_date = date_match.group(1).strip()
#             attack_date = re.sub(r'[<>:"/\\|?*]', '', raw_date)
#         else:
#             attack_date = "Unknown_Date"
        
#         return report_text, attack_date
    
#     except Exception as e:
#         print(f"LLM Error: {e}")
#         import traceback
#         traceback.print_exc()
#         return None

# def compress_logs(cluster):
#     sample = cluster[:20]
#     events = []
#     for e in sample:
#         timestamp = e.get('timestamp', 'N/A')
#         log_source = e.get('log_source', 'N/A')
#         source_ip = e.get('source_ip', 'N/A')

#         http_method = e.get('http_method', 'N/A')
#         http_uri = e.get('http_uri', 'N/A')
#         http_status = e.get('http_status', 'N/A')
#         user_agent = e.get('user_agent', 'N/A')

#         response_size = e.get('response_size', 'N/A')

#         modsec_rule_id = e.get('modsec_rule_id', 'N/A')
#         modsec_msg = e.get('modsec_msg', 'N/A')
        
#         waf_action = e.get('waf_action', 'N/A')
        
#         event_str = f"[{timestamp}] source={log_source} | ip={source_ip} | "
#         event_str += f"{http_method} {http_uri} | status={http_status} | "
#         event_str += f"ua={user_agent} | response_size={response_size} | "
#         event_str += f"modsec_rule={modsec_rule_id} | modsec_msg={modsec_msg} | "
#         event_str += f"waf_action={waf_action}"
        
#         events.append(event_str)
#     return "\n".join(events)

# def create_postmortem(cluster, cluster_filename):
#     logs = compress_logs(cluster)

#     system_prompt = """You are a Senior SOC Analyst. Transform raw security logs into a public-facing incident report written as a professional article.

# CRITICAL FORMATTING RULES:
# - Use markdown headings: ## for sections, ### for timestamps
# - Write in plain prose with clear section headings on separate lines
# - Use paragraph breaks to separate ideas
# - Write for a general audience - explain technical concepts in simple terms
# - Focus on storytelling and narrative flow
# - Be transparent and blameless

# Writing style:
# - Professional yet accessible to non-technical readers
# - Educational - explain what happened and why it matters
# - Narrative-driven - tell the story chronologically
# - Transparent about what went wrong and what we're doing to fix it

# Be factual and evidence-based. Do not speculate or invent missing data."""

#     user_prompt = f"""Your Task

# Analyze the security logs below and generate a public-facing incident report written as a professional article.

# Phase 1: Chain of Thought Evidence Analysis

# Use <thought_process> tags to analyze:
# 1. What was the attack and what was the attacker trying to achieve?
# 2. Create a chronological timeline with exact timestamps
# 3. Identify the root cause, what is the target? Why did this happen? What vulernabilities that led this happened?
# 4. What was the impact?
# 5. How did our defenses perform?
# 6. What evidence supports your analysis?

# Phase 2: Generate Report

# Output format:
# 1. Attack date in <attack_date> tags (YYYY-MM-DD)
# 2. Complete report in <post_mortem> tags

# Report Structure:

# Write each section heading on its own line, followed by narrative paragraphs.

# Executive Summary
# Write a summary paragraph explaining what happened, when it happened, and the overall impact. Write for a general audience who may not understand technical details.

# Background
# Explain in 2 short paragraphs, in simple terms what type of attack this was and how it works. Describe what systems were affected and what security measures we have in place. Make it understandable for someone without a security background.

# Incident Timeline
# Use exact headers in 'YYYY Month DD HH:MM UTC' format on their own line for each major event. Follow each timestamp with a narrative paragraph explaining the attacker's actions and the system's response as a continuous story.

# Root Cause Analysis
# Explain exactly how the attack succeeded. Identify the Target, the specific Trigger (the payload or exploit used), and vulnerabilities or gaps allowed this to happen. Weave these technical details into a readable explanation rather than a dry checklist.


# Learnings 
# In a short paragraph, conclude with what we've learned from this incident and our commitment to improving our security. Acknowledge the gaps we've identified and express our commitment to transparency.

# End with:
# Report Date: [date]
# Report Author: Security Operations Team

# Writing Guidelines:
# 1. Write in complete paragraphs, not bullet points
# 2. Explain technical terms in simple language
# 3. Tell a story - make it engaging and readable
# 4. Be honest about what went wrong
# 5. Write for a general audience, not security experts
# 6. Use clear, simple language

# Logs to Analyze:

# {logs}

# Begin your analysis in <thought_process> tags, then output the attack date in <attack_date> tags, followed by the complete report in <post_mortem> tags."""

#     print(f"[System] Requesting CoT analysis for {cluster_filename}...")
    
#     result = call_llm(system_prompt, user_prompt)
#     if result is None:
#         print(f"[System] LLM call failed for {cluster_filename}. No report generated.")
#         return
    
#     postmortem_text, attack_date = result
    
#     os.makedirs(POSTMORTEM_DIR, exist_ok=True)
    
#     cluster_base = cluster_filename.replace(".json", "")
#     filename = os.path.join(POSTMORTEM_DIR, f"{attack_date}_{cluster_base}_Post_Mortem.md")
    
#     with open(filename, 'w', encoding='utf-8') as f:
#         f.write(postmortem_text)
    
#     print(f"[OK] Post-Mortem saved: {os.path.basename(filename)}")

# def run_pipeline():
#     start_time = time.time()
#     clusters = load_all_clusters()
    
#     if not clusters:
#         print("No clusters found. Run clustering.py first.")
#         return
    
#     print(f"Found {len(clusters)} clusters\n")
#     print("=" * 60)
    
#     for idx, (filename, data) in enumerate(clusters, 1):
#         print(f"\n[{idx}/{len(clusters)}] Processing: {filename}")
#         print(f"  Events: {len(data)}")
#         create_postmortem(data, filename)
    
#     end_time = time.time()
#     duration = end_time - start_time
    
#     print("\n" + "=" * 60)
#     print(f"Pipeline complete! Generated {len(clusters)} post-mortems in {POSTMORTEM_DIR}/")
#     print(f"Total time: {duration:.2f} seconds ({duration/60:.2f} minutes)")

# if __name__ == "__main__":
#     run_pipeline()