# INC-001 — Evidence-Grounded Incident Report

## Executive Summary

Within the investigated window, host **HOST_1** was targeted by web attacks originating from at least three distinct client IPs recorded as actors (`IP_1`, `IP_2`, `IP_3`), each associated with the `initial_access` phase. The earliest successful attack selected as the investigation seed is event `1778008682.44620403` ("A web attack returned code 200 (success)", actor `IP_2`) [evt 1778008682.44620403]. Wazuh rule classifications in the context map these events to ATT&CK techniques including Exploit Public-Facing Application (T1190) [evt 1778008682.44620403] and Web Shell (T1505.003) [evt 1778092068.26477724]. Multiple file-creation events in the web directory were recorded, including files flagged as "possible web shell scripting file" [evt 1778090134.16543539]. **Observed** activity is limited to web attack attempts/responses, integrity and file-creation telemetry, and Wazuh rule classifications. **No compromise is confirmed**: there is no process-execution telemetry after any shell drop, no outbound connection evidence, and no authentication evidence tying access to a session (per `missing_evidence`). The campaign linkage between the three IPs is not proven.

## Investigation Scope

- **Incident ID:** INC-001.
- **Host in scope:** `HOST_1`.
- **Window:** start `2026-05-05TIP_4+07:00`, end `2026-05-09TIP_5+07:00` (reproduced verbatim; the context states all times are UTC, while these scope bounds display a `+07:00` offset — see Uncertainty).
- **Seed event:** `1778008682.44620403` [evt 1778008682.44620403].
- **Seed selection method:** `earliest_successful_attack`; rule group `attack`; required `http_200 = true` [evt 1778008682.44620403].
- **Data drawn on:** the `attack_techniques`, `timeline`, `actors`, `targets`, `supporting_evidence`, `weakening_evidence`, `missing_evidence`, `not_observed`, and `unknown` fields of the incident context.

The timeline buckets sum to 1,257 events across six phases: `other` (16), `file_change` (510), `recon` (333), `attack` (279), `initial_access` (11), `webshell` (108).

## Timeline

All times as provided in the context (context states UTC; source strings contain redaction placeholders reproduced verbatim).

| Phase | Count | First | Last |
|---|---|---|---|
| other | 16 | `2026-05-04TIP_6.649Z` [evt 1777914252.1808335] | `2026-05-07TIP_7.669Z` |
| file_change | 510 | `2026-05-04TIP_12.487Z` [evt 1777914632.4377665] | `2026-05-07TIP_13.665Z` |
| recon | 333 | `2026-05-04TIP_16.668Z` [evt 1777915124.6606601] | `2026-05-07TIP_17.279Z` |
| attack | 279 | `2026-05-05TIP_23.228Z` [evt 1778008680.44572392] | `2026-05-05TIP_9.376Z` |
| initial_access | 11 | `2026-05-05TIP_24.321Z` [evt 1778008682.44620403] | `2026-05-09TIP_25.959Z` |
| webshell | 108 | `2026-05-06TIP_30.534Z` [evt 1778090134.16543539] | `2026-05-07TIP_31.910Z` |

Notable ordering (observed, per phase examples): reconnaissance (multiple web 400 errors from `IP_18`) [evt 1777915124.6606601] precedes the `attack` phase (web server 400 errors from `IP_2`) [evt 1778008680.44572392], which precedes the first `initial_access` 200 response [evt 1778008682.44620403]. File-change and webshell file-creation events continue across `2026-05-04` to `2026-05-07` [evt 1777914632.4377665] [evt 1778090134.16543539]. The final `initial_access` event falls at the end of the window on `2026-05-09` [evt 1778342465.487206552].

## Observed Activity

**Observed only — no inference of success beyond the stated detection.**

Reconnaissance:
- Multiple web server 400 error codes from the same source IP (`IP_18`) [evt 1777915124.6606601] [evt 1777915136.6617139] [evt 1777915146.6708904] [evt 1777915156.6919665] [evt 1777915168.6987270].

Attack phase:
- Web server 400 error codes attributed to `IP_2` [evt 1778008680.44572392] [evt 1778008680.44573042] [evt 1778008680.44573648].

Initial access (HTTP 200 recorded):
- "A web attack returned code 200 (success)" from `IP_2` [evt 1778008682.44620403] [evt 1778008688.44988854].
- SQL injection attempt from `IP_2` [evt 1778008686.44929936].
- "A web attack returned code 200 (success)" from `IP_3` [evt 1778090552.18608068].
- "A web attack returned code 200 (success)" from `IP_1`, followed by six additional `initial_access` events from `IP_1` through the end of the window [evt 1778342465.487206552] [evt 1778342621.488485421] [evt 1778343029.492450524] [evt 1778343047.492535763] [evt 1778343090.493039437] [evt 1778343213.494091275] [evt 1778343261.494620040].

File changes:
- Integrity checksum changed events [evt 1777914632.4377665] [evt 1777914632.4378875] [evt 1777942225.153270257].
- File creation in web directory, e.g., `FILE_234` [evt 1777955366.224942723], `FILE_240` [evt 1777955366.224943387], `FILE_235` [evt 1777955366.224944050], and many subsequent files [evt 1777955367.224944713].

Webshell-linked file creation:
- "Possible web shell scripting file (FILE_372) created" [evt 1778090134.16543539]; similarly `FILE_375` [evt 1778090240.17102030], `FILE_377` [evt 1778090273.17162032], `FILE_379` [evt 1778090290.17343120], `FILE_381` [evt 1778090313.17408976].

Other/routine:
- Listened ports status (netstat) changed [evt 1777914252.1808335] [evt 1778000659.1581390] [evt 1778087066.1557128].
- Web server 500 error code [evt 1778008690.45051475].
- Dpkg (Debian Package) half configured [evt 1778107232.102488788].

**Inferred (clearly labelled):** The phase ordering and shared IP reuse are consistent with a reconnaissance-to-attack-to-follow-on-file-drop sequence, but this is an inference from event ordering and rule phases, not a confirmed causal chain. The context's `linkage_summary` counts structural links (e.g., `PRECEDES` 1562, `SAME_URL_PATH` 1953, `SAME_RULE` 1614) rather than proving a single actor.

## Entities

Actors (all listed under `initial_access`):
- `IP_1` — 7 events [evt 1778342465.487206552], [evt 1778342621.488485421], [evt 1778343029.492450524], [evt 1778343047.492535763], [evt 1778343090.493039437], [evt 1778343213.494091275], [evt 1778343261.494620040].
- `IP_2` — 3 events [evt 1778008682.44620403], [evt 1778008686.44929936], [evt 1778008688.44988854].
- `IP_3` — 1 event [evt 1778090552.18608068].
- `IP_18` — appears as actor in reconnaissance examples [evt 1777915124.6606601]; not listed among the three `actors` entries.

Hosts:
- `HOST_1` (sole host in `targets.hosts`).

Files:
- `FILE_1` through `FILE_472` are listed as targets. Representative creation events cite specific files such as `FILE_234` [evt 1777955366.224942723] and `FILE_372` [evt 1778090134.16543539].

URLs:
- `URL_1` through `URL_566` are listed as targets, including several non-generic entries that appear as web request parameters:
  - `/FQDN_86?rest_route=%2Fessential-blocks%2Fv1%2Fproducts&is_frontend=true&attributes={\"__file\":\"/etc%2fpasswd\"}` — references `/etc/passwd` (context list only; no event_id mapped).
  - `URL_300?action=likebtn_prx&likebtn_q=aHR0cDovL2xpa2VidG4uY29tLm9hc3QubWU=` — contains a base64 parameter (context list only; no event_id mapped).
  - `FILE_591/?callback={\"class\":\"LP_Debug\",\"method\":\"var_dump\"}&args=...` — references a `var_dump` callback (context list only; no event_id mapped).
  (These are presented as members of the target URL set; the context provides no event_id linkage for them.)

## ATT&CK Techniques

All techniques are `source: wazuh_rule` — i.e., **detection classifications, not confirmed adversary behavior**.

| Technique | Name | Tactic | Representative evidence |
|---|---|---|---|
| T1565.001 | Stored Data Manipulation | Impact | [evt 1777914632.4377665], [evt 1777942225.153270257] |
| T1595.002 | Vulnerability Scanning | Reconnaissance | [evt 1777915124.6606601], [evt 1777958814.247336072] |
| T1105 | Ingress Tool Transfer | Command and Control | [evt 1777955366.224942723], [evt 1778046247.283230917] |
| T1505 | Server Software Component | Persistence | [evt 1777955366.224942723], [evt 1778090134.16543539] |
| T1190 | Exploit Public-Facing Application | Initial Access | [evt 1778008682.44620403], [evt 1778090552.18608068], [evt 1778342465.487206552] |
| T1055 | Process Injection | Defense Evasion | [evt 1778008686.44929936], [evt 1778008690.45042729] |
| T1083 | File and Directory Discovery | Privilege Escalation | [evt 1778008690.45042729], [evt 1778008690.45054819] |
| T1070.004 | File Deletion | Defense Evasion | [evt 1778054163.353987772], [evt 1778090108.16418199] |
| T1485 | Data Destruction | Impact | [evt 1778054163.353987772], [evt 1778155132.366870909] |
| T1505.003 | Web Shell | Persistence | [evt 1778092068.26477724], [evt 1778092094.26736090] |

## Supporting Evidence

The **strongest observed** items are:
- HTTP 200 responses on web attacks from `IP_2` [evt 1778008682.44620403] [evt 1778008688.44988854], `IP_3` [evt 1778090552.18608068], and `IP_1` [evt 1778342465.487206552]. These establish that requests classified as attacks returned a success code; they do **not** establish code execution or compromise.
- SQL injection attempt [evt 1778008686.44929936].
- File creation in the web directory, including `FILE_234` [evt 1777955366.224942723], `FILE_240` [evt 1777955366.224943387], `FILE_235` [evt 1777955366.224944050], and the wider set through [evt 1777955369.225009181]. The `supporting_evidence` block lists these as `[File creation on web directory]` statements.
- Possible web shell scripting files: `FILE_372` [evt 1778090134.16543539], `FILE_375` [evt 1778090240.17102030], `FILE_377` [evt 1778090273.17162032], `FILE_379` [evt 1778090290.17343120], `FILE_381` [evt 1778090313.17408976].
- Integrity checksum changed events on `HOST_1` file set [evt 1777914632.4377665] [evt 1777942225.153270257].

## Weakening/Missing Evidence

Weakening evidence (from context):
- Initial access and file changes are **not directly linked** in telemetry — no shared actor/session observed.
- The candidate set includes 16 routine/`other` events that may be background traffic [evt 1777914252.1808335] [evt 1778107232.102488788].
- Attack indicators span 3 distinct client IPs; campaign linkage between them is **not proven** (`IP_1`, `IP_2`, `IP_3`).

Missing evidence (from context):
- Process execution telemetry after any shell drop.
- Outbound network connections following shell interaction.
- Web server logs outside the ingested window.
- Authentication logs tying the initial access to a session.

Not observed (from context):
- A successful response (2xx) **from the dropped shell endpoints** (distinct from the 2xx responses to the attack requests themselves, e.g., [evt 1778008682.44620403]).
- Confirmed persistence mechanism.

## Uncertainty

- **Timestamp formatting:** scope bounds and timeline times are reproduced verbatim and contain redaction placeholders (e.g., `TIP_4`); the scope bounds show a `+07:00` offset while the reporting standard is UTC. Exact normalized UTC values cannot be independently confirmed from the provided strings.
- **Attribution:** whether `IP_1`, `IP_2`, and `IP_3` belong to one campaign or operator is unknown; linkage is not proven.
- **Nature of files:** file-creation events and "possible web shell" classifications indicate file creation and Wazuh rule matching respectively; they do not establish file contents, intent, or that the files were ever executed.
- **Attribution of `IP_18`:** `IP_18` appears in reconnaissance examples but is not in the `actors` list; its relationship to the three actors is unproven.
- **Wazuh classifications:** every ATT&CK mapping is `source: wazuh_rule`; these are detection labels, not confirmed techniques.

Unknown (from context):
- Whether commands were executed through the dropped shells.
- Whether credentials from `wp_users` were used.
- Whether data was exfiltrated.
- Whether the server was fully compromised.

## Impact

Based only on the provided context:
- **Observed:** Attack-classified requests against `HOST_1` received HTTP 200 responses [evt 1778008682.44620403] [evt 1778090552.18608068] [evt 1778342465.487206552]; file-creation and integrity-change events were recorded in the web directory and on the host [evt 1777955366.224942723] [evt 1777914632.4377665].
- **Inferred:** If the created files were functional, the Wazuh-classified persistence techniques (T1505, T1505.003) could imply a durable foothold [evt 1778090134.16543539] [evt 1778092094.26736090]. This remains unverified.
- **Unknown:** Actual impact — code execution, credential use, exfiltration, and full compromise are all unconfirmed.

Because process execution, outbound C2, and authentication evidence are all missing, **no confirmed loss, data destruction, or compromise is established**; the T1485/T1070.004 classifications are rule labels without corroborating artifacts.

## Conclusion

Within the investigated window, `HOST_1` was targeted by web attacks from `IP_1`, `IP_2`, and `IP_3`, with several attack requests returning HTTP 200 [evt 1778008682.44620403] [evt 1778090552.18608068] [evt 1778342465.487206552]. Wazuh classified the activity across ten ATT&CK techniques spanning Reconnaissance, Initial Access, Persistence, Defense Evasion, Privilege Escalation, Command and Control, and Impact, and recorded file creation in the web directory including files flagged as possible web shells [evt 1778090134.16543539]. However, the evidence does not establish a confirmed compromise: there is no process-execution, outbound-connection, or authentication telemetry; shell endpoints were never observed returning 2xx; campaign linkage among the three IPs is unproven; and the 16 `other` events may be background noise. Recommended next-step evidence (not present here) would be process execution, egress connections, and authentication logs, which are explicitly listed as missing.