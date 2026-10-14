# Incident Report — INC-001

## Executive Summary

Between 2026-05-04 and 2026-05-09, host `HOST_1` generated 1,257 events across six identified phases (recon, attack, initial_access, file_change, webshell, other) [evt 1777914252.1808335]. The investigation seed was the earliest successful attack event — a web attack returning HTTP 200 — `1778008682.44620403` [evt 1778008682.44620403]. Three source IPs (`IP_1`, `IP_2`, `IP_3`) were associated with `initial_access` events [evt 1778008682.44620403, evt 1778090552.18608068, evt 1778342465.487206552]. File activity includes "[File creation on web directory]" events [evt 1777955366.224942723], webshell file-creation alerts [evt 1778090134.16543539], integrity checksum changes [evt 1777914632.4377665], and file-deletion/data-destruction indicators [evt 1778054163.353987772].

No compromise is confirmed in this report. All attack classifications below originate from Wazuh rule classifications, and file creation alone is not evidence of execution or persistence.

## Investigation Scope

- Incident ID: `INC-001`
- Host in scope: `HOST_1`
- Window: `2026-05-05TIP_4+07:00` to `2026-05-09TIP_5+07:00` (as recorded in context; all times stated here are UTC per reporting convention)
- Seed event: `1778008682.44620403`
- Seed selection method: `earliest_successful_attack`, rule group `attack`, requiring HTTP 200 (success) [evt 1778008682.44620403]
- Observed pre-window activity begins 2026-05-04 [evt 1777914252.1808335]

## Timeline

| Phase | Count | First | Last | Representative event(s) |
|---|---|---|---|---|
| other | 16 | 2026-05-04TIP_6.649Z | 2026-05-07TIP_7.669Z | netstat port change [evt 1777914252.1808335]; web 500 error [evt 1778008690.45051475]; dpkg half configured [evt 1778107232.102488788] |
| file_change | 510 | 2026-05-04TIP_12.487Z | 2026-05-07TIP_13.665Z | integrity checksum changed [evt 1777914632.4377665, evt 1777914632.4378875]; web-dir file creation [evt 1777955366.224942723] |
| recon | 333 | 2026-05-04TIP_16.668Z | 2026-05-07TIP_17.279Z | multiple 400s from same source [evt 1777915124.6606601, evt 1777915136.6617139] |
| attack | 279 | 2026-05-05TIP_23.228Z | 2026-05-05TIP_9.376Z | web server 400 error codes from IP_2 [evt 1778008680.44572392, evt 1778008680.44573042] |
| initial_access | 11 | 2026-05-05TIP_24.321Z | 2026-05-09TIP_25.959Z | HTTP 200 web attack [evt 1778008682.44620403]; SQL injection attempt [evt 1778008686.44929936] |
| webshell | 108 | 2026-05-06TIP_30.534Z | 2026-05-07TIP_31.910Z | possible webshell scripting file created [evt 1778090134.16543539, evt 1778090240.17102030] |

## Observed Activity

**Reconnaissance (observed).** Repeated "Multiple web server 400 error codes from same source ip" events attributed to `IP_18` begin 2026-05-04 [evt 1777915124.6606601, evt 1777915136.6617139, evt 1777915146.6708904]. Note `IP_18` does not appear among the three actors later associated with `initial_access`.

**Attack / initial access (observed).** On 2026-05-05, `IP_2` produced bursts of web server 400 errors [evt 1778008680.44572392] followed by a web attack returning HTTP 200 (success) [evt 1778008682.44620403], an SQL injection attempt [evt 1778008686.44929936], and a further HTTP 200 attack [evt 1778008688.44988854]. On 2026-05-06, `IP_3` produced a success code 200 web attack [evt 1778090552.18608068]. On 2026-05-09, `IP_1` produced a success code 200 web attack [evt 1778342465.487206552], followed by six further `IP_1` events [evt 1778342621.488485421, evt 1778343029.492450524, evt 1778343047.492535763, evt 1778343090.493039437, evt 1778343213.494091275, evt 1778343261.494620040]. A web server 500 (internal error) was recorded on 2026-05-05 [evt 1778008690.45051475].

**File changes (observed).** Integrity checksum changes were recorded from 2026-05-04 [evt 1777914632.4377665, evt 1777914632.4378875]. Numerous "[File creation on web directory]" events were recorded on 2026-05-05 [evt 1777955366.224942723, evt 1777955366.224943387, evt 1777955367.224944713]. Webshell-phase alerts for "[File creation]: Possible web shell scripting file ... created" occurred on 2026-05-06 [evt 1778090134.16543539, evt 1778090240.17102030, evt 1778090273.17162032].

**Deletion / destruction indicators (reported by rule classification).** File-deletion and data-destruction classifications were recorded on 2026-05-05 [evt 1778054163.353987772, evt 1778054165.354081056] and 2026-05-06 [evt 1778090108.16418199, evt 1778090135.16559032].

**System/background activity (observed).** "Listened ports status (netstat) changed" events occurred repeatedly in the window [evt 1777914252.1808335, evt 1778000659.1581390, evt 1778087066.1557128], and a "Dpkg (Debian Package) half configured" event was recorded 2026-05-06 [evt 1778107232.102488788].

## Entities

- **Hosts:** `HOST_1`
- **Actors (source IPs):**
  - `IP_1` — phase `initial_access`; 7 events [evt 1778342465.487206552, evt 1778342621.488485421, evt 1778343029.492450524, evt 1778343047.492535763, evt 1778343090.493039437, evt 1778343213.494091275, evt 1778343261.494620040]
  - `IP_2` — phase `initial_access`; 3 events [evt 1778008682.44620403, evt 1778008686.44929936, evt 1778008688.44988854]
  - `IP_3` — phase `initial_access`; 1 event [evt 1778090552.18608068]
  - `IP_18` — appears in recon events only [evt 1777915124.6606601]
- **Files:** 472 file references (`FILE_1`–`FILE_472`) are enumerated as in-scope targets.
- **URLs:** 566 URL references (`URL_1`–`URL_566`) are enumerated as in-scope targets, including a query with a path-traversal-style `__file` parameter `["/FQDN_86?rest_route=%2Fessential-blocks%2Fv1%2Fproducts&...attributes={\"__file\":\"/etc%2fpasswd\"}"]`.

## ATT&CK Techniques

All entries are `wazuh_rule`-sourced classifications, not independently confirmed activity.

| Technique | Name | Tactic | Representative evidence |
|---|---|---|---|
| T1595.002 | Vulnerability Scanning | Reconnaissance | [evt 1777915124.6606601] |
| T1190 | Exploit Public-Facing Application | Initial Access | [evt 1778008682.44620403, evt 1778008686.44929936] |
| T1055 | Process Injection | Defense Evasion | [evt 1778008686.44929936] |
| T1083 | File and Directory Discovery | Privilege Escalation | [evt 1778008690.45042729] |
| T1105 | Ingress Tool Transfer | Command and Control | [evt 1777955366.224942723] |
| T1505 | Server Software Component | Persistence | [evt 1777955366.224942723] |
| T1505.003 | Web Shell | Persistence | [evt 1778092068.26477724, evt 1778092094.26736090] |
| T1070.004 | File Deletion | Defense Evasion | [evt 1778054163.353987772] |
| T1485 | Data Destruction | Impact | [evt 1778054163.353987772] |
| T1565.001 | Stored Data Manipulation | Impact | [evt 1777914632.4377665] |

## Supporting Evidence

- Web-directory file creation, e.g. `FILE_234` and adjacent files created in the same second [evt 1777955366.224942723, evt 1777955366.224943387, evt 1777955366.224944050].
- Webshell "possible web shell scripting file created" alerts, e.g. files `FILE_372`, `FILE_375`, `FILE_377`, `FILE_379`, `FILE_381` [evt 1778090134.16543539, evt 1778090240.17102030, evt 1778090273.17162032, evt 1778090290.17343120, evt 1778090313.17408976].
- Successful web attack (HTTP 200), the investigation seed [evt 1778008682.44620403], plus two further 200s [evt 1778008688.44988854, evt 1778090552.18608068].
- SQL injection attempt [evt 1778008686.44929936].
- Integrity checksum changes across multiple files [evt 1777914632.4377665, evt 1777942225.153270257].
- File deletion / data destruction classification events [evt 1778054163.353987772, evt 1778090135.16559032].
- Linkage summary counts indicate co-occurrence: SAME_URL_PATH 1953, SAME_RULE 1614, PRECEDES 1562, SAME_ACTOR 1350, SHARED_TECHNIQUE 1028, SAME_FILE 318.

## Weakening/Missing Evidence

- "initial access and file changes are not directly linked in telemetry (no shared actor/session observed)."
- "candidate set includes 16 routine/other events that may be background traffic" [evt 1777914252.1808335, evt 1778000659.1581390, evt 1778107232.102488788].
- "attack indicators span 3 distinct client IP(s); campaign linkage between them is not proven" [evt 1778008682.44620403, evt 1778090552.18608068, evt 1778342465.487206552].
- Webshell-phase and file-creation events are attributed to `actor: null`; no source IP is bound to those file creations [evt 1778090134.16543539, evt 1777955366.224942723].
- `IP_18` (recon) is not among the `initial_access` actors, so recon-to-exploitation linkage is not established [evt 1777915124.6606601].

## Uncertainty

- **Unknown:** Whether any created file was executed, interpreted, or accessed. File creation is not proof of execution or persistence [evt 1778090134.16543539].
- **Unknown:** Whether the three source IPs represent one campaign or independent activity; no shared actor/session is observed.
- **Unknown:** Whether `IP_18` is related to `IP_1`/`IP_2`/`IP_3` [evt 1777915124.6606601].
- **Unknown:** Whether deletion/destruction classifications reflect attacker action or routine system behavior; data-destruction labels are Wazuh rule classifications [evt 1778054163.353987772].
- **Unknown:** Whether successful HTTP 200 responses reflect genuine exploitation or only successful request handling; the seed requires only HTTP 200 [evt 1778008682.44620403].
- **Unknown:** The nature and intent of netstat port-change and dpkg half-configured events [evt 1778000659.1581390, evt 1778107232.102488788].

## Impact

**Observed:** In-scope host `HOST_1` shows reconnaissance, repeated attack traffic, successful-code (200) attack events, hundreds of file integrity/creation changes, webshell-classification alerts, and file-deletion/data-destruction classifications within 2026-05-04 to 2026-05-09 [evt 1778008682.44620403, evt 1777914632.4377665, evt 1778090134.16543539, evt 1778054163.353987772].

**Inferred (low confidence):** The clustering of recon, exploitation, file creation, and deletion/destruction classifications on one host is consistent with an intrusion attempt against a public-facing application [evt 1777915124.6606601, evt 1778008682.44620403].

**Unknown:** No confirmed data loss, no confirmed persistence, and no confirmed command-and-control channel can be asserted from the available context.

## Conclusion

Three source IPs generated `initial_access` events on `HOST_1`, seeded by an HTTP 200 web attack from `IP_2` [evt 1778008682.44620403, evt 1778090552.18608068, evt 1778342465.487206552]. Wazuh rule classifications place activity across Reconnaissance, Initial Access, Defense Evasion, Persistence, Command and Control, Privilege Escalation, and Impact (T1565.001, T1595.002, T1105, T1505, T1190, T1055, T1083, T1070.004, T1485, T1505.003). The strongest indicators are web-directory and webshell file creation [evt 1778090134.16543539] and file deletion/data destruction events [evt 1778054163.353987772]. However, initial access and file changes are not directly linked in telemetry, the three IPs are not proven to be a single campaign, and no file execution, persistence, or confirmed compromise is established. Recommended next steps (not yet performed): bind file-creation events to a source actor, verify whether created files were executed, and correlate the three IPs and `IP_18` to a common session.