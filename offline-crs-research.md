# Offline OWASP CRS replay for raw access logs

Research date: 2026-09-15. Sources are pinned to OWASP CRS v4.29.0, Coraza v3.7.0, and ModSecurity v3.0.16 where a versioned source is available.

## Decision

Yes. We can run CRS against historical logs without installing or changing the customer’s WAF. The missing piece is a ModSecurity-compatible rule engine that receives reconstructed transactions. CRS itself is a rule set, not a classifier or a dataset. The CRS README describes it as generic attack-detection rules for ModSecurity, Coraza, or another compatible WAF, and its install guide assumes that an engine is already present.

The best fit is a small offline Go runner embedding Coraza. Coraza is a Go library, supports ModSecurity SecLang, and documents CRS v4 compatibility. The existing Python pipeline can stream normalized JSONL records to that runner and consume JSONL match records. This does not require an HTTP listener, backend application, or WAF deployment.

Sources:

- [CRS README](https://github.com/coreruleset/coreruleset/blob/v4.29.0/README.md#L9-L15)
- [CRS installation guide](https://github.com/coreruleset/coreruleset/blob/v4.29.0/INSTALL.md#L1-L3), which assumes a compatible ModSecurity engine
- [ModSecurity library overview](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/README.md#L21-L46), which says the library applies SecRules to HTTP content supplied by connectors
- [Coraza README](https://github.com/corazawaf/coraza/blob/v3.7.0/README.md#L14-L29), [core usage](https://github.com/corazawaf/coraza/blob/v3.7.0/README.md#L54-L92)

## What a full replay needs

ModSecurity-compatible engines evaluate a transaction in phases. Connection and URI data are supplied first, then request headers, request body, response headers, response body, and logging. ModSecurity’s own C example calls those APIs in that order. Coraza exposes the same lifecycle in its transaction interface.

- [ModSecurity transaction C example](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/examples/simple_example_using_c/test.c#L59-L74)
- [ModSecurity transaction API](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/headers/modsecurity/transaction.h#L340-L392)
- [Coraza transaction interface](https://github.com/corazawaf/coraza/blob/v3.7.0/types/transaction.go#L12-L56), [body and response methods](https://github.com/corazawaf/coraza/blob/v3.7.0/types/transaction.go#L78-L154)

The sparse access-log fields map as follows:

| Observed log field | Coraza input | CRS variables available | Result |
| --- | --- | --- | --- |
| client/peer IP | `ProcessConnection(client, cPort, server, sPort)` | `REMOTE_ADDR` | Use the actual peer IP. Do not replace it with an untrusted XFF value. |
| method | `ProcessURI(..., method, ...)` | `REQUEST_METHOD`, `REQUEST_LINE` | Request-method rules can run. |
| raw path plus query | first `ProcessURI` argument | `REQUEST_URI_RAW`, parsed `REQUEST_URI`, `QUERY_STRING`, `ARGS_GET`, `ARGS`, `REQUEST_FILENAME`, `REQUEST_BASENAME` | This is the most useful part of replay. Pass the original request target, including its original encoding. |
| HTTP version | third `ProcessURI` argument | `REQUEST_PROTOCOL`, `REQUEST_LINE` | Protocol and request-line rules can run. |
| User-Agent | `AddRequestHeader("User-Agent", value)` | `REQUEST_HEADERS:User-Agent` | CRS rule 913100 can inspect it. |
| X-Forwarded-For | `AddRequestHeader("X-Forwarded-For", value)` | `REQUEST_HEADERS:X-Forwarded-For` | It is only a supplied header. CRS does not turn it into `REMOTE_ADDR`; apply a separately configured proxy-trust policy. |
| response status | `ProcessResponseHeaders(status, responseProtocol)` | `RESPONSE_STATUS` | Status-dependent phase-3 rules can run, but this is not a complete response replay. |

Coraza’s implementation confirms that `ProcessURI` sets method, protocol, raw URI, and request line; parses the query into GET arguments; and derives URI, basename, filename, and query-string variables. It also says that `ProcessRequestBody` should be called even when no body is expected, so phase-2 rules that can use query arguments still execute.

- [Coraza `ProcessURI` implementation](https://github.com/corazawaf/coraza/blob/v3.7.0/internal/corazawaf/transaction.go#L810-L867)
- [Coraza body-phase guidance](https://github.com/corazawaf/coraza/blob/v3.7.0/types/transaction.go#L78-L105)
- [ModSecurity variable reference for request URI, headers, method, and status](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#request_uri), [request headers](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#request_headers), [request method](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#request_method), [response status](https://github.com/owasp-modsecurity/ModSecurity/wiki/Reference-Manual-%28v2.x%29#response_status)

## What sparse logs cannot reproduce

This must be labeled partial coverage. An access log with method, target, protocol, status, User-Agent, and XFF does not contain the request headers, cookies, request body, response headers, or response body that many CRS rules inspect.

Examples from CRS v4.29.0:

- [911100](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/REQUEST-911-METHOD-ENFORCEMENT.conf#L28-L38) uses `REQUEST_METHOD` and is replayable.
- [913100](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/REQUEST-913-SCANNER-DETECTION.conf#L38-L50) uses `REQUEST_HEADERS:User-Agent` and is replayable when the field was logged.
- [930100](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf#L35-L54) combines URI, ARGS, headers, files, and XML. A sparse replay can cover only the URI and query portions.
- [942100](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf#L46-L66) inspects cookies, User-Agent, Referer, XML, and ARGS. Query SQLi remains useful, but a missing body, cookie, or header is a real blind spot.
- [950130](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/RESPONSE-950-DATA-LEAKAGES.conf#L55-L73) inspects `RESPONSE_BODY`, so a status-only response cannot detect directory or error-content leakage. [950100](https://github.com/coreruleset/coreruleset/blob/v4.29.0/rules/RESPONSE-950-DATA-LEAKAGES.conf#L140-L152) shows the narrower status-only case.
- CRS also has protocol-compliance rules for headers such as Host, Content-Type, Content-Length, Accept, and Range. An empty synthetic header is not evidence that the original header was empty. Missing fields should stay missing and be recorded in coverage metadata.

Coraza’s recommended configuration makes the same limitation explicit: without request-body access it cannot see POST parameters, and without response-body access it cannot inspect response content for errors or data leakage.

- [Coraza recommended request-body configuration](https://github.com/corazawaf/coraza/blob/v3.7.0/coraza.conf-recommended#L21-L40)
- [Coraza recommended response-body configuration](https://github.com/corazawaf/coraza/blob/v3.7.0/coraza.conf-recommended#L92-L106)

The output should therefore say `coverage: partial`, list `observed_fields` and `missing_fields`, and avoid presenting a no-match as proof that the request was benign.

## Recommended runner

Keep the Python code responsible for log parsing, field-presence tracking, and pipeline integration. Add a long-lived Go command that loads one pinned CRS configuration at startup and processes one transaction per JSONL input record.

The per-record lifecycle is:

```text
NewTransaction
  -> ProcessConnection
  -> ProcessURI(raw_target, method, http_version)
  -> add only headers that were actually observed
  -> ProcessRequestHeaders
  -> write body if captured, then ProcessRequestBody
  -> ProcessResponseHeaders if status is known
  -> write response body if captured, then ProcessResponseBody
  -> ProcessLogging
  -> Close
```

Run in `SecRuleEngine DetectionOnly`. Coraza documents that this evaluates rules while suppressing disruptive actions. Collect `tx.MatchedRules()` and emit each rule ID, phase, file, line, version, tags, message, and matched variable. The public interfaces expose all of those fields.

- [Coraza DetectionOnly configuration](https://github.com/corazawaf/coraza/blob/v3.7.0/coraza.conf-recommended#L1-L8)
- [Coraza matched-rule fields](https://github.com/corazawaf/coraza/blob/v3.7.0/types/rule_match.go#L8-L49)
- [Coraza rule metadata fields](https://github.com/corazawaf/coraza/blob/v3.7.0/types/rules.go#L6-L22)

Use two explicit profiles. A `sparse-access-log` profile should exclude or annotate rules whose decision depends on fields that were not logged. A `full-transaction` profile can enable normal CRS behavior when request and response captures become available. Never invent Host, cookies, Content-Type, or body values to make the transaction look complete.

## CLI choice

The reviewed official repositories do not provide a purpose-built historical access-log replay CLI. Coraza’s documented `httpe2e` command is an end-to-end test utility that requires a proxy and an httpbin endpoint, and its package documentation says the proxy under test must already have Coraza integrated. Coraza lists Go FTW as a rule-testing engine, not an access-log replay tool. ModSecurity’s `tools/rules-check` loads SecLang files and reports parser errors; it does not process transactions.

- [Coraza e2e CLI documentation](https://github.com/corazawaf/coraza/blob/v3.7.0/README.md#L114-L136)
- [Coraza e2e package contract](https://github.com/corazawaf/coraza/blob/v3.7.0/http/e2e/doc.go#L6-L32)
- [ModSecurity rules-check utility](https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.16/tools/rules-check/rules-check.cc#L32-L92)

A small Coraza runner is therefore the clean solution. It uses the actual CRS rules and engine, keeps the Python pipeline intact, works offline, and can later accept richer captures without another detector rewrite. Validate it against the CRS regression suite and hand-labeled real requests, then report its results as `CRS-compatible partial replay` rather than as the verdict a live WAF would have produced.
