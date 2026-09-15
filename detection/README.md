# Detection data

`http-signatures.json` contains versioned local HTTP rules. These rules are not OWASP Core Rule Set or libinjection. Keep the names and provenance accurate when adding rules.

`threat-intel.json` is an empty snapshot schema. Populate it from an approved threat-intelligence export. Each indicator has this shape:

```json
{
  "id": "feed-indicator-id",
  "value": "203.0.113.7",
  "severity": "high",
  "confidence": 0.95
}
```

Supported indicator collections are `ips`, `domains`, `urls`, `file_names`, `file_hashes`, and `users`. Update `feed.name`, `feed.version`, and `feed.retrieved_at` whenever the snapshot changes.

`trusted-proxies.json` starts empty so the pipeline does not trust `X-Forwarded-For` by default. Add only networks controlled by the deployment. The resolver walks a trusted forwarded chain from right to left and selects the first untrusted address.

## Offline OWASP CRS replay

The repository includes `crs-replay`, a JSONL command built with Coraza and the embedded OWASP CRS package. Stage 2 starts it once per batch and attaches its real matched rule IDs to each HTTP event. The runner uses the `sparse-access-log` profile and removes the CRS 920 protocol-enforcement group because missing historical headers must not be treated as headers that were absent from the original request.

Run its tests with:

```sh
cd crs-replay
go test ./...
```

## Upstream OWASP CRS results

Run OWASP CRS in ModSecurity, Coraza, or the existing WAF. Pass matched rule IDs into normalized event details through one of these fields:

- `owasp_crs_rule_ids`
- `modsecurity_rule_ids`
- `crs_rule_ids`

Include `owasp_crs_version` when available. Stage 2 records these matches with `rule_source` set to `owasp-crs-upstream`. It does not claim local rules are CRS rules.

The embedded CRS package brings its supported libinjection implementation through Coraza. Local Python regular expressions remain labeled as custom HTTP rules.
