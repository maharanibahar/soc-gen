# Offline CRS replay

This command evaluates historical HTTP access-log records with Coraza and the embedded OWASP Core Rule Set. It does not require the source WAF to run ModSecurity.

The command reads one JSON object per line from standard input and writes one result per line to standard output. It accepts the repository's nested normalized event shape and the equivalent flat HTTP fields.

```sh
printf '%s\n' '{"event_id":"EV-1","ip":"192.0.2.10","method":"GET","path":"/?file=../../../etc/passwd","protocol":"HTTP/1.1"}' \
  | mise exec -- go run ./crs-replay
```

Each result includes:

- Coraza and embedded CRS package versions read from Go build information
- matched rule IDs, messages, severity, tags, and variables
- `is_attack`, based on the CRS `attack-*` tags
- observed and missing fields
- the phases evaluated by the sparse replay profile

The runner processes request phases 1 and 2. It removes CRS rules `920000-920999` because protocol-enforcement rules can produce false findings when historical logs did not retain headers such as `Host` or `Content-Type`. It does not run response phases because an access-log status without response headers or a response body is not a complete response transaction.

No-match results have partial coverage unless the record contains all requested fields. They are not proof that the historical request was benign.

## Development

The project uses the Go version managed by `mise`:

```sh
cd crs-replay
mise exec -- go test ./...
```
