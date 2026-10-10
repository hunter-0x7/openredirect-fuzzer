# OpenRedirect Fuzzer

A concurrent open-redirect scanner for **authorized security testing**.

> ⚠️ **Authorized use only**: only scan systems you own or are explicitly permitted to test.

## What it does

- Reads URL templates from file or stdin.
- Reads payloads from file.
- Replaces a keyword (`FUZZ` by default) with each payload.
- Sends concurrent HTTP requests with redirect following disabled.
- Classifies redirects accurately instead of treating every 3xx as vulnerable.

## Key improvements

- Reusable HTTP client/transport (no per-request client creation).
- Redirect classification with normalized host comparison:
  - Resolves relative and protocol-relative `Location` values.
  - Normalizes host case and default ports (`:80`, `:443`) before comparison.
  - Distinguishes same-origin/same-host redirects from external redirects.
- Dangerous schemes (`javascript:`, `data:`, `file:`) are marked suspicious.
- Optional HEAD→GET fallback when HEAD is rejected (403/405/501).
- Input deduplication (URLs and payloads).
- Signal-aware cancellation (`SIGINT`, `SIGTERM`).
- Structured JSON output with metadata, while preserving text output.
- Scanner buffer increased for long lines, with scanner errors surfaced.

## Build

```bash
go mod download
go build -o openredirect-fuzzer .
```

## Usage

```bash
./openredirect-fuzzer -p payloads.txt -u urls.txt
cat urls.txt | ./openredirect-fuzzer -p payloads.txt
```

## Flags

Existing flags are preserved:

- `-payloads, -p` payload file (required)
- `-urls, -u` URL templates file (optional; stdin if omitted)
- `-keyword, -k` replacement keyword (default `FUZZ`)
- `-concurrency, -c` worker count (default `100`)
- `-timeout, -t` request timeout as **Go duration** (default `10s`, examples: `5s`, `1m`)
- `-output, -o` output file path
- `-method, -m` request method (`HEAD`, `GET`, `POST`; default `HEAD`)
- `-verbose, -v` verbose logging

Additional flags:

- `-user-agent` custom User-Agent (default `OpenRedirectFuzzer/2.0`)
- `-head-fallback` fallback to GET when HEAD is rejected (`true` by default)
- `-format` output format: `auto`, `text`, `json` (default `auto`)
  - `auto` uses JSON when output filename ends in `.json`, otherwise text.

## Examples

```bash
# Basic scan
./openredirect-fuzzer -p payloads.txt -u urls.txt

# Faster scan with custom timeout
./openredirect-fuzzer -p payloads.txt -u urls.txt -c 200 -t 5s

# Force GET requests
./openredirect-fuzzer -p payloads.txt -u urls.txt -m GET

# Save text output
./openredirect-fuzzer -p payloads.txt -u urls.txt -o findings.txt

# Save JSON output
./openredirect-fuzzer -p payloads.txt -u urls.txt -o findings.json
# or
./openredirect-fuzzer -p payloads.txt -u urls.txt -o findings.out -format json
```

## Output

### Text format

Preserves the traditional line-oriented format for findings:

```text
[FOUND] https://target.example/redirect?next=//evil.example (Payload: //evil.example) redirects to //evil.example [external-http-redirect]
```

Errors are also recorded:

```text
[ERROR] https://target.example/... (Payload: ...) <request error>
```

### JSON format

JSON includes summary and per-request metadata:

- `timestamp`
- `template_url`
- `url`
- `payload`
- `method`
- `fallback_used`
- `status_code`
- `location_header` (raw)
- `effective_location` (resolved)
- `classification`
- `reason`
- `external`
- `found`
- `error`

## Classification behavior

A result is only marked as a finding when redirect behavior is suspicious, such as:

- external HTTP(S) host redirect
- dangerous non-HTTP(S) redirect schemes (`javascript`, `data`, `file`)

Same-origin and same-host redirects are not reported as vulnerabilities.

Malformed `Location` values are handled safely and classified without crashing.

## Limitations

- The scanner inspects the first response only (redirect following disabled by design).
- It does not execute JavaScript or browser-level redirect logic.
- Rate limiting is not built in; use concurrency and timeout controls responsibly.

## License

MIT
