# OpenRedirect Fuzzer

A high-performance, concurrent open redirect vulnerability fuzzer written in Go.

## Features

✅ **High Performance**
- Concurrent goroutines for parallel testing
- Connection pooling and efficient resource usage
- Progress bar for real-time status

✅ **Flexible Input**
- Accept URLs from file or stdin
- Load custom payloads from wordlist file
- Customizable keyword replacement

✅ **Accurate Detection**
- HTTP redirect detection via status codes (3xx)
- Location header verification
- Network error handling

✅ **Professional CLI**
- Multiple command-line flags for customization
- Verbose mode for debugging
- Optional output file for results

## Installation

### Prerequisites
- Go 1.21 or higher

### Build

```bash
git clone https://github.com/hunter-0x7/openredirect-fuzzer.git
cd openredirect-fuzzer
go mod download
go build -o openredirect-fuzzer
```

## Usage

### Basic Usage

```bash
# Read URLs from file, use custom payloads
./openredirect-fuzzer -payloads payloads.txt -urls urls.txt

# Read URLs from stdin
cat urls.txt | ./openredirect-fuzzer -payloads payloads.txt
```

### Command-Line Flags

```
-payloads, -p       Input file with payloads (required)
-urls, -u           Input file with URLs (optional, reads stdin if not provided)
-keyword, -k        Keyword to replace in URLs (default: "FUZZ")
-concurrency, -c    Number of concurrent workers (default: 100)
-timeout, -t        Request timeout in seconds (default: 10)
-output, -o         Output file for results (optional)
-method, -m         HTTP method: HEAD/GET/POST (default: HEAD)
-verbose, -v        Enable verbose logging
```

### Examples

```bash
# Basic fuzzing with custom payloads
./openredirect-fuzzer -p payloads.txt -u urls.txt

# Read from stdin with 50 workers
cat urls.txt | ./openredirect-fuzzer -p payloads.txt -c 50

# Save results to file
./openredirect-fuzzer -p payloads.txt -u urls.txt -o results.txt

# Verbose mode with custom timeout
./openredirect-fuzzer -p payloads.txt -u urls.txt -t 15 -v

# Using GET method with custom keyword
./openredirect-fuzzer -p payloads.txt -u urls.txt -m GET -k PAYLOAD
```

## Input File Formats

### Payloads File
One payload per line. Lines starting with `#` are treated as comments and ignored.

Example `payloads.txt`:
```
//example.com
//google.com
https://example.com
/https://google.com
//google.com/%2f..
```

### URLs File
One URL per line. The keyword (default: `FUZZ`) will be replaced with each payload.

Example `urls.txt`:
```
http://example.com/redirect?url=FUZZ
http://example.com/login?return=FUZZ
http://example.com/page?redirect_uri=FUZZ
```

## Output

The tool will output detected redirects in the following format:

```
[FOUND] http://example.com/redirect?url=//google.com redirects to //google.com
```

If `-output` flag is specified, results will also be saved to the output file.

## Performance Tips

- **Increase concurrency**: Use `-c 200` or higher for faster testing (adjust based on system resources)
- **Reduce timeout**: Use `-t 5` for faster response handling, but may miss slow servers
- **Use HEAD method**: Default HEAD is faster than GET/POST

## Error Handling

The tool gracefully handles:
- Network timeouts
- Connection errors
- Invalid URLs
- Malformed responses

Errors are logged to stderr and don't stop the fuzzing process.

## License

MIT

## Author

Created with ❤️ for security research

---

**Disclaimer**: This tool is for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
