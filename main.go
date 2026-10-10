package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
)

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorCyan    = "\033[36m"
	colorMagenta = "\033[35m"

	maxScannerTokenSize = 2 * 1024 * 1024
	maxDrainBytes       = 4096
)

var allowedMethods = map[string]struct{}{
	http.MethodHead: {},
	http.MethodGet:  {},
	http.MethodPost: {},
}

type Result struct {
	Timestamp         time.Time `json:"timestamp"`
	TemplateURL       string    `json:"template_url"`
	URL               string    `json:"url"`
	Payload           string    `json:"payload"`
	Method            string    `json:"method"`
	FallbackUsed      bool      `json:"fallback_used"`
	StatusCode        int       `json:"status_code"`
	LocationHeader    string    `json:"location_header,omitempty"`
	EffectiveLocation string    `json:"effective_location,omitempty"`
	Classification    string    `json:"classification"`
	Reason            string    `json:"reason"`
	External          bool      `json:"external"`
	Found             bool      `json:"found"`
	Error             string    `json:"error,omitempty"`
}

type Config struct {
	PayloadsFile string
	URLsFile     string
	Keyword      string
	Concurrency  int
	Timeout      time.Duration
	OutputFile   string
	Method       string
	Verbose      bool
	UserAgent    string
	HeadFallback bool
	OutputFormat string
}

type FuzzerStats struct {
	TotalRequests        int64
	SuccessfulTests      int64
	VulnerabilitiesFound int64
}

type Scanner struct {
	cfg    Config
	client *http.Client
}

type JSONReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	Summary     struct {
		TotalRequests   int64 `json:"total_requests"`
		SuccessfulTests int64 `json:"successful_tests"`
		Findings        int64 `json:"findings"`
		Errors          int64 `json:"errors"`
	} `json:"summary"`
	Results []Result `json:"results"`
}

var outputMutex sync.Mutex

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
}

func run() error {
	config := parseFlags()
	if err := validateConfig(&config); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	printBanner()

	payloads, err := loadPayloads(config.PayloadsFile)
	if err != nil {
		return fmt.Errorf("failed to load payloads: %w", err)
	}
	payloads = uniqueStrings(payloads)
	if len(payloads) == 0 {
		return errors.New("no payloads to test")
	}
	fmt.Printf("%s[INFO]%s Loaded %d unique payloads from %s\n", colorBlue, colorReset, len(payloads), config.PayloadsFile)

	var urls []string
	if config.URLsFile != "" {
		urls, err = loadURLs(config.URLsFile)
		if err != nil {
			return fmt.Errorf("failed to load URLs: %w", err)
		}
		fmt.Printf("%s[INFO]%s Loaded %d URLs from %s\n", colorBlue, colorReset, len(urls), config.URLsFile)
	} else {
		urls, err = readFromStdin()
		if err != nil {
			return fmt.Errorf("failed to read stdin: %w", err)
		}
		fmt.Printf("%s[INFO]%s Loaded %d URLs from stdin\n", colorBlue, colorReset, len(urls))
	}

	urls = uniqueStrings(urls)
	if len(urls) == 0 {
		return errors.New("no URLs to test")
	}

	totalTests := len(urls) * len(payloads)
	fmt.Printf("%s[INFO]%s Starting fuzzing with %d concurrent workers\n", colorBlue, colorReset, config.Concurrency)
	fmt.Printf("%s[INFO]%s Total tests: %d (URLs: %d × Payloads: %d)\n", colorBlue, colorReset, totalTests, len(urls), len(payloads))

	bar := progressbar.NewOptions(
		totalTests,
		progressbar.OptionSetDescription("Fuzzing"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	scanner := newScanner(config)
	results, stats := fuzz(ctx, urls, payloads, config, scanner, bar)

	if ctx.Err() != nil {
		fmt.Printf("\n%s[WARN]%s Scan interrupted: %v\n", colorYellow, colorReset, ctx.Err())
	}

	fmt.Printf("\n%s[INFO]%s Fuzzing complete!\n", colorBlue, colorReset)
	fmt.Printf("%s[STATS]%s Total Requests: %d, Successful: %d, Vulnerabilities Found: %d\n",
		colorBlue,
		colorReset,
		atomic.LoadInt64(&stats.TotalRequests),
		atomic.LoadInt64(&stats.SuccessfulTests),
		atomic.LoadInt64(&stats.VulnerabilitiesFound),
	)

	if config.OutputFile != "" {
		format, err := resolveOutputFormat(config.OutputFormat, config.OutputFile)
		if err != nil {
			return err
		}
		if err := saveResults(config.OutputFile, format, results, stats); err != nil {
			return err
		}
	}

	return nil
}

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.PayloadsFile, "payloads", "", "Payloads file (required)")
	flag.StringVar(&config.PayloadsFile, "p", "", "Payloads file (required) - shorthand")
	flag.StringVar(&config.URLsFile, "urls", "", "URLs file (optional, reads stdin if not provided)")
	flag.StringVar(&config.URLsFile, "u", "", "URLs file - shorthand")
	flag.StringVar(&config.Keyword, "keyword", "FUZZ", "Keyword to replace in URLs")
	flag.StringVar(&config.Keyword, "k", "FUZZ", "Keyword to replace - shorthand")
	flag.IntVar(&config.Concurrency, "concurrency", 100, "Number of concurrent workers")
	flag.IntVar(&config.Concurrency, "c", 100, "Number of concurrent workers - shorthand")
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Second, "Request timeout (Go duration, e.g. 10s, 1m)")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Request timeout (Go duration) - shorthand")
	flag.StringVar(&config.OutputFile, "output", "", "Output file for results")
	flag.StringVar(&config.OutputFile, "o", "", "Output file - shorthand")
	flag.StringVar(&config.Method, "method", "HEAD", "HTTP method (HEAD/GET/POST)")
	flag.StringVar(&config.Method, "m", "HEAD", "HTTP method - shorthand")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose logging - shorthand")
	flag.StringVar(&config.UserAgent, "user-agent", "OpenRedirectFuzzer/2.0", "User-Agent header")
	flag.BoolVar(&config.HeadFallback, "head-fallback", true, "Fallback to GET when HEAD is rejected (403/405/501)")
	flag.StringVar(&config.OutputFormat, "format", "auto", "Output format: auto, text, or json")

	flag.Parse()
	return config
}

func validateConfig(config *Config) error {
	if config.PayloadsFile == "" {
		return errors.New("payloads file is required (-p flag)")
	}
	if strings.TrimSpace(config.Keyword) == "" {
		return errors.New("keyword cannot be empty")
	}
	if config.Concurrency < 1 || config.Concurrency > 2000 {
		return fmt.Errorf("concurrency must be between 1 and 2000, got %d", config.Concurrency)
	}
	if config.Timeout <= 0 || config.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout must be between 1ms and 5m, got %s", config.Timeout)
	}
	method := strings.ToUpper(strings.TrimSpace(config.Method))
	if _, ok := allowedMethods[method]; !ok {
		return fmt.Errorf("unsupported method %q (supported: HEAD, GET, POST)", config.Method)
	}
	config.Method = method
	config.OutputFormat = strings.ToLower(strings.TrimSpace(config.OutputFormat))
	if config.OutputFormat == "" {
		config.OutputFormat = "auto"
	}
	if config.OutputFormat != "auto" && config.OutputFormat != "text" && config.OutputFormat != "json" {
		return fmt.Errorf("unsupported output format %q (supported: auto, text, json)", config.OutputFormat)
	}
	if strings.TrimSpace(config.UserAgent) == "" {
		config.UserAgent = "OpenRedirectFuzzer/2.0"
	}
	return nil
}

func printBanner() {
	banner := `
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║   %s  ___  ____  _____ _   __  ____  ___________  ____  ________   %s      ║
║   %s / _ \/ __ \/ ____/ | / / / __ \/ ____/ / _ \/ __ \/_  __/ /   %s      ║
║   %s/ // / /_/ / __/ /  |/ / / / / / __/ / / // / /_/ / / / / /    %s      ║
║   %s/ _  / ____/ /___ / /|  / / /_/ / /___/ / // / _, _/ / / / /____%s      ║
║   %s/_/ |_/_/   /_____/_/ |_/  \____/_____/_//_/ /_/ |_| /_/_/_____/%s      ║
║                                                                            ║
║         %s🔍 High-Performance Open Redirect Vulnerability Scanner 🔍%s     ║
║                                                                            ║
║                        %sv2.0 | By Security Research%s                     ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
`
	fmt.Printf(banner,
		colorCyan, colorReset,
		colorMagenta, colorReset,
		colorGreen, colorReset,
		colorYellow, colorReset,
		colorRed, colorReset,
		colorBlue, colorReset,
		colorCyan, colorReset)
	fmt.Println()
}

func loadPayloads(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLines(file)
}

func loadURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readLines(file)
}

func readFromStdin() ([]string, error) {
	return readLines(os.Stdin)
}

func readLines(r io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxScannerTokenSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, item := range in {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func newScanner(config Config) *Scanner {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          config.Concurrency*2 + 10,
		MaxIdleConnsPerHost:   config.Concurrency + 5,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &Scanner{cfg: config, client: client}
}

type workItem struct {
	template string
	target   string
	payload  string
}

func fuzz(ctx context.Context, urls, payloads []string, config Config, scanner *Scanner, bar *progressbar.ProgressBar) ([]Result, FuzzerStats) {
	workChan := make(chan workItem, config.Concurrency*2)
	resultChan := make(chan Result, config.Concurrency*2)
	var workerWG sync.WaitGroup
	var results []Result
	stats := FuzzerStats{}

	for i := 0; i < config.Concurrency; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case w, ok := <-workChan:
					if !ok {
						return
					}
					result := scanner.Check(ctx, w.target, w.payload, w.template)
					resultChan <- result
				}
			}
		}()
	}

	go func() {
		defer close(workChan)
		for _, u := range urls {
			for _, p := range payloads {
				select {
				case <-ctx.Done():
					return
				case workChan <- workItem{
					template: u,
					target:   strings.ReplaceAll(u, config.Keyword, p),
					payload:  p,
				}:
				}
			}
		}
	}()

	go func() {
		workerWG.Wait()
		close(resultChan)
	}()

	seenFindings := make(map[string]struct{})
	for result := range resultChan {
		_ = bar.Add(1)
		atomic.AddInt64(&stats.TotalRequests, 1)
		if result.Error == "" {
			atomic.AddInt64(&stats.SuccessfulTests, 1)
		}
		if result.Found {
			key := result.URL + "|" + result.Payload + "|" + result.LocationHeader + "|" + result.Classification
			if _, exists := seenFindings[key]; !exists {
				seenFindings[key] = struct{}{}
				atomic.AddInt64(&stats.VulnerabilitiesFound, 1)
				outputMutex.Lock()
				fmt.Printf("\n%s[✓ FOUND]%s %s %s→%s %s [%s]\n",
					colorGreen,
					colorReset,
					result.URL,
					colorYellow,
					colorReset,
					result.LocationHeader,
					result.Reason,
				)
				outputMutex.Unlock()
			}
		}

		if config.Verbose {
			outputMutex.Lock()
			if result.Error != "" {
				fmt.Printf("\n%s[✗ ERROR]%s %s (%s)\n", colorRed, colorReset, result.URL, result.Error)
			} else {
				fmt.Printf("\n%s[→ TESTING]%s %s (%d)\n", colorYellow, colorReset, result.URL, result.StatusCode)
			}
			outputMutex.Unlock()
		}

		results = append(results, result)
	}

	return results, stats
}

func (s *Scanner) Check(ctx context.Context, targetURL, payload, templateURL string) Result {
	result := Result{
		Timestamp:      time.Now().UTC(),
		TemplateURL:    templateURL,
		URL:            targetURL,
		Payload:        payload,
		Method:         s.cfg.Method,
		Classification: "no-redirect",
		Reason:         "No redirect status code observed",
	}

	resp, err := s.doRequest(ctx, s.cfg.Method, targetURL)
	if err != nil {
		result.Classification = "request-error"
		result.Reason = "Request failed"
		result.Error = err.Error()
		return result
	}
	statusCode := resp.StatusCode
	location := resp.Header.Get("Location")
	drainAndClose(resp.Body)

	if s.cfg.Method == http.MethodHead && s.cfg.HeadFallback && shouldFallbackToGET(statusCode) {
		fallbackResp, fallbackErr := s.doRequest(ctx, http.MethodGet, targetURL)
		if fallbackErr != nil {
			result.FallbackUsed = true
			result.Method = http.MethodGet
			result.Classification = "request-error"
			result.Reason = "GET fallback failed"
			result.Error = fallbackErr.Error()
			return result
		}
		statusCode = fallbackResp.StatusCode
		location = fallbackResp.Header.Get("Location")
		drainAndClose(fallbackResp.Body)
		result.FallbackUsed = true
		result.Method = http.MethodGet
	}

	result.StatusCode = statusCode
	result.LocationHeader = location

	if statusCode < 300 || statusCode > 399 {
		return result
	}

	if location == "" {
		result.Classification = "redirect-without-location"
		result.Reason = "3xx response did not include a Location header"
		return result
	}

	classification, reason, effectiveLocation, external, found := classifyRedirect(targetURL, location)
	result.Classification = classification
	result.Reason = reason
	result.EffectiveLocation = effectiveLocation
	result.External = external
	result.Found = found
	return result
}

func (s *Scanner) doRequest(ctx context.Context, method, targetURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.cfg.UserAgent)
	return s.client.Do(req)
}

func shouldFallbackToGET(statusCode int) bool {
	switch statusCode {
	case http.StatusMethodNotAllowed, http.StatusForbidden, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.CopyN(io.Discard, body, maxDrainBytes)
	_ = body.Close()
}

func classifyRedirect(originalURL, location string) (classification, reason, effectiveLocation string, external, found bool) {
	originalParsed, err := url.Parse(originalURL)
	if err != nil {
		return "malformed-original-url", "Original URL could not be parsed", "", false, false
	}

	location = strings.TrimSpace(location)
	locationParsed, err := url.Parse(location)
	if err != nil {
		return "malformed-location", "Location header could not be parsed", "", false, false
	}

	scheme := strings.ToLower(locationParsed.Scheme)
	if scheme != "" && !isHTTPScheme(scheme) {
		if isDangerousScheme(scheme) {
			return "suspicious-scheme", "Location uses dangerous non-HTTP(S) scheme", location, true, true
		}
		return "non-http-scheme", "Location uses non-HTTP(S) scheme", location, false, false
	}

	effective := originalParsed.ResolveReference(locationParsed)
	effectiveLocation = effective.String()

	originHost := normalizedHostPort(originalParsed)
	effectiveHost := normalizedHostPort(effective)

	if originHost == effectiveHost {
		if strings.EqualFold(originalParsed.Scheme, effective.Scheme) {
			return "same-origin", "Redirect remained on the same origin", effectiveLocation, false, false
		}
		return "same-host", "Redirect remained on the same host", effectiveLocation, false, false
	}

	return "external-http-redirect", "Redirect target host differs from origin", effectiveLocation, true, true
}

func isHTTPScheme(scheme string) bool {
	return scheme == "http" || scheme == "https"
}

func isDangerousScheme(scheme string) bool {
	switch scheme {
	case "javascript", "data", "file":
		return true
	default:
		return false
	}
}

func normalizedHostPort(u *url.URL) string {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	scheme := strings.ToLower(u.Scheme)

	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}

	if port == "" {
		return host
	}
	return net.JoinHostPort(host, port)
}

func resolveOutputFormat(requested, filename string) (string, error) {
	if requested == "auto" {
		if strings.EqualFold(filepath.Ext(filename), ".json") {
			return "json", nil
		}
		return "text", nil
	}
	return requested, nil
}

func saveResults(filename, format string, results []Result, stats FuzzerStats) error {
	results = sortedResults(results)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch format {
	case "text":
		if err := writeTextResults(file, results); err != nil {
			return err
		}
	case "json":
		if err := writeJSONResults(file, results, stats); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported output format %q", format)
	}

	fmt.Printf("%s[✓ INFO]%s Results saved to %s (%s)\n", colorBlue, colorReset, filename, format)
	return nil
}

func sortedResults(results []Result) []Result {
	copied := make([]Result, len(results))
	copy(copied, results)
	sort.SliceStable(copied, func(i, j int) bool {
		if copied[i].URL != copied[j].URL {
			return copied[i].URL < copied[j].URL
		}
		if copied[i].Payload != copied[j].Payload {
			return copied[i].Payload < copied[j].Payload
		}
		if copied[i].Method != copied[j].Method {
			return copied[i].Method < copied[j].Method
		}
		if copied[i].LocationHeader != copied[j].LocationHeader {
			return copied[i].LocationHeader < copied[j].LocationHeader
		}
		return copied[i].Error < copied[j].Error
	})
	return copied
}

func writeTextResults(w io.Writer, results []Result) error {
	for _, result := range results {
		if result.Found {
			line := fmt.Sprintf("[FOUND] %s (Payload: %s) redirects to %s [%s]\n",
				result.URL,
				result.Payload,
				result.LocationHeader,
				result.Classification,
			)
			if _, err := io.WriteString(w, line); err != nil {
				return err
			}
		}
		if result.Error != "" {
			line := fmt.Sprintf("[ERROR] %s (Payload: %s) %s\n", result.URL, result.Payload, result.Error)
			if _, err := io.WriteString(w, line); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeJSONResults(w io.Writer, results []Result, stats FuzzerStats) error {
	report := JSONReport{
		GeneratedAt: time.Now().UTC(),
		Results:     results,
	}
	report.Summary.TotalRequests = stats.TotalRequests
	report.Summary.SuccessfulTests = stats.SuccessfulTests
	report.Summary.Findings = stats.VulnerabilitiesFound
	for _, result := range results {
		if result.Error != "" {
			report.Summary.Errors++
		}
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
