package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schollz/progressbar/v3"
)

// Color codes for terminal output
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

// Result represents a finding
type Result struct {
	URL            string
	Payload        string
	StatusCode     int
	LocationHeader string
	Found          bool
}

// Config holds command line flags
type Config struct {
	PayloadsFile string
	URLsFile     string
	Keyword      string
	Concurrency  int
	Timeout      time.Duration
	OutputFile   string
	Method       string
	Verbose      bool
}

// FuzzerStats holds statistics
type FuzzerStats struct {
	TotalRequests    int64
	SuccessfulTests  int64
	VulnerabilitiesFound int64
}

var stats FuzzerStats
var outputMutex sync.Mutex
var results []Result

func main() {
	// Parse command line flags
	config := parseFlags()

	// Validate required flags
	if config.PayloadsFile == "" {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s Payloads file is required (-p flag)\n", colorRed, colorReset)
		os.Exit(1)
	}

	// Print banner
	printBanner()

	// Load payloads
	payloads, err := loadPayloads(config.PayloadsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to load payloads: %v\n", colorRed, colorReset, err)
		os.Exit(1)
	}
	fmt.Printf("%s[INFO]%s Loaded %d payloads from %s\n", colorBlue, colorReset, len(payloads), config.PayloadsFile)

	// Load URLs
	var urls []string
	if config.URLsFile != "" {
		var loadErr error
		urls, loadErr = loadURLs(config.URLsFile)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to load URLs: %v\n", colorRed, colorReset, loadErr)
			os.Exit(1)
		}
		fmt.Printf("%s[INFO]%s Loaded %d URLs from %s\n", colorBlue, colorReset, len(urls), config.URLsFile)
	} else {
		// Read from stdin
		urls = readFromStdin()
		fmt.Printf("%s[INFO]%s Loaded %d URLs from stdin\n", colorBlue, colorReset, len(urls))
	}

	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s No URLs to test\n", colorRed, colorReset)
		os.Exit(1)
	}

	fmt.Printf("%s[INFO]%s Starting fuzzing with %d concurrent workers\n", colorBlue, colorReset, config.Concurrency)
	fmt.Printf("%s[INFO]%s Total tests: %d (URLs: %d × Payloads: %d)\n", colorBlue, colorReset, len(urls)*len(payloads), len(urls), len(payloads))

	// Create progress bar
	bar := progressbar.NewOptions(
		len(urls)*len(payloads),
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

	// Start fuzzing
	fuzz(urls, payloads, config, bar)

	// Print results
	fmt.Printf("\n%s[INFO]%s Fuzzing complete!\n", colorBlue, colorReset)
	fmt.Printf("%s[STATS]%s Total Requests: %d, Vulnerabilities Found: %d\n", 
		colorBlue, colorReset, atomic.LoadInt64(&stats.TotalRequests), atomic.LoadInt64(&stats.VulnerabilitiesFound))

	// Save results if output file specified
	if config.OutputFile != "" {
		saveResults(config.OutputFile)
	}
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
	flag.DurationVar(&config.Timeout, "timeout", 10*time.Second, "Request timeout")
	flag.DurationVar(&config.Timeout, "t", 10*time.Second, "Request timeout - shorthand")
	flag.StringVar(&config.OutputFile, "output", "", "Output file for results")
	flag.StringVar(&config.OutputFile, "o", "", "Output file - shorthand")
	flag.StringVar(&config.Method, "method", "HEAD", "HTTP method (HEAD/GET/POST)")
	flag.StringVar(&config.Method, "m", "HEAD", "HTTP method - shorthand")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose logging")
	flag.BoolVar(&config.Verbose, "v", false, "Enable verbose logging - shorthand")

	flag.Parse()

	// Handle shorthand flag precedence
	if flag.Lookup("p").Value.String() != "" && config.PayloadsFile == "" {
		config.PayloadsFile = flag.Lookup("p").Value.String()
	}
	if flag.Lookup("u").Value.String() != "" && config.URLsFile == "" {
		config.URLsFile = flag.Lookup("u").Value.String()
	}

	return config
}

func printBanner() {
	banner := `
   ╔═══════════════════════════════════════════════════════════╗
   ║   OpenRedirect Fuzzer v1.0                                ║
   ║   High-Performance Open Redirect Vulnerability Scanner    ║
   ╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

func loadPayloads(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			payloads = append(payloads, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return payloads, nil
}

func loadURLs(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

func readFromStdin() []string {
	var urls []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			urls = append(urls, line)
		}
	}
	return urls
}

func fuzz(urls []string, payloads []string, config Config, bar *progressbar.ProgressBar) {
	// Create work channel
	type work struct {
		url     string
		payload string
	}

	workChan := make(chan work, config.Concurrency*2)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range workChan {
				testURL := strings.ReplaceAll(w.url, config.Keyword, w.payload)
				result := checkRedirect(testURL, w.payload, config)
				
				bar.Add(1)

				if result.Found {
					outputMutex.Lock()
					fmt.Printf("\n%s[FOUND]%s %s redirects to %s\n", 
						colorGreen, colorReset, result.URL, result.LocationHeader)
					results = append(results, result)
					atomic.AddInt64(&stats.VulnerabilitiesFound, 1)
					outputMutex.Unlock()
				} else if config.Verbose {
					outputMutex.Lock()
					fmt.Printf("\n%s[TESTING]%s %s\n", colorYellow, colorReset, testURL)
					outputMutex.Unlock()
				}

				atomic.AddInt64(&stats.TotalRequests, 1)
			}
		}()
	}

	// Feed work to workers
	go func() {
		for _, u := range urls {
			for _, p := range payloads {
				workChan <- work{url: u, payload: p}
			}
		}
		close(workChan)
	}()

	wg.Wait()
}

func checkRedirect(targetURL string, payload string, config Config) Result {
	result := Result{
		URL:     targetURL,
		Payload: payload,
		Found:   false,
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create request
	req, err := http.NewRequest(config.Method, targetURL, nil)
	if err != nil {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to create request: %v\n", colorRed, colorReset, err)
		}
		return result
	}

	req.Header.Set("User-Agent", "OpenRedirectFuzzer/1.0")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		if config.Verbose {
			fmt.Fprintf(os.Stderr, "%s[ERROR]%s Request failed: %v\n", colorRed, colorReset, err)
		}
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	// Check for redirect status codes (3xx)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			result.LocationHeader = location
			result.Found = true

			// Check if redirect is to an external domain (potential open redirect)
			if isExternalRedirect(targetURL, location) {
				result.Found = true
			}
		}
	}

	return result
}

func isExternalRedirect(originalURL, redirectLocation string) bool {
	// Parse original URL
	originalParsed, err := url.Parse(originalURL)
	if err != nil {
		return false
	}

	// Parse redirect location
	redirectParsed, err := url.Parse(redirectLocation)
	if err != nil {
		return false
	}

	// Check if it's a protocol-relative URL
	if strings.HasPrefix(redirectLocation, "//") {
		return true
	}

	// Check if it's a different domain
	if redirectParsed.Host != "" && redirectParsed.Host != originalParsed.Host {
		return true
	}

	return false
}

func saveResults(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s[ERROR]%s Failed to create output file: %v\n", colorRed, colorReset, err)
		return err
	}
	defer file.Close()

	for _, result := range results {
		line := fmt.Sprintf("[FOUND] %s (Payload: %s) redirects to %s\n", 
			result.URL, result.Payload, result.LocationHeader)
		if _, err := io.WriteString(file, line); err != nil {
			return err
		}
	}

	fmt.Printf("%s[INFO]%s Results saved to %s\n", colorBlue, colorReset, filename)
	return nil
}
