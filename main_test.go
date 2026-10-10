package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClassifyRedirect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		original       string
		location       string
		classification string
		external       bool
		found          bool
	}{
		{
			name:           "external absolute redirect",
			original:       "https://example.com/login?next=FUZZ",
			location:       "https://evil.example/landing",
			classification: "external-http-redirect",
			external:       true,
			found:          true,
		},
		{
			name:           "relative redirect same origin",
			original:       "https://example.com/login?next=FUZZ",
			location:       "/dashboard",
			classification: "same-origin",
			external:       false,
			found:          false,
		},
		{
			name:           "protocol relative external redirect",
			original:       "https://example.com/login?next=FUZZ",
			location:       "//evil.example/path",
			classification: "external-http-redirect",
			external:       true,
			found:          true,
		},
		{
			name:           "same host absolute redirect",
			original:       "https://example.com/login?next=FUZZ",
			location:       "https://example.com/account",
			classification: "same-origin",
			external:       false,
			found:          false,
		},
		{
			name:           "default port normalization",
			original:       "http://example.com/login?next=FUZZ",
			location:       "http://EXAMPLE.com:80/path",
			classification: "same-origin",
			external:       false,
			found:          false,
		},
		{
			name:           "dangerous scheme javascript",
			original:       "https://example.com/login?next=FUZZ",
			location:       "javascript:alert(1)",
			classification: "suspicious-scheme",
			external:       true,
			found:          true,
		},
		{
			name:           "malformed location header",
			original:       "https://example.com/login?next=FUZZ",
			location:       "http://[::1",
			classification: "malformed-location",
			external:       false,
			found:          false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			classification, _, _, external, found := classifyRedirect(tc.original, tc.location)
			if classification != tc.classification {
				t.Fatalf("classification = %q, want %q", classification, tc.classification)
			}
			if external != tc.external {
				t.Fatalf("external = %v, want %v", external, tc.external)
			}
			if found != tc.found {
				t.Fatalf("found = %v, want %v", found, tc.found)
			}
		})
	}
}

func TestCheckHeadFallbackToGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodHead:
			w.WriteHeader(http.StatusMethodNotAllowed)
		case http.MethodGet:
			w.Header().Set("Location", "https://evil.example")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	cfg := Config{
		Method:       http.MethodHead,
		Timeout:      2 * time.Second,
		Concurrency:  1,
		UserAgent:    "test-agent",
		HeadFallback: true,
	}
	scanner := newScanner(cfg)

	result := scanner.Check(context.Background(), server.URL, "payload", server.URL)
	if !result.FallbackUsed {
		t.Fatalf("expected HEAD fallback to GET")
	}
	if result.Method != http.MethodGet {
		t.Fatalf("method = %s, want GET", result.Method)
	}
	if !result.Found {
		t.Fatalf("expected external redirect finding")
	}
	if result.Classification != "external-http-redirect" {
		t.Fatalf("classification = %s, want external-http-redirect", result.Classification)
	}
}

func TestCheckContextCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := Config{
		Method:       http.MethodGet,
		Timeout:      3 * time.Second,
		Concurrency:  1,
		UserAgent:    "test-agent",
		HeadFallback: false,
	}
	scanner := newScanner(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := scanner.Check(ctx, server.URL, "payload", server.URL)
	if result.Error == "" {
		t.Fatalf("expected cancellation error")
	}
	if result.Classification != "request-error" {
		t.Fatalf("classification = %s, want request-error", result.Classification)
	}
}

func TestSaveResultsJSONOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "results.json")

	results := []Result{
		{
			URL:            "https://b.example",
			Payload:        "p2",
			Method:         "GET",
			StatusCode:     302,
			LocationHeader: "https://evil.example",
			Classification: "external-http-redirect",
			Reason:         "Redirect target host differs from origin",
			Found:          true,
			External:       true,
		},
		{
			URL:            "https://a.example",
			Payload:        "p1",
			Method:         "HEAD",
			StatusCode:     301,
			LocationHeader: "/ok",
			Classification: "same-origin",
			Reason:         "Redirect remained on the same origin",
			Found:          false,
		},
	}

	stats := FuzzerStats{TotalRequests: 2, SuccessfulTests: 2, VulnerabilitiesFound: 1}
	if err := saveResults(outputFile, "json", results, stats); err != nil {
		t.Fatalf("saveResults() error = %v", err)
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(content, &report); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if report.Summary.TotalRequests != 2 {
		t.Fatalf("total_requests = %d, want 2", report.Summary.TotalRequests)
	}
	if len(report.Results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(report.Results))
	}
	if report.Results[0].URL != "https://a.example" {
		t.Fatalf("results not deterministically sorted by URL")
	}
}

func TestResolveOutputFormatAuto(t *testing.T) {
	t.Parallel()

	format, err := resolveOutputFormat("auto", "scan-results.json")
	if err != nil {
		t.Fatalf("resolveOutputFormat() error = %v", err)
	}
	if format != "json" {
		t.Fatalf("format = %s, want json", format)
	}

	format, err = resolveOutputFormat("auto", "scan-results.txt")
	if err != nil {
		t.Fatalf("resolveOutputFormat() error = %v", err)
	}
	if format != "text" {
		t.Fatalf("format = %s, want text", format)
	}
}

func TestValidateConfigRejectsInvalidMethod(t *testing.T) {
	t.Parallel()

	cfg := Config{
		PayloadsFile: "payloads.txt",
		Keyword:      "FUZZ",
		Concurrency:  10,
		Timeout:      10 * time.Second,
		Method:       "TRACE",
		OutputFormat: "auto",
	}

	err := validateConfig(&cfg)
	if err == nil {
		t.Fatalf("expected validation error")
	}
	if !strings.Contains(err.Error(), "unsupported method") {
		t.Fatalf("unexpected error: %v", err)
	}
}
