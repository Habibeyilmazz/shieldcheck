package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Habibeyilmazz/shieldcheck/internal/scan"
)

// fixture is a local plain-HTTP site with no security headers: a D, because
// plain HTTP is not held against a loopback address.
func fixture(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html>fixture</html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cli(args ...string) (code int, stdout, stderr string) {
	var out, errw bytes.Buffer
	code = run(args, &out, &errw)
	return code, out.String(), errw.String()
}

func TestParseArgsAcceptsFlagsAnywhere(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	format := fs.String("format", "", "")
	probe := fs.Bool("probe", false, "")
	pos, err := parseArgs(fs, []string{"--probe", "example.com", "--format", "json", "extra"})
	if err != nil || !slices.Equal(pos, []string{"example.com", "extra"}) || *format != "json" || !*probe {
		t.Errorf("pos=%v format=%q probe=%v err=%v", pos, *format, *probe, err)
	}
	*probe = false
	pos, err = parseArgs(fs, []string{"a", "--", "--probe", "b"})
	if err != nil || !slices.Equal(pos, []string{"a", "--probe", "b"}) || *probe {
		t.Errorf("after --: pos=%v probe=%v err=%v", pos, *probe, err)
	}
}

func TestScanCommand(t *testing.T) {
	srv := fixture(t)

	code, out, _ := cli("scan", srv.URL, "--allow-private", "--format", "json")
	var rep scan.Report
	if err := json.Unmarshal([]byte(out), &rep); code != 0 || err != nil || rep.Grade != "D" {
		t.Fatalf("json scan: code %d, err %v, grade %q", code, err, rep.Grade)
	}

	code, out, _ = cli(srv.URL, "--allow-private", "--fix", "Netlify") // "scan" is optional, platform names are not case-sensitive
	if code != 0 || !strings.Contains(out, "Grade D") || !strings.Contains(out, "[[headers]]") || strings.Contains(out, "\x1b[") {
		t.Errorf("terminal scan: code %d\n%s", code, out)
	}

	code, _, errOut := cli("scan", srv.URL, "--allow-private", "--min-grade", "b", "--format", "sarif")
	if code != 1 || !strings.Contains(errOut, "below the required B") {
		t.Errorf("--min-grade B on a D site: code %d, stderr %q", code, errOut)
	}

	file := filepath.Join(t.TempDir(), "report.html")
	code, out, errOut = cli("scan", srv.URL, "--allow-private", "--format", "html", "--output", file)
	html, _ := os.ReadFile(file)
	if code != 0 || out != "" || !strings.Contains(string(html), `aria-label="Grade D"`) || !strings.Contains(errOut, "report written to") {
		t.Errorf("--output: code %d, stdout %q, stderr %q, file %d bytes", code, out, errOut, len(html))
	}
}

func TestScanCommandErrors(t *testing.T) {
	srv := fixture(t)
	cases := map[string][]string{
		"non-public address":  {"scan", srv.URL},
		"exactly one URL":     {"scan"},
		"unknown --format":    {"scan", "example.com", "--format", "xml"},
		"--min-grade must be": {"scan", "example.com", "--min-grade", "E"},
		"unknown --fix":       {"scan", "example.com", "--fix", "iis"},
		"unsupported scheme":  {"scan", "ftp://example.com"},
		"not defined: -bogus": {"scan", "example.com", "--bogus"},
		"serve takes no":      {"serve", "extra"},
		"Usage:":              {},
	}
	for want, args := range cases {
		if code, _, errOut := cli(args...); code != 2 || !strings.Contains(errOut, want) {
			t.Errorf("%v: code %d, stderr %q; want 2 and %q", args, code, errOut, want)
		}
	}
	for _, args := range [][]string{{"help"}, {"scan", "--help"}, {"serve", "-h"}} {
		if code, out, errOut := cli(args...); code != 0 || !strings.Contains(out+errOut, "Usage:") {
			t.Errorf("%v: code %d, want 0 and the usage text", args, code)
		}
	}
	if code, out, _ := cli("version"); code != 0 || !strings.Contains(out, scan.Version) {
		t.Errorf("version: %d %q", code, out)
	}
}

func get(s *server, target string, edit func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", target, nil)
	req.Host = "127.0.0.1:4110"
	req.Header.Set("Sec-Fetch-Site", "same-origin") // what a browser sends from the UI's own pages
	if edit != nil {
		edit(req)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func TestServeUI(t *testing.T) {
	srv := fixture(t)
	s := newServer()
	s.opts.AllowPrivate = true
	query := "/scan?url=" + srv.URL

	home := get(s, "/", nil)
	if home.Code != 200 || !strings.Contains(home.Body.String(), "Scan site") || strings.Contains(home.Body.String(), `name="probe"`) {
		t.Errorf("home page: %d", home.Code)
	}
	// The page's inline style and script must carry the nonce its own CSP allows.
	nonce := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(home.Header().Get("Content-Security-Policy"))
	if nonce == nil || strings.Count(home.Body.String(), `nonce="`+nonce[1]+`"`) != 2 {
		t.Errorf("CSP %q does not match the nonces in the page", home.Header().Get("Content-Security-Policy"))
	}
	if again := get(s, "/", nil); again.Header().Get("Content-Security-Policy") == home.Header().Get("Content-Security-Policy") {
		t.Error("nonce is reused between responses")
	}

	page := get(s, query, nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `aria-label="Grade D"`) || !strings.Contains(page.Body.String(), "format=sarif") {
		t.Errorf("scan page: %d\n%s", page.Code, page.Body.String())
	}

	dl := get(s, query+"&format=json", nil)
	var rep scan.Report
	if err := json.Unmarshal(dl.Body.Bytes(), &rep); err != nil || rep.Grade != "D" || !strings.Contains(dl.Header().Get("Content-Disposition"), `filename="shieldcheck-127.0.0.1.json"`) {
		t.Errorf("json download: %v, %q", err, dl.Header().Get("Content-Disposition"))
	}
	if rep.ScannedAt.IsZero() || len(s.cache) != 1 {
		t.Errorf("download should reuse the cached report; cache has %d entries", len(s.cache))
	}
	if dl := get(s, query+"&format=html", nil); strings.Contains(dl.Body.String(), "<form") {
		t.Error("downloaded HTML report should not contain the scan form")
	}

	// Probing is off unless the server was started with --probe.
	if get(s, query+"&probe=1", nil); len(s.cache) != 1 {
		t.Error("probe=1 was honoured without --probe")
	}
}

func TestServeRefusesWhatItShould(t *testing.T) {
	srv := fixture(t)
	s := newServer() // private targets not allowed
	cases := []struct {
		name   string
		target string
		edit   func(*http.Request)
		status int
		want   string
	}{
		{"private target", "/scan?url=" + srv.URL, nil, 400, "--allow-private"},
		{"bad scheme", "/scan?url=file:///etc/passwd", nil, 400, "unsupported scheme"},
		{"missing url", "/scan", nil, 400, "no URL given"},
		{"DNS rebinding", "/", func(r *http.Request) { r.Host = "attacker.test:4110" }, 403, "forbidden"},
		{"cross-site request", "/scan?url=" + srv.URL, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403, "forbidden"},
		{"cross-site home page", "/", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }, 403, "forbidden"},
		{"scan without fetch metadata", "/scan?url=" + srv.URL, func(r *http.Request) { r.Header.Del("Sec-Fetch-Site") }, 403, "forbidden"},
		{"POST", "/scan", func(r *http.Request) { r.Method = "POST" }, 405, "not allowed"},
		{"unknown path", "/admin", nil, 404, "not found"},
	}
	for _, tc := range cases {
		rec := get(s, tc.target, tc.edit)
		if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.want) {
			t.Errorf("%s: status %d, want %d with %q\n%s", tc.name, rec.Code, tc.status, tc.want, rec.Body.String())
		}
	}
	// Typing the address (Sec-Fetch-Site: none) and tools that send no fetch metadata can load the form.
	for _, site := range []string{"none", ""} {
		if ok := get(s, "/", func(r *http.Request) { r.Host = "localhost:4110"; r.Header.Set("Sec-Fetch-Site", site) }); ok.Code != 200 {
			t.Errorf("home page with Sec-Fetch-Site %q: %d", site, ok.Code)
		}
	}

	// With every slot busy a new scan is turned away instead of queued.
	for range cap(s.slots) {
		s.slots <- struct{}{}
	}
	if rec := get(s, "/scan?url=https://example.com", nil); rec.Code != 429 {
		t.Errorf("busy server: status %d, want 429", rec.Code)
	}
}

// Third-party actions run with the job's token, so each is pinned to a full
// commit SHA (a tag can be moved), and checkout must not leave the token in
// .git/config for later steps.
func TestWorkflowsPinActionsAndDropCredentials(t *testing.T) {
	files, _ := filepath.Glob(".github/workflows/*.yml")
	files = append(files, "action.yml")
	uses := regexp.MustCompile(`(?m)^\s*- uses: (\S+)`)
	pinned := regexp.MustCompile(`^[\w.-]+/[\w./-]+@[0-9a-f]{40}$`)
	for _, name := range files {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range uses.FindAllStringSubmatch(string(b), -1) {
			if !strings.HasPrefix(m[1], "./") && !pinned.MatchString(m[1]) {
				t.Errorf("%s: %s is not pinned to a commit SHA", name, m[1])
			}
		}
		if c, p := strings.Count(string(b), "actions/checkout@"), strings.Count(string(b), "persist-credentials: false"); c != p {
			t.Errorf("%s: %d checkouts but %d with persist-credentials: false", name, c, p)
		}
	}
}
