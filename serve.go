package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Habibeyilmazz/shieldcheck/internal/report"
	"github.com/Habibeyilmazz/shieldcheck/internal/scan"
)

func cmdServe(args []string, stderr io.Writer) int {
	fs := newFlagSet("serve", stderr)
	port := fs.Int("port", 4110, "")
	s := newServer()
	fs.BoolVar(&s.probeAllowed, "probe", false, "")
	fs.BoolVar(&s.opts.AllowPrivate, "allow-private", false, "")
	if rest, err := parseArgs(fs, args); err != nil {
		return exitCode(err)
	} else if len(rest) > 0 {
		fmt.Fprintf(stderr, "shieldcheck: serve takes no arguments, got %q\n", rest)
		return 2
	}
	// Loopback only, by design: the UI fetches whatever URL it is given.
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		fmt.Fprintf(stderr, "shieldcheck: %v\n", err)
		return 2
	}
	fmt.Fprintf(stderr, "shieldcheck UI on http://%s (Ctrl+C to stop)\n", ln.Addr())
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	fmt.Fprintf(stderr, "shieldcheck: %v\n", srv.Serve(ln))
	return 2
}

type cached struct {
	rep *scan.Report
	at  time.Time
}

type server struct {
	opts         scan.Options
	probeAllowed bool
	slots        chan struct{} // limits concurrent scans

	mu    sync.Mutex
	cache map[string]cached // recent reports, so downloads do not rescan
}

func newServer() *server {
	return &server{slots: make(chan struct{}, 4), cache: map[string]cached{}}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The UI is for the person at this machine only. Checking Host stops DNS
	// rebinding; checking Sec-Fetch-Site stops other websites from making the
	// browser trigger scans. Scans need the header to be present, so a browser
	// too old to send it cannot be used as a blind proxy either.
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	site := r.Header.Get("Sec-Fetch-Site")
	own := site == "same-origin" || site == "none"
	if (host != "127.0.0.1" && host != "localhost") || (site != "" && !own) || (r.URL.Path == "/scan" && !own) {
		http.Error(w, "forbidden: open the UI directly at its 127.0.0.1 address, in a browser that sends Sec-Fetch-Site", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nonce := make([]byte, 16)
	rand.Read(nonce)
	page := report.Page{Serve: true, ProbeAllowed: s.probeAllowed, Nonce: hex.EncodeToString(nonce)}
	h := w.Header()
	h.Set("Content-Security-Policy", fmt.Sprintf("default-src 'none'; style-src 'nonce-%[1]s'; script-src 'nonce-%[1]s'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'", page.Nonce))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Cache-Control", "no-store")

	switch r.URL.Path {
	case "/":
		s.render(w, http.StatusOK, page)
	case "/scan":
		s.handleScan(w, r, page)
	case "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) render(w http.ResponseWriter, status int, page report.Page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	report.HTML(w, page)
}

var unsafeFilename = regexp.MustCompile(`[^a-z0-9.-]+`)

func (s *server) handleScan(w http.ResponseWriter, r *http.Request, page report.Page) {
	q := r.URL.Query()
	page.URL = strings.TrimSpace(q.Get("url"))
	page.Probe = s.probeAllowed && q.Get("probe") == "1"

	rep, status, err := s.report(r.Context(), page.URL, page.Probe)
	if err != nil {
		page.Error = err.Error()
		s.render(w, status, page)
		return
	}
	download := func(contentType, ext string) {
		u, _ := url.Parse(rep.FinalURL)
		name := unsafeFilename.ReplaceAllString(strings.ToLower(u.Hostname()), "-")
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="shieldcheck-%s.%s"`, name, ext))
	}
	switch q.Get("format") {
	case "json":
		download("application/json", "json")
		report.JSON(w, rep)
	case "sarif":
		download("application/sarif+json", "sarif")
		report.SARIF(w, rep)
	case "html":
		download("text/html; charset=utf-8", "html")
		report.HTML(w, report.Page{Report: rep})
	default:
		page.Report = rep
		s.render(w, http.StatusOK, page)
	}
}

// report returns a cached report or runs a scan. On failure it returns the
// HTTP status to answer with.
func (s *server) report(ctx context.Context, raw string, probe bool) (*scan.Report, int, error) {
	if _, _, err := scan.NormalizeURL(raw); err != nil {
		return nil, http.StatusBadRequest, err
	}
	key := fmt.Sprint(raw, " ", probe)
	s.mu.Lock()
	c, ok := s.cache[key]
	s.mu.Unlock()
	if ok && time.Since(c.at) < 10*time.Minute {
		return c.rep, 0, nil
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return nil, http.StatusTooManyRequests, errors.New("four scans are already running; try again in a moment")
	}
	opts := s.opts
	opts.Probe = probe
	rep, err := scan.Run(ctx, raw, opts)
	var blocked *scan.BlockedError
	switch {
	case errors.As(err, &blocked):
		return nil, http.StatusBadRequest, fmt.Errorf("%s resolves to %s, a private or local address. Restart with \"shieldcheck serve --allow-private\" to scan internal hosts", raw, blocked.Addr)
	case err != nil:
		return nil, http.StatusBadGateway, err
	}
	s.mu.Lock()
	if len(s.cache) >= 32 {
		clear(s.cache)
	}
	s.cache[key] = cached{rep, time.Now()}
	s.mu.Unlock()
	return rep, 0, nil
}
