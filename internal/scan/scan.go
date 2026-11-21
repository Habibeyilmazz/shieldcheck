// Package scan runs passive security checks against a single URL.
package scan

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const Version = "0.1.1"

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
	Pass     Severity = "pass"
)

// Severities in report order.
var Severities = []Severity{Critical, High, Medium, Low, Info, Pass}

// penalty is what one finding of each severity costs out of 100.
var penalty = map[Severity]int{Critical: 40, High: 20, Medium: 8, Low: 3}

// Fix is a copy-paste remedy. Platform is one of Platforms' IDs, or "any".
type Fix struct {
	Platform string `json:"platform"`
	Where    string `json:"where,omitempty"` // file or config block the snippet belongs in
	Snippet  string `json:"snippet"`
}

type Finding struct {
	ID       string   `json:"id"`
	Category string   `json:"category"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Detail   string   `json:"detail,omitempty"` // what was observed
	Risk     string   `json:"risk,omitempty"`   // why it matters, in plain English
	Advice   string   `json:"advice,omitempty"` // how to fix it, in a sentence
	Fixes    []Fix    `json:"fixes,omitempty"`
	// Header is set when the fix is "send this response header".
	Header *Header `json:"header,omitempty"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Hop struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
}

type TLSInfo struct {
	Version   string    `json:"version"`
	Cipher    string    `json:"cipher"`
	Protocols []string  `json:"protocols"` // versions the server accepted
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	NotAfter  time.Time `json:"notAfter"`
	DaysLeft  int       `json:"daysLeft"`
}

type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	Target     string    `json:"target"`
	FinalURL   string    `json:"finalUrl"`
	ScannedAt  time.Time `json:"scannedAt"`
	DurationMs int64     `json:"durationMs"`
	Grade      string    `json:"grade"`
	Score      int       `json:"score"`
	Probed     bool      `json:"probed"`
	Redirects  []Hop     `json:"redirects"`
	TLS        *TLSInfo  `json:"tls,omitempty"`
	Findings   []Finding `json:"findings"`
	// HeaderFixes combines every "add this header" fix into one snippet per platform.
	HeaderFixes []Fix `json:"headerFixes,omitempty"`
}

// Count returns how many findings have the given severity.
func (r *Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

type Options struct {
	AllowPrivate bool          // permit loopback/private/link-local targets
	Probe        bool          // also request /.git/HEAD and /.env
	Timeout      time.Duration // whole scan; default 45s

	RootCAs   *x509.CertPool                                           // nil = system roots
	LookupTXT func(ctx context.Context, name string) ([]string, error) // nil = system resolver
}

// NormalizeURL validates user input. implied reports that the scheme was not
// given and https was assumed.
func NormalizeURL(raw string) (u *url.URL, implied bool, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, false, errors.New("no URL given")
	}
	if len(raw) > 2048 {
		return nil, false, errors.New("URL is too long")
	}
	// A "://" after the first / ? or # belongs to the path or query
	// ("site.example/?next=https://..."), not to a scheme.
	if i := strings.Index(raw, "://"); i < 0 || strings.ContainsAny(raw[:i], "/?#") {
		raw, implied = "https://"+raw, true
	}
	u, err = url.Parse(raw)
	if err != nil {
		return nil, false, fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, false, fmt.Errorf("unsupported scheme %q: only http and https can be scanned", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, false, errors.New("URL has no host")
	}
	if u.User != nil {
		return nil, false, errors.New("URLs with embedded credentials are not accepted")
	}
	if strings.ContainsFunc(u.Hostname(), func(r rune) bool { return r > unicode.MaxASCII }) {
		// The TLS and DNS checks compare names byte for byte, so a Unicode
		// hostname would be reported as a certificate that does not match.
		return nil, false, errors.New("hostnames with non-ASCII letters are not supported: give the domain in its xn-- form")
	}
	u.Fragment = ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u, implied, nil
}

// page is everything the checks look at.
type page struct {
	hops  []hop
	final hop
	body  []byte
}

// Run scans one URL and returns the graded report.
func Run(ctx context.Context, raw string, o Options) (*Report, error) {
	start := time.Now()
	target, implied, err := NormalizeURL(raw)
	if err != nil {
		return nil, err
	}
	if o.Timeout <= 0 {
		o.Timeout = 45 * time.Second
	}
	if o.LookupTXT == nil {
		o.LookupTXT = net.DefaultResolver.LookupTXT
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	c := newClient(o)
	defer c.http.CloseIdleConnections()

	hops, body, err := c.follow(ctx, target)
	var blocked *BlockedError
	if err != nil && implied && len(hops) == 0 && !errors.As(err, &blocked) {
		// No scheme was given and HTTPS is unreachable: fall back to HTTP so the
		// missing HTTPS gets reported instead of a bare connection error.
		plain := *target
		plain.Scheme = "http"
		if h, b, err2 := c.follow(ctx, &plain); err2 == nil {
			target, hops, body, err = &plain, h, b, nil
		}
	}
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // drop the 'Get "url":' prefix; the URL is named below
		}
		return nil, fmt.Errorf("could not fetch %s: %w", target, err)
	}
	p := &page{hops: hops, final: hops[len(hops)-1], body: body}

	rep := &Report{
		Tool: "shieldcheck", Version: Version,
		Target: target.String(), FinalURL: p.final.URL.String(),
		ScannedAt: start.UTC().Truncate(time.Second), Probed: o.Probe,
	}
	for _, h := range hops {
		rep.Redirects = append(rep.Redirects, Hop{h.URL.String(), h.Status})
	}

	findings := checkHeaders(p)
	findings = append(findings, checkCookies(p)...)
	findings = append(findings, checkContent(p)...)
	if s := p.final.Status; s >= 400 {
		// Not a fault of its own, but the reader must know the grade is not
		// about the page they asked for.
		findings = append(findings, Finding{ID: "page.error-status", Category: "content", Severity: Info,
			Title:  fmt.Sprintf("The page answered %d, so an error page was graded", s),
			Detail: fmt.Sprintf("%s answers %d %s.", p.final.URL, s, http.StatusText(s)),
			Advice: "Error pages often send different headers and cookies than working pages. Check the URL, and if the site blocks automated requests (401, 403, 429), scan from a network or address it allows."})
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(fs []Finding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}
	wg.Go(func() { add(checkTransport(ctx, c, p)) })
	wg.Go(func() {
		info, fs := checkTLS(ctx, c, p)
		mu.Lock()
		rep.TLS = info
		mu.Unlock()
		add(fs)
	})
	wg.Go(func() { add(checkDNS(ctx, o.LookupTXT, p.final.URL.Hostname())) })
	wg.Go(func() { add(checkSecurityTxt(ctx, c, p.final.URL)) })
	if o.Probe {
		wg.Go(func() { add(checkProbes(ctx, c, p.final.URL)) })
	}
	wg.Wait()

	finish(rep, findings)
	rep.DurationMs = time.Since(start).Milliseconds()
	return rep, nil
}

var categoryOrder = map[string]int{"transport": 0, "tls": 1, "headers": 2, "cookies": 3, "content": 4, "dns": 5, "disclosure": 6}

// finish sorts findings, grades the report and builds the combined header fix.
func finish(rep *Report, findings []Finding) {
	rank := map[Severity]int{}
	for i, s := range Severities {
		rank[s] = i
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Category != b.Category {
			return categoryOrder[a.Category] < categoryOrder[b.Category]
		}
		return a.ID < b.ID
	})
	rep.Findings = findings
	rep.Score, rep.Grade = Grade(findings)

	var pairs [][2]string
	for _, f := range findings {
		if f.Header != nil {
			pairs = append(pairs, [2]string{f.Header.Name, f.Header.Value})
		}
	}
	if len(pairs) > 1 {
		rep.HeaderFixes = headersFix(pairs)
	}
}

// Grade turns findings into a 0-100 score and a letter. Any critical finding
// is an F no matter what else is right.
func Grade(findings []Finding) (int, string) {
	score, critical := 100, false
	for _, f := range findings {
		score -= penalty[f.Severity]
		critical = critical || f.Severity == Critical
	}
	score = max(score, 0)
	switch {
	case critical || score < 45:
		return score, "F"
	case score < 60:
		return score, "D"
	case score < 75:
		return score, "C"
	case score < 90:
		return score, "B"
	}
	return score, "A"
}

// GradeBelow reports whether grade got is worse than min. Both must be one of A B C D F.
func GradeBelow(got, min string) bool {
	const order = "ABCDF"
	return strings.Index(order, got) > strings.Index(order, min)
}

// clip keeps observed, attacker-controlled strings short and on one line.
func clip(s string) string {
	s = strings.Join(strings.Fields(strings.ToValidUTF8(s, "?")), " ")
	if r := []rune(s); len(r) > 200 {
		s = string(r[:200]) + "…"
	}
	return s
}
