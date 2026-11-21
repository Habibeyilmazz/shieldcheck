package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	ok := map[string]string{
		"example.com":                          "https://example.com/",
		" https://example.com ":                "https://example.com/",
		"http://example.com/a?b#c":             "http://example.com/a?b",
		"example.com:8443/path":                "https://example.com:8443/path",
		"example.com/?next=http://other.test/": "https://example.com/?next=http://other.test/",
	}
	for in, want := range ok {
		u, _, err := NormalizeURL(in)
		if err != nil || u.String() != want {
			t.Errorf("NormalizeURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"", "ftp://example.com", "file:///etc/passwd", "javascript://x", "https://", "https://user:pw@example.com", "https://exa mple.com", "https://bücher.example", strings.Repeat("a", 3000)} {
		if u, _, err := NormalizeURL(in); err == nil {
			t.Errorf("NormalizeURL(%q) = %s, want an error", in, u)
		}
	}
	if _, implied, _ := NormalizeURL("example.com"); !implied {
		t.Error("scheme should be reported as implied")
	}
}

func TestGrade(t *testing.T) {
	n := func(sev Severity, count int) []Finding {
		return slices.Repeat([]Finding{{Severity: sev}}, count)
	}
	cases := []struct {
		findings []Finding
		score    int
		grade    string
	}{
		{nil, 100, "A"},
		{n(Pass, 9), 100, "A"},
		{n(Info, 5), 100, "A"},
		{n(Low, 3), 91, "A"},
		{n(Low, 4), 88, "B"},
		{n(High, 1), 80, "B"},
		{append(n(High, 1), n(Medium, 1)...), 72, "C"},
		{n(High, 2), 60, "C"},
		{append(n(High, 2), n(Low, 1)...), 57, "D"},
		{n(High, 3), 40, "F"},
		{n(Critical, 1), 60, "F"}, // a critical finding is always an F
		{n(High, 9), 0, "F"},
	}
	for _, tc := range cases {
		if score, grade := Grade(tc.findings); score != tc.score || grade != tc.grade {
			t.Errorf("Grade(%d findings) = %d %s, want %d %s", len(tc.findings), score, grade, tc.score, tc.grade)
		}
	}
	if !GradeBelow("C", "B") || GradeBelow("B", "B") || GradeBelow("A", "D") || !GradeBelow("F", "D") {
		t.Error("GradeBelow ordering is wrong")
	}
}

func TestEvaluateCSP(t *testing.T) {
	cases := map[string][]string{
		"default-src 'self'; base-uri 'self'":                                           {"csp.ok"},
		"default-src 'self'":                                                            {"csp.base-uri"},
		"img-src *; base-uri 'none'":                                                    {"csp.no-script-restriction"},
		"default-src 'self' 'unsafe-inline'; base-uri 'self'":                           {"csp.unsafe-inline"},
		"script-src 'self' 'unsafe-inline' 'unsafe-eval'; base-uri 'self'":              {"csp.unsafe-inline", "csp.unsafe-eval"},
		"script-src 'unsafe-inline' 'nonce-r4nd0m'; base-uri 'self'":                    {"csp.ok"}, // the nonce makes browsers ignore unsafe-inline
		"script-src 'unsafe-inline' https: 'strict-dynamic' 'nonce-x'; base-uri 'none'": {"csp.ok"},
		"script-src https: 'nonce-r4nd0m'; base-uri 'none'":                             {"csp.wildcard"}, // a nonce alone does not cancel https:
		"script-src 'unsafe-inline' 'strict-dynamic'; base-uri 'none'":                  {"csp.ok"},
		"SCRIPT-SRC https:; base-uri 'self'":                                            {"csp.wildcard"},
		"default-src 'self'; script-src *; base-uri 'self'":                             {"csp.wildcard"},
		"script-src 'self'; script-src *; base-uri 'self'":                              {"csp.ok"}, // the first directive wins
		"default-src 'none'; script-src data:; base-uri 'self'":                         {"csp.wildcard"},
	}
	for policy, want := range cases {
		var got []string
		for _, f := range evaluateCSP(parseCSP(policy), policy) {
			got = append(got, f.ID)
		}
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", policy, got, want)
		}
	}
}

func headerFindings(h http.Header, body string) map[string]Severity {
	u, _ := url.Parse("https://fixture.test/")
	hp := hop{URL: u, Status: 200, Header: h}
	return ids(checkHeaders(&page{hops: []hop{hp}, final: hp, body: []byte(body)}))
}

func TestHeaderVariants(t *testing.T) {
	cases := []struct {
		name, header, value, body, want string
	}{
		{"HSTS max-age 0", "Strict-Transport-Security", "max-age=0", "", "hsts.disabled"},
		{"HSTS without max-age", "Strict-Transport-Security", "includeSubDomains", "", "hsts.disabled"},
		{"HSTS short", "Strict-Transport-Security", "max-age=86400; includeSubDomains", "", "hsts.short"},
		{"HSTS quoted", "Strict-Transport-Security", `max-age="31536000"; includeSubDomains; preload`, "", "hsts.ok"},
		{"HSTS no subdomains", "Strict-Transport-Security", "max-age=31536000", "", "hsts.no-subdomains"},
		{"XFO sameorigin", "X-Frame-Options", "sameorigin", "", "frame.ok"},
		{"XFO allow-from is obsolete", "X-Frame-Options", "ALLOW-FROM https://a.test", "", "frame.missing"},
		{"frame-ancestors", "Content-Security-Policy", "frame-ancestors 'self'", "", "frame.ok"},
		{"frame-ancestors wildcard", "Content-Security-Policy", "frame-ancestors *", "", "frame.missing"},
		{"report-only CSP", "Content-Security-Policy-Report-Only", "default-src 'self'", "", "csp.report-only"},
		{"meta CSP", "X-Unrelated", "1", `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; base-uri 'self'">`, "csp.meta-only"},
		{"meta CSP cannot stop framing", "X-Unrelated", "1", `<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">`, "frame.missing"},
		{"referrer unsafe", "Referrer-Policy", "no-referrer, unsafe-url", "", "referrer.unsafe"},
		{"referrer fallback list", "Referrer-Policy", "no-referrer, strict-origin-when-cross-origin", "", "referrer.ok"},
		{"nosniff case", "X-Content-Type-Options", "NoSniff", "", "xcto.ok"},
		{"server without version", "Server", "nginx", "", "xcto.missing"},
		{"server with version", "Server", "nginx/1.18.0", "", "disclosure.version"},
	}
	for _, tc := range cases {
		got := headerFindings(http.Header{tc.header: {tc.value}}, tc.body)
		if _, ok := got[tc.want]; !ok {
			t.Errorf("%s: want %s, got %v", tc.name, tc.want, got)
		}
	}
	// frame-ancestors wins over X-Frame-Options when both are sent.
	both := headerFindings(http.Header{"Content-Security-Policy": {"frame-ancestors *"}, "X-Frame-Options": {"DENY"}}, "")
	if both["frame.missing"] != Medium || both["frame.ok"] != "" {
		t.Errorf("frame-ancestors * with X-Frame-Options: DENY: %v", both)
	}
	// A product name with a digit in it is not a version number.
	for _, server := range []string{"nginx", "AmazonS3", "ECS (dcb/7F84)", "HTTP3-edge"} {
		if got := headerFindings(http.Header{"Server": {server}}, ""); got["disclosure.version"] != "" {
			t.Errorf("Server: %s was reported as a version disclosure", server)
		}
	}
	for _, server := range []string{"Apache/2.4.58 (Ubuntu)", "Microsoft-IIS/10.0", "Jetty(9.4.51)"} {
		if got := headerFindings(http.Header{"Server": {server}}, ""); got["disclosure.version"] != Low {
			t.Errorf("Server: %s was not reported as a version disclosure", server)
		}
	}
}

func TestCookies(t *testing.T) {
	u, _ := url.Parse("https://fixture.test/")
	check := func(cookies ...*http.Cookie) map[string]Severity {
		h := hop{URL: u, Cookies: cookies}
		return ids(checkCookies(&page{hops: []hop{h}, final: h}))
	}
	got := check(&http.Cookie{Name: "PHPSESSID"}, &http.Cookie{Name: "csrftoken", Secure: true, SameSite: http.SameSiteStrictMode})
	if got["cookie.no-secure"] != Medium || got["cookie.no-httponly"] != Medium || got["cookie.no-samesite"] != Low {
		t.Errorf("session cookie without flags: %v", got)
	}
	// A CSRF cookie that scripts must read is fine without HttpOnly; a theme cookie without Secure is only low.
	got = check(&http.Cookie{Name: "csrftoken", Secure: true, SameSite: http.SameSiteLaxMode}, &http.Cookie{Name: "theme", SameSite: http.SameSiteLaxMode})
	if _, bad := got["cookie.no-httponly"]; bad || got["cookie.no-secure"] != Low {
		t.Errorf("non-session cookies: %v", got)
	}
	// The same name set by two hosts in a redirect chain is two cookies: the secure one does not hide the other.
	other, _ := url.Parse("https://login.fixture.test/")
	hops := []hop{{URL: other, Cookies: []*http.Cookie{{Name: "sid", HttpOnly: true, SameSite: http.SameSiteLaxMode}}},
		{URL: u, Cookies: []*http.Cookie{{Name: "sid", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}}}}
	if got := ids(checkCookies(&page{hops: hops, final: hops[1]})); got["cookie.no-secure"] != Medium {
		t.Errorf("cookies from two hosts: %v", got)
	}
	if got := check(); got["cookie.none"] != Pass {
		t.Errorf("no cookies: %v", got)
	}
}

func TestMixedContentRespectsUpgradeInsecureRequests(t *testing.T) {
	u, _ := url.Parse("https://fixture.test/")
	h := hop{URL: u, Header: http.Header{"Content-Type": {"text/html"}, "Content-Security-Policy": {"upgrade-insecure-requests"}}}
	body := `<SCRIPT SRC='http://a.test/x.js'></SCRIPT><form action=http://a.test/post><iframe src="https://ok.test/">`
	fs := checkContent(&page{hops: []hop{h}, final: h, body: []byte(body)})
	if len(fs) != 1 || fs[0].ID != "mixed.active" || fs[0].Severity != Info || !strings.HasPrefix(fs[0].Detail, "2 found") {
		t.Errorf("got %+v", fs)
	}
}

func TestHTTPRedirectFinding(t *testing.T) {
	// Each case is the chain of plain-HTTP answers: status and Location per hop.
	type answer struct {
		status   int
		location string
	}
	cases := []struct {
		chain []answer
		want  string
	}{
		{[]answer{{301, "https://fixture.test/"}}, "https.redirect-ok"},
		{[]answer{{308, "https://www.fixture.test/"}}, "https.redirect-ok"},
		{[]answer{{200, ""}}, "https.no-redirect"},
		{[]answer{{403, ""}}, "https.http-other"},
		{[]answer{{302, ""}}, "https.http-other"},
		{[]answer{{301, "http://www.fixture.test/"}, {301, "https://www.fixture.test/"}}, "https.redirect-ok"},
		{[]answer{{302, "/home"}, {200, ""}}, "https.no-redirect"},
	}
	for _, tc := range cases {
		var chain []hop
		for i, a := range tc.chain {
			u, _ := url.Parse(fmt.Sprintf("http://hop%d.fixture.test/", i))
			h := hop{URL: u, Status: a.status, Header: http.Header{}}
			if a.location != "" {
				h.Header.Set("Location", a.location)
			}
			chain = append(chain, h)
		}
		if got := httpRedirectFinding(chain); got.ID != tc.want {
			t.Errorf("%v: got %s, want %s", tc.chain, got.ID, tc.want)
		}
	}
}

func TestMailDomains(t *testing.T) {
	cases := map[string][]string{
		"www.example.com":       {"example.com"},
		"app.eu.example.com":    {"app.eu.example.com", "eu.example.com", "example.com"},
		"Example.COM.":          {"example.com"},
		"127.0.0.1":             nil,
		"::1":                   nil,
		"localhost":             nil,
		"dev.localhost":         nil,
		"a.b.c.d.e.example.com": {"a.b.c.d.e.example.com", "b.c.d.e.example.com", "c.d.e.example.com", "d.e.example.com"},
		// The walk stops at the registrable domain, not at the registry above it.
		"www.example.com.tr": {"example.com.tr"},
		"shop.example.co.uk": {"shop.example.co.uk", "example.co.uk"},
		"example.co":         {"example.co"},
		"www.gov.uk":         {"gov.uk"}, // a site of its own, and the one that was asked about
	}
	for host, want := range cases {
		if got := mailDomains(host); !slices.Equal(got, want) {
			t.Errorf("mailDomains(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDNSChecks(t *testing.T) {
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	zone := func(records map[string][]string) lookupTXT {
		return func(_ context.Context, name string) ([]string, error) {
			if r, ok := records[name]; ok {
				return r, nil
			}
			return nil, notFound
		}
	}
	cases := []struct {
		name    string
		host    string
		records map[string][]string
		want    map[string]Severity
	}{
		{"all good", "www.example.com", map[string][]string{
			"example.com":        {"google-site-verification=abc", "v=spf1 include:_spf.mail.test -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; rua=mailto:d@example.com"},
		}, map[string]Severity{"spf.ok": Pass, "dmarc.ok": Pass}},
		{"nothing", "example.com", nil, map[string]Severity{"spf.missing": Medium, "dmarc.missing": Medium}},
		{"records inherited from the parent domain", "app.example.com", map[string][]string{
			"example.com":        {"v=spf1 ~all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject; sp=none"},
		}, map[string]Severity{"spf.ok": Pass, "dmarc.none": Low}},
		{"permissive", "example.com", map[string][]string{
			"example.com":        {"v=spf1 +all"},
			"_dmarc.example.com": {"v=DMARC1; p=none"},
		}, map[string]Severity{"spf.pass-all": High, "dmarc.none": Low}},
		{"broken", "example.com", map[string][]string{
			"example.com":        {"v=spf1 -all", "v=spf1 mx -all"},
			"_dmarc.example.com": {"v=DMARC1; pct=100"},
		}, map[string]Severity{"spf.multiple": Medium, "dmarc.invalid": Medium}},
		{"two DMARC records", "example.com", map[string][]string{
			"example.com":        {"v=spf1 -all"},
			"_dmarc.example.com": {"v=DMARC1; p=reject", "v=DMARC1; p=none"},
		}, map[string]Severity{"spf.ok": Pass, "dmarc.multiple": Medium}},
		{"spf lookalike is ignored", "example.com", map[string][]string{
			"example.com": {"v=spf10 -all", "v=spf1 mx"},
		}, map[string]Severity{"spf.no-all": Low, "dmarc.missing": Medium}},
		{"ip address", "192.0.2.10", nil, map[string]Severity{"dns.skipped": Info}},
	}
	for _, tc := range cases {
		got := ids(checkDNS(context.Background(), zone(tc.records), tc.host))
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
		for id, sev := range tc.want {
			if got[id] != sev {
				t.Errorf("%s: %s = %q, want %q (all: %v)", tc.name, id, got[id], sev, got)
			}
		}
	}

	// SPF found on a parent domain must say so: it does not cover the subdomain.
	for _, f := range checkDNS(context.Background(), zone(map[string][]string{"example.com": {"v=spf1 -all"}}), "app.example.com") {
		if f.ID == "spf.ok" && !strings.Contains(f.Detail, "app.example.com has no SPF record of its own") {
			t.Errorf("inherited SPF detail = %q", f.Detail)
		}
	}

	// A resolver failure must not be reported as "no record".
	failing := func(context.Context, string) ([]string, error) { return nil, errors.New("i/o timeout") }
	got := ids(checkDNS(context.Background(), failing, "example.com"))
	if got["spf.unchecked"] != Info || got["dmarc.unchecked"] != Info || len(got) != 2 {
		t.Errorf("resolver failure: %v", got)
	}
}

func TestHeadersFixSnippetsAreWellFormed(t *testing.T) {
	fixes := headersFix([][2]string{{"Content-Security-Policy", strictCSP}, {"X-Frame-Options", "SAMEORIGIN"}})
	if len(fixes) != len(Platforms) {
		t.Fatalf("got %d fixes, want %d", len(fixes), len(Platforms))
	}
	for i, f := range fixes {
		if f.Platform != Platforms[i].ID || f.Where == "" {
			t.Errorf("fix %d = %+v", i, f)
		}
		for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "frame-ancestors 'self'"} {
			if !strings.Contains(f.Snippet, header) {
				t.Errorf("%s snippet lacks %q", f.Platform, header)
			}
		}
		if f.Platform == "vercel" { // vercel.json must be pasteable as strict JSON
			var v struct {
				Headers []struct {
					Source  string
					Headers []struct{ Key, Value string }
				}
			}
			if err := json.Unmarshal([]byte(f.Snippet), &v); err != nil || len(v.Headers) != 1 || len(v.Headers[0].Headers) != 2 || v.Headers[0].Headers[0].Value != strictCSP {
				t.Errorf("vercel snippet is not the expected JSON (%v):\n%s", err, f.Snippet)
			}
		}
	}
}

func TestClip(t *testing.T) {
	if got := clip("  a\tb\r\n c  "); got != "a b c" {
		t.Errorf("clip whitespace = %q", got)
	}
	long := clip(strings.Repeat("é", 300))
	if n := len([]rune(long)); n != 201 || !strings.HasSuffix(long, "…") {
		t.Errorf("clip kept %d runes", n)
	}
	if got := clip("ok\xff\xfe"); got != "ok?" {
		t.Errorf("clip invalid UTF-8 = %q", got)
	}
}
