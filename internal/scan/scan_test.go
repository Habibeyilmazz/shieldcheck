package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---- fixtures ----

// goodSite does everything right.
func goodSite() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Contact: mailto:security@fixture.test\nExpires: %s\n", time.Now().AddDate(0, 6, 0).UTC().Format(time.RFC3339))
	})
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
		fmt.Fprint(w, `<!doctype html><title>ok</title><img src="/logo.png"><script src="/app.js"></script>`)
	})
	return mux
}

// badSite does everything wrong, and leaks /.git and /.env.
func badSite() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/HEAD", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ref: refs/heads/main\n") })
	mux.HandleFunc("/.env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "DB_PASSWORD=fixture-not-a-real-secret\n")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// A "soft 404": HTML with status 200, as many single-page apps do.
			fmt.Fprint(w, "<html>not found</html>")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "fixture/1.2.3")
		w.Header().Set("X-Powered-By", "PHP/5.6")
		http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: "x"})
		http.SetCookie(w, &http.Cookie{Name: "theme", Value: "dark"})
		fmt.Fprint(w, `<html><!-- <script src="http://commented.test/x.js"></script> -->
<script src="http://cdn.fixture.test/lib.js"></script>
<link rel="stylesheet" href="http://cdn.fixture.test/site.css">
<link rel="canonical" href="http://fixture.test/">
<img src="http://img.fixture.test/a.png"><a href="http://fixture.test/">link</a></html>`)
	})
	return mux
}

func selfSigned(t *testing.T, notAfter time.Time, dnsName string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	if dnsName != "" {
		tmpl.DNSNames = []string{dnsName}
	} else {
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func tlsServer(t *testing.T, h http.Handler, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = cfg
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected legacy handshakes are expected
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func trust(srv *httptest.Server) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return pool
}

func run(t *testing.T, url string, o Options) *Report {
	t.Helper()
	o.AllowPrivate = true
	rep, err := Run(context.Background(), url, o)
	if err != nil {
		t.Fatalf("Run(%s): %v", url, err)
	}
	return rep
}

func ids(fs []Finding) map[string]Severity {
	m := map[string]Severity{}
	for _, f := range fs {
		m[f.ID] = f.Severity
	}
	return m
}

func wantIDs(t *testing.T, got map[string]Severity, want ...string) {
	t.Helper()
	for _, id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("missing finding %s; got %v", id, got)
		}
	}
}

// ---- end to end ----

func TestGoodSiteGetsA(t *testing.T) {
	srv := tlsServer(t, goodSite(), nil)
	rep := run(t, srv.URL, Options{RootCAs: trust(srv), Probe: true})
	if rep.Grade != "A" || rep.Score != 100 {
		t.Errorf("grade %s score %d, want A 100", rep.Grade, rep.Score)
	}
	for _, f := range rep.Findings {
		if f.Severity != Pass && f.Severity != Info {
			t.Errorf("unexpected %s finding %s: %s", f.Severity, f.ID, f.Detail)
		}
	}
	wantIDs(t, ids(rep.Findings), "csp.ok", "hsts.ok", "frame.ok", "cookie.ok", "tls.cert-ok", "tls.protocols-ok", "securitytxt.ok", "mixed.none", "exposed.none")
	if rep.TLS == nil || rep.TLS.Version != "TLS 1.3" {
		t.Errorf("TLS info = %+v", rep.TLS)
	}
}

func TestBadPlainHTTPSite(t *testing.T) {
	srv := httptest.NewServer(badSite())
	defer srv.Close()
	rep := run(t, srv.URL, Options{Probe: true})
	if rep.Grade != "F" {
		t.Errorf("grade %s, want F", rep.Grade)
	}
	got := ids(rep.Findings)
	wantIDs(t, got, "https.local", "csp.missing", "frame.missing", "xcto.missing", "referrer.missing", "permissions.missing",
		"coop.missing", "cookie.no-httponly", "cookie.no-samesite", "disclosure.version", "securitytxt.missing", "exposed.git", "exposed.env")
	for _, id := range []string{"hsts.missing", "cookie.no-secure", "mixed.active"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s only makes sense over HTTPS, but was reported for an HTTP site", id)
		}
	}
	if len(rep.HeaderFixes) != len(Platforms) {
		t.Errorf("combined header fixes = %d, want one per platform", len(rep.HeaderFixes))
	}
	for _, f := range rep.Findings {
		if strings.Contains(f.Detail+f.Title, "fixture-not-a-real-secret") {
			t.Errorf("%s leaks the contents of .env into the report", f.ID)
		}
		if f.Severity != Pass && f.Severity != Info && f.Risk == "" {
			t.Errorf("%s has no risk explanation", f.ID)
		}
		if f.Severity != Pass && f.Severity != Info && len(f.Fixes) == 0 {
			t.Errorf("%s has no fix", f.ID)
		}
	}
}

func TestPlainHTTPIsCriticalExceptOnLoopback(t *testing.T) {
	transport := func(raw string) Finding {
		u, _ := url.Parse(raw)
		h := hop{URL: u, Status: 200, Header: http.Header{}}
		return checkTransport(context.Background(), nil, &page{hops: []hop{h}, final: h})[0]
	}
	for _, raw := range []string{"http://fixture.test/", "http://192.168.1.20/", "http://localhost.fixture.test/"} {
		if f := transport(raw); f.ID != "https.missing" || f.Severity != Critical {
			t.Errorf("%s: got %s (%s), want https.missing (critical)", raw, f.ID, f.Severity)
		}
	}
	for _, raw := range []string{"http://localhost:3000/", "http://app.localhost/", "http://127.0.0.1:8080/", "http://[::1]:8080/", "http://LOCALHOST./"} {
		if f := transport(raw); f.ID != "https.local" || f.Severity != Info {
			t.Errorf("%s: got %s (%s), want https.local (info)", raw, f.ID, f.Severity)
		}
	}

	// So a dev server that sends the right headers can pass a grade gate.
	srv := httptest.NewServer(goodSite())
	defer srv.Close()
	if rep := run(t, srv.URL, Options{}); rep.Grade != "A" {
		t.Errorf("local plain-HTTP site with every header: grade %s (%d), findings %v", rep.Grade, rep.Score, ids(rep.Findings))
	}
}

func TestHTTPSTwin(t *testing.T) {
	for raw, want := range map[string]string{
		"http://fixture.test/a?b=1": "https://fixture.test/a?b=1",
		"http://fixture.test:80/":   "https://fixture.test/",
		"http://[2001:db8::1]/":     "https://[2001:db8::1]/",
		"http://fixture.test:8080/": "", // no HTTPS port to guess
		"http://localhost/":         "", // local addresses are not graded on HTTPS
		"http://127.0.0.1/":         "",
		"https://fixture.test/":     "",
	} {
		u, _ := url.Parse(raw)
		got := ""
		if twin := httpsTwin(u); twin != nil {
			got = twin.String()
		}
		if got != want {
			t.Errorf("httpsTwin(%s) = %q, want %q", raw, got, want)
		}
	}
}

// An http:// scan is only moved to the https:// address when that address
// would work in a browser.
func TestFollowIfTrusted(t *testing.T) {
	secure := tlsServer(t, goodSite(), nil)
	u, _ := url.Parse(secure.URL + "/")
	ctx := context.Background()

	hops, body := newClient(Options{AllowPrivate: true, RootCAs: trust(secure)}).followIfTrusted(ctx, u)
	if len(hops) != 1 || hops[0].Status != 200 || !strings.Contains(string(body), "<title>ok</title>") {
		t.Errorf("trusted certificate: hops %+v, body %q", hops, body)
	}
	if hops, _ := newClient(Options{AllowPrivate: true}).followIfTrusted(ctx, u); hops != nil {
		t.Error("followed an HTTPS address whose certificate browsers reject")
	}

	plain := httptest.NewServer(goodSite())
	defer plain.Close()
	back := tlsServer(t, http.RedirectHandler(plain.URL+"/", http.StatusFound), nil)
	u, _ = url.Parse(back.URL + "/")
	if hops, _ := newClient(Options{AllowPrivate: true, RootCAs: trust(back)}).followIfTrusted(ctx, u); hops != nil {
		t.Error("followed an HTTPS address that redirects back to plain HTTP")
	}
	down, _ := url.Parse("https://" + plain.Listener.Addr().String() + "/")
	if hops, _ := newClient(Options{AllowPrivate: true}).followIfTrusted(ctx, down); hops != nil {
		t.Error("followed an address that does not speak TLS")
	}
}

func TestProbesOnlyRunWhenAsked(t *testing.T) {
	var probed atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.git") || r.URL.Path == "/.env" {
			probed.Add(1)
		}
	}))
	defer srv.Close()
	rep := run(t, srv.URL, Options{})
	if probed.Load() > 0 {
		t.Error("requested /.git or /.env without Probe")
	}
	if _, ok := ids(rep.Findings)["exposed.none"]; ok {
		t.Error("reported probe results without probing")
	}
}

func TestBadTLSSite(t *testing.T) {
	srv := tlsServer(t, badSite(), &tls.Config{MinVersion: tls.VersionTLS10})
	rep := run(t, srv.URL, Options{}) // no RootCAs: httptest's certificate is untrusted
	got := ids(rep.Findings)
	wantIDs(t, got, "tls.cert-untrusted", "tls.legacy-protocol", "hsts.missing", "cookie.no-secure", "mixed.active", "mixed.passive")
	if rep.Grade != "F" {
		t.Errorf("grade %s, want F for an untrusted certificate", rep.Grade)
	}
	for _, f := range rep.Findings {
		if f.ID == "mixed.active" && (!strings.HasPrefix(f.Detail, "2 found") || strings.Contains(f.Detail, "commented")) {
			t.Errorf("mixed.active detail = %q, want the script and stylesheet only", f.Detail)
		}
	}
}

func TestCertificateProblems(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		dnsName  string
		wantID   string
		wantSev  Severity
	}{
		{"expired", time.Now().Add(-time.Hour), "", "tls.cert-expired", Critical},
		{"wrong host", time.Now().AddDate(1, 0, 0), "other.fixture.test", "tls.cert-hostname", Critical},
		{"expiring in 10 days", time.Now().AddDate(0, 0, 10), "", "tls.cert-expiring", High},
		{"expiring in 20 days", time.Now().AddDate(0, 0, 20), "", "tls.cert-expiring", Medium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, pool := selfSigned(t, tc.notAfter, tc.dnsName)
			srv := tlsServer(t, goodSite(), &tls.Config{Certificates: []tls.Certificate{cert}})
			rep := run(t, srv.URL, Options{RootCAs: pool})
			if sev, ok := ids(rep.Findings)[tc.wantID]; !ok || sev != tc.wantSev {
				t.Errorf("want %s (%s), got %v", tc.wantID, tc.wantSev, ids(rep.Findings))
			}
		})
	}
}

func TestRedirectChainIsRecorded(t *testing.T) {
	secure := tlsServer(t, goodSite(), nil)
	plain := httptest.NewServer(http.RedirectHandler(secure.URL+"/", http.StatusMovedPermanently))
	defer plain.Close()
	rep := run(t, plain.URL, Options{RootCAs: trust(secure)})
	if len(rep.Redirects) != 2 || rep.Redirects[0].Status != 301 || rep.FinalURL != secure.URL+"/" {
		t.Errorf("redirects = %+v, final %s", rep.Redirects, rep.FinalURL)
	}
	wantIDs(t, ids(rep.Findings), "https.redirect-ok")
}

func TestPlainHTTPChainIsFollowedUntilHTTPS(t *testing.T) {
	var secureHits atomic.Int32
	secure := tlsServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { secureHits.Add(1) }), nil)
	www := httptest.NewServer(http.RedirectHandler(secure.URL+"/", http.StatusMovedPermanently))
	defer www.Close()
	apex := httptest.NewServer(http.RedirectHandler(www.URL+"/", http.StatusMovedPermanently))
	defer apex.Close()

	u, _ := url.Parse(apex.URL + "/")
	chain := newClient(Options{AllowPrivate: true}).followPlain(context.Background(), u)
	if len(chain) != 2 || secureHits.Load() != 0 {
		t.Fatalf("chain = %d hops, %d requests to the HTTPS target; want 2 and 0", len(chain), secureHits.Load())
	}
	if f := httpRedirectFinding(chain); f.ID != "https.redirect-ok" || !strings.Contains(f.Detail, www.URL) {
		t.Errorf("finding = %s %q", f.ID, f.Detail)
	}

	// The same chain, reached by starting the scan on http://.
	rep := run(t, apex.URL, Options{RootCAs: trust(secure)})
	wantIDs(t, ids(rep.Findings), "https.redirect-ok")

	loop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer loop.Close()
	u, _ = url.Parse(loop.URL + "/")
	if chain := newClient(Options{AllowPrivate: true}).followPlain(context.Background(), u); len(chain) != maxRedirects+1 {
		t.Errorf("redirect loop: %d hops, want it to stop at %d", len(chain), maxRedirects+1)
	}
}

func TestDowngradeRedirect(t *testing.T) {
	second := tlsServer(t, goodSite(), nil)
	plain := httptest.NewServer(http.RedirectHandler(second.URL+"/", http.StatusFound))
	defer plain.Close()
	secure := tlsServer(t, http.RedirectHandler(plain.URL+"/", http.StatusFound), nil)
	rep := run(t, secure.URL, Options{})
	wantIDs(t, ids(rep.Findings), "redirect.downgrade")
}

func TestErrorPageIsSaidToBeAnErrorPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/members" {
			http.Error(w, "go away", http.StatusForbidden)
		}
	}))
	defer srv.Close()
	blocked := run(t, srv.URL+"/members", Options{})
	if _, ok := ids(blocked.Findings)["page.error-status"]; !ok || !strings.Contains(fmt.Sprint(blocked.Findings), "answers 403 Forbidden") {
		t.Errorf("a 403 page was graded without saying so: %v", ids(blocked.Findings))
	}
	if _, ok := ids(run(t, srv.URL, Options{}).Findings)["page.error-status"]; ok {
		t.Error("a 200 page was reported as an error page")
	}
}

func TestFindingIDsAreUnique(t *testing.T) {
	// https to http twice: each ID is an HTML anchor and a SARIF rule, so the
	// second downgrade must not add a second finding with the same ID.
	var plain, secure *httptest.Server
	plain = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secure.URL+map[string]string{"/1": "/2", "/3": "/end"}[r.URL.Path], http.StatusFound)
	}))
	defer plain.Close()
	secure = tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := map[string]string{"/": "/1", "/2": "/3"}[r.URL.Path]; next != "" {
			http.Redirect(w, r, plain.URL+next, http.StatusFound)
		}
	}), nil)
	rep := run(t, secure.URL, Options{RootCAs: trust(secure)})
	if len(rep.Redirects) != 5 {
		t.Fatalf("redirects = %v, want 5 hops", rep.Redirects)
	}
	seen := map[string]bool{}
	for _, f := range rep.Findings {
		if seen[f.ID] {
			t.Errorf("finding %s is reported twice", f.ID)
		}
		seen[f.ID] = true
	}
	if !seen["redirect.downgrade"] {
		t.Errorf("no downgrade finding: %v", ids(rep.Findings))
	}
}

func TestRedirectToOtherSchemeIsRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "file:///etc/passwd")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Run(context.Background(), srv.URL, Options{AllowPrivate: true}); err == nil || !strings.Contains(err.Error(), "unsupported location") {
		t.Errorf("err = %v, want unsupported location", err)
	}
}

func TestRedirectLoopStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"x", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Run(context.Background(), srv.URL, Options{AllowPrivate: true}); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("err = %v, want too many redirects", err)
	}
}

// ---- SSRF guard ----

func TestIsPublic(t *testing.T) {
	private := []string{
		"127.0.0.1", "127.8.8.8", "10.0.0.1", "172.16.5.4", "192.168.1.1", "169.254.169.254", "0.0.0.0", "0.1.2.3",
		"100.64.0.1", "192.0.0.1", "192.0.2.1", "198.18.0.1", "198.51.100.7", "203.0.113.9", "224.0.0.1", "240.0.0.1", "255.255.255.255",
		"::1", "::", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::10.0.0.1",
		"64:ff9b::7f00:1", "2001:db8::1", "2002:7f00:1::1", "2001::1", "fec0::1", "168.63.129.16", "fe80::1%eth0",
	}
	for _, s := range private {
		if isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	for _, s := range []string{"93.184.216.34", "1.1.1.1", "8.8.8.8", "172.32.0.1", "100.128.0.1", "2606:4700::1111", "::ffff:8.8.8.8"} {
		if !isPublic(netip.MustParseAddr(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestPrivateTargetsAreBlocked(t *testing.T) {
	var hit atomic.Bool
	srv := tlsServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }), nil)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	for _, target := range []string{
		srv.URL,                     // literal loopback IP
		"https://localhost:" + port, // a name that resolves to loopback
		"http://[::1]:" + port,
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://0x7f.1:" + port,                    // odd spellings must not slip through
	} {
		_, err := Run(context.Background(), target, Options{Timeout: 5 * time.Second})
		var blocked *BlockedError
		if err == nil {
			t.Errorf("%s: scan succeeded, want it refused", target)
		} else if !errors.As(err, &blocked) && !strings.Contains(err.Error(), "no such host") {
			t.Errorf("%s: err = %v, want BlockedError", target, err)
		}
	}
	if hit.Load() {
		t.Error("a request reached the private server")
	}

	// The guard sits on the dialer, so raw TLS handshakes are covered too.
	c := newClient(Options{})
	if _, err := c.handshake(context.Background(), srv.Listener.Addr().String(), "127.0.0.1", tls.VersionTLS12, tls.VersionTLS13); err == nil {
		t.Error("TLS handshake to a private address was not blocked")
	}
}

// A public site that redirects to an internal address is the classic way
// around an SSRF check that only looks at the URL the user typed.
func TestRedirectToPrivateAddressIsBlocked(t *testing.T) {
	var hit atomic.Bool
	internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer internal.Close()
	public := httptest.NewServer(http.RedirectHandler(internal.URL+"/admin", http.StatusFound))
	defer public.Close()

	// Every fixture is on loopback, so let exactly one address through to play
	// the public site. All other connections still go through the guard.
	c := newClient(Options{})
	c.http.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == public.Listener.Addr().String() {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
		return c.dialer.DialContext(ctx, network, addr)
	}
	u, _ := url.Parse(public.URL + "/")
	hops, _, err := c.follow(context.Background(), u)
	var blocked *BlockedError
	if !errors.As(err, &blocked) || len(hops) != 1 || hops[0].Status != http.StatusFound {
		t.Errorf("err = %v after %d hops, want BlockedError after the redirect was read", err, len(hops))
	}
	if chain := c.followPlain(context.Background(), u); len(chain) != 1 {
		t.Errorf("followPlain made %d requests, want it to stop at the blocked hop", len(chain))
	}
	if hit.Load() {
		t.Error("a request reached the internal server through a redirect")
	}
}

func TestRedirectingHostNeedsAValidCertificateToo(t *testing.T) {
	final := tlsServer(t, goodSite(), nil)
	cert, _ := selfSigned(t, time.Now().AddDate(1, 0, 0), "") // not in the trusted pool
	first := tlsServer(t, http.RedirectHandler(final.URL+"/", http.StatusMovedPermanently), &tls.Config{Certificates: []tls.Certificate{cert}})
	rep := run(t, first.URL, Options{RootCAs: trust(final)})
	got := ids(rep.Findings)
	if got["tls.redirect-cert"] != Critical || got["tls.cert-ok"] != Pass || rep.Grade != "F" {
		t.Errorf("grade %s, findings %v", rep.Grade, got)
	}
}

func TestFailedRequestsAreNotReportedAsClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			panic(http.ErrAbortHandler) // drop the connection
		}
	}))
	defer srv.Close()
	got := ids(run(t, srv.URL, Options{Probe: true}).Findings)
	if got["exposed.unchecked"] != Info || got["securitytxt.unchecked"] != Info {
		t.Errorf("want unchecked findings, got %v", got)
	}
	for _, id := range []string{"exposed.none", "securitytxt.missing"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s reported although the request failed", id)
		}
	}
}

func TestOversizedResponsesAreRefused(t *testing.T) {
	huge := strings.Repeat("a", 100<<10)
	header := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Padding", huge) }))
	defer header.Close()
	if _, err := Run(context.Background(), header.URL, Options{AllowPrivate: true}); err == nil {
		t.Error("a 100 KB response header was accepted")
	}
	location := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/"+huge[:3000])
		w.WriteHeader(http.StatusFound)
	}))
	defer location.Close()
	if _, err := Run(context.Background(), location.URL, Options{AllowPrivate: true}); err == nil || len(err.Error()) > 600 {
		t.Errorf("overlong redirect: err = %.80v", err)
	}
}

// Old servers and appliances often still offer only RSA key exchange, which Go
// leaves out of its default cipher suites. Browsers still connect to them, so
// the scanner must too: they are the sites with the most to report.
func TestLegacyCipherSuitesCanStillBeScanned(t *testing.T) {
	srv := tlsServer(t, goodSite(), &tls.Config{
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	})
	rep := run(t, srv.URL, Options{RootCAs: trust(srv)})
	got := ids(rep.Findings)
	if rep.TLS == nil || got["tls.legacy-protocol"] != Medium || got["tls.cert-ok"] != Pass {
		t.Errorf("TLS info %+v, findings %v", rep.TLS, got)
	}

	// The same goes for a server stuck on TLS 1.0 and 1.1.
	old := tlsServer(t, goodSite(), &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	if got := ids(run(t, old.URL, Options{RootCAs: trust(old)}).Findings); got["tls.legacy-protocol"] != High {
		t.Errorf("TLS 1.0/1.1 only: findings %v, want tls.legacy-protocol (high)", got)
	}
}

func TestErrorsArePlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + ln.Addr().String() + "/"
	ln.Close()
	_, err = Run(context.Background(), closed, Options{AllowPrivate: true})
	if err == nil || !strings.Contains(err.Error(), "nothing is listening at that address") {
		t.Errorf("refused connection: %v", err)
	}
	_, err = Run(context.Background(), "not a url ::", Options{})
	if err == nil || strings.Contains(err.Error(), "parse") || !strings.Contains(err.Error(), "not a valid URL") {
		t.Errorf("bad URL: %v", err)
	}
	if got := fetchFailure(&net.DNSError{Err: "no such host", Name: "x.invalid", IsNotFound: true}); !strings.Contains(got, "does not exist") {
		t.Errorf("DNS failure: %q", got)
	}
	if got := fetchFailure(&net.DNSError{Err: "i/o timeout", IsTimeout: true}); !strings.Contains(got, "in time") {
		t.Errorf("timeout: %q", got)
	}
}
