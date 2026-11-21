package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

const (
	userAgent    = "shieldcheck/" + Version + " (+https://github.com/Habibeyilmazz/shieldcheck)"
	maxRedirects = 10
	maxBody      = 1 << 20
)

// BlockedError is returned when a connection to a non-public address is refused.
type BlockedError struct{ Addr netip.Addr }

func (e *BlockedError) Error() string {
	return fmt.Sprintf("refusing to connect to non-public address %s", e.Addr)
}

// Ranges that netip's Is* helpers do not cover: reserved, documentation,
// carrier-grade NAT, IPv6 ranges that embed an IPv4 address, the deprecated
// IPv6 site-local range, and Azure's in-VM platform endpoint.
var blockedPrefixes = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24",
		"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "168.63.129.16/32",
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2001:db8::/32", "2002::/16", "fec0::/10",
	} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

// isPublic reports whether a is a globally routable unicast address.
func isPublic(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() ||
		a.IsLinkLocalUnicast() || a.IsMulticast() {
		return false
	}
	for _, p := range blockedPrefixes {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// scanSuites is every cipher suite Go implements, including the ones it no
// longer offers by default (RSA key exchange, 3DES, RC4). The scanner only
// observes, browsers still connect to servers that need these, and those
// servers are the ones with the most to report.
var scanSuites = func() []uint16 {
	var ids []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		ids = append(ids, s.ID)
	}
	return ids
}()

type client struct {
	http    *http.Client
	dialer  *net.Dialer
	rootCAs *x509.CertPool
}

func newClient(o Options) *client {
	d := &net.Dialer{Timeout: 8 * time.Second}
	if !o.AllowPrivate {
		// The SSRF guard lives at connect time, on the address actually being
		// dialled. That covers the first request, every redirect hop and DNS
		// answers that change between lookups, for HTTP and raw TLS alike.
		d.Control = func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if !isPublic(ap.Addr()) {
				return &BlockedError{ap.Addr()}
			}
			return nil
		}
	}
	return &client{
		dialer:  d,
		rootCAs: o.RootCAs,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy:       nil, // a proxy would hide the real destination from the dial guard
				DialContext: d.DialContext,
				// Certificates are verified and reported by checkTLS; skipping
				// verification here lets the other checks still run on a site
				// whose certificate is broken.
				TLSClientConfig:        &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, CipherSuites: scanSuites},
				TLSHandshakeTimeout:    8 * time.Second,
				ResponseHeaderTimeout:  12 * time.Second,
				MaxResponseHeaderBytes: 64 << 10, // the default is 10 MB, which a hostile site could make us keep
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

type hop struct {
	URL     *url.URL
	Status  int
	Header  http.Header
	Cookies []*http.Cookie
}

// get performs one GET without following redirects. The caller closes the body.
func (c *client) get(ctx context.Context, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,*/*;q=0.8")
	return c.http.Do(req)
}

// follow GETs u, following redirects by hand so every hop's headers are kept.
// It returns the hops made so far even on error.
func (c *client) follow(ctx context.Context, u *url.URL) ([]hop, []byte, error) {
	var hops []hop
	for range maxRedirects + 1 {
		resp, err := c.get(ctx, u)
		if err != nil {
			return hops, nil, err
		}
		hops = append(hops, hop{u, resp.StatusCode, resp.Header, resp.Cookies()})
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			resp.Body.Close()
			return hops, body, nil
		}
		resp.Body.Close()
		next, err := u.Parse(loc)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") || next.Hostname() == "" || len(loc) > 2048 {
			return hops, nil, fmt.Errorf("%s redirects to an unsupported location %q", u, clip(loc))
		}
		next.Fragment = ""
		u = next
	}
	return hops, nil, errors.New("too many redirects")
}
