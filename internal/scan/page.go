package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Cookie names that usually carry a login. CSRF tokens are left out on
// purpose: many frameworks need scripts to read them.
var sessionCookie = regexp.MustCompile(`(?i)sess|sid$|auth|token|jwt|login`)
var csrfCookie = regexp.MustCompile(`(?i)csrf|xsrf`)

func checkCookies(p *page) []Finding {
	// A later response overwrites a cookie of the same name from the same
	// host, as in a browser. Hosts are kept apart: their cookies coexist.
	seen := map[string]*http.Cookie{}
	var keys, names []string
	for _, h := range p.hops {
		for _, c := range h.Cookies {
			key := h.URL.Hostname() + " " + c.Name
			if _, ok := seen[key]; !ok {
				keys = append(keys, key)
				if !slices.Contains(names, c.Name) {
					names = append(names, c.Name)
				}
			}
			seen[key] = c
		}
	}
	if len(names) == 0 {
		return []Finding{{ID: "cookie.none", Category: "cookies", Severity: Pass, Title: "No cookies are set by this page"}}
	}
	https := p.final.URL.Scheme == "https"

	// Each issue becomes one finding that lists the affected cookies. Values
	// are never reported, only names.
	type issue struct {
		id, title, risk string
		sev             Severity
		names           []string
	}
	issues := []*issue{
		{id: "cookie.no-secure", title: "Cookies are sent without the Secure flag",
			risk: "A cookie without Secure is also sent over plain HTTP. Anyone on the same network who can get the browser to make one unencrypted request to your domain can read it. For a session cookie, that means taking over the account."},
		{id: "cookie.no-httponly", title: "Session cookies are readable by JavaScript",
			risk: "Without HttpOnly, any script running on the page can read the cookie, so a single cross-site scripting bug or compromised third-party script is enough to steal logged-in sessions."},
		{id: "cookie.no-samesite", title: "Cookies do not set SameSite",
			risk: "SameSite controls whether a cookie is sent when another site makes a request to yours. Leaving it to browser defaults means cross-site request forgery protection differs from browser to browser."},
	}
	flag := func(i *issue, c *http.Cookie, sev Severity) {
		if !slices.Contains(i.names, c.Name) {
			i.names = append(i.names, c.Name)
		}
		if i.sev == "" || (sev == Medium && i.sev == Low) {
			i.sev = sev
		}
	}
	for _, key := range keys {
		c := seen[key]
		session := sessionCookie.MatchString(c.Name) && !csrfCookie.MatchString(c.Name)
		if https && !c.Secure {
			if session {
				flag(issues[0], c, Medium)
			} else {
				flag(issues[0], c, Low)
			}
		}
		if session && !c.HttpOnly {
			flag(issues[1], c, Medium)
		}
		if c.SameSite == 0 || c.SameSite == http.SameSiteDefaultMode { // absent, or a value browsers do not know
			flag(issues[2], c, Low)
		}
	}
	var out []Finding
	for _, i := range issues {
		if len(i.names) > 0 {
			out = append(out, Finding{ID: i.id, Category: "cookies", Severity: i.sev, Title: i.title,
				Detail: "Affected: " + clip(strings.Join(i.names, ", ")), Risk: i.risk,
				Advice: "Set the flags where the cookie is created. Lax is the right SameSite value for most session cookies.", Fixes: cookieFix})
		}
	}
	if len(out) == 0 {
		out = append(out, Finding{ID: "cookie.ok", Category: "cookies", Severity: Pass, Title: "Cookie flags are set",
			Detail: "Checked: " + clip(strings.Join(names, ", "))})
	}
	return out
}

func checkTransport(ctx context.Context, c *client, p *page) []Finding {
	f := func(id string, sev Severity, title, detail, risk, advice string, fixes []Fix) Finding {
		return Finding{ID: id, Category: "transport", Severity: sev, Title: title, Detail: detail, Risk: risk, Advice: advice, Fixes: fixes}
	}
	const plainRisk = "Everything sent over plain HTTP, including passwords, cookies and page content, can be read and changed by anyone between the visitor and your server: other people on the Wi-Fi, the network operator, a compromised router."
	var out []Finding
	if p.final.URL.Scheme != "https" {
		if isLoopbackHost(p.final.URL.Hostname()) {
			// A dev server on this machine is plain HTTP by design, and browsers
			// treat it as a secure context. Grading it as "no HTTPS" would make
			// every local scan an F whatever else is fixed.
			return []Finding{f("https.local", Info, "HTTPS is not graded on a local address",
				"The final URL is "+p.final.URL.String()+", which only this machine can reach.", "",
				"Scan the deployed site as well: HTTPS, the certificate, TLS versions, HSTS and the Secure cookie flag can only be checked there.", nil)}
		}
		return []Finding{f("https.missing", Critical, "Site is served over plain HTTP",
			"The final URL is "+p.final.URL.String()+".", plainRisk,
			"Get a certificate (Let's Encrypt is free), serve the site over HTTPS, then redirect HTTP to it.", httpsRedirectFix)}
	}
	for i := 1; i < len(p.hops); i++ {
		if p.hops[i-1].URL.Scheme == "https" && p.hops[i].URL.Scheme == "http" {
			out = append(out, f("redirect.downgrade", High, "Redirect chain drops from HTTPS to HTTP",
				p.hops[i-1].URL.String()+" redirects to "+p.hops[i].URL.String(),
				"One unencrypted hop is enough for a network attacker to read the request, including its cookies, and to send the visitor somewhere else entirely.",
				"Change the redirect target to an https:// URL.", nil))
			break // one finding per report: IDs are unique in the HTML and SARIF output
		}
	}
	if len(p.hops) > 4 {
		out = append(out, f("redirect.chain", Info, fmt.Sprintf("%d redirects before the page loads", len(p.hops)-1), "",
			"Each redirect adds a round trip for every first-time visitor.", "Redirect straight to the final URL.", nil))
	}

	// Does plain HTTP end up on HTTPS? Use the scan's own plain-HTTP hops if it
	// started on http://, otherwise ask port 80 and follow it while it stays on
	// http://, so "http://site to http://www.site to https://www.site" counts.
	var chain []hop
	for _, h := range p.hops {
		if h.URL.Scheme != "http" {
			break
		}
		chain = append(chain, h)
	}
	if len(chain) == 0 {
		if port := p.final.URL.Port(); port != "" && port != "443" {
			return out // a non-standard HTTPS port has no matching HTTP port to test
		}
		host := p.final.URL.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]" // IPv6 literal
		}
		chain = c.followPlain(ctx, &url.URL{Scheme: "http", Host: host, Path: "/"})
		if len(chain) == 0 {
			return append(out, f("https.no-http", Pass, "Plain HTTP is not offered", "Port 80 did not answer.", "", "", nil))
		}
	}
	return append(out, httpRedirectFinding(chain))
}

// httpsTwin is the https:// address a browser would try for a page that was
// served over plain HTTP: same host, path and query on port 443. It is nil
// when there is none to try: the page is already HTTPS, on a local address
// (not graded on HTTPS at all) or on a port of its own.
func httpsTwin(u *url.URL) *url.URL {
	if u.Scheme != "http" || isLoopbackHost(u.Hostname()) || (u.Port() != "" && u.Port() != "80") {
		return nil
	}
	twin := *u
	twin.Scheme, twin.Host = "https", u.Hostname()
	if strings.Contains(twin.Host, ":") {
		twin.Host = "[" + twin.Host + "]" // IPv6 literal
	}
	return &twin
}

// followIfTrusted fetches an https:// URL, but only if its host presents a
// certificate browsers accept and the redirects stay on HTTPS. Otherwise it
// returns nil: a host that answers on port 443 with some other site's
// certificate does not have working HTTPS.
func (c *client) followIfTrusted(ctx context.Context, u *url.URL) ([]hop, []byte) {
	state, err := c.handshake(ctx, hostPort(u), u.Hostname(), tls.VersionTLS10, tls.VersionTLS13)
	if err != nil || len(state.PeerCertificates) == 0 || judgeChain(state.PeerCertificates, u.Hostname(), c.rootCAs) != nil {
		return nil, nil
	}
	hops, body, err := c.follow(ctx, u)
	if err != nil || hops[len(hops)-1].URL.Scheme != "https" {
		return nil, nil
	}
	return hops, body
}

// isLoopbackHost reports whether host names this machine: localhost, a
// .localhost name or a loopback IP address.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// followPlain GETs u and follows redirects for as long as they stay on
// http://. It stops at the first answer that is not such a redirect, without
// requesting an https:// target, and returns the answers it got.
func (c *client) followPlain(ctx context.Context, u *url.URL) []hop {
	var chain []hop
	for len(chain) <= maxRedirects {
		resp, err := c.get(ctx, u)
		if err != nil {
			break
		}
		resp.Body.Close()
		chain = append(chain, hop{URL: u, Status: resp.StatusCode, Header: resp.Header})
		loc := resp.Header.Get("Location")
		next, err := u.Parse(loc)
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" || err != nil || next.Scheme != "http" || next.Hostname() == "" {
			break
		}
		u = next
	}
	return chain
}

// httpRedirectFinding judges where a plain-HTTP request for the site ends up.
// chain is the request and any redirects that stayed on http://.
func httpRedirectFinding(chain []hop) Finding {
	last := chain[len(chain)-1]
	who := last.URL.String()
	if len(chain) > 1 {
		who = fmt.Sprintf("%s redirects to %s, which", chain[0].URL, last.URL)
	}
	f := Finding{Category: "transport", Detail: clip(fmt.Sprintf("%s answers %d.", who, last.Status))}
	loc, _ := last.URL.Parse(last.Header.Get("Location"))
	switch {
	case last.Status >= 300 && last.Status < 400 && loc != nil && loc.Scheme == "https":
		f.ID, f.Severity, f.Title = "https.redirect-ok", Pass, "HTTP redirects to HTTPS"
		f.Detail = clip(fmt.Sprintf("%s answers %d to %s", who, last.Status, loc))
	case last.Status >= 200 && last.Status < 300:
		f.ID, f.Severity, f.Title = "https.no-redirect", High, "Plain HTTP does not redirect to HTTPS"
		f.Risk = "Visitors who type the domain or follow an old http:// link stay on the unencrypted version, where everything they send and receive can be read and changed by anyone on the network path."
		f.Advice = "Answer every plain HTTP request with a permanent redirect to the same URL on https://."
		f.Fixes = httpsRedirectFix
	default:
		f.ID, f.Severity, f.Title = "https.http-other", Info, "Plain HTTP neither serves the site nor redirects to HTTPS"
		f.Advice = "A redirect to https:// is friendlier to visitors with old links."
		f.Fixes = httpsRedirectFix
	}
	return f
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	// shortcut: regular expressions instead of an HTML parser, so markup inside
	// <script> strings or odd quoting can be misread; switch to
	// golang.org/x/net/html if false positives show up.
	resourceTag = regexp.MustCompile(`(?is)<(script|iframe|link|img|audio|video|source|embed|object|form)\b([^>]*)>`)
	httpAttr    = regexp.MustCompile(`(?i)\b(?:src|href|action|data)\s*=\s*["']?\s*(http://[^"'\s>]+)`)
	stylesheet  = regexp.MustCompile(`(?i)\brel\s*=\s*["']?[^"'>]*stylesheet`)
)

// checkContent looks for http:// resources on an https:// page.
func checkContent(p *page) []Finding {
	if p.final.URL.Scheme != "https" || !strings.Contains(p.final.Header.Get("Content-Type"), "html") {
		return nil
	}
	var active, passive []string
	for _, m := range resourceTag.FindAllSubmatch(htmlComment.ReplaceAll(p.body, nil), -1) {
		tag := strings.ToLower(string(m[1]))
		a := httpAttr.FindSubmatch(m[2])
		if a == nil || (tag == "link" && !stylesheet.Match(m[2])) {
			continue
		}
		u := string(a[1])
		if slices.Contains([]string{"img", "audio", "video", "source"}, tag) {
			passive = append(passive, u)
		} else {
			active = append(active, u)
		}
	}
	if len(active)+len(passive) == 0 {
		return []Finding{{ID: "mixed.none", Category: "content", Severity: Pass, Title: "No mixed content in the page HTML"}}
	}
	// With upgrade-insecure-requests the browser rewrites these to https:// itself.
	_, upgraded := parseCSP(p.final.Header.Get("Content-Security-Policy"))["upgrade-insecure-requests"]
	sample := func(urls []string) string {
		return fmt.Sprintf("%d found, for example %s", len(urls), clip(strings.Join(urls[:min(len(urls), 3)], ", ")))
	}
	fix := anyFix("Response header, as a stopgap until the URLs are changed", "Content-Security-Policy: upgrade-insecure-requests")
	const advice = "Change the URLs to https://. If the other server has no HTTPS, host the file yourself."
	var out []Finding
	if len(active) > 0 {
		sev, note := High, ""
		if upgraded {
			sev, note = Info, " Your CSP sets upgrade-insecure-requests, so browsers that support it fetch these over HTTPS."
		}
		out = append(out, Finding{ID: "mixed.active", Category: "content", Severity: sev,
			Title: "Page loads scripts, styles, frames or submits forms over plain HTTP", Detail: sample(active) + "." + note,
			Risk:   "A network attacker can replace an http:// script or stylesheet with their own and take over the page, even though the page itself came over HTTPS. Browsers block most of these requests, so the feature is probably broken for your visitors already.",
			Advice: advice, Fixes: fix})
	}
	if len(passive) > 0 {
		sev := Low
		if upgraded {
			sev = Info
		}
		out = append(out, Finding{ID: "mixed.passive", Category: "content", Severity: sev,
			Title: "Page loads images or media over plain HTTP", Detail: sample(passive) + ".",
			Risk:   "Images and media fetched over http:// can be swapped or watched by a network attacker, and browsers either upgrade the request or mark the page as not fully secure.",
			Advice: advice, Fixes: fix})
	}
	return out
}
