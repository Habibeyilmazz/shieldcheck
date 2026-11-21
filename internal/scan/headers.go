package scan

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// csp maps a lowercased directive name to its source list.
type csp map[string][]string

func parseCSP(v string) csp {
	p := csp{}
	for part := range strings.SplitSeq(v, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		name := strings.ToLower(f[0])
		if _, dup := p[name]; !dup { // browsers ignore repeated directives
			p[name] = f[1:]
		}
	}
	return p
}

// has reports whether the source list contains one of the given sources or prefixes.
func has(sources []string, want ...string) bool {
	for _, s := range sources {
		s = strings.ToLower(s)
		for _, w := range want {
			if s == w || (strings.HasSuffix(w, "-") && strings.HasPrefix(s, w)) {
				return true
			}
		}
	}
	return false
}

var metaCSP = regexp.MustCompile(`(?is)<meta\b[^>]*http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>`)
var metaContent = regexp.MustCompile(`(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func checkHeaders(p *page) []Finding {
	h := p.final.Header
	https := p.final.URL.Scheme == "https"
	var out []Finding
	f := func(id string, sev Severity, title, detail, risk, advice string) Finding {
		return Finding{ID: id, Category: "headers", Severity: sev, Title: title, Detail: detail, Risk: risk, Advice: advice}
	}

	// Content-Security-Policy
	const cspRisk = "Without a Content Security Policy, any script an attacker manages to inject into a page (cross-site scripting) runs with full access to your users' sessions and data. A policy tells the browser which scripts and resources are allowed, so injected ones are blocked."
	const cspAdvice = "Start with this policy in Content-Security-Policy-Report-Only, watch the browser console for violations, then switch to the enforcing header. Frameworks that emit inline scripts (Next.js included) need a nonce-based policy rather than this static one."
	policies := h.Values("Content-Security-Policy")
	var policy csp
	switch {
	case len(policies) > 0:
		// shortcut: only the first policy is analysed; browsers enforce all of
		// them together. Evaluate each one if sites with several show up.
		policy = parseCSP(policies[0])
		out = append(out, evaluateCSP(policy, policies[0])...)
	case metaCSP.Match(p.body):
		m := metaContent.FindSubmatch(metaCSP.Find(p.body))
		if m != nil {
			raw := string(m[1]) + string(m[2])
			policy = parseCSP(raw)
			out = append(out, evaluateCSP(policy, raw)...)
		}
		out = append(out, withHeader(f("csp.meta-only", Low, "Content Security Policy is only set in a <meta> tag",
			"No Content-Security-Policy response header; the page sets one with <meta http-equiv>.",
			"A policy delivered in a meta tag cannot use frame-ancestors, sandbox or reporting, and does not protect anything the browser parses before it reaches the tag.",
			"Send the same policy as a response header."), "Content-Security-Policy", strictCSP))
	case h.Get("Content-Security-Policy-Report-Only") != "":
		out = append(out, withHeader(f("csp.report-only", Medium, "Content Security Policy is in report-only mode",
			"Only Content-Security-Policy-Report-Only is sent.",
			"A report-only policy logs violations but blocks nothing, so injected scripts still run.",
			"Once the reports are clean, send the same policy as Content-Security-Policy."), "Content-Security-Policy", strictCSP))
	default:
		out = append(out, withHeader(f("csp.missing", High, "No Content Security Policy",
			"The response has no Content-Security-Policy header.", cspRisk, cspAdvice), "Content-Security-Policy", strictCSP))
	}

	// Strict-Transport-Security (only meaningful over HTTPS)
	if https {
		const hstsValue = "max-age=31536000; includeSubDomains"
		const hstsRisk = "Without HSTS a browser will still try plain HTTP when a user types your domain or follows an old link. Someone on the same network (public Wi-Fi, a compromised router) can intercept that first request and keep the user on a fake, unencrypted copy of your site."
		const hstsAdvice = "Only add includeSubDomains if every subdomain is served over HTTPS."
		v := h.Get("Strict-Transport-Security")
		maxAge, subs := parseHSTS(v)
		switch {
		case v == "":
			out = append(out, withHeader(f("hsts.missing", High, "No HTTP Strict Transport Security (HSTS)",
				"The response has no Strict-Transport-Security header.", hstsRisk, hstsAdvice), "Strict-Transport-Security", hstsValue))
		case maxAge <= 0:
			out = append(out, withHeader(f("hsts.disabled", High, "HSTS is switched off",
				"Strict-Transport-Security: "+clip(v), "A max-age of 0 (or a missing max-age) tells browsers to forget the HTTPS-only rule. "+hstsRisk, hstsAdvice), "Strict-Transport-Security", hstsValue))
		case maxAge < 15552000:
			out = append(out, withHeader(f("hsts.short", Low, "HSTS max-age is shorter than six months",
				"Strict-Transport-Security: "+clip(v), "Browsers forget the HTTPS-only rule after max-age seconds. A short value leaves returning visitors unprotected again sooner than necessary.", "Use at least six months; one year (31536000) is the usual value."), "Strict-Transport-Security", hstsValue))
		case !subs:
			out = append(out, f("hsts.no-subdomains", Info, "HSTS does not cover subdomains",
				"Strict-Transport-Security: "+clip(v), "Without includeSubDomains, a subdomain can still be reached over plain HTTP, which also lets a network attacker set cookies for the parent domain.", "Add includeSubDomains once every subdomain is served over HTTPS."))
		default:
			out = append(out, f("hsts.ok", Pass, "HSTS is enabled", "Strict-Transport-Security: "+clip(v), "", ""))
		}
	}

	// Clickjacking: X-Frame-Options or CSP frame-ancestors. A meta-tag policy
	// cannot set frame-ancestors, so only the header policy counts.
	xfo := strings.ToUpper(strings.TrimSpace(h.Get("X-Frame-Options")))
	var fa []string
	hasFA := false
	if len(policies) > 0 {
		fa, hasFA = policy["frame-ancestors"]
	}
	switch {
	case hasFA && !has(fa, "*", "http:", "https:"):
		out = append(out, f("frame.ok", Pass, "Framing is restricted", "CSP frame-ancestors "+clip(strings.Join(fa, " ")), "", ""))
	case xfo == "DENY" || xfo == "SAMEORIGIN":
		out = append(out, f("frame.ok", Pass, "Framing is restricted", "X-Frame-Options: "+xfo, "", ""))
	default:
		detail := "Neither X-Frame-Options nor a CSP frame-ancestors directive is sent."
		if xfo != "" {
			detail = "X-Frame-Options: " + clip(xfo) + " is not a value browsers honour."
		} else if hasFA {
			detail = "CSP frame-ancestors allows any site: " + clip(strings.Join(fa, " "))
		}
		out = append(out, withHeader(f("frame.missing", Medium, "Page can be embedded in other sites (clickjacking)", detail,
			"Another site can load your page in an invisible frame and trick users into clicking buttons on it, such as confirming a payment or changing a setting, while they think they are clicking something else.",
			"Use DENY instead if nothing of yours frames the page. The modern equivalent is the CSP directive frame-ancestors 'self' or 'none'."), "X-Frame-Options", "SAMEORIGIN"))
	}

	// X-Content-Type-Options
	if strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		out = append(out, f("xcto.ok", Pass, "MIME sniffing is disabled", "X-Content-Type-Options: nosniff", "", ""))
	} else {
		out = append(out, withHeader(f("xcto.missing", Low, "Browsers may guess content types (MIME sniffing)",
			"X-Content-Type-Options: nosniff is not sent.",
			"Without it a browser may treat a file as a different type than you declared. An uploaded \"image\" that is really a script can then be executed.", ""), "X-Content-Type-Options", "nosniff"))
	}

	// Referrer-Policy. The last recognised token in the list is the one applied.
	ref := strings.ToLower(h.Get("Referrer-Policy"))
	tokens := strings.FieldsFunc(ref, func(r rune) bool { return r == ',' || r == ' ' })
	const refValue = "strict-origin-when-cross-origin"
	switch {
	case len(tokens) == 0:
		out = append(out, withHeader(f("referrer.missing", Low, "No Referrer-Policy",
			"The response has no Referrer-Policy header.",
			"The Referer header tells other sites which page a visitor came from. Modern browsers default to a safe policy, but older ones send the full URL, which can leak IDs or tokens that appear in your URLs.", ""), "Referrer-Policy", refValue))
	case slices.Contains([]string{"unsafe-url", "no-referrer-when-downgrade"}, tokens[len(tokens)-1]):
		out = append(out, withHeader(f("referrer.unsafe", Low, "Referrer-Policy leaks full URLs to other sites",
			"Referrer-Policy: "+clip(ref),
			"This policy sends the complete URL of your pages, including the path and query string, to every external site a visitor navigates to or loads resources from.", ""), "Referrer-Policy", refValue))
	default:
		out = append(out, f("referrer.ok", Pass, "Referrer-Policy is set", "Referrer-Policy: "+clip(ref), "", ""))
	}

	// Permissions-Policy
	if h.Get("Permissions-Policy") != "" {
		out = append(out, f("permissions.ok", Pass, "Permissions-Policy is set", "Permissions-Policy: "+clip(h.Get("Permissions-Policy")), "", ""))
	} else {
		out = append(out, withHeader(f("permissions.missing", Low, "No Permissions-Policy",
			"The response has no Permissions-Policy header.",
			"Without it, your page and any third-party script or frame it loads may ask for the camera, microphone, location and other powerful browser features.",
			"Switch off what you do not use. To allow a feature for your own pages write, for example, geolocation=(self)."),
			"Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"))
	}

	// Cross-Origin-Opener-Policy / Cross-Origin-Resource-Policy
	if v := h.Get("Cross-Origin-Opener-Policy"); v != "" {
		out = append(out, f("coop.ok", Pass, "Cross-Origin-Opener-Policy is set", "Cross-Origin-Opener-Policy: "+clip(v), "", ""))
	} else {
		out = append(out, withHeader(f("coop.missing", Low, "No Cross-Origin-Opener-Policy",
			"The response has no Cross-Origin-Opener-Policy header.",
			"A page that opens yours in a new window, or that yours opens, keeps a handle to it. That handle enables cross-window attacks and side-channel leaks such as Spectre.",
			"Use same-origin-allow-popups instead if you rely on OAuth or payment pop-ups that talk back to the page."), "Cross-Origin-Opener-Policy", "same-origin"))
	}
	if v := h.Get("Cross-Origin-Resource-Policy"); v != "" {
		out = append(out, f("corp.ok", Pass, "Cross-Origin-Resource-Policy is set", "Cross-Origin-Resource-Policy: "+clip(v), "", ""))
	} else {
		out = append(out, withHeader(f("corp.missing", Info, "No Cross-Origin-Resource-Policy",
			"The response has no Cross-Origin-Resource-Policy header.",
			"Other sites can embed your responses as images, scripts or media, which is the starting point for some cross-site data leaks.",
			"Use same-site if subdomains load each other's files, or cross-origin for assets that are meant to be embedded elsewhere (a public CDN, for example)."), "Cross-Origin-Resource-Policy", "same-origin"))
	}

	// Version disclosure
	var leaks []string
	if v := h.Get("Server"); strings.ContainsAny(v, "0123456789") {
		leaks = append(leaks, "Server: "+clip(v))
	}
	for _, name := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(name); v != "" {
			leaks = append(leaks, name+": "+clip(v))
		}
	}
	if len(leaks) > 0 {
		d := f("disclosure.version", Low, "Response headers reveal server software", strings.Join(leaks, "; "),
			"Naming the exact software and version makes it easy for automated scanners to match your server against lists of known vulnerabilities.", "")
		d.Category, d.Fixes = "disclosure", disclosureFix
		out = append(out, d)
	}
	return out
}

// evaluateCSP judges the quality of one enforced policy.
func evaluateCSP(p csp, raw string) []Finding {
	var out []Finding
	add := func(id string, sev Severity, title, risk, advice string) {
		out = append(out, Finding{ID: id, Category: "headers", Severity: sev, Title: title,
			Detail: "Content-Security-Policy: " + clip(raw), Risk: risk, Advice: advice,
			Fixes: anyFix("Example of a strict policy (generate a fresh nonce for every response)",
				"Content-Security-Policy: script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'")})
	}
	script, ok := p["script-src"]
	if !ok {
		script, ok = p["default-src"]
	}
	// A nonce, hash or 'strict-dynamic' makes browsers ignore 'unsafe-inline' and host allowlists.
	strict := has(script, "'nonce-", "'sha256-", "'sha384-", "'sha512-", "'strict-dynamic'")
	switch {
	case !ok:
		add("csp.no-script-restriction", Medium, "Content Security Policy does not restrict scripts",
			"The policy has neither script-src nor default-src, so scripts can still be loaded from anywhere and injected inline. That is the main thing a CSP exists to stop.",
			"Add default-src 'self' and a script-src that lists what you actually load.")
	case has(script, "'unsafe-inline'") && !strict:
		add("csp.unsafe-inline", Medium, "Content Security Policy allows inline scripts ('unsafe-inline')",
			"With 'unsafe-inline' the browser runs any <script> block or onclick attribute found in the page, including ones an attacker injected. The policy then gives almost no protection against cross-site scripting.",
			"Move inline scripts into files, or keep them and allow each one with a per-response nonce or a hash.")
	case has(script, "*", "http:", "https:", "data:") && !strict:
		add("csp.wildcard", Medium, "Content Security Policy allows scripts from any host",
			"A script source of *, https:, http: or data: lets a page load scripts from anywhere, so an attacker who can inject a script tag can point it at their own server.",
			"List the specific hosts you load scripts from, or switch to nonces with 'strict-dynamic'.")
	}
	if has(script, "'unsafe-eval'") {
		add("csp.unsafe-eval", Low, "Content Security Policy allows eval() ('unsafe-eval')",
			"'unsafe-eval' lets code be built from strings at runtime with eval() or new Function(). If attacker-controlled text reaches one of those calls it runs as script.",
			"Remove 'unsafe-eval'. If a library needs it, look for a CSP-compatible build.")
	}
	if _, ok := p["base-uri"]; !ok {
		add("csp.base-uri", Low, "Content Security Policy has no base-uri",
			"default-src does not cover <base>. An injected <base href> tag makes every relative script URL on the page load from the attacker's server.",
			"Add base-uri 'self' (or 'none').")
	}
	if len(out) == 0 {
		out = append(out, Finding{ID: "csp.ok", Category: "headers", Severity: Pass, Title: "Content Security Policy is in place",
			Detail: fmt.Sprintf("%d directives, no unsafe script sources.", len(p))})
	}
	return out
}

// parseHSTS returns max-age in seconds (-1 if absent) and whether includeSubDomains is set.
func parseHSTS(v string) (maxAge int, subdomains bool) {
	maxAge = -1
	for part := range strings.SplitSeq(v, ";") {
		k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "max-age":
			if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil {
				maxAge = n
			}
		case "includesubdomains":
			subdomains = true
		}
	}
	return maxAge, subdomains
}
