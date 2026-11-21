package scan

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var (
	secContact = regexp.MustCompile(`(?mi)^contact:[ \t]*\S+`)
	secExpires = regexp.MustCompile(`(?mi)^expires:[ \t]*(\S+)`)
)

func checkSecurityTxt(ctx context.Context, c *client, final *url.URL) []Finding {
	f := func(id string, sev Severity, title, detail, risk, advice string, fixes []Fix) Finding {
		return Finding{ID: id, Category: "disclosure", Severity: sev, Title: title, Detail: detail, Risk: risk, Advice: advice, Fixes: fixes}
	}
	u := final.ResolveReference(&url.URL{Path: "/.well-known/security.txt"})
	fix := anyFix("File served at "+u.String(), fmt.Sprintf(
		"Contact: mailto:security@%s\nExpires: %s\nPreferred-Languages: en",
		final.Hostname(), time.Now().UTC().AddDate(1, 0, 0).Format("2006-01-02T15:04:05Z")))
	const advice = "Use a contact address that is actually read. With Next.js, Vercel or Netlify, put the file at public/.well-known/security.txt (or the same path in your publish directory)."

	hops, body, err := c.follow(ctx, u)
	// Requiring a Contact line rules out "soft 404" pages that answer 200 with HTML.
	if err != nil || hops[len(hops)-1].Status != 200 || !secContact.Match(body) {
		return []Finding{f("securitytxt.missing", Low, "No security.txt", "No valid file at "+u.String()+".",
			"When someone finds a vulnerability in your site, security.txt tells them where to report it. Without it, reports get lost in support inboxes, or are not sent at all.", advice, fix)}
	}
	m := secExpires.FindSubmatch(body)
	if m == nil {
		return []Finding{f("securitytxt.no-expires", Low, "security.txt has no Expires field", u.String(),
			"RFC 9116 requires an Expires date so that researchers can tell whether the contact details are still current.", advice, fix)}
	}
	if t, err := time.Parse(time.RFC3339, string(m[1])); err != nil || t.Before(time.Now()) {
		return []Finding{f("securitytxt.expired", Low, "security.txt has expired", "Expires: "+clip(string(m[1])),
			"An expired security.txt signals that the contact details may be stale, so researchers may not trust them.", "Update the Expires date; a year ahead at most. "+advice, fix)}
	}
	return []Finding{f("securitytxt.ok", Pass, "security.txt is published", u.String(), "", "", nil)}
}

var (
	gitHead = regexp.MustCompile(`^(ref: refs/|[0-9a-f]{40}\s*$)`)
	envLine = regexp.MustCompile(`(?m)^(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=`)
)

// checkProbes requests two well-known paths that should never be public. It
// only runs with Options.Probe. The response bodies are never put in the report.
func checkProbes(ctx context.Context, c *client, final *url.URL) []Finding {
	probe := func(path string) (status int, contentType string, body []byte) {
		resp, err := c.get(ctx, final.ResolveReference(&url.URL{Path: path}))
		if err != nil {
			return 0, "", nil
		}
		defer resp.Body.Close()
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, resp.Header.Get("Content-Type"), body
	}
	f := func(id, title, path, risk, advice string) Finding {
		return Finding{ID: id, Category: "disclosure", Severity: Critical, Title: title,
			Detail: final.ResolveReference(&url.URL{Path: path}).String() + " is publicly readable.", Risk: risk, Advice: advice, Fixes: exposedFix}
	}
	var out []Finding
	if status, _, body := probe("/.git/HEAD"); status == 200 && gitHead.Match(body) {
		out = append(out, f("exposed.git", "Git repository is publicly downloadable", "/.git/HEAD",
			"With the .git folder exposed, anyone can download your full source code and its history, including every password, API key or config file that was ever committed.",
			"Block the path, then treat every secret in the repository's history as leaked and rotate it."))
	}
	if status, ct, body := probe("/.env"); status == 200 && !strings.Contains(ct, "html") && envLine.Match(body) {
		out = append(out, f("exposed.env", "Environment file (.env) is publicly readable", "/.env",
			".env files usually hold database passwords, API keys and signing secrets. Bots request this path on every site they find, so assume the contents have already been copied.",
			"Block the path and rotate every secret in the file."))
	}
	if len(out) == 0 {
		out = append(out, Finding{ID: "exposed.none", Category: "disclosure", Severity: Pass, Title: "/.git/HEAD and /.env are not exposed"})
	}
	return out
}
