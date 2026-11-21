// Package report renders a scan.Report as terminal text, JSON, SARIF or HTML.
package report

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/Habibeyilmazz/shieldcheck/internal/scan"
)

var labels = map[scan.Severity]string{
	scan.Critical: "Critical", scan.High: "High", scan.Medium: "Medium",
	scan.Low: "Low", scan.Info: "Info", scan.Pass: "Passed",
}

func JSON(w io.Writer, r *scan.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// summary is "2 high, 1 medium, 6 passed".
func summary(r *scan.Report) string {
	var parts []string
	for _, s := range scan.Severities {
		if n := r.Count(s); n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(labels[s])))
		}
	}
	if n := len(r.Ignored); n > 0 {
		parts = append(parts, fmt.Sprintf("%d ignored", n))
	}
	return strings.Join(parts, ", ")
}

// ---- terminal ----

type TerminalOptions struct {
	Color    bool
	Platform string // print fixes for this platform ID; "" prints none
}

var ansi = map[scan.Severity]string{
	scan.Critical: "1;31", scan.High: "31", scan.Medium: "33",
	scan.Low: "36", scan.Info: "2", scan.Pass: "32",
}

// sanitize drops control characters so that text taken from the scanned site
// cannot inject terminal escape sequences.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' {
			return -1
		}
		return r
	}, s)
}

// wrap breaks s into lines of at most width characters, each prefixed by indent.
func wrap(s, indent string, width int) string {
	var b strings.Builder
	col := 0
	for _, word := range strings.Fields(s) {
		if col > 0 && col+1+len(word) > width {
			b.WriteString("\n")
			col = 0
		}
		if col == 0 {
			b.WriteString(indent)
		} else {
			b.WriteString(" ")
			col++
		}
		b.WriteString(word)
		col += len(word)
	}
	return b.String()
}

func Terminal(w io.Writer, r *scan.Report, o TerminalOptions) error {
	paint := func(code, s string) string {
		if !o.Color {
			return s
		}
		return "\x1b[" + code + "m" + s + "\x1b[0m"
	}
	gradeColor := map[string]string{"A": "1;32", "B": "1;32", "C": "1;33", "D": "1;33", "F": "1;31"}[r.Grade]
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	p("\n  %s  %s\n", paint(gradeColor, "Grade "+r.Grade), paint("2", fmt.Sprintf("%d/100", r.Score)))
	p("  %s\n", sanitize(r.FinalURL))
	if r.FinalURL != r.Target {
		p("  %s\n", paint("2", "redirected from "+sanitize(r.Target)))
	}
	p("  %s\n", summary(r))
	if t := r.TLS; t != nil {
		p("  %s\n", paint("2", sanitize(fmt.Sprintf("%s, certificate from %s, expires %s", t.Version, t.Issuer, t.NotAfter.Format("2 Jan 2006")))))
	}

	const indent = "            "
	printFix := func(fix scan.Fix) {
		p("%s%s\n", indent, paint("2", sanitize(fix.Where)+":"))
		for line := range strings.SplitSeq(sanitize(fix.Snippet), "\n") {
			p("%s  %s\n", indent, paint("36", line))
		}
	}
	// With several headers to add, their config is printed once, together,
	// instead of as near-identical blocks under every finding.
	combined := o.Platform != "" && len(r.HeaderFixes) > 0
	for _, f := range r.Findings {
		if f.Severity == scan.Pass {
			continue
		}
		p("\n  %s%s  %s\n", paint(ansi[f.Severity], fmt.Sprintf("%-10s", strings.ToUpper(labels[f.Severity]))), sanitize(f.Title), paint("2", f.ID))
		if f.Detail != "" {
			p("%s\n", paint("2", wrap(sanitize(f.Detail), indent, 66)))
		}
		if f.Risk != "" {
			p("%s\n", wrap("Risk: "+f.Risk, indent, 66))
		}
		advice := "Fix: " + f.Advice
		if h := f.Header; h != nil {
			p("%sFix: send %s: %s\n", indent, h.Name, h.Value)
			advice = f.Advice
		}
		if f.Advice != "" {
			p("%s\n", wrap(advice, indent, 66))
		}
		for _, fix := range f.Fixes {
			if o.Platform == "" || (fix.Platform != "any" && fix.Platform != o.Platform) || (combined && f.Header != nil) {
				continue
			}
			printFix(fix)
		}
	}
	if combined {
		p("\n  %s\n", paint("1", "ALL HEADERS TO ADD, AS ONE SNIPPET"))
		for _, fix := range r.HeaderFixes {
			if fix.Platform == o.Platform {
				printFix(fix)
			}
		}
	}

	if n := r.Count(scan.Pass); n > 0 {
		p("\n  %s\n", paint(ansi[scan.Pass], fmt.Sprintf("PASSED (%d)", n)))
		for _, f := range r.Findings {
			if f.Severity == scan.Pass {
				p("%s\n", wrap(sanitize(f.Title), indent, 66))
			}
		}
	}
	if len(r.Ignored) > 0 {
		p("\n  %s\n", paint("2", fmt.Sprintf("IGNORED (%d), not graded", len(r.Ignored))))
		for _, f := range r.Ignored {
			p("%s  %s\n", wrap(sanitize(f.Title), indent, 66), paint("2", f.ID))
		}
	}
	if o.Platform == "" && len(r.Findings) > r.Count(scan.Pass) {
		p("\n  %s\n", paint("2", "Add --fix nginx|apache|caddy|nextjs|vercel|netlify for copy-paste config."))
	}
	if !r.Probed {
		p("  %s\n", paint("2", "Add --probe to also test for exposed /.git/HEAD and /.env."))
	}
	p("\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// ---- SARIF 2.1.0 ----

type obj = map[string]any

func SARIF(w io.Writer, r *scan.Report) error {
	level := map[scan.Severity]string{scan.Critical: "error", scan.High: "error", scan.Medium: "warning", scan.Low: "note", scan.Info: "note"}
	// GitHub's 0-10 scale for security results.
	score := map[scan.Severity]string{scan.Critical: "9.5", scan.High: "8.0", scan.Medium: "5.5", scan.Low: "3.0", scan.Info: "0.0"}
	// GitHub code scanning refuses an upload whose locations are http(s) URLs
	// ("unrecognized SARIF location URI scheme"), so the site is written as a
	// relative path: host/path. A ":" in the first segment would read as a scheme.
	location := "site"
	if u, err := url.Parse(r.FinalURL); err == nil && u.Hostname() != "" {
		location = strings.ReplaceAll(u.Hostname(), ":", "-") + u.EscapedPath()
	}
	rules, results := []obj{}, []obj{}
	for _, f := range r.Findings {
		if f.Severity == scan.Pass {
			continue
		}
		help := strings.TrimSpace(f.Risk + "\n\n" + f.Advice)
		for _, fix := range f.Fixes {
			help += fmt.Sprintf("\n\n%s (%s):\n%s", fix.Where, fix.Platform, fix.Snippet)
		}
		rules = append(rules, obj{
			"id":                   f.ID,
			"name":                 f.ID,
			"shortDescription":     obj{"text": f.Title},
			"fullDescription":      obj{"text": first(f.Risk, f.Title)},
			"help":                 obj{"text": first(strings.TrimSpace(help), f.Title)},
			"defaultConfiguration": obj{"level": level[f.Severity]},
			"properties":           obj{"tags": []string{"security", f.Category}, "security-severity": score[f.Severity]},
		})
		results = append(results, obj{
			"ruleId":    f.ID,
			"ruleIndex": len(rules) - 1,
			"level":     level[f.Severity],
			"message":   obj{"text": strings.TrimSpace(f.Title+". "+f.Detail) + " (" + r.FinalURL + ")"},
			"locations": []obj{{"physicalLocation": obj{"artifactLocation": obj{"uri": location}}}},
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(obj{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []obj{{
			"tool": obj{"driver": obj{
				"name": "shieldcheck", "version": r.Version,
				"informationUri": "https://github.com/Habibeyilmazz/shieldcheck",
				"rules":          rules,
			}},
			"results": results,
			// Ignored findings are left out of the results, as they are left out of the grade.
			"properties": obj{"grade": r.Grade, "score": r.Score, "target": r.Target, "ignored": ignoredIDs(r)},
		}},
	})
}

func ignoredIDs(r *scan.Report) []string {
	ids := []string{}
	for _, f := range r.Ignored {
		ids = append(ids, f.ID)
	}
	return ids
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ---- HTML ----

//go:embed report.html
var pageSource string

var pageTmpl = template.Must(template.New("page").Funcs(template.FuncMap{"join": strings.Join}).Parse(pageSource))

// Page is what the HTML template renders. With Serve false it is the
// self-contained report file; with Serve true it is the local web UI.
type Page struct {
	Report *scan.Report // nil shows only the form
	Serve  bool
	URL    string // form value
	Error  string
	// ProbeAllowed shows the probe checkbox; Probe is its state.
	ProbeAllowed, Probe bool
	Nonce               string // CSP nonce for the inline style and script
	// Ignore is the UI's ignore list; Unmatched the IDs in it that matched nothing.
	Ignore, Unmatched []string
}

// Link is the UI address of this scan with the ignore list given, reusing
// the report just shown. With a format it is that download instead.
func (p Page) Link(ignore []string, format string) string {
	q := url.Values{"url": {p.URL}, "regrade": {"1"}}
	if p.Probe {
		q.Set("probe", "1")
	}
	if len(ignore) > 0 {
		q.Set("ignore", strings.Join(ignore, ","))
	}
	if format != "" {
		q.Set("format", format)
	}
	return "/scan?" + q.Encode()
}

func (p Page) IgnoreLink(id string) string { return p.Link(append(slices.Clip(p.Ignore), id), "") }

func (p Page) UnignoreLink(id string) string {
	return p.Link(slices.DeleteFunc(slices.Clone(p.Ignore), func(s string) bool { return s == id }), "")
}

// Command is the CLI line that reproduces this page's grade, for CI.
func (p Page) Command() string {
	target := p.URL
	if strings.ContainsFunc(target, func(r rune) bool {
		return !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:/._-", r)
	}) {
		target = "'" + strings.ReplaceAll(target, "'", `'\''`) + "'"
	}
	cmd := "shieldcheck scan " + target
	if p.Probe {
		cmd += " --probe"
	}
	var ids []string
	if p.Report != nil {
		for _, f := range p.Report.Ignored {
			ids = append(ids, f.ID)
		}
	}
	return cmd + " --ignore " + strings.Join(ids, ",")
}

type count struct {
	Severity scan.Severity
	Label    string
	N        int
}

type view struct {
	Page
	Platforms      any
	Issues, Passed []scan.Finding
	Counts         []count
	Labels         map[scan.Severity]string
	Scanned        string
}

func HTML(w io.Writer, p Page) error {
	v := view{Page: p, Platforms: scan.Platforms, Labels: labels}
	if r := p.Report; r != nil {
		for _, f := range r.Findings {
			if f.Severity == scan.Pass {
				v.Passed = append(v.Passed, f)
			} else {
				v.Issues = append(v.Issues, f)
			}
		}
		for _, s := range scan.Severities {
			if n := r.Count(s); n > 0 {
				v.Counts = append(v.Counts, count{s, labels[s], n})
			}
		}
		v.Scanned = r.ScannedAt.Format("2 Jan 2006, 15:04 UTC")
	}
	return pageTmpl.Execute(w, v)
}
