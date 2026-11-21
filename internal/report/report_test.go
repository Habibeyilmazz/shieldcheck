package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Habibeyilmazz/shieldcheck/internal/scan"
)

// sample is a report whose observed data is hostile: markup and terminal
// escape sequences, as a scanned site could send in a header.
func sample() *scan.Report {
	return &scan.Report{
		Tool: "shieldcheck", Version: scan.Version, Target: "https://fixture.test/", FinalURL: "https://fixture.test/",
		ScannedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Grade: "C", Score: 69,
		TLS: &scan.TLSInfo{Version: "TLS 1.3", Issuer: "Fixture CA", NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)},
		Findings: []scan.Finding{
			{ID: "csp.missing", Category: "headers", Severity: scan.High, Title: "No Content Security Policy", Risk: "Injected scripts run.", Advice: "Add one.",
				Fixes: []scan.Fix{{Platform: "nginx", Where: "nginx: server block", Snippet: `add_header Content-Security-Policy "default-src 'self'" always;`},
					{Platform: "caddy", Where: "Caddyfile", Snippet: `header Content-Security-Policy "default-src 'self'"`}}},
			{ID: "disclosure.version", Category: "disclosure", Severity: scan.Low, Title: "Response headers reveal server software",
				Detail: "Server: <script>alert(1)</script>\x1b[2J\x1b]0;owned\x07/1.0", Risk: "Version leak."},
			{ID: "spf.missing", Category: "dns", Severity: scan.Medium, Title: "No SPF record", Risk: "Spoofing.",
				Fixes: []scan.Fix{{Platform: "any", Where: "DNS TXT record", Snippet: `fixture.test.  TXT  "v=spf1 -all"`}}},
			{ID: "hsts.ok", Category: "headers", Severity: scan.Pass, Title: "HSTS is enabled"},
		},
	}
}

func TestTerminal(t *testing.T) {
	var plain bytes.Buffer
	if err := Terminal(&plain, sample(), TerminalOptions{}); err != nil {
		t.Fatal(err)
	}
	out := plain.String()
	for _, want := range []string{"Grade C", "69/100", "1 high, 1 medium, 1 low, 1 passed", "HIGH", "No Content Security Policy", "Risk: Injected scripts run.", "PASSED (1)", "HSTS is enabled", "--fix nginx"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("escape sequences from the scanned site reached the terminal: %q", out)
	}
	if strings.Contains(out, "add_header") {
		t.Error("fix snippets printed without --fix")
	}

	var fixed bytes.Buffer
	Terminal(&fixed, sample(), TerminalOptions{Platform: "caddy", Color: true})
	out = fixed.String()
	if !strings.Contains(out, `header Content-Security-Policy`) || strings.Contains(out, "add_header") {
		t.Errorf("--fix caddy should print only the Caddy snippet:\n%s", out)
	}
	if !strings.Contains(out, `v=spf1 -all`) {
		t.Error("platform-independent fixes should be printed for every --fix platform")
	}
	if !strings.Contains(out, "\x1b[31m") || strings.Contains(out, "\x1b[2J") {
		t.Errorf("colour output should contain our own codes only: %q", out)
	}
}

func TestTerminalPrintsHeaderConfigOnce(t *testing.T) {
	header := func(id, name, value string) scan.Finding {
		return scan.Finding{ID: id, Category: "headers", Severity: scan.Low, Title: "No " + name, Header: &scan.Header{Name: name, Value: value},
			Fixes: []scan.Fix{{Platform: "nginx", Where: "nginx", Snippet: "add_header " + name + " \"" + value + "\" always;"}}}
	}
	rep := sample()
	rep.Findings = append(rep.Findings, header("xcto.missing", "X-Content-Type-Options", "nosniff"), header("referrer.missing", "Referrer-Policy", "no-referrer"))
	rep.HeaderFixes = []scan.Fix{
		{Platform: "nginx", Where: "nginx", Snippet: "add_header X-Content-Type-Options \"nosniff\" always;\nadd_header Referrer-Policy \"no-referrer\" always;"},
		{Platform: "caddy", Where: "Caddyfile", Snippet: "header X-Content-Type-Options \"nosniff\""},
	}
	var b bytes.Buffer
	Terminal(&b, rep, TerminalOptions{Platform: "nginx"})
	out := b.String()
	if n := strings.Count(out, "add_header X-Content-Type-Options"); n != 1 {
		t.Errorf("the nosniff config is printed %d times, want once in the combined snippet:\n%s", n, out)
	}
	for _, want := range []string{"AS ONE SNIPPET", "Fix: send Referrer-Policy: no-referrer", "add_header Referrer-Policy", "add_header Content-Security-Policy"} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "header X-Content-Type-Options \"nosniff\"\n") && strings.Contains(out, "Caddyfile") {
		t.Errorf("another platform's combined snippet was printed:\n%s", out)
	}

	b.Reset()
	Terminal(&b, rep, TerminalOptions{})
	if strings.Contains(b.String(), "AS ONE SNIPPET") {
		t.Error("combined snippet printed without --fix")
	}
}

func TestWrap(t *testing.T) {
	got := wrap("one two three four five", "  ", 9)
	if got != "  one two\n  three\n  four five" {
		t.Errorf("wrap = %q", got)
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var back scan.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.Grade != "C" || back.Score != 69 || len(back.Findings) != 4 || back.Findings[0].Fixes[0].Platform != "nginx" || back.TLS.Issuer != "Fixture CA" {
		t.Errorf("round trip lost data: %+v", back)
	}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string
					Rules []struct {
						ID   string
						Help struct{ Text string }
					}
				}
			}
			Results []struct {
				RuleID    string
				RuleIndex int
				Level     string
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct{ ArtifactLocation struct{ URI string } }
				}
			}
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 || doc.Runs[0].Tool.Driver.Name != "shieldcheck" {
		t.Fatalf("unexpected envelope: %s", buf.String())
	}
	run := doc.Runs[0]
	if len(run.Results) != 3 || len(run.Tool.Driver.Rules) != 3 { // the passed check is not a result
		t.Fatalf("results %d rules %d, want 3 and 3", len(run.Results), len(run.Tool.Driver.Rules))
	}
	levels := map[string]string{}
	for _, r := range run.Results {
		levels[r.RuleID] = r.Level
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
		}
		// GitHub code scanning rejects http(s) location URIs, so the location is
		// a relative path and the URL is in the message.
		if uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "fixture.test/" || !strings.Contains(r.Message.Text, "https://fixture.test/") {
			t.Errorf("result %s: location %q, message %q", r.RuleID, uri, r.Message.Text)
		}
	}
	if levels["csp.missing"] != "error" || levels["spf.missing"] != "warning" || levels["disclosure.version"] != "note" {
		t.Errorf("levels = %v", levels)
	}
	if !strings.Contains(run.Tool.Driver.Rules[0].Help.Text, "add_header") {
		t.Error("rule help should include the fix snippets")
	}
}

func TestSARIFLocationIsARelativePath(t *testing.T) {
	for final, want := range map[string]string{
		"https://fixture.test/app/sign%20in?next=/": "fixture.test/app/sign%20in",
		"http://localhost:3000/":                    "localhost/",
		"http://[::1]:8080/":                        "--1/",
		"https://fixture.test":                      "fixture.test",
	} {
		rep := sample()
		rep.FinalURL = final
		var buf bytes.Buffer
		if err := SARIF(&buf, rep); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), `"uri": "`+want+`"`) {
			t.Errorf("%s: want location %q in\n%s", final, want, buf.String())
		}
	}
}

func TestHTML(t *testing.T) {
	var file bytes.Buffer
	if err := HTML(&file, Page{Report: sample()}); err != nil {
		t.Fatal(err)
	}
	out := file.String()
	for _, want := range []string{`aria-label="Grade C"`, "<b>69</b> out of 100", "No Content Security Policy", "Injected scripts run.", `data-p="caddy"`, "HSTS is enabled", "Fixture CA", "2 Jan 2026"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report lacks %q", want)
		}
	}
	if strings.Contains(out, "<script>alert(1)") {
		t.Error("markup from the scanned site was not escaped")
	}
	// The report file must stand alone: no form, no links back to a server, nothing fetched.
	for _, bad := range []string{"<form", `href="/`, `src="`, "nonce="} {
		if strings.Contains(out, bad) {
			t.Errorf("self-contained report contains %q", bad)
		}
	}

	var ui bytes.Buffer
	HTML(&ui, Page{Serve: true, ProbeAllowed: true, Nonce: "n0nce", URL: "https://fixture.test/?a=1&b=2", Report: sample()})
	out = ui.String()
	for _, want := range []string{`<form class="scan"`, `<style nonce="n0nce">`, `<script nonce="n0nce">`, `name="probe"`, `/scan?url=https%3a%2f%2ffixture.test%2f%3fa%3d1%26b%3d2&amp;format=json`} {
		if !strings.Contains(out, want) {
			t.Errorf("UI page lacks %q", want)
		}
	}

	var failed bytes.Buffer
	HTML(&failed, Page{Serve: true, URL: `"><img src=x>`, Error: "no such host <b>"})
	out = failed.String()
	if !strings.Contains(out, "no such host &lt;b&gt;") || strings.Contains(out, "<img src=x>") {
		t.Errorf("error page does not escape its input:\n%s", out)
	}
}

func TestIgnoredFindingsAreShownButNotGraded(t *testing.T) {
	rep := sample()
	rep.Ignored = []scan.Finding{{ID: "coop.missing", Category: "headers", Severity: scan.Low, Title: "No Cross-Origin-Opener-Policy"}}

	var term, sarif, page bytes.Buffer
	Terminal(&term, rep, TerminalOptions{})
	if out := term.String(); !strings.Contains(out, "1 passed, 1 ignored") || !strings.Contains(out, "IGNORED (1)") || !strings.Contains(out, "coop.missing") {
		t.Errorf("terminal does not list the ignored finding:\n%s", out)
	}

	SARIF(&sarif, rep)
	var doc struct {
		Runs []struct {
			Results    []struct{ RuleID string }
			Properties struct{ Ignored []string }
		}
	}
	if err := json.Unmarshal(sarif.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Runs[0].Results {
		if r.RuleID == "coop.missing" {
			t.Error("an ignored finding is a SARIF result")
		}
	}
	if got := doc.Runs[0].Properties.Ignored; len(got) != 1 || got[0] != "coop.missing" {
		t.Errorf("SARIF run properties ignored = %v", got)
	}

	HTML(&page, Page{Report: rep})
	if out := page.String(); !strings.Contains(out, "Ignored, not graded") || !strings.Contains(out, "<code>coop.missing</code>") || !strings.Contains(out, `<code class="fid">csp.missing</code>`) {
		t.Error("HTML report does not show the ignored finding and the finding IDs")
	}
}
