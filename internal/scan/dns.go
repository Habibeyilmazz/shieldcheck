package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

type lookupTXT func(ctx context.Context, name string) ([]string, error)

// secondLevel are the labels registries commonly sell names under below a
// two-letter country code: example.co.uk, example.com.tr.
// shortcut: a dozen common labels instead of the public-suffix list, so a
// rarer suffix is still walked one level too far; embed the list if that
// produces wrong advice.
var secondLevel = []string{"ac", "co", "com", "edu", "gen", "gov", "mil", "ne", "net", "nom", "or", "org"}

// mailDomains returns the domains to look at for email records: the host
// without "www.", then each parent down to the registrable domain (two
// labels, or three under a suffix such as co.uk). This is the DNS tree walk
// from the DMARC specification, without a public-suffix list.
func mailDomains(host string) []string {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if _, err := netip.ParseAddr(host); err == nil || !strings.Contains(host, ".") {
		return nil
	}
	for _, tld := range []string{".localhost", ".local", ".test", ".internal", ".example", ".invalid"} {
		if strings.HasSuffix(host, tld) {
			return nil
		}
	}
	labels := strings.Split(strings.TrimPrefix(host, "www."), ".")
	shortest := 2
	if n := len(labels); n > 2 && len(labels[n-1]) == 2 && slices.Contains(secondLevel, labels[n-2]) {
		shortest = 3 // "co.uk" is a registry, not the parent domain of example.co.uk
	}
	var out []string
	for i := 0; i+shortest <= len(labels) && len(out) < 4; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// findTXT returns the TXT records at prefix+domain that start with tag, for
// the first candidate domain that has any.
func findTXT(ctx context.Context, lookup lookupTXT, prefix string, domains []string, tag string) (domain string, records []string, err error) {
	for _, d := range domains {
		txts, err := lookup(ctx, prefix+d)
		var dnsErr *net.DNSError
		if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
			return "", nil, err
		}
		for _, t := range txts {
			t = strings.TrimSpace(t)
			if rest, ok := cutPrefixFold(t, tag); ok && (rest == "" || rest[0] == ' ' || rest[0] == ';') {
				records = append(records, t)
			}
		}
		if len(records) > 0 {
			return d, records, nil
		}
	}
	return "", nil, nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func checkDNS(ctx context.Context, lookup lookupTXT, host string) []Finding {
	f := func(id string, sev Severity, title, detail, risk, advice string, fixes []Fix) Finding {
		return Finding{ID: id, Category: "dns", Severity: sev, Title: title, Detail: detail, Risk: risk, Advice: advice, Fixes: fixes}
	}
	domains := mailDomains(host)
	if len(domains) == 0 {
		return []Finding{f("dns.skipped", Info, "Email authentication (SPF, DMARC) not checked", "The target is an IP address or a local name, so there is no public DNS to look at.", "", "", nil)}
	}
	apex := domains[len(domains)-1]
	const spoofRisk = "Anyone can send email that claims to come from your domain. Phishing mail that appears to come from you reaches your users' and colleagues' inboxes, and your genuine mail is more likely to be treated as spam."
	var out []Finding

	// SPF
	spfFix := anyFix("DNS TXT record", fmt.Sprintf("; if the domain sends no email at all\n%s.  TXT  \"v=spf1 -all\"\n\n; if it does, list your mail provider (theirs will give you the include)\n%s.  TXT  \"v=spf1 include:_spf.example-provider.com -all\"", apex, apex))
	switch d, recs, err := findTXT(ctx, lookup, "", domains, "v=spf1"); {
	case err != nil:
		out = append(out, f("spf.unchecked", Info, "SPF could not be checked", "DNS lookup failed: "+clip(err.Error()), "", "", nil))
	case len(recs) == 0:
		out = append(out, f("spf.missing", Medium, "No SPF record", "No TXT record starting with v=spf1 on "+strings.Join(domains, " or ")+".",
			"SPF lists the servers allowed to send mail for your domain. "+spoofRisk, "Publish an SPF record, even if the domain never sends mail.", spfFix))
	case len(recs) > 1:
		out = append(out, f("spf.multiple", Medium, "More than one SPF record", fmt.Sprintf("%s has %d v=spf1 records.", d, len(recs)),
			"Receiving servers treat several SPF records as an error and ignore all of them, which is the same as having none.", "Merge them into a single record.", spfFix))
	default:
		spf := evaluateSPF(d, recs[0], f, spfFix)
		if d != domains[0] {
			spf.Detail += fmt.Sprintf(" (%s has no SPF record of its own. SPF is not inherited, so this is the parent domain's record; a DMARC policy is what protects subdomains.)", domains[0])
		}
		out = append(out, spf)
	}

	// DMARC
	dmarcFix := anyFix("DNS TXT record", fmt.Sprintf("_dmarc.%s.  TXT  \"v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@%s\"", apex, apex))
	switch d, recs, err := findTXT(ctx, lookup, "_dmarc.", domains, "v=DMARC1"); {
	case err != nil:
		out = append(out, f("dmarc.unchecked", Info, "DMARC could not be checked", "DNS lookup failed: "+clip(err.Error()), "", "", nil))
	case len(recs) == 0:
		out = append(out, f("dmarc.missing", Medium, "No DMARC record", "No TXT record at _dmarc."+apex+".",
			"DMARC tells receiving mail servers what to do with mail that fails SPF and DKIM checks. Without it, they usually deliver it. "+spoofRisk,
			"Start with p=none and a rua address to collect reports, then move to quarantine or reject.", dmarcFix))
	case len(recs) > 1:
		out = append(out, f("dmarc.multiple", Medium, "More than one DMARC record", fmt.Sprintf("_dmarc.%s has %d v=DMARC1 records.", d, len(recs)),
			"Receiving servers ignore DMARC altogether when a domain publishes more than one record. "+spoofRisk, "Keep a single record.", dmarcFix))
	default:
		policy := dmarcTag(recs[0], "p")
		if sp := dmarcTag(recs[0], "sp"); sp != "" && d != domains[0] {
			policy = sp // the record was inherited from a parent domain
		}
		detail := fmt.Sprintf("_dmarc.%s: %s", d, clip(recs[0]))
		switch policy {
		case "quarantine", "reject":
			out = append(out, f("dmarc.ok", Pass, "DMARC policy is enforced ("+policy+")", detail, "", "", nil))
		case "none":
			out = append(out, f("dmarc.none", Low, "DMARC is in monitoring mode (p=none)", detail,
				"With p=none, receivers report on mail that fails authentication but still deliver it, so spoofed mail gets through.",
				"Once the reports show your real mail passing, change the policy to quarantine and then reject.", dmarcFix))
		default:
			out = append(out, f("dmarc.invalid", Medium, "DMARC record has no valid policy", detail,
				"A DMARC record without p=none, quarantine or reject is ignored by receivers. "+spoofRisk, "Fix the p= tag.", dmarcFix))
		}
	}
	return out
}

func evaluateSPF(domain, rec string, f func(string, Severity, string, string, string, string, []Fix) Finding, fix []Fix) Finding {
	detail := domain + ": " + clip(rec)
	all, redirect := "", false
	for _, term := range strings.Fields(strings.ToLower(rec)) {
		if strings.HasSuffix(term, "all") && len(term) <= 4 {
			all = term
		}
		redirect = redirect || strings.HasPrefix(term, "redirect=")
	}
	switch {
	case all == "all" || all == "+all":
		return f("spf.pass-all", High, "SPF record allows every server to send as your domain", detail,
			"+all authorises the whole internet to send mail as your domain, which is worse than having no SPF record.", "End the record with -all (or ~all while you are testing).", fix)
	case all == "?all":
		return f("spf.neutral", Low, "SPF record ends in ?all (neutral)", detail,
			"?all tells receivers you have no opinion about mail from unlisted servers, so SPF does not help them reject forgeries.", "End the record with -all (or ~all while you are testing).", fix)
	case all == "" && !redirect:
		return f("spf.no-all", Low, "SPF record has no \"all\" rule", detail,
			"Without a final all rule, mail from unlisted servers gets a neutral result and SPF does not help receivers reject forgeries.", "End the record with -all (or ~all while you are testing).", fix)
	}
	return f("spf.ok", Pass, "SPF record is published", detail, "", "", nil)
}

// dmarcTag returns the lowercased value of one tag in a DMARC record.
func dmarcTag(rec, tag string) string {
	for part := range strings.SplitSeq(rec, ";") {
		if k, v, ok := strings.Cut(part, "="); ok && strings.EqualFold(strings.TrimSpace(k), tag) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}
