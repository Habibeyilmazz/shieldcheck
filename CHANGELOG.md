# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-21

First release.

### Added

- `shieldcheck scan <url>`: passive audit graded A to F. Checks security
  headers (CSP quality, HSTS, framing, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, CORP, version disclosure), TLS (certificate chain,
  hostname, expiry, protocol versions 1.0 to 1.3), cookie flags, HTTP to HTTPS
  redirects, downgrade redirects, mixed content, SPF, DMARC and security.txt.
- `--probe`: opt-in requests for `/.git/HEAD` and `/.env`.
- Every finding has a plain-English risk and a fix for nginx, Apache, Caddy,
  Next.js, Vercel and Netlify, plus one combined snippet for all missing headers.
- Output formats: terminal, JSON, SARIF 2.1.0 and a self-contained HTML report.
- `--min-grade` exits with status 1 when the grade is worse, for CI.
- `shieldcheck serve`: web UI on 127.0.0.1 with report downloads.
- SSRF guard in the dialer: non-public addresses are refused on every
  connection (first request, redirects, TLS handshakes) unless
  `--allow-private` is given.
- Composite GitHub Action (`action.yml`) and CI workflow.

### Notes for whoever works on this next

- Layout: `internal/scan` (checks, `client.go` holds the SSRF guard, `fixes.go`
  the snippets), `internal/report` (renderers and `report.html`, which is both
  the HTML report and the web UI), root package (`main.go` CLI, `serve.go` UI).
- No third-party dependencies; keep it that way unless there is a strong reason.
- Tests use `httptest` fixtures only. `go test -race ./...` must stay clean.
- Grading weights and thresholds live in `scan.go` (`penalty`, `Grade`) and are
  documented in the README; change both together.
- Known shortcuts are marked with `shortcut:` comments (regex-based mixed
  content detection) and listed under Limitations in the README.
- Not verified: SARIF upload to GitHub code scanning; the fix snippets were
  written from each platform's documentation and not run against live servers.
