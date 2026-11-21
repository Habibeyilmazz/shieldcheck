# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-11-22

Fixes from an independent first-run review: a fresh clone, the README followed
literally, and every reported gap checked by running it.

### Fixed

- SARIF reports were rejected by GitHub code scanning ("unrecognized SARIF
  location URI scheme") because each result's location was the scanned URL.
  The location is now the site as a relative path (`host/path`) and the URL is
  in the result message. Confirmed by uploading a report: accepted, with the
  expected alert severities.
- A site whose plain-HTTP address redirects to another `http://` address
  before reaching HTTPS was reported as "neither serves the site nor redirects
  to HTTPS", and one that ended on a plain-HTTP page was only an info finding.
  The port 80 check now follows redirects while they stay on `http://`.
- Plain HTTP on `localhost`, `*.localhost` or a loopback IP is no longer a
  critical finding, so a dev server is graded on its headers and a
  `--min-grade` gate on a server started inside a CI job can pass. Any other
  plain-HTTP host is still critical.
- `shieldcheck scan --help` and `serve --help` exit 0 instead of 2.
- A target without a scheme but with a URL in its query
  (`site.example/?next=http://...`) was rejected as an unsupported scheme.

### Added

- Release archives for Linux, macOS and Windows (amd64 and arm64) with
  checksums, built by `.github/workflows/release.yml` when a `v*` tag is pushed.
- CI job `live-fixes`: pastes the generated header, exposed-dotfile and
  version-disclosure snippets into real nginx, Apache and Caddy and requires
  the rescan to go from F to A.
- Tests: a redirect to a private address is blocked after the first hop; SARIF
  locations are relative paths.

### Changed

- README: binary install, SARIF upload workflow, what is and is not tested
  about the fix snippets. Screenshots now show a real scan of example.com.

### Notes for whoever works on this next

- To release: bump `Version` in `internal/scan/scan.go`, add a changelog
  section with the same number, push, then push the tag. The release workflow
  refuses a tag that does not match and takes its notes from this file.
- Tags are never moved. The README's action example pins the latest tag, so
  update it when releasing.
- Every httptest fixture is on loopback, so `https.missing` (critical) cannot
  be reached end to end any more; `TestPlainHTTPIsCriticalExceptOnLoopback`
  covers it by calling `checkTransport` directly.
- Still not verified: the TLS, HTTPS-redirect and cookie snippets on a live
  server, and anything on Next.js, Vercel or Netlify.

## [0.1.0] - 2026-11-21

First release.

### Added

- `shieldcheck scan <url>`: passive audit graded A to F. Checks security
  headers (CSP quality, HSTS, framing, X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, CORP, version disclosure), TLS (certificate chain,
  hostname, expiry, protocol versions 1.0 to 1.3, certificates of redirecting
  hosts), cookie flags, HTTP to HTTPS
  redirects, downgrade redirects, mixed content, SPF, DMARC and security.txt.
- `--probe`: opt-in requests for `/.git/HEAD` and `/.env`.
- Every finding has a plain-English risk and a fix for nginx, Apache, Caddy,
  Next.js, Vercel and Netlify, plus one combined snippet for all missing headers.
- Output formats: terminal, JSON, SARIF 2.1.0 and a self-contained HTML report.
- `--min-grade` exits with status 1 when the grade is worse, for CI.
- `shieldcheck serve`: web UI on 127.0.0.1 with report downloads. It rejects
  foreign `Host` headers and cross-site requests, and needs `Sec-Fetch-Site`
  to start a scan.
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
- A read-only second-opinion review (Codex) was run before release; its ten
  findings (CSP nonce vs. scheme sources, frame-ancestors precedence, duplicate
  DMARC, per-host cookies, failed probes reported as clean, header size cap,
  redirect-hop certificates and others) are fixed and covered by tests.
- Not verified: SARIF upload to GitHub code scanning; the fix snippets were
  written from each platform's documentation and not run against live servers.
