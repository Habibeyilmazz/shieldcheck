# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.5] - 2026-11-22

### Added (perf-a11y round 16)

- SARIF: findings ignored with `--ignore` or in the web UI are now results
  carrying `suppressions` (`external`, `accepted`), so GitHub code scanning
  shows them as dismissed instead of not at all. They stay out of the grade.
- `e2e/ui.mjs`: a Playwright check of `shieldcheck serve` in Chromium (one h1,
  `lang`, scan by form submit, every link/button/input has a name, no console
  errors). Not run in CI (it needs a Playwright install); run it by hand with
  `NODE_PATH=<dir with playwright> node e2e/ui.mjs` after `go build`.

### Notes (perf-a11y round 16)

- Measured, nothing worth changing: binary 13.9 MB, `shieldcheck version`
  7 ms, UI home page 12.4 KB with no external requests, first load in
  Chromium 53 ms. The page is small enough that compression or splitting would
  add code for no visible gain.
- No unused code or dependencies found (standard library only).
- Still open: job summary not seen rendered on GitHub, Windows console colour,
  Playwright test is manual. Ports 4110-4114 held by earlier-round processes
  were left alone.
- Commits from this round are co-authored by Claude Fable 5.2.

### Added (feature round 15)

- Subresource Integrity check: scripts (`<script src>`) and stylesheets
  (`<link rel=stylesheet>`) loaded from another site without an `integrity`
  attribute are reported as `sri.missing` (low), with the risk, a sample of
  the URLs and an HTML snippet showing `integrity` plus `crossorigin` and the
  `openssl` command that computes the hash. Passes are `sri.ok` (all hashed)
  and `sri.none` (nothing from other sites). "Another site" means a different
  registrable domain, using the same heuristic as the SPF/DMARC walk, so
  `cdn.example.com` on `www.example.com` is not flagged. Only the page
  already fetched is read; no third-party file is requested.

### Notes (feature round 15)

- Picked because it was on the roadmap and a supply-chain compromise of a
  CDN script (polyfill.io) is a risk a passive scan can show; a multi-URL scan
  was the other candidate but changes every output format and the action's
  outputs.
- Checked against a fixture page on 4117 (terminal, `--fix`, Markdown,
  SARIF, HTML) and a real scan of example.com (now `sri.none`, 6 passed).
- Ports 4110-4114 were already held by fixture and serve processes from an
  earlier round; they were left alone.
- Still open from earlier rounds: job summary not seen rendered on GitHub,
  SARIF suppressions, Windows console colour.
- Commits from this round are co-authored by Claude Opus 5.5.

### Fixed (reliability round 13)

- A scan cut short by `--timeout` or Ctrl-C after the first response used to
  print a graded report in which the unfinished checks were "could not be
  checked" (no penalty), so the grade was better than a full scan's and could
  pass `--min-grade` with exit 0. It now fails with exit 2.
- Cookies: a `Set-Cookie` that expires a cookie (`Max-Age=0`, past `Expires`)
  is a deletion, not a cookie missing Secure/HttpOnly/SameSite.
- HSTS: a `max-age` too large for an integer was reported as "HSTS is switched
  off"; it is now treated as a very long max-age.
- security.txt: an `Expires` that is not an RFC 3339 timestamp (for example a
  bare date) is reported as unreadable, not as "expired"; the expiry paths now
  have tests.
- DNS: hosts with five or more labels (`a.b.c.d.example.com`) looked up SPF and
  DMARC only up to `d.example.com`, never reaching the registrable domain, so
  they could report "No DMARC record" wrongly. The walk keeps the host, then
  its last three parents.
- Terminal report: lines wrap by characters, not bytes, so accented and CJK
  text is not broken early.

### Notes (reliability round 13)

- Tried and found sound: odd URLs (IPv6, userinfo, IDN, port 0, control
  characters), hostile fixture servers (lying Content-Length, invalid UTF-8
  headers, 3000 cookies, redirect loop, empty and non-HTTP replies, markup in
  header values in HTML/Markdown/SARIF output), concurrent `serve` requests
  under the race detector, a real browser (Playwright) form submit, ignore and
  JSON download against `serve`.
- Still open: SARIF suppressions, Windows console colour, `go.mod` at `go 1.25`
  (not a bug), the job summary has not been seen rendered on GitHub.
- Commits from this round are co-authored by Claude Fable 5.2.

## [0.1.4] - 2026-11-22

This release adds the Markdown report and the action's job summary and
outputs, plus the unreleased fixes from rounds 10 and 11 below.

### Added (feature round 12)

- `--format markdown`: the grade, a table of findings (severity, what was
  seen, how to fix it, ID), ignored findings and passed checks, for a pull
  request comment or a job summary. Text from the scanned site is
  backslash-escaped so it cannot add markup, links, images or raw HTML.
- `--summary FILE` appends that Markdown to FILE next to the normal output,
  for `$GITHUB_STEP_SUMMARY`.
- GitHub Action: every run adds the report to the job summary (input
  `summary: "false"` turns it off) and sets outputs `grade` and `score`, also
  when `min-grade` fails the step. CI checks the outputs on the failing gate.

### Notes (feature round 12)

- Picked because a CI user of the action saw nothing but a pass/fail and a log;
  it was on the roadmap. The action reads `grade`/`score` from the summary's
  first line, `## shieldcheck: grade X (N/100)`; a test pins that line.
- Checked by running the action's script locally against a fixture on 4116
  with and without a failing `min-grade`, and the CLI against example.com.
- Still open: SARIF suppressions (ignored findings are left out of results
  rather than marked suppressed), Windows console colour, `go.mod` at `go 1.25`
  (the minimum supported Go, not a bug).
- Commits from this round are co-authored by Claude Opus 5.5.

### Security (security round 11)

- Terminal report: bidi control characters (U+202E and friends, "Trojan
  Source") in text taken from the scanned site are now dropped along with
  other control characters, so a hostile header or certificate name cannot
  make a line display in a different order from what the site sent.

### Notes (security round 11)

- Checked by running `serve` on 4116: a foreign `Host`, cross-site
  `Sec-Fetch-Site`, a `/scan` without that header and POST are refused; scans
  of `127.0.0.1` and `169.254.169.254` and a malformed ignore list get 400.
  The action passes inputs through the environment; workflow actions are
  pinned to SHAs. The git history has no secrets and one author identity.
- govulncheck v1.9.0 with local Go 1.27.3: only GO-2026-6859 (standard
  library, fixed in Go 1.27.4); CI's vulncheck job uses the latest stable Go.
- Still open: SARIF suppressions, Windows console, `go.mod` at `go 1.25`.
- Commits from this round are co-authored by Claude Opus 5.5.

### Changed (design round 10)

- Web UI and HTML report: "Ignore this finding" and the HTML/JSON/SARIF
  download links are now at least 24 px tall (were 17 and 21 px); the `--probe`
  checkbox is larger and centred on its label instead of sitting on the
  baseline.
- Terminal report: "Fix: send Header: value" now reads "Fix: Send ...", like
  every other fix line.
- README screenshots retaken from the running UI (example.com, light and dark).

### Notes (design round 10)

- Looked at real screenshots at 1280 px and 390 px, light and dark: home,
  error, report; keyboard focus rings and reduced-motion spinner were already
  fine. Nothing else looked broken or cramped, so nothing else was changed.
- proxy.golang.org lists v0.1.3 but `@latest` still answered v0.1.2 (proxy
  cache, not a repo problem; it refreshes on its own).
- Still open: SARIF suppressions, Windows console. Processes on 4110-4114 were
  not started by this round and were left alone; this round used 4116.
- Commits from this round are co-authored by Claude Opus 5.5.

## [0.1.3] - 2026-11-22

This release ships `--ignore` (CLI, action input and web UI) and the fixes
below; 0.1.2 did not have them.

### Fixed (first-run round 9)

- The README documented `--ignore` and the action's `ignore` input while the
  latest release (0.1.2), `go install ...@latest` and the README's
  `uses: ...@v0.1.2` all lacked them: following the README gave
  "flag provided but not defined: -ignore", and a source build called itself
  0.1.2 too. Released as 0.1.3 and the README points at `@v0.1.3`.
- `shieldcheck serve` on a port that is already taken (for example by an
  earlier `serve`) now says to pick another with `--port N`, not only
  "address already in use".
- `--output`: an error when closing the file (a full disk can surface only
  there) is now reported with exit status 2 instead of being dropped.

### Notes (first-run round 9)

- Followed the README literally in a fresh folder: release archive
  (checksum OK, scan of example.com OK), build from source, `serve`.
  Whole code read again; nothing else worth changing was found.
- Still open: SARIF suppressions, Windows console. Processes on 4110-4114
  were not started by this round and were left alone; it used 4116.
- Commits from this round are co-authored by Claude Opus 5.5.

### Fixed (perf-a11y round)

- Web UI: the "--ignore" CLI line now includes `--allow-private` when `serve`
  runs with it, so the copied command reproduces the grade.
- Web UI accessibility: "Download report" was an h2 before the h1 (heading
  order was h2, h1, h2...), now plain text; the ignore and "Grade it again"
  links' accessible names start with their visible text (WCAG 2.5.3).

### Notes (perf-a11y round)

- Measured, nothing to fix: release binary 9.5 MB stripped (13.9 MB unstripped
  dev build; release.yml already uses `-s -w -trimpath`); `version` starts in
  under 10 ms; the web UI report page is 20 KB with no external requests, 50 ms
  per page view on loopback; no horizontal scroll at 320 px; text contrast
  passes 4.5:1 in light and dark (checked by script in Chromium, no axe or
  Lighthouse installed); every control has a name. No unused code or
  dependencies found (stdlib only, `go vet` clean).
- Still open: SARIF suppressions (adding ignored findings as results with
  `suppressions` is valid SARIF, but how GitHub code scanning treats them is
  unverified, and getting it wrong would open alerts for ignored findings, so
  they stay out); Windows console untested. Processes on 4110-4114 were not
  started by this round and were left alone; this round used 4115 and stopped it.
- Commits from this round are co-authored by Claude Fable 5.2.

### Added (feature round 2)

- Web UI ignore list, the same as `--ignore`: "Ignore this finding" on each
  finding and "Grade it again" on each ignored one regrade the report on
  screen from the cached scan (`/scan?...&ignore=a,b&regrade=1`), without
  hitting the site again. The ignored list ends with the matching
  `shieldcheck scan URL --ignore ...` line to copy into CI, and the HTML,
  JSON and SARIF downloads carry the ignore list. IDs that matched nothing
  are named with a "remove" link. The `ignore` parameter is validated
  (finding-ID characters only, at most 50) and the cached report is never
  changed by it.
- Rescanning from the form keeps the ignore list; changing the URL drops it
  (a small script; without JavaScript the list is kept and shown).

### Notes for whoever works on this next (feature round 2)

- Checked in Chromium against a local fixture: ignore two findings (F to C,
  about 100 ms, no rescan), the copy button copies the command, rescanning
  keeps the list, another URL drops it, "Grade it again" restores the grade.
- (Fixed in the perf-a11y round: the CLI line now carries `--allow-private`.)
- Still open: SARIF suppressions (not verified how GitHub shows them),
  Windows console. This round did not start the processes on 4110-4114 and
  left them alone. Commits are co-authored by Claude Opus 5.5.

### Added (launch round)

- README: "Compared with other tools" (SSL Labs, testssl.sh, securityheaders.com,
  MDN Observatory, ZAP, Nikto: what each is for and when to pick it instead)
  and a Contributing section.
- CONTRIBUTING.md, SECURITY.md, issue forms and a pull request template.
- Repo topics and description reviewed with `gh repo edit`.
- Not done: web UI ignore field and SARIF suppressions (still open, see the
  feature-round notes below); Windows console still untested. A `serve`
  process on 4110 from an earlier round was left running, not started here.
- Commits from this round are co-authored by Claude Fable 5.2.

### Fixed

- Web UI: scanning the same URL again within ten minutes returned the old
  report, so a fix could not be checked. Viewing a page now always rescans;
  only the JSON/SARIF/HTML downloads reuse the report just shown.

### Notes (reliability pass)

- Tried to break the CLI and `serve` with: redirect loops, bad or `ftp://`
  Location, 200 MB bodies, 204 with no body, malformed headers and cookies,
  empty/huge/non-ASCII/odd-scheme URLs, empty and unknown `--ignore` IDs, a
  bad `--output` path, other timezones, an unresolvable host, ten parallel
  UI scans (4 run, the rest get 429 by design). All gave a clear error or a
  grade; nothing else needed changing. Not tested: Windows console.
- Commits from this round are co-authored by Claude Sonnet 5.5.

### Added

- `--ignore ID[,ID...]` (repeatable) and the action input `ignore`: accept a
  finding you have decided to live with, such as `coop.missing` on a site that
  needs OAuth pop-ups or `tls.legacy-protocol` set by a CDN plan. Ignored
  findings do not count towards the score, the grade or `--min-grade`, and no
  longer go into the combined header snippet. They are still shown: an
  "Ignored, not graded" list in the terminal and HTML reports, `ignored` in
  JSON, `runs[0].properties.ignored` in SARIF (left out of the results).
  An ID that matches nothing is named in a warning on stderr.
- The HTML report and web UI show each finding's ID under its title, so it can
  be copied into `--ignore`.

### Notes for whoever works on this next (feature round)

- Why this feature: with `--min-grade` in CI, a site that cannot or will not
  fix one finding had no way to pass the gate except lowering the grade for
  everything. It is CLI and action only; the web UI has no ignore field.
- `scan.Ignore` regrades through the same `finish` the scan uses. CI's
  `action` job checks it end to end (D fixture, two IDs ignored, `min-grade: B`
  passes).
- SARIF suppressions (`suppressions: [{kind: external}]`) would be the
  standard way to carry ignored results; they were not used because how
  GitHub code scanning displays them was not verified.
- Commits from this round carry a `Co-Authored-By: Claude Opus 5.5` line,
  the model that actually wrote them.

### Security

A security pass over the whole repository. The scanner code itself had
nothing to fix; the changes are to CI and the action.

- Every third-party action in the workflows and in `action.yml` is pinned to
  a full commit SHA (the tag is in a comment), so a moved tag cannot change
  what runs with the job's token. `actions/checkout` runs with
  `persist-credentials: false`. A test (`TestWorkflowsPinActionsAndDropCredentials`)
  fails if either slips back.
- New CI job `vulncheck`: `govulncheck` (pinned to v1.9.0) on the latest
  stable Go, the same Go the release binaries are built with.

### Notes for whoever works on this next (security pass)

- Checked by running, found fine: the SSRF guard against decimal, hex,
  short-form and IPv4-mapped loopback, `0`, metadata `169.254.169.254`,
  `fd00::/8` and a public name resolving to `::1`; `serve` refusing a foreign
  `Host`, cross-site and same-site `Sec-Fetch-Site`, a `/scan` without the
  header and POST; a `<script>` URL is escaped in the page. Terminal output
  strips control characters from everything taken from the site (recommended
  header values are constants). The git history has no secrets and one
  author identity.
- govulncheck on a local Go 1.27.3 reports GO-2026-6859 (standard library
  `net/http`, fixed in 1.27.4). Our code is not changed by it; binaries built
  with a patched Go do not have it. `go.mod` still says `go 1.25`, which the
  Go team no longer patches, so a `go install` with an old Go gets an
  unpatched standard library.
- The README's example workflows still use tags (`actions/checkout@v5`,
  `upload-sarif@v4`, this action at a tag) to stay readable. Users may want
  to pin them.
- The leftover processes on ports 4110-4114 from an earlier session were
  left running; this pass did not start them, so it did not stop them.

A design and UX pass on the web UI and the HTML report: screenshots at
1280px and 390px in light and dark, an axe-core run (WCAG 2.2 AA and best
practice) on the home, report and error pages, and the CLI error messages.

### Fixed

- Scanning `http://site` for a site that has working HTTPS was graded as
  "no HTTPS" (critical). The scan now tries the same address on `https://`
  and, if a browser would accept its certificate, grades that, so the result
  matches scanning `https://site`: the missing redirect (high).
- Fix snippets wider than the column could only be scrolled with a mouse.
  They can now be focused and scrolled with the keyboard.
- The page had no `<main>` landmark around the form and the intro; there is
  now exactly one.

### Changed

- While a scan runs, the web UI shows a status line ("Scanning ...", with a
  spinner that stands still under reduced motion, announced to screen
  readers) and dims the previous result, instead of only relabelling the
  button.
- A scan that cannot start says why in plain words before the network error:
  nothing listening at the address, a hostname that does not exist, or no
  answer in time. A URL that does not parse no longer repeats itself inside
  Go's parse error. Both the CLI and the web UI show this.
- README screenshots retaken from the running UI (one real scan of
  example.com); the findings shot is now the dark theme.

### Notes for whoever works on this next

- Checked and left alone: typography, spacing, focus rings, the platform
  switch, colour contrast (axe finds no violations now), the 390px layout,
  print styles, the terminal report. The UI has no other motion.
- The axe and screenshot scripts were throwaway and are not in the repo.
  To look at the UI, run `shieldcheck serve --port 4115 --allow-private` and
  any local fixture server.
- Still true: the Windows binary has not been run in a real console; no
  container image.

## [0.1.2] - 2026-11-22

A second independent first-run review: fresh clone, the release archive and
`go install` tried as the README says, the whole code read, the web UI driven
in a browser. Install and quickstart worked as written; these are the things
that were wrong or confusing after that.

### Fixed

- For a site under a country-code suffix (`www.example.com.tr`,
  `example.co.uk`) the SPF and DMARC lookup went one level too far, searched
  `com.tr` / `co.uk`, and the fix told you to publish records there. The walk
  now stops at the registrable domain for the common second-level labels.
- A URL that answers with an error status (a 404, or a 403 from bot
  protection) was graded with nothing in the report to say that an error page
  was what got graded. There is now an info finding, `page.error-status`.
- `--fix` in the terminal printed a near-identical config block under every
  missing header, nine in a row for a bare site. The config for all missing
  headers is now printed once, as one snippet, after the findings.
- A redirect chain that drops from HTTPS to HTTP twice produced two findings
  with the same ID (a duplicate anchor in the HTML report, a duplicate rule in
  SARIF). It is reported once.
- Scanning an `http://` address of a site that does have HTTPS advised
  "get a certificate". The advice now also covers that case.
- A hostname typed with non-ASCII letters (`bücher.example`) is refused with
  a message asking for the `xn--` form. It used to be scanned and could come
  back with a false "certificate does not match the hostname" (critical),
  because certificates list the `xn--` name.
- `--fix NGINX` (any case) is accepted.
- No ANSI colour codes on Windows, where a console prints them as text unless
  the program switches it over first.

### Added

- CI runs the tests on macOS and Windows, the two systems the release ships
  binaries for that had never run them.
- `.gitattributes` keeps LF line endings on every system.

### Notes for whoever works on this next

- Checked and found fine, so no need to redo: the release archive (checksum,
  unpack, run), `go install ...@latest`, build from source, every README usage
  example, the web UI in Chromium at desktop and phone width (scan, blocked
  private target, bad input, downloads, no external requests), `serve`
  refusing foreign `Host` and cross-site requests.
- Not verified: the Windows binary in a real console (CI only runs the tests
  and `version` there). Colour on Windows needs `SetConsoleMode`; see the
  `shortcut:` comment in `main.go`.
- Not done: scanning `http://site` when the site has HTTPS is still graded as
  "plain HTTP" (critical) while `https://site` gets "no redirect" (high). The
  scan could follow up on HTTPS itself; it only says so in the advice.
- Converting a Unicode hostname to its `xn--` form needs punycode, which the
  standard library does not export; that is why such input is refused.
- Still true from 0.1.1: TLS, HTTPS-redirect and cookie snippets and
  everything for Next.js, Vercel and Netlify are not run live; no container
  image.

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
- A server that only offers RSA key exchange, or only TLS 1.0 and 1.1, could
  not be scanned at all ("tls: handshake failure"). The scanner now offers
  every TLS version and cipher suite Go implements.
- A `Server` header such as `AmazonS3` was reported as revealing a version
  because it contains a digit. Only something that looks like a version
  number (`1.24`) counts now.
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
- The README's code scanning workflow (the action at `v0.1.1`, then
  `github/codeql-action/upload-sarif@v4`) was run once on a temporary branch
  after the release: the upload was accepted and produced 11 alerts. The
  branch and its alerts were removed afterwards, so the Security tab is empty.
- Still not verified: the TLS, HTTPS-redirect and cookie snippets on a live
  server, and anything on Next.js, Vercel or Netlify. There is no container
  image.

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
