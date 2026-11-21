# Contributing

Thanks for looking. shieldcheck is a small Go program with no third-party dependencies, and the aim is to keep it that way.

## Useful contributions

- A false positive or a wrong grade, with the URL's response headers (never cookie values or secrets).
- A fix snippet that does not work on its platform.
- A new check that is passive (normal GET/HEAD requests only) and comes with a plain-English risk and a fix per platform.

Out of scope: crawling, fuzzing, payloads, brute force, anything that needs the scanner to log in. `--probe` is the only place that requests well-known paths.

## Setup

Go 1.25 or newer.

```sh
git clone https://github.com/Habibeyilmazz/shieldcheck
cd shieldcheck
go build -o shieldcheck .
go test ./... && go vet ./... && gofmt -l .
```

`gofmt -l .` must print nothing. Tests use local `httptest` servers; do not add tests that need the internet.

## Where things are

- `internal/scan`: the checks, the SSRF guard and the fix snippets
- `internal/report`: terminal, JSON, SARIF and HTML output
- root package: the CLI and the web UI (`serve.go`)

A new check needs a test next to it in `internal/scan`. Anything that fetches a URL must go through the scanner's SSRF-guarded dialer.

## Pull requests

Keep them small and describe what you ran to check them. Add a line to `CHANGELOG.md` under Unreleased. README claims must match what the code does.

Only scan sites you own or are authorised to test, including when you reproduce a bug.
