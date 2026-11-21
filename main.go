// shieldcheck is a passive website security auditor for sites you own.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/Habibeyilmazz/shieldcheck/internal/report"
	"github.com/Habibeyilmazz/shieldcheck/internal/scan"
)

const usage = `shieldcheck ` + scan.Version + `: passive website security auditor.
Scan only sites you own or are authorised to test.

Usage:
  shieldcheck scan <url> [flags]    grade one site
  shieldcheck serve [flags]         local web UI on 127.0.0.1
  shieldcheck version

Scan flags:
  --format terminal|json|sarif|html   output format (default terminal)
  --output FILE                       write the report to FILE instead of stdout
  --min-grade A|B|C|D                 exit with status 1 if the grade is worse
  --fix PLATFORM                      print fixes for nginx, apache, caddy, nextjs, vercel or netlify
  --ignore ID[,ID...]                 leave these findings out of the grade (repeatable)
  --probe                             also request /.git/HEAD and /.env
  --allow-private                     allow loopback, private and link-local addresses
  --timeout DURATION                  limit for the whole scan (default 45s)
  --no-color                          plain terminal output

Serve flags:
  --port N           port on 127.0.0.1 (default 4110)
  --probe            offer the /.git/HEAD and /.env probe in the UI
  --allow-private    allow loopback, private and link-local targets

Exit status: 0 ok, 1 grade below --min-grade, 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "-version", "--version":
		fmt.Fprintln(stdout, "shieldcheck", scan.Version)
		return 0
	case "serve":
		return cmdServe(args[1:], stderr)
	case "scan":
		args = args[1:]
	}
	return cmdScan(args, stdout, stderr)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	return fs
}

// exitCode is what a flag parsing error ends the program with: asking for
// help is not a failure.
func exitCode(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}

// parseArgs lets flags come before or after positional arguments, which the
// flag package does not do by itself. Everything after "--" is positional.
func parseArgs(fs *flag.FlagSet, args []string) (positional []string, err error) {
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if n := len(args) - len(rest); len(rest) == 0 || (n > 0 && args[n-1] == "--") {
			return append(positional, rest...), nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("scan", stderr)
	format := fs.String("format", "terminal", "")
	output := fs.String("output", "", "")
	minGrade := fs.String("min-grade", "", "")
	fix := fs.String("fix", "", "")
	noColor := fs.Bool("no-color", false, "")
	var ignore []string
	fs.Func("ignore", "", func(v string) error {
		for id := range strings.SplitSeq(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ignore = append(ignore, id)
			}
		}
		return nil
	})
	var o scan.Options
	fs.BoolVar(&o.Probe, "probe", false, "")
	fs.BoolVar(&o.AllowPrivate, "allow-private", false, "")
	fs.DurationVar(&o.Timeout, "timeout", 45*time.Second, "")
	urls, err := parseArgs(fs, args)
	if err != nil {
		return exitCode(err)
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "shieldcheck: "+format+"\n", a...)
		return 2
	}
	*minGrade, *fix = strings.ToUpper(*minGrade), strings.ToLower(*fix)
	switch {
	case len(urls) != 1:
		return fail("expected exactly one URL, got %d (see shieldcheck help)", len(urls))
	case !slices.Contains([]string{"terminal", "json", "sarif", "html"}, *format):
		return fail("unknown --format %q", *format)
	case !slices.Contains([]string{"", "A", "B", "C", "D"}, *minGrade):
		return fail("--min-grade must be A, B, C or D")
	case *fix != "" && !slices.ContainsFunc(scan.Platforms, func(p struct{ ID, Name string }) bool { return p.ID == *fix }):
		return fail("unknown --fix platform %q", *fix)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := scan.Run(ctx, urls[0], o)
	if err != nil {
		var blocked *scan.BlockedError
		if errors.As(err, &blocked) {
			return fail("%v\nUse --allow-private if you really mean to scan an internal host.", err)
		}
		return fail("%v", err)
	}
	if len(ignore) > 0 {
		for _, id := range scan.Ignore(rep, ignore) {
			fmt.Fprintf(stderr, "shieldcheck: --ignore %s matched no finding\n", id)
		}
	}

	out := stdout
	if *output != "" {
		file, err := os.Create(*output)
		if err != nil {
			return fail("%v", err)
		}
		defer file.Close()
		out = file
	}
	switch *format {
	case "json":
		err = report.JSON(out, rep)
	case "sarif":
		err = report.SARIF(out, rep)
	case "html":
		err = report.HTML(out, report.Page{Report: rep})
	default:
		// shortcut: no colour on Windows, where a console only understands ANSI
		// codes after SetConsoleMode; add that call if colour is wanted there.
		color := !*noColor && *output == "" && os.Getenv("NO_COLOR") == "" && runtime.GOOS != "windows" && isTerminal(stdout)
		err = report.Terminal(out, rep, report.TerminalOptions{Color: color, Platform: *fix})
	}
	if err != nil {
		return fail("writing report: %v", err)
	}
	if *output != "" {
		fmt.Fprintf(stderr, "Grade %s (%d/100) for %s, report written to %s\n", rep.Grade, rep.Score, rep.FinalURL, *output)
	}
	if *minGrade != "" && scan.GradeBelow(rep.Grade, *minGrade) {
		fmt.Fprintf(stderr, "shieldcheck: grade %s is below the required %s\n", rep.Grade, *minGrade)
		return 1
	}
	return 0
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
