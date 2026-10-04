// Package cli is the command-line front end, written so that tests can call
// Run directly instead of starting a process.
package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/sriharifortitude/actionwarden/internal/report"
	"github.com/sriharifortitude/actionwarden/internal/rules"
	"github.com/sriharifortitude/actionwarden/internal/scan"
)

const usage = `usage: actionwarden scan [--format terminal|json|sarif] [--brief] [--fail-on LEVEL] [PATH...]
       actionwarden rules

  scan     check workflow files. PATH is a workflow file, or a directory: its
           .github/workflows if it has one, otherwise the .yml/.yaml files in it.
           With no PATH, the current directory.
  rules    list every rule with what it protects against and how to fix it

  --format    terminal (default), json, or sarif for GitHub code scanning
  --brief     terminal format: one line per finding, without the fix
  --fail-on   lowest severity that makes the exit code 1: low, medium, high
              (default), critical, or none

exit codes: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage
error or a file that could not be read

suppress a finding with a reason, on its line or the line above:
  # actionwarden:ignore AW001 -- vendored, reviewed 2026-10-01`

// Run executes the command and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	code, err := run(args, stdout, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "actionwarden: %v\n\n%s\n", err, usage)
		return 2
	}
	return code
}

func run(args []string, stdout, stderr io.Writer) (int, error) {
	if len(args) == 0 {
		return 0, fmt.Errorf("no command given")
	}
	switch args[0] {
	case "rules":
		if len(args) > 1 {
			return 0, fmt.Errorf("rules takes no arguments")
		}
		listRules(stdout)
		return 0, nil
	case "scan":
		return scanCommand(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0, nil
	}
	return 0, fmt.Errorf("unknown command %q", args[0])
}

func listRules(w io.Writer) {
	for i, r := range rules.All {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s  %-8s %s (%s)\n", r.ID, strings.ToUpper(r.Severity.String()), r.Title, r.Name)
		fmt.Fprintf(w, "    why: %s\n    fix: %s\n", r.Why, r.Fix)
	}
}

func scanCommand(args []string, stdout, stderr io.Writer) (int, error) {
	format := "terminal"
	brief := false
	failOn, failNone := rules.High, false
	var paths []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		flag, inline, hasInline := arg, "", false
		if strings.HasPrefix(arg, "--") {
			if k, v, ok := strings.Cut(arg, "="); ok {
				flag, inline, hasInline = k, v, true
			}
		}
		value := func() (string, error) {
			if hasInline {
				return inline, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", flag)
			}
			i++
			return args[i], nil
		}
		switch flag {
		case "--format":
			v, err := value()
			if err != nil {
				return 0, err
			}
			if v != "terminal" && v != "json" && v != "sarif" {
				return 0, fmt.Errorf("unknown format %q", v)
			}
			format = v
		case "--brief":
			brief = true
		case "--fail-on":
			v, err := value()
			if err != nil {
				return 0, err
			}
			s, none, ok := rules.ParseSeverity(v)
			if !ok {
				return 0, fmt.Errorf("unknown severity %q", v)
			}
			failOn, failNone = s, none
		default:
			if strings.HasPrefix(arg, "-") && arg != "-" {
				return 0, fmt.Errorf("unknown option %s", arg)
			}
			paths = append(paths, arg)
		}
	}
	if len(paths) == 0 {
		paths = []string{"."}
	}

	res, err := scan.Paths(paths)
	if err != nil {
		return 0, err
	}
	for _, e := range res.Errors {
		fmt.Fprintf(stderr, "actionwarden: %s\n", e)
	}
	if res.Workflows == 0 && len(res.Errors) == 0 {
		return 0, fmt.Errorf("no workflow files found in %s", strings.Join(paths, ", "))
	}

	switch format {
	case "json":
		err = report.JSON(stdout, res)
	case "sarif":
		err = report.SARIF(stdout, res)
	default:
		report.Terminal(stdout, res, brief)
	}
	if err != nil {
		return 0, err
	}

	if len(res.Errors) > 0 {
		fmt.Fprintf(stderr, "actionwarden: %d file(s) could not be read and are not covered by the result above\n", len(res.Errors))
		return 2, nil
	}
	if !failNone {
		for _, f := range res.Findings {
			if f.Severity >= failOn {
				return 1, nil
			}
		}
	}
	return 0, nil
}
