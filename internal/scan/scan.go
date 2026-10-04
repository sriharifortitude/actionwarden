// Package scan finds workflow files, runs the rules over them and applies
// suppression comments.
package scan

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/sriharifortitude/actionwarden/internal/rules"
	"github.com/sriharifortitude/actionwarden/internal/workflow"
)

// MaxFileBytes is the largest workflow file read. Real ones are a few
// kilobytes; the cap keeps a hostile file from using the machine's memory.
const MaxFileBytes = 4 << 20

// Result is everything a scan found.
type Result struct {
	Workflows  int
	Findings   []rules.Finding
	Suppressed int
	// Errors are files that could not be read or parsed. They are not in
	// Findings because a file that was not read says nothing about its safety.
	Errors []string
}

// Files expands the paths given into workflow files. A directory yields the
// files in its .github/workflows when it has that, otherwise the .yml and
// .yaml files directly inside it.
func Files(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%s: no such file or directory", p)
			}
			return nil, fmt.Errorf("%s: %v", p, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		dir := p
		if sub := filepath.Join(p, ".github", "workflows"); isDir(sub) {
			dir = sub
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", dir, err)
		}
		var inDir []string
		for _, e := range entries {
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if !e.IsDir() && (ext == ".yml" || ext == ".yaml") {
				inDir = append(inDir, filepath.Join(dir, e.Name()))
			}
		}
		sort.Strings(inDir)
		files = append(files, inDir...)
	}
	return files, nil
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no such file")
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("larger than %d MiB; refusing it", MaxFileBytes>>20)
	}
	return data, nil
}

// Paths scans the files named by paths.
func Paths(paths []string) (*Result, error) {
	files, err := Files(paths)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	for _, file := range files {
		data, err := readCapped(file)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		fs, suppressed, err := Source(displayPath(file), data)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", file, err))
			continue
		}
		res.Workflows++
		res.Findings = append(res.Findings, fs...)
		res.Suppressed += suppressed
	}
	return res, nil
}

func displayPath(p string) string { return filepath.ToSlash(p) }

var directive = regexp.MustCompile(`actionwarden:ignore\s+(AW\d{3})(?:\s|:|$)(.*)$`)

// reasonOf is the text after the rule ID, minus an optional `--` or `:`.
func reasonOf(rest string) string {
	rest = strings.TrimSpace(rest)
	rest = strings.TrimPrefix(rest, "--")
	rest = strings.TrimPrefix(rest, ":")
	return strings.TrimSpace(rest)
}

// Source runs the rules over one workflow's text and applies the suppression
// comments in it. It returns the findings that remain and how many were
// suppressed.
func Source(path string, src []byte) ([]rules.Finding, int, error) {
	w, err := workflow.Parse(path, src)
	if err != nil {
		return nil, 0, err
	}
	lines := strings.Split(string(src), "\n")
	var kept []rules.Finding
	suppressed := 0
	reasonless := map[int]bool{}
	for _, f := range rules.Run(w) {
		switch status, at := suppression(lines, f); status {
		case suppressedWithReason:
			suppressed++
		case suppressedNoReason:
			kept = append(kept, f)
			if !reasonless[at] {
				reasonless[at] = true
				kept = append(kept, rules.Finding{
					Rule: rules.Meta.ID, Severity: rules.Meta.Severity, File: path, Line: at,
					Message: fmt.Sprintf("this comment suppresses %s but gives no reason, so it suppresses nothing", f.Rule),
					Fix:     rules.Meta.Fix,
				})
			}
		default:
			kept = append(kept, f)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if kept[i].Line != kept[j].Line {
			return kept[i].Line < kept[j].Line
		}
		return kept[i].Rule < kept[j].Rule
	})
	return kept, suppressed, nil
}

type status int

const (
	notSuppressed status = iota
	suppressedWithReason
	suppressedNoReason
)

// suppression looks for `# actionwarden:ignore AWnnn -- reason` on the
// finding's line, or alone on the line above it.
func suppression(lines []string, f rules.Finding) (status, int) {
	for _, candidate := range []int{f.Line, f.Line - 1} {
		if candidate < 1 || candidate > len(lines) {
			continue
		}
		text := strings.TrimRight(lines[candidate-1], "\r")
		if candidate == f.Line-1 && !strings.HasPrefix(strings.TrimSpace(text), "#") {
			continue
		}
		idx := strings.Index(text, "#")
		if idx < 0 {
			continue
		}
		m := directive.FindStringSubmatch(text[idx:])
		if m == nil || m[1] != f.Rule {
			continue
		}
		if reasonOf(m[2]) == "" {
			return suppressedNoReason, candidate
		}
		return suppressedWithReason, candidate
	}
	return notSuppressed, 0
}
