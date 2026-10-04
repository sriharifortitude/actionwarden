package scan

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sriharifortitude/actionwarden/internal/rules"
)

const head = "on: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: x\n    steps:\n"

func ids(fs []rules.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestASuppressionNeedsAReason(t *testing.T) {
	cases := []struct {
		name, step string
		wantRules  []string
		suppressed int
	}{
		{"no comment", "      - uses: o/a@v1\n", []string{"AW001"}, 0},
		{"same line, with reason", "      - uses: o/a@v1 # actionwarden:ignore AW001 -- vendored and reviewed\n", nil, 1},
		{"line above, with reason", "      # actionwarden:ignore AW001 -- vendored and reviewed\n      - uses: o/a@v1\n", nil, 1},
		{"colon separator", "      - uses: o/a@v1 # actionwarden:ignore AW001: reviewed\n", nil, 1},
		{"no reason", "      - uses: o/a@v1 # actionwarden:ignore AW001\n", []string{"AW000", "AW001"}, 0},
		{"dash but empty reason", "      - uses: o/a@v1 # actionwarden:ignore AW001 --   \n", []string{"AW000", "AW001"}, 0},
		{"another rule's id", "      - uses: o/a@v1 # actionwarden:ignore AW002 -- reason\n", []string{"AW001"}, 0},
		{"two lines above", "      # actionwarden:ignore AW001 -- reason\n      - name: x\n        uses: o/a@v1\n", []string{"AW001"}, 0},
		{"code line above is not a comment line", "      - run: echo # actionwarden:ignore AW001 -- reason\n      - uses: o/a@v1\n", []string{"AW001"}, 0},
	}
	for _, c := range cases {
		fs, suppressed, err := Source("wf.yml", []byte(head+c.step))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := ids(fs); !reflect.DeepEqual(got, c.wantRules) || suppressed != c.suppressed {
			t.Errorf("%s: rules %v suppressed %d, want %v and %d", c.name, got, suppressed, c.wantRules, c.suppressed)
		}
	}
}

func TestASuppressionOnlyCoversItsOwnFinding(t *testing.T) {
	src := head + "      - uses: o/a@v1 # actionwarden:ignore AW001 -- reviewed\n      - uses: o/b@v1\n"
	fs, suppressed, _ := Source("wf.yml", []byte(src))
	if len(fs) != 1 || fs[0].Line != 9 || suppressed != 1 {
		t.Errorf("%+v suppressed=%d", fs, suppressed)
	}
}

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDirectoryDiscovery(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/b.yml", head+"      - run: x\n")
	write(t, root, ".github/workflows/a.yaml", head+"      - run: x\n")
	write(t, root, ".github/workflows/notes.md", "not yaml")
	write(t, root, ".github/workflows/sub/c.yml", head)
	files, err := Files([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, filepath.Base(f))
	}
	if !reflect.DeepEqual(names, []string{"a.yaml", "b.yml"}) {
		t.Errorf("sorted, yaml only, not recursive: %v", names)
	}

	flat := t.TempDir()
	write(t, flat, "ci.yml", head)
	if files, _ := Files([]string{flat}); len(files) != 1 {
		t.Errorf("a plain directory of workflows: %v", files)
	}
}

func TestAMissingPathIsAnError(t *testing.T) {
	if _, err := Files([]string{filepath.Join(t.TempDir(), "nope")}); err == nil || !strings.Contains(err.Error(), "no such file or directory") {
		t.Errorf("%v", err)
	}
}

func TestABadFileIsReportedAndTheRestStillScanned(t *testing.T) {
	root := t.TempDir()
	write(t, root, "good.yml", head+"      - uses: o/a@v1\n")
	write(t, root, "bad.yml", "on: [\n")
	write(t, root, "notworkflow.yml", "- just\n- a list\n")
	res, err := Paths([]string{root})
	if err != nil {
		t.Fatal(err)
	}
	if res.Workflows != 1 || len(res.Findings) != 1 || len(res.Errors) != 2 {
		t.Fatalf("workflows=%d findings=%d errors=%v", res.Workflows, len(res.Findings), res.Errors)
	}
	if !strings.Contains(res.Errors[0], "bad.yml") || !strings.Contains(res.Errors[1], "notworkflow.yml") {
		t.Errorf("each error names its file: %v", res.Errors)
	}
}

func TestAnOversizedFileIsRefused(t *testing.T) {
	root := t.TempDir()
	p := write(t, root, "big.yml", "")
	f, _ := os.OpenFile(p, os.O_WRONLY, 0o644)
	_ = f.Truncate(MaxFileBytes + 1)
	f.Close()
	res, _ := Paths([]string{p})
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "larger than 4 MiB") {
		t.Errorf("%v", res.Errors)
	}
}

func TestWindowsLineEndings(t *testing.T) {
	src := strings.ReplaceAll(head+"      - uses: o/a@v1 # actionwarden:ignore AW001 -- reviewed\n", "\n", "\r\n")
	fs, suppressed, err := Source("wf.yml", []byte(src))
	if err != nil || len(fs) != 0 || suppressed != 1 {
		t.Errorf("%v %v %d", err, fs, suppressed)
	}
}
