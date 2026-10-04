package rules

import (
	"reflect"
	"strings"
	"testing"

	"github.com/sriharifortitude/actionwarden/internal/workflow"
)

// run parses a workflow written inline and returns "RULE:line" for each finding.
func run(t *testing.T, yaml string) []string {
	t.Helper()
	w, err := workflow.Parse("wf.yml", []byte(strings.TrimLeft(yaml, "\n")))
	if err != nil {
		t.Fatalf("workflow does not parse: %v", err)
	}
	var out []string
	for _, f := range Run(w) {
		out = append(out, f.Rule+":"+itoa(f.Line))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func only(t *testing.T, id, yaml string) []string {
	t.Helper()
	var out []string
	for _, f := range run(t, yaml) {
		if strings.HasPrefix(f, id+":") {
			out = append(out, f)
		}
	}
	return out
}

const perms = "permissions:\n  contents: read\n"

func TestPinning(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	cases := []struct {
		name, uses string
		want       []string
	}{
		{"full sha", "actions/checkout@" + sha + " # v4", nil},
		{"first-party tag", "actions/checkout@v4", []string{"AW001:8"}},
		{"third-party tag", "docker/build-push-action@v6", []string{"AW001:8"}},
		{"branch", "dtolnay/rust-toolchain@master", []string{"AW001:8"}},
		{"local action", "./.github/actions/setup", nil},
		{"container by tag", "docker://alpine:3.20", []string{"AW001:8"}},
		{"container by digest", "docker://alpine@sha256:" + strings.Repeat("a", 64), nil},
		{"short sha is not a sha", "owner/action@" + sha[:7], []string{"AW001:8"}},
		{"expression ref", "${{ inputs.action }}", nil},
	}
	for _, c := range cases {
		wf := "on: push\n" + perms + "jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: " + c.uses + "\n"
		if got := only(t, "AW001", wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPinningSeverity(t *testing.T) {
	wf := "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n      - uses: o/a@v1\n      - uses: o/b@main\n"
	w, _ := workflow.Parse("wf.yml", []byte(wf))
	var got []Severity
	for _, f := range Run(w) {
		got = append(got, f.Severity)
	}
	if !reflect.DeepEqual(got, []Severity{Low, Medium, High}) {
		t.Errorf("first-party tag, third-party tag, branch: %v", got)
	}
}

func TestReusableWorkflowsArePinnedToo(t *testing.T) {
	wf := "on: push\n" + perms + "jobs:\n  call:\n    uses: org/repo/.github/workflows/x.yml@v1\n"
	if got := only(t, "AW001", wf); len(got) != 1 {
		t.Errorf("%v", got)
	}
}

func TestInjection(t *testing.T) {
	cases := []struct {
		name, step string
		want       []string
	}{
		{"title in run", "run: echo ${{ github.event.issue.title }}", []string{"AW002:8"}},
		{"head ref in run", "run: git checkout ${{ github.head_ref }}", []string{"AW002:8"}},
		{"commit message in format", "run: echo ${{ format('msg {0}', github.event.head_commit.message) }}", []string{"AW002:8"}},
		{"routed through env", "env:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"", nil},
		{"boolean use", "run: echo ${{ contains(github.event.issue.title, 'x') }}", nil},
		{"safe context", "run: echo ${{ github.event.pull_request.number }} ${{ github.sha }}", nil},
		{"toJSON of event", "run: echo '${{ toJSON(github.event) }}'", []string{"AW002:8"}},
		{"github-script", "uses: actions/github-script@v7\n        with:\n          script: |\n            const t = '${{ github.event.issue.title }}'", []string{"AW002:11"}},
		{"github-script safe", "uses: actions/github-script@v7\n        with:\n          script: |\n            const t = context.payload.issue.title", nil},
		{"unparsable expression still checked", "run: echo ${{ github.event.issue.title @@ }}", []string{"AW002:8"}},
		{"in an if", "if: ${{ contains(github.event.issue.body, 'x') }}\n        run: echo hi", nil},
	}
	for _, c := range cases {
		wf := "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - " + c.step + "\n"
		if got := only(t, "AW002", wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestInjectionLineInsideABlock(t *testing.T) {
	wf := `
on: push
permissions: {}
jobs:
  a:
    runs-on: x
    steps:
      - run: |
          echo start
          echo safe
          echo "${{ github.event.issue.title }}"
          echo "${{ github.event.comment.body }}"
`
	got := only(t, "AW002", wf)
	if !reflect.DeepEqual(got, []string{"AW002:10", "AW002:11"}) {
		t.Errorf("each expression is reported at its own line: %v", got)
	}
}

func TestInjectionIsCriticalUnderAPrivilegedTrigger(t *testing.T) {
	sev := func(on string) Severity {
		w, _ := workflow.Parse("wf.yml", []byte("on: "+on+"\n"+perms+"jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n"))
		for _, f := range Run(w) {
			if f.Rule == "AW002" {
				return f.Severity
			}
		}
		t.Fatal("no AW002")
		return 0
	}
	if sev("issues") != Critical || sev("pull_request_target") != Critical || sev("push") != High {
		t.Error("severity should follow the trigger's privilege")
	}
}

func TestPwnRequest(t *testing.T) {
	co := func(on, with string) string {
		return "on: " + on + "\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with:\n" + with + "\n"
	}
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"head sha under pull_request_target", co("pull_request_target", "          ref: ${{ github.event.pull_request.head.sha }}"), []string{"AW003:10"}},
		{"head ref", co("pull_request_target", "          ref: ${{ github.head_ref }}"), []string{"AW003:10"}},
		{"fork repository", co("pull_request_target", "          repository: ${{ github.event.pull_request.head.repo.full_name }}"), []string{"AW003:10"}},
		{"merge ref", co("pull_request_target", "          ref: refs/pull/${{ github.event.number }}/merge"), []string{"AW003:10"}},
		{"workflow_run head", co("workflow_run", "          ref: ${{ github.event.workflow_run.head_sha }}"), []string{"AW003:10"}},
		{"plain pull_request is fine", co("pull_request", "          ref: ${{ github.event.pull_request.head.sha }}"), nil},
		{"base sha is fine", co("pull_request_target", "          ref: ${{ github.event.pull_request.base.sha }}"), nil},
		{"default checkout is fine", co("pull_request_target", "          fetch-depth: 0"), nil},
	}
	for _, c := range cases {
		if got := only(t, "AW003", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPwnRequestSeverity(t *testing.T) {
	w, _ := workflow.Parse("wf.yml", []byte("on: workflow_run\n"+perms+"jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.workflow_run.head_sha }}\n"))
	for _, f := range Run(w) {
		if f.Rule == "AW003" && f.Severity != High {
			t.Errorf("workflow_run alone is high, not critical: %v", f.Severity)
		}
	}
}

func TestPermissions(t *testing.T) {
	job := "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n"
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"none anywhere", "on: push\n" + job, []string{"AW004:3"}},
		{"top-level read", "on: push\n" + perms + job, nil},
		{"top-level empty", "on: push\npermissions: {}\n" + job, nil},
		{"job-level only", "on: push\njobs:\n  a:\n    runs-on: x\n    permissions:\n      contents: read\n    steps:\n      - run: make\n", nil},
		{"write-all", "on: push\npermissions: write-all\n" + job, []string{"AW004:2"}},
		{"read-all", "on: push\npermissions: read-all\n" + job, nil},
		{"job write-all", "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    permissions: write-all\n    steps:\n      - run: make\n", []string{"AW004:7"}},
		{"top-level write with several jobs", "on: push\npermissions:\n  contents: write\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: a\n  b:\n    runs-on: x\n    steps:\n      - run: b\n", []string{"AW004:2"}},
		{"top-level write with one job", "on: push\npermissions:\n  contents: write\n" + job, nil},
	}
	for _, c := range cases {
		if got := only(t, "AW004", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestArtifactCredentials(t *testing.T) {
	wf := func(checkoutWith, path string) string {
		return "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n" + checkoutWith +
			"      - uses: actions/upload-artifact@v4\n        with:\n          path: " + path + "\n"
	}
	persistFalse := "        with:\n          persist-credentials: false\n"
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"whole tree, credentials kept", wf("", "."), []string{"AW005:11"}},
		{"glob, credentials kept", wf("", "'**'"), []string{"AW005:11"}},
		{"the .git directory", wf("", ".git/"), []string{"AW005:11"}},
		{"whole tree, credentials dropped", wf(persistFalse, "."), nil},
		{"a build directory", wf("", "dist/"), nil},
		{"expression value counts as kept", wf("        with:\n          persist-credentials: ${{ inputs.keep }}\n", "."), []string{"AW005:13"}},
	}
	for _, c := range cases {
		if got := only(t, "AW005", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSelfHosted(t *testing.T) {
	wf := func(on, runsOn string) string {
		return "on: " + on + "\n" + perms + "jobs:\n  a:\n    runs-on: " + runsOn + "\n    steps:\n      - run: make\n"
	}
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"list, from a pull request", wf("pull_request", "[self-hosted, linux]"), []string{"AW006:6"}},
		{"string, from a comment", wf("issue_comment", "self-hosted"), []string{"AW006:6"}},
		{"hosted runner", wf("pull_request", "ubuntu-latest"), nil},
		{"self-hosted on push only", wf("push", "self-hosted"), nil},
	}
	for _, c := range cases {
		if got := only(t, "AW006", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestUnsafeCommands(t *testing.T) {
	step := func(run string) string {
		return "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - " + run + "\n"
	}
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"set-env", step(`run: echo "::set-env name=A::b"`), []string{"AW007:8"}},
		{"add-path", step(`run: echo "::add-path::/x"`), []string{"AW007:8"}},
		{"the file-based way", step(`run: echo "A=b" >> "$GITHUB_ENV"`), nil},
		{"unsecure flag", "on: push\n" + perms + "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: true\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n", []string{"AW007:5"}},
		{"flag set false", "on: push\n" + perms + "env:\n  ACTIONS_ALLOW_UNSECURE_COMMANDS: false\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: make\n", nil},
	}
	for _, c := range cases {
		if got := only(t, "AW007", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestPipeToShell(t *testing.T) {
	step := func(run string) string {
		return "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: " + run + "\n"
	}
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"curl to sh", step("curl -fsSL https://x.sh | sh"), []string{"AW008:8"}},
		{"curl to sudo bash", step("curl -fsSL https://x.sh | sudo bash -s -- --yes"), []string{"AW008:8"}},
		{"wget to bash", step("wget -qO- https://x.sh | bash"), []string{"AW008:8"}},
		{"process substitution", step("bash <(curl -s https://x.sh)"), []string{"AW008:8"}},
		{"download then run", step("curl -fsSLo x.sh https://x.sh && sha256sum -c x.sum && sh x.sh"), nil},
		{"piped elsewhere", step("curl -s https://x | jq .name"), nil},
		{"commented out", "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: |\n          # curl https://x | sh\n          make\n", nil},
		{"continued line", "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - run: |\n          curl -fsSL https://x.sh \\\n            | sh\n", []string{"AW008:8"}},
	}
	for _, c := range cases {
		if got := only(t, "AW008", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSecretsInherit(t *testing.T) {
	wf := func(uses, secrets string) string {
		return "on: push\n" + perms + "jobs:\n  call:\n    uses: " + uses + "\n    secrets: " + secrets + "\n"
	}
	if got := only(t, "AW009", wf("org/repo/.github/workflows/x.yml@v1", "inherit")); !reflect.DeepEqual(got, []string{"AW009:7"}) {
		t.Errorf("%v", got)
	}
	if got := only(t, "AW009", wf("./.github/workflows/x.yml", "inherit")); len(got) != 1 {
		t.Errorf("a local workflow is still reported, at a lower severity: %v", got)
	}
	if got := only(t, "AW009", "on: push\n"+perms+"jobs:\n  call:\n    uses: org/r/.github/workflows/x.yml@v1\n    secrets:\n      TOKEN: ${{ secrets.TOKEN }}\n"); got != nil {
		t.Errorf("named secrets are fine: %v", got)
	}
}

func TestAlwaysTrueCondition(t *testing.T) {
	step := func(cond string) string {
		return "on: push\n" + perms + "jobs:\n  a:\n    runs-on: x\n    steps:\n      - if: " + cond + "\n        run: make\n"
	}
	cases := []struct {
		name, wf string
		want     []string
	}{
		{"expression then comparison", step(`${{ github.actor }} == 'dependabot[bot]'`), []string{"AW010:8"}},
		{"text before the expression", step(`startsWith(${{ github.ref }}, 'x')`), []string{"AW010:8"}},
		{"whole condition inside", step(`${{ github.actor == 'dependabot[bot]' }}`), nil},
		{"no delimiters", step(`github.actor == 'dependabot[bot]'`), nil},
		{"two expressions", step(`${{ a }} && ${{ b }}`), []string{"AW010:8"}},
		{"padded whole expression", step(`"  ${{ github.actor == 'x' }}  "`), nil},
	}
	for _, c := range cases {
		if got := only(t, "AW010", c.wf); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestEveryRuleIsDocumentedAndOrdered(t *testing.T) {
	seen := map[string]bool{}
	prev := ""
	for _, r := range All {
		if r.ID <= prev {
			t.Errorf("%s is out of order after %s", r.ID, prev)
		}
		prev = r.ID
		if seen[r.ID] || r.Name == "" || r.Title == "" || r.Why == "" || r.Fix == "" || r.Check == nil {
			t.Errorf("%s is incomplete or duplicated", r.ID)
		}
		seen[r.ID] = true
	}
}
