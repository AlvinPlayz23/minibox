//go:build linux

package build

import (
	"strings"
	"testing"
)

func TestParseBasic(t *testing.T) {
	df := `
# comment
FROM alpine:3.20 AS base
ARG VERSION=1.0
ENV APP_HOME=/srv DEBUG=$VERSION
WORKDIR /srv
COPY --chown=1000:1000 app/ config/ /srv/
RUN echo hi && \
    echo there
CMD ["./app", "--serve"]
ENTRYPOINT /bin/sh -c
EXPOSE 80 443/tcp
USER 1000
LABEL keep=me
`
	insts, err := Parse([]byte(df))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"FROM", "ARG", "ENV", "WORKDIR", "COPY", "RUN", "CMD", "ENTRYPOINT", "EXPOSE", "USER", "LABEL"}
	if len(insts) != len(want) {
		t.Fatalf("got %d instructions: %v", len(insts), insts)
	}
	for i, w := range want {
		if insts[i].Name != w {
			t.Errorf("inst %d: got %q want %q", i, insts[i].Name, w)
		}
	}
	if got := strings.Fields(insts[5].Args); len(got) != 5 || got[0] != "echo" || got[4] != "there" {
		t.Errorf("continuation: %q", insts[5].Args)
	}
}

func TestJSONOrShell(t *testing.T) {
	a, err := ParseJSONOrShell(`["./app", "--serve"]`)
	if err != nil || len(a) != 2 || a[0] != "./app" {
		t.Errorf("%v %v", a, err)
	}
	a, err = ParseJSONOrShell(`echo hi`)
	if err != nil || len(a) != 3 || a[0] != "/bin/sh" || a[2] != "echo hi" {
		t.Errorf("%v %v", a, err)
	}
	if _, err := ParseJSONOrShell(`["unclosed`); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestEnvAndSubstitute(t *testing.T) {
	p, err := ParseEnv(`A=1 B="two words"`)
	if err != nil {
		t.Fatal(err)
	}
	if p[1][1] != "two words" {
		t.Errorf("%v", p)
	}
	p2, err := ParseEnv("LEGACY value here")
	if err != nil || p2[0][0] != "LEGACY" || p2[0][1] != "value here" {
		t.Errorf("%v %v", p2, err)
	}
	vars := map[string]string{"VERSION": "1.0"}
	if got := Substitute("v$VERSION-${VERSION}-$$", vars); got != "v1.0-1.0-$" {
		t.Errorf("%q", got)
	}
}

func TestCopyParse(t *testing.T) {
	ch, srcs, dst, err := ParseCopy("a b /srv/")
	if err != nil || ch != "" || len(srcs) != 2 || dst != "/srv/" {
		t.Errorf("%q %v %q %v", ch, srcs, dst, err)
	}
	ch, _, _, err = ParseCopy("--chown=1000:1000 a /srv")
	if err != nil || ch != "1000:1000" {
		t.Errorf("%q %v", ch, err)
	}
	if _, _, _, err := ParseCopy("--from=builder a /b"); err == nil {
		t.Error("--from accepted")
	}
	if _, _, _, err := ParseCopy("onlyone"); err == nil {
		t.Error("single arg accepted")
	}
	if _, _, err := ParseChown("1000:1000"); err != nil {
		t.Error(err)
	}
	if _, _, err := ParseChown("nobody:nogroup"); err == nil {
		t.Error("name chown accepted")
	}
}

func TestContextFilesRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := ContextFiles(dir, []string{"/abs"}, "/dst", "/"); err == nil {
		t.Error("absolute src accepted")
	}
	if _, _, err := ContextFiles(dir, []string{"../escape"}, "/dst", "/"); err == nil {
		t.Error("escape accepted")
	}
	if _, _, err := ContextFiles(dir, []string{"missing"}, "/dst", "/"); err == nil {
		t.Error("missing src accepted")
	}
}
