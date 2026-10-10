//go:build linux

// Package build implements `minibox build` for a Dockerfile subset:
// FROM, RUN, COPY, ENV, WORKDIR, CMD, ENTRYPOINT, EXPOSE, USER, ARG.
package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Instruction is one parsed Dockerfile line.
type Instruction struct {
	Name string // uppercase, e.g. RUN
	Args string // raw remainder
	Line int    // 1-based source line (for errors)
}

// Parse parses Dockerfile bytes into instructions. It handles backslash
// continuations and full-line comments. Inline comments are NOT stripped
// (matching Docker behavior).
func Parse(data []byte) ([]Instruction, error) {
	// Join continuations first.
	var lines []struct {
		text string
		line int
	}
	var cur strings.Builder
	curLine := 0
	flush := func() {
		if cur.Len() > 0 || curLine > 0 {
			lines = append(lines, struct {
				text string
				line int
			}{cur.String(), curLine})
			cur.Reset()
			curLine = 0
		}
	}
	raw := strings.Split(string(data), "\n")
	for i, l := range raw {
		ln := i + 1
		// Strip trailing \r (Windows-edited files).
		l = strings.TrimSuffix(l, "\r")
		trimmedRight := strings.TrimRight(l, " \t")
		if strings.HasSuffix(trimmedRight, "\\") {
			// Continuation: drop the backslash, join with a space.
			part := strings.TrimSuffix(trimmedRight, "\\")
			if curLine == 0 {
				curLine = ln
			}
			cur.WriteString(part)
			cur.WriteString(" ")
			continue
		}
		if curLine == 0 {
			curLine = ln
		}
		cur.WriteString(l)
		flush()
	}
	var out []Instruction
	for _, l := range lines {
		t := strings.TrimSpace(l.text)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		name, args, _ := strings.Cut(t, " ")
		name = strings.ToUpper(strings.TrimSpace(name))
		args = strings.TrimSpace(args)
		// Directives like "# syntax=..." are comments; parser directives are ignored.
		if name == "" {
			continue
		}
		out = append(out, Instruction{Name: name, Args: args, Line: l.line})
	}
	return out, nil
}

// SplitArgs splits COPY/RUN-style args respecting single/double quotes.
func SplitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	esc := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\' && quote == 0:
			esc = true
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && (r == ' ' || r == '\t'):
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// ParseJSONOrShell parses CMD/ENTRYPOINT/RUN args: JSON array form or shell form.
// Shell form wraps in /bin/sh -c (for CMD/ENTRYPOINT); for RUN it also wraps.
func ParseJSONOrShell(args string) ([]string, error) {
	t := strings.TrimSpace(args)
	if strings.HasPrefix(t, "[") {
		var arr []string
		dec := json.NewDecoder(strings.NewReader(t))
		if err := dec.Decode(&arr); err != nil {
			return nil, fmt.Errorf("could not parse JSON array form %q: %w", args, err)
		}
		if extra := strings.TrimSpace(strings.TrimPrefix(t, jsonArrayPrefix(t))); extra != "" {
			_ = extra
		}
		return arr, nil
	}
	if t == "" {
		return nil, nil
	}
	return []string{"/bin/sh", "-c", t}, nil
}

func jsonArrayPrefix(t string) string {
	dec := json.NewDecoder(strings.NewReader(t))
	var arr []string
	_ = dec.Decode(&arr)
	return t[:int(dec.InputOffset())]
}

// ParseEnv parses ENV args: KEY=VAL pairs or legacy KEY VALUE.
func ParseEnv(args string) ([][2]string, error) {
	if strings.Contains(args, "=") {
		var out [][2]string
		for _, f := range SplitArgs(args) {
			k, v, ok := strings.Cut(f, "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("bad ENV entry %q; use KEY=VALUE", f)
			}
			out = append(out, [2]string{k, v})
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("ENV needs at least one KEY=VALUE")
		}
		return out, nil
	}
	k, v, _ := strings.Cut(args, " ")
	k = strings.TrimSpace(k)
	v = strings.TrimSpace(v)
	if k == "" || v == "" {
		return nil, fmt.Errorf("bad ENV %q; use KEY=VALUE or KEY VALUE", args)
	}
	return [][2]string{{k, v}}, nil
}

// Substitute expands $VAR and ${VAR} using vars. Unknown vars expand to "".
// $$ escapes to $.
func Substitute(s string, vars map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 < len(s) && s[i+1] == '$' {
			b.WriteByte('$')
			i += 2
			continue
		}
		if i+1 < len(s) && s[i+1] == '{' {
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteByte(s[i])
				i++
				continue
			}
			name := s[i+2 : i+2+end]
			b.WriteString(vars[name])
			i += 2 + end + 1
			continue
		}
		j := i + 1
		for j < len(s) && (s[j] == '_' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 'A' && s[j] <= 'Z' || s[j] >= '0' && s[j] <= '9') {
			j++
		}
		if j == i+1 {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(vars[s[i+1:j]])
		i = j
	}
	return b.String()
}

// ParseCopy splits COPY args into flags, sources and destination.
func ParseCopy(args string) (chown string, srcs []string, dst string, err error) {
	fields := SplitArgs(args)
	var rest []string
	for _, f := range fields {
		if strings.HasPrefix(f, "--chown=") {
			chown = strings.TrimPrefix(f, "--chown=")
			continue
		}
		if strings.HasPrefix(f, "--") {
			return "", nil, "", fmt.Errorf("unsupported COPY flag %q (only --chown=uid:gid is supported; COPY --from is not: multi-stage builds are not supported)", f)
		}
		rest = append(rest, f)
	}
	if len(rest) < 2 {
		return "", nil, "", fmt.Errorf("COPY needs at least one source and a destination")
	}
	return chown, rest[:len(rest)-1], rest[len(rest)-1], nil
}

// ParseChown parses uid[:gid] numerically (names are not resolvable at build time).
func ParseChown(s string) (uid, gid int, err error) {
	u, g, _ := strings.Cut(s, ":")
	uid, err = strconv.Atoi(u)
	if err != nil {
		return 0, 0, fmt.Errorf("--chown=%q: only numeric uid[:gid] is supported (got non-numeric user)", s)
	}
	gid = uid
	if g != "" {
		if gid, err = strconv.Atoi(g); err != nil {
			return 0, 0, fmt.Errorf("--chown=%q: only numeric uid[:gid] is supported", s)
		}
	}
	return uid, gid, nil
}

// ContextFiles resolves COPY sources under contextDir, returning (hostPath, tarName) pairs.
// dst is resolved against workdir (container absolute or relative).
func ContextFiles(contextDir string, srcs []string, dst, workdir string) (pairs [][2]string, dstDir string, err error) {
	if filepath.IsAbs(dst) {
		dstDir = filepath.Clean(dst)
	} else {
		if workdir == "" {
			workdir = "/"
		}
		dstDir = filepath.Clean(filepath.Join(workdir, dst))
	}
	multi := len(srcs) > 1
	dstIsDir := strings.HasSuffix(dst, "/") || multi || dstDir == "/"
	for _, src := range srcs {
		if filepath.IsAbs(src) {
			return nil, "", fmt.Errorf("COPY source %q must be relative to the build context", src)
		}
		clean := filepath.Clean(src)
		if clean == ".." || strings.HasPrefix(clean, "../") {
			return nil, "", fmt.Errorf("COPY source %q escapes the build context", src)
		}
		host := filepath.Join(contextDir, clean)
		matches, gerr := filepath.Glob(host)
		if gerr != nil || len(matches) == 0 {
			return nil, "", fmt.Errorf("COPY source %q: no such file in the build context", src)
		}
		sort.Strings(matches)
		for _, m := range matches {
			rel, _ := filepath.Rel(contextDir, m)
			name := rel
			if dstIsDir {
				name = filepath.Join(strings.TrimPrefix(dstDir, "/"), filepath.Base(m))
				if st, serr := os.Stat(m); serr == nil && st.IsDir() {
					// Directory copy: contents go under dst/basename.
					name = filepath.Join(strings.TrimPrefix(dstDir, "/"), filepath.Base(m))
				}
			} else {
				name = strings.TrimPrefix(dstDir, "/")
			}
			pairs = append(pairs, [2]string{m, filepath.ToSlash(name)})
		}
	}
	return pairs, dstDir, nil
}
