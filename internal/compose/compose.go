//go:build linux

// Package compose implements a tiny subset of Compose-style YAML for
// `minibox up/down` without external dependencies. Supported schema:
//
//	services:
//	  web:
//	    image: alpine
//	    command: sh -c '...'        # string or list
//	    ports: ["8080:80"]          # list
//	    environment: ["A=1"]        # list, or mapping {A: 1}
//	    volumes: ["data:/data"]     # list
//	    network: bridge             # optional
//	    restart: always             # optional
//	    working_dir: /srv           # optional
//	    user: "1000"                # optional
//	    hostname: web               # optional
package compose

import (
	"fmt"
	"strings"
)

// Service is one service definition.
type Service struct {
	Name        string
	Image       string
	Command     []string
	CommandRaw  string // original string form (for error messages)
	Ports       []string
	Environment []string
	Volumes     []string
	Network     string
	Restart     string
	Workdir     string
	User        string
	Hostname    string
}

// Project is a parsed file.
type Project struct {
	Services []Service
}

type line struct {
	indent int
	text   string
	num    int
}

func splitLines(data []byte) []line {
	var out []line
	for i, raw := range strings.Split(string(data), "\n") {
		raw = strings.TrimSuffix(raw, "\r")
		// Strip inline comments starting with ' #' (naive but fine for our schema).
		text := raw
		if idx := strings.Index(text, " #"); idx >= 0 {
			text = text[:idx]
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := 0
		for _, r := range raw {
			if r == ' ' {
				indent++
			} else if r == '\t' {
				indent += 8
			} else {
				break
			}
		}
		out = append(out, line{indent: indent, text: strings.TrimSpace(text), num: i + 1})
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'' {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Parse parses the compose file subset.
func Parse(data []byte) (*Project, error) {
	lines := splitLines(data)
	p := &Project{}
	i := 0
	// Skip optional top-level keys until services:.
	for i < len(lines) {
		if lines[i].indent == 0 && strings.HasPrefix(lines[i].text, "services:") {
			rest := strings.TrimSpace(strings.TrimPrefix(lines[i].text, "services:"))
			if rest != "" && rest != "{}" {
				return nil, fmt.Errorf("line %d: services: takes a mapping, not %q", lines[i].num, rest)
			}
			i++
			break
		}
		i++
	}
	if i >= len(lines) && len(p.Services) == 0 {
		// No services: key at all?
		has := false
		for _, l := range lines {
			if l.indent == 0 && strings.HasPrefix(l.text, "services:") {
				has = true
			}
		}
		if !has {
			return nil, fmt.Errorf("no top-level `services:` mapping found")
		}
	}
	for i < len(lines) {
		l := lines[i]
		if l.indent == 0 {
			return nil, fmt.Errorf("line %d: only `services:` is supported at top level (got %q)", l.num, l.text)
		}
		if l.indent != 2 {
			return nil, fmt.Errorf("line %d: service names must be indented 2 spaces (got %d)", l.num, l.indent)
		}
		name := strings.TrimSuffix(l.text, ":")
		if name == "" || strings.ContainsAny(name, " \t:") {
			return nil, fmt.Errorf("line %d: bad service name %q", l.num, l.text)
		}
		svc := Service{Name: name}
		i++
		ni, err := parseService(lines, i, &svc)
		if err != nil {
			return nil, err
		}
		i = ni
		if svc.Image == "" {
			return nil, fmt.Errorf("service %q: missing required `image:`", name)
		}
		p.Services = append(p.Services, svc)
	}
	if len(p.Services) == 0 {
		return nil, fmt.Errorf("no services defined under `services:`")
	}
	return p, nil
}

func parseService(lines []line, i int, svc *Service) (int, error) {
	for i < len(lines) && lines[i].indent > 2 {
		l := lines[i]
		if l.indent != 4 {
			return 0, fmt.Errorf("line %d: service keys must be indented 4 spaces", l.num)
		}
		key, val, _ := strings.Cut(l.text, ":")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "image", "network", "restart", "working_dir", "user", "hostname":
			if val == "" {
				return 0, fmt.Errorf("line %d: %s: needs a value", l.num, key)
			}
			v := unquote(val)
			switch key {
			case "image":
				svc.Image = v
			case "network":
				svc.Network = v
			case "restart":
				svc.Restart = v
			case "working_dir":
				svc.Workdir = v
			case "user":
				svc.User = v
			case "hostname":
				svc.Hostname = v
			}
			i++
		case "command":
			if val != "" {
				svc.CommandRaw = val
				if strings.HasPrefix(strings.TrimSpace(val), "[") {
					items, err := parseInlineList(val)
					if err != nil {
						return 0, fmt.Errorf("line %d: %w", l.num, err)
					}
					svc.Command = items
				} else {
					// String form: split respecting quotes.
					svc.Command = splitShell(unquote(val))
				}
				i++
			} else {
				items, ni, err := parseList(lines, i+1, 6)
				if err != nil {
					return 0, err
				}
				svc.Command = items
				i = ni
			}
		case "ports", "volumes":
			items, ni, err := parseStringList(lines, i, val)
			if err != nil {
				return 0, err
			}
			if key == "ports" {
				svc.Ports = items
			} else {
				svc.Volumes = items
			}
			i = ni
		case "environment":
			items, ni, err := parseEnv(lines, i, val)
			if err != nil {
				return 0, err
			}
			svc.Environment = items
			i = ni
		default:
			return 0, fmt.Errorf("line %d: unsupported key %q (supported: image, command, ports, environment, volumes, network, restart, working_dir, user, hostname)", l.num, key)
		}
	}
	return i, nil
}

// parseStringList parses `key: [a, b]` inline or a `- item` block list.
func parseStringList(lines []line, i int, val string) ([]string, int, error) {
	if val != "" {
		items, err := parseInlineList(val)
		if err != nil {
			return nil, 0, fmt.Errorf("line %d: %w", lines[i].num, err)
		}
		return items, i + 1, nil
	}
	return parseList(lines, i+1, 6)
}

func parseInlineList(val string) ([]string, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil, nil
	}
	if !strings.HasPrefix(val, "[") || !strings.HasSuffix(val, "]") {
		return nil, fmt.Errorf("expected a [a, b] list or a `- item` block list, got %q", val)
	}
	inner := strings.TrimSpace(val[1 : len(val)-1])
	if inner == "" {
		return nil, nil
	}
	var out []string
	for _, part := range strings.Split(inner, ",") {
		out = append(out, unquote(strings.TrimSpace(part)))
	}
	return out, nil
}

func parseList(lines []line, i int, wantIndent int) ([]string, int, error) {
	var out []string
	for i < len(lines) && lines[i].indent >= wantIndent {
		l := lines[i]
		if l.indent != wantIndent || !strings.HasPrefix(l.text, "- ") && l.text != "-" {
			return nil, 0, fmt.Errorf("line %d: expected `- item` list entries", l.num)
		}
		out = append(out, unquote(strings.TrimSpace(strings.TrimPrefix(l.text, "-"))))
		i++
	}
	if len(out) == 0 {
		return nil, 0, fmt.Errorf("line %d: expected at least one `- item`", lines[i-1].num)
	}
	return out, i, nil
}

// parseEnv handles `environment: [A=1]` and mapping form:
//
//	environment:
//	  A: 1
//	  B: two words
func parseEnv(lines []line, i int, val string) ([]string, int, error) {
	if val != "" {
		return parseStringList(lines, i, val)
	}
	var out []string
	j := i + 1
	for j < len(lines) && lines[j].indent >= 6 {
		l := lines[j]
		if l.indent != 6 {
			return nil, 0, fmt.Errorf("line %d: environment entries must be indented 6 spaces", l.num)
		}
		if strings.HasPrefix(l.text, "- ") || l.text == "-" {
			items, ni, err := parseList(lines, j, 6)
			if err != nil {
				return nil, 0, err
			}
			return items, ni, nil
		}
		k, v, ok := strings.Cut(l.text, ":")
		if !ok {
			return nil, 0, fmt.Errorf("line %d: environment mapping entries look like `KEY: value`", l.num)
		}
		out = append(out, strings.TrimSpace(k)+"="+unquote(strings.TrimSpace(v)))
		j++
	}
	if len(out) == 0 {
		return nil, 0, fmt.Errorf("line %d: environment: needs a list or mapping", lines[i].num)
	}
	return out, j, nil
}

func splitShell(s string) []string {
	// Respect quotes; no globbing or expansion (compose files are static).
	var out []string
	var cur strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote == 0 && (r == '"' || r == '\''):
			quote = r
		case quote == 0 && (r == ' ' || r == '\t'):
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
