//go:build linux

package image

import (
	"fmt"
	"strconv"
	"strings"
)

// Reference is a parsed image reference.
type Reference struct {
	Registry string // docker.io, ghcr.io, localhost:5000, ...
	Repo     string // library/alpine
	Tag      string // "latest" unless Digest is set
	Digest   string // sha256:<hex> or ""
}

// Name is the canonical form: registry/repo:tag or registry/repo@digest.
func (r Reference) Name() string {
	if r.Digest != "" {
		return r.Registry + "/" + r.Repo + "@" + r.Digest
	}
	return r.Registry + "/" + r.Repo + ":" + r.Tag
}

// APIHost is the host serving the v2 API (docker.io lives at registry-1.docker.io).
func (r Reference) APIHost() string {
	if r.Registry == "docker.io" {
		return "registry-1.docker.io"
	}
	return r.Registry
}

// ManifestRef is the tag or digest used in manifest URLs.
func (r Reference) ManifestRef() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// ParseReference parses alpine, alpine:3.20, docker.io/library/alpine:3.20,
// ghcr.io/org/app@sha256:..., localhost:5000/x. Docker Hub rules apply:
// a first component is a registry iff it contains '.' or ':' or is "localhost".
func ParseReference(s string) (Reference, error) {
	orig := s
	bad := func(why string) (Reference, error) {
		return Reference{}, fmt.Errorf("invalid image reference %q: %s; examples: alpine, alpine:3.20, ghcr.io/org/app:v1, repo@sha256:<64 hex>", orig, why)
	}
	if s == "" || len(s) > 512 || strings.ContainsAny(s, " \t\r\n\x00") {
		return bad("empty or contains whitespace")
	}
	var r Reference
	if i := strings.Index(s, "@"); i >= 0 {
		if _, err := ParseDigest(s[i+1:]); err != nil {
			return bad("bad digest")
		}
		r.Digest, s = s[i+1:], s[:i]
	}
	// Tag: a ':' after the last '/'.
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[i:], "/") {
		r.Tag, s = s[i+1:], s[:i]
		if !tagRe().MatchString(r.Tag) {
			return bad("bad tag")
		}
	}
	if r.Digest != "" {
		r.Tag = "" // the digest wins; the tag is only a hint
	} else if r.Tag == "" {
		r.Tag = "latest"
	}
	r.Registry = "docker.io"
	if i := strings.Index(s, "/"); i >= 0 {
		first := s[:i]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			r.Registry, s = first, s[i+1:]
		}
	}
	if r.Registry == "index.docker.io" || r.Registry == "registry-1.docker.io" {
		r.Registry = "docker.io"
	}
	if !hostRe().MatchString(r.Registry) {
		return bad("bad registry host")
	}
	if host, port, ok := strings.Cut(r.Registry, ":"); ok {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return bad(fmt.Sprintf("bad registry port %q in %q", port, host))
		}
	}
	if r.Registry == "docker.io" && !strings.Contains(s, "/") {
		s = "library/" + s
	}
	if s == "" || len(s) > 255 || !nameRe().MatchString(s) {
		return bad("repository must be lowercase letters, digits, '.', '_', '-' separated by '/'")
	}
	r.Repo = s
	return r, nil
}

var hostRe = lazyRe(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:[0-9]{1,5})?$`)
