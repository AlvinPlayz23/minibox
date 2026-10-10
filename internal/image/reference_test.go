//go:build linux

package image

import "testing"

func TestParseReference(t *testing.T) {
	ok := map[string]string{
		"alpine":                            "docker.io/library/alpine:latest",
		"alpine:3.20":                       "docker.io/library/alpine:3.20",
		"docker.io/library/alpine:3.20":     "docker.io/library/alpine:3.20",
		"index.docker.io/library/alpine":    "docker.io/library/alpine:latest",
		"bitnami/redis:7":                   "docker.io/bitnami/redis:7",
		"ghcr.io/org/app:v1":                "ghcr.io/org/app:v1",
		"localhost:5000/x":                  "localhost:5000/x:latest",
		"localhost/x":                       "localhost/x:latest",
		"registry.example.com:8443/a/b/c:1": "registry.example.com:8443/a/b/c:1",
		"alpine@sha256:" + hex64('a'):       "docker.io/library/alpine@sha256:" + hex64('a'),
	}
	for in, want := range ok {
		r, err := ParseReference(in)
		if err != nil || r.Name() != want {
			t.Errorf("%q => %q, %v; want %q", in, r.Name(), err, want)
		}
	}
	for _, bad := range []string{"", " ", "A/b", "a b", "alpine:", "alpine@sha256:xyz", "alpine@md5:abc", "a//b", "-x", "/x", "x/", "ghcr.io/", "alpine:tag:two", "UPPER", "a:../x", "host:99999999/x"} {
		if r, err := ParseReference(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, r.Name())
		}
	}
	if r, _ := ParseReference("alpine"); r.APIHost() != "registry-1.docker.io" {
		t.Error(r.APIHost())
	}
}

func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

func FuzzParseReference(f *testing.F) {
	for _, s := range []string{"alpine", "a/b:c", "localhost:5000/x@sha256:" + hex64('0'), "", "::", "a@@b", "//", "A:B"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseReference(s)
		if err != nil {
			return
		}
		// Anything accepted must round-trip to itself and be a safe path component set.
		r2, err := ParseReference(r.Name())
		if err != nil || r2 != r {
			t.Fatalf("%q -> %+v -> %+v (%v)", s, r, r2, err)
		}
		st := &Store{Root: "/r"}
		p, _, err := st.imagePath(s)
		if err != nil {
			t.Fatalf("accepted ref has no path: %v", err)
		}
		if len(p) < 3 || p[:10] != "/r/images/" || containsDotDot(p) {
			t.Fatalf("unsafe path %q for %q", p, s)
		}
	})
}

func containsDotDot(p string) bool {
	for i := 0; i+1 < len(p); i++ {
		if p[i] == '.' && p[i+1] == '.' && (i == 0 || p[i-1] == '/') && (i+2 == len(p) || p[i+2] == '/') {
			return true
		}
	}
	return false
}
