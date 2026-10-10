//go:build linux

package image

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func dig(b []byte) string { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }

func tarGz(t *testing.T, files map[string]string) (gz []byte, diffID string) {
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for n, c := range files {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(c))
	}
	tw.Close()
	diffID = dig(raw.Bytes())
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	zw.Write(raw.Bytes())
	zw.Close()
	return out.Bytes(), diffID
}

// fakeRegistry serves one image "app" (an index with a linux/<arch> and an attestation entry)
// behind bearer-token auth. corrupt flips a byte in the layer blob responses
// only (the config stays intact so the pull reaches layer verification).
func fakeRegistry(t *testing.T, corrupt bool) (*httptest.Server, *atomic.Int32) {
	l1, d1 := tarGz(t, map[string]string{"a.txt": "layer one"})
	l2, d2 := tarGz(t, map[string]string{"b.txt": "layer two"})
	cfg, _ := json.Marshal(map[string]any{
		"created": "2024-01-01T00:00:00Z",
		"config":  map[string]any{"Entrypoint": []string{"/bin/app"}, "Cmd": []string{"--x"}, "Env": []string{"A=1"}, "WorkingDir": "/srv", "User": "1000", "ExposedPorts": map[string]any{"80/tcp": map[string]any{}}},
		"rootfs":  map[string]any{"type": "layers", "diff_ids": []string{d1, d2}},
	})
	mf, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": map[string]any{"mediaType": "x", "digest": dig(cfg), "size": len(cfg)},
		"layers": []any{map[string]any{"digest": dig(l1), "size": len(l1)}, map[string]any{"digest": dig(l2), "size": len(l2)}}})
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []any{
		map[string]any{"digest": dig([]byte("other")), "platform": map[string]any{"os": "unknown", "architecture": "unknown"}},
		map[string]any{"mediaType": mtOCIManifest, "digest": dig(mf), "size": len(mf), "platform": map[string]any{"os": "linux", "architecture": runtime.GOARCH}},
	}})
	var tokenHits atomic.Int32
	blobs := map[string][]byte{dig(cfg): cfg, dig(l1): l1, dig(l2): l2}
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		if r.URL.Query().Get("scope") != "repository:team/app:pull" {
			http.Error(w, "bad scope", 400)
		}
		json.NewEncoder(w).Encode(map[string]string{"token": "sekrit"})
	})
	mux.HandleFunc("/v2/team/app/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sekrit" {
			w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="fake",scope="repository:team/app:pull"`, srv.URL))
			w.WriteHeader(401)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/v2/team/app/")
		switch {
		case p == "manifests/latest":
			w.Write(idx)
		case p == "manifests/"+dig(mf):
			w.Write(mf)
		case strings.HasPrefix(p, "blobs/"):
			b, ok := blobs[strings.TrimPrefix(p, "blobs/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			// Corrupt layers only: the config must verify so the pull
			// reaches compressed-blob verification (the point of the test).
			if corrupt && !bytes.Equal(b, cfg) {
				b = append([]byte(nil), b...)
				b[len(b)/2] ^= 0xff
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &tokenHits
}

func TestPullFromRegistry(t *testing.T) {
	srv, tokens := fakeRegistry(t, false)
	host := strings.TrimPrefix(srv.URL, "http://") // 127.0.0.1:port => plain http
	s := &Store{Root: t.TempDir()}
	img, err := s.Pull(context.Background(), NewClient(), host+"/team/app:latest", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Layers) != 2 || img.Config.WorkingDir != "/srv" || img.Config.User != "1000" ||
		img.Config.Entrypoint[0] != "/bin/app" || img.Config.Cmd[0] != "--x" || img.Config.Env[0] != "A=1" ||
		len(img.Config.ExposedPorts) != 1 || img.Config.ExposedPorts[0] != "80/tcp" {
		t.Fatalf("config not applied: %+v", img)
	}
	if tokens.Load() == 0 {
		t.Error("no bearer token fetched")
	}
	lowers, err := s.LowerDirs(img)
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range []string{"b.txt", "a.txt"} { // topmost first
		if b, err := os.ReadFile(lowers[i].Dir + "/" + f); err != nil || len(b) == 0 {
			t.Errorf("layer %d missing %s: %v", i, f, err)
		}
	}
	got, err := s.GetImage(host + "/team/app")
	if err != nil || got.Digest != img.Digest {
		t.Fatalf("GetImage: %v", err)
	}
	// Second pull is a no-op for layers.
	if _, err := s.Pull(context.Background(), NewClient(), host+"/team/app:latest", nil); err != nil {
		t.Fatal(err)
	}
}

func TestPullRejectsCorruptedBlob(t *testing.T) {
	srv, _ := fakeRegistry(t, true)
	host := strings.TrimPrefix(srv.URL, "http://")
	s := &Store{Root: t.TempDir()}
	_, err := s.Pull(context.Background(), NewClient(), host+"/team/app:latest", nil)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("corrupted blob accepted: %v", err)
	}
	ents, _ := os.ReadDir(s.blobsDir())
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("blob visible after mismatch: %s", e.Name())
		}
	}
	if imgs, _ := s.ListImages(); len(imgs) != 0 {
		t.Fatal("image recorded despite failure")
	}
}

func TestPullDiffIDMismatchNotPublished(t *testing.T) {
	// A layer whose compressed digest is right but whose content doesn't match the config diff_id.
	s := &Store{Root: t.TempDir()}
	gz, _ := tarGz(t, map[string]string{"x": "y"})
	p := s.blobsDir()
	os.MkdirAll(p, 0o755)
	os.WriteFile(p+"/"+strings.TrimPrefix(dig(gz), "sha256:"), gz, 0o644)
	r, _ := os.Open(p + "/" + strings.TrimPrefix(dig(gz), "sha256:"))
	dr, _ := Decompress(r)
	_, err := s.UnpackLayerVerified("", dr, DefaultExtractOptions(), "sha256:"+hex64('f'))
	if err == nil || !strings.Contains(err.Error(), "diffID mismatch") {
		t.Fatalf("%v", err)
	}
	if ents, _ := os.ReadDir(s.layersDir()); len(ents) != 0 && !(len(ents) == 1 && ents[0].Name() == "l") {
		t.Fatalf("layer published: %v", ents)
	}
}

func TestParseChallengeCaseInsensitive(t *testing.T) {
	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		ch := parseChallenge(scheme + ` realm="https://auth.example/token",service="s",scope="repository:a/b:pull"`)
		if ch["realm"] != "https://auth.example/token" || ch["service"] != "s" || ch["scope"] != "repository:a/b:pull" {
			t.Errorf("%q => %v", scheme, ch)
		}
	}
}

func TestFetchTokenAccessTokenOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OAuth-style response with only access_token (no "token" key).
		json.NewEncoder(w).Encode(map[string]string{"access_token": "tok123", "token_type": "Bearer"})
	}))
	defer srv.Close()
	c := NewClient()
	for _, scheme := range []string{"Bearer", "BEARER"} {
		tok, err := c.fetchToken(context.Background(),
			Reference{Registry: "example.com", Repo: "a/b"},
			fmt.Sprintf(`%s realm="%s/t",service="s"`, scheme, srv.URL))
		if err != nil || tok != "tok123" {
			t.Errorf("%s: tok=%q err=%v", scheme, tok, err)
		}
	}
}

func TestSizeCappedReader(t *testing.T) {
	// Exact size passes through untouched.
	r := &sizeCappedReader{r: strings.NewReader("12345678"), max: 8}
	if b, err := io.ReadAll(r); err != nil || string(b) != "12345678" {
		t.Errorf("exact: %q %v", b, err)
	}
	// Overlong is rejected, not silently truncated.
	r = &sizeCappedReader{r: strings.NewReader("123456789"), max: 8}
	b, err := io.ReadAll(r)
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("overlong: %q %v", b, err)
	}
	// Short bodies pass (digest verification rejects them later).
	r = &sizeCappedReader{r: strings.NewReader("123"), max: 8}
	if b, err := io.ReadAll(r); err != nil || string(b) != "123" {
		t.Errorf("short: %q %v", b, err)
	}
}

func TestWatchdogBodyStall(t *testing.T) {
	// A server that sends headers and then stalls mid-body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Stall until the client goes away (or a bound, for safety).
		select {
		case <-r.Context().Done():
		case <-time.After(30 * time.Second):
		}
	}))
	defer srv.Close()
	c := NewClient()
	c.StallTimeout = 150 * time.Millisecond
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	// The request carries ctx so the watchdog's cancel aborts the transport
	// read, exactly like get() wires its derived context.
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL, nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	rc := watchBody(ctx, cancel, resp.Body, c.stallTimeout())
	if _, err := io.ReadAll(rc); err != errStalled {
		t.Fatalf("stall: %v", err)
	}
	rc.Close()
	// Live data passes through untouched.
	ctx2, cancel2 := context.WithCancelCause(context.Background())
	defer cancel2(nil)
	rc2 := watchBody(ctx2, cancel2, io.NopCloser(strings.NewReader("data")), time.Second)
	if b, err := io.ReadAll(rc2); err != nil || string(b) != "data" {
		t.Errorf("live: %q %v", b, err)
	}
	rc2.Close()
}

func TestGC(t *testing.T) {
	srv, _ := fakeRegistry(t, false)
	host := strings.TrimPrefix(srv.URL, "http://")
	s := &Store{Root: t.TempDir()}
	if _, err := s.Pull(context.Background(), NewClient(), host+"/team/app", nil); err != nil {
		t.Fatal(err)
	}
	res, err := s.GC(false)
	if err != nil || res.Layers != 0 || res.Blobs != 0 {
		t.Fatalf("GC removed live data: %+v %v", res, err)
	}
	if _, err := s.RemoveImage(host + "/team/app"); err != nil {
		t.Fatal(err)
	}
	res, err = s.GC(true)
	if err != nil || res.Layers != 2 || res.Blobs != 2 {
		t.Fatalf("GC: %+v %v", res, err)
	}
}
