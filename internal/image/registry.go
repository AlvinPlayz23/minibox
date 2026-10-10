//go:build linux

package image

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	mtOCIIndex     = "application/vnd.oci.image.index.v1+json"
	mtDockerList   = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	mtDockerV2     = "application/vnd.docker.distribution.manifest.v2+json"
	acceptManifest = mtOCIIndex + ", " + mtDockerList + ", " + mtOCIManifest + ", " + mtDockerV2
	maxManifest    = 4 << 20
)

type descriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
	Platform  *struct {
		Architecture string `json:"architecture"`
		OS           string `json:"os"`
		Variant      string `json:"variant"`
	} `json:"platform"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    descriptor   `json:"config"`
	Layers    []descriptor `json:"layers"`
	Manifests []descriptor `json:"manifests"`
}

// Client is a minimal OCI distribution (registry v2) client with bearer-token auth.
type Client struct {
	HTTP *http.Client
	// Platform to select from manifest lists.
	OS, Arch, Variant string
	// StallTimeout bounds how long a response body may go without yielding
	// bytes (zero means bodyIdleTimeout). Tests set this low.
	StallTimeout time.Duration

	mu     sync.Mutex
	tokens map[string]string // scope -> bearer token
}

// NewClient returns a client for the host platform.
func NewClient() *Client {
	v := ""
	if runtime.GOARCH == "arm" {
		v = "v7"
	}
	return &Client{
		HTTP: &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 60 * time.Second, MaxIdleConnsPerHost: 8}},
		OS:   "linux", Arch: runtime.GOARCH, Variant: v,
		tokens: map[string]string{},
	}
}

func scheme(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" || h == "127.0.0.1" || h == "::1" {
		return "http"
	}
	for _, x := range strings.Split(os.Getenv("MINIBOX_INSECURE_REGISTRIES"), ",") {
		if x != "" && x == host {
			return "http"
		}
	}
	return "https"
}

// credentials looks in MINIBOX_REGISTRY_USER/PASS, then ~/.docker/config.json.
func credentials(registry string) (user, pass string) {
	if u := os.Getenv("MINIBOX_REGISTRY_USER"); u != "" {
		return u, os.Getenv("MINIBOX_REGISTRY_PASS")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	b, err := os.ReadFile(filepath.Join(home, ".docker", "config.json"))
	if err != nil {
		return "", ""
	}
	var cfg struct {
		Auths map[string]struct{ Auth string } `json:"auths"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return "", ""
	}
	for _, k := range []string{registry, "https://" + registry, "https://index.docker.io/v1/"} {
		if k == "https://index.docker.io/v1/" && registry != "docker.io" {
			continue
		}
		if a, ok := cfg.Auths[k]; ok && a.Auth != "" {
			if d, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
				u, p, _ := strings.Cut(string(d), ":")
				return u, p
			}
		}
	}
	return "", ""
}

func parseChallenge(h string) map[string]string {
	out := map[string]string{}
	h = strings.TrimSpace(h)
	// The auth-scheme name is case-insensitive (RFC 9110 §11.4).
	if i := strings.IndexByte(h, ' '); i > 0 && strings.EqualFold(h[:i], "bearer") {
		h = strings.TrimSpace(h[i+1:])
	}
	for _, part := range strings.Split(h, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok {
			out[strings.ToLower(k)] = strings.Trim(v, `"`)
		}
	}
	return out
}

func (c *Client) fetchToken(ctx context.Context, ref Reference, challenge string) (string, error) {
	ch := parseChallenge(challenge)
	realm := ch["realm"]
	if realm == "" {
		return "", errors.New("registry sent a Bearer challenge without a realm")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if ch["service"] != "" {
		q.Set("service", ch["service"])
	}
	scope := ch["scope"]
	if scope == "" {
		scope = "repository:" + ref.Repo + ":pull"
	}
	q.Set("scope", scope)
	u.RawQuery = q.Encode()
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if user, pass := credentials(ref.Registry); user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch auth token from %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("auth token request to %s failed: %s; check the image name or set MINIBOX_REGISTRY_USER/MINIBOX_REGISTRY_PASS", u.Host, resp.Status)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&t); err != nil {
		return "", err
	}
	tok := t.Token
	if tok == "" {
		tok = t.AccessToken
	}
	if tok == "" {
		return "", errors.New("auth response had no token")
	}
	c.mu.Lock()
	c.tokens[ref.Registry+"|"+ref.Repo] = tok
	c.mu.Unlock()
	return tok, nil
}

// bodyIdleTimeout bounds how long a response body may go without yielding
// bytes. ResponseHeaderTimeout only covers headers, and callers use
// context.Background(), so without this a registry that stalls mid-layer
// would block a pull forever with nothing to retry on.
const bodyIdleTimeout = 60 * time.Second

// errStalled reports a stalled body; downloadBlob retries on it.
var errStalled = errors.New("registry stopped sending data (60s without bytes)")

// watchdogBody cancels its request when the body goes idle, interrupting an
// otherwise uninterruptible blocked Read.
type watchdogBody struct {
	io.ReadCloser
	ctx     context.Context
	cancel  context.CancelCauseFunc
	timeout time.Duration
	mu      sync.Mutex
	last    time.Time
	done    chan struct{}
	once    sync.Once
}

func watchBody(ctx context.Context, cancel context.CancelCauseFunc, rc io.ReadCloser, timeout time.Duration) io.ReadCloser {
	b := &watchdogBody{ReadCloser: rc, ctx: ctx, cancel: cancel, timeout: timeout, last: time.Now(), done: make(chan struct{})}
	go b.watch()
	return b
}

func (b *watchdogBody) touch() {
	b.mu.Lock()
	b.last = time.Now()
	b.mu.Unlock()
}

func (b *watchdogBody) watch() {
	t := time.NewTicker(b.timeout / 4)
	defer t.Stop()
	for {
		select {
		case <-b.done:
			return
		case now := <-t.C:
			b.mu.Lock()
			idle := now.Sub(b.last)
			b.mu.Unlock()
			if idle > b.timeout {
				b.cancel(errStalled)
				return
			}
		}
	}
}

func (b *watchdogBody) stop() {
	b.once.Do(func() { close(b.done) })
}

func (b *watchdogBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.touch()
	}
	if err != nil {
		b.stop()
		if context.Cause(b.ctx) == errStalled {
			return 0, errStalled
		}
	}
	return n, err
}

func (b *watchdogBody) Close() error {
	b.stop()
	b.cancel(nil) // release the derived context; the parent is often Background
	return b.ReadCloser.Close()
}

// stallTimeout returns the configured body idle timeout.
func (c *Client) stallTimeout() time.Duration {
	if c.StallTimeout > 0 {
		return c.StallTimeout
	}
	return bodyIdleTimeout
}

// get performs an authenticated GET, answering one 401 challenge. The caller closes the body.
func (c *Client) get(ctx context.Context, ref Reference, path, accept string) (*http.Response, error) {
	u := scheme(ref.APIHost()) + "://" + ref.APIHost() + "/v2/" + ref.Repo + path
	ctx, cancel := context.WithCancelCause(ctx)
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			cancel(nil)
			return nil, err
		}
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		c.mu.Lock()
		tok := c.tokens[ref.Registry+"|"+ref.Repo]
		c.mu.Unlock()
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		} else if user, pass := credentials(ref.Registry); user != "" && attempt > 0 {
			req.SetBasicAuth(user, pass)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			cancel(nil)
			if context.Cause(ctx) == errStalled {
				return nil, errStalled
			}
			return nil, fmt.Errorf("contact registry %s: %w; check your network", ref.APIHost(), err)
		}
		if resp.StatusCode == 401 && attempt == 0 {
			ch := resp.Header.Get("Www-Authenticate")
			resp.Body.Close()
			if strings.HasPrefix(strings.ToLower(ch), "bearer") {
				if _, err := c.fetchToken(ctx, ref, ch); err != nil {
					cancel(nil)
					return nil, err
				}
				continue
			}
			// Basic auth registries: retry with credentials if we have any.
			if user, _ := credentials(ref.Registry); user != "" {
				continue
			}
			cancel(nil)
			return nil, fmt.Errorf("registry %s requires authentication; set MINIBOX_REGISTRY_USER/MINIBOX_REGISTRY_PASS", ref.Registry)
		}
		fail := func(format string, a ...any) (*http.Response, error) {
			resp.Body.Close()
			return nil, fmt.Errorf(format, a...)
		}
		var ferr error
		var fresp *http.Response
		switch {
		case resp.StatusCode == 404:
			fresp, ferr = fail("%s not found on %s (404); check the name and tag", ref.Name(), ref.Registry)
		case resp.StatusCode == 401 || resp.StatusCode == 403:
			fresp, ferr = fail("access to %s denied (%s); it may be private: set MINIBOX_REGISTRY_USER/MINIBOX_REGISTRY_PASS", ref.Name(), resp.Status)
		case resp.StatusCode == 429:
			fresp, ferr = fail("registry %s rate-limited the request (429); wait and retry, or authenticate", ref.Registry)
		case resp.StatusCode != 200:
			fresp, ferr = fail("registry %s returned %s for %s", ref.Registry, resp.Status, path)
		default:
			resp.Body = watchBody(ctx, cancel, resp.Body, c.stallTimeout())
			return resp, nil
		}
		cancel(nil)
		return fresp, ferr
	}
	cancel(nil)
	return nil, errors.New("authentication failed")
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

// fetchManifest downloads a manifest; when ref is a digest, the body must match it.
func (c *Client) fetchManifest(ctx context.Context, ref Reference, tagOrDigest, wantDigest string) ([]byte, string, error) {
	resp, err := c.get(ctx, ref, "/manifests/"+tagOrDigest, acceptManifest)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxManifest+1))
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxManifest {
		return nil, "", errors.New("manifest too large")
	}
	d := sha(b)
	if wantDigest != "" && d != wantDigest {
		return nil, "", fmt.Errorf("manifest digest mismatch: expected %s, got %s (corrupted or tampered response)", wantDigest, d)
	}
	return b, d, nil
}

func (c *Client) pick(list []descriptor) (descriptor, error) {
	var fallback *descriptor
	for i, m := range list {
		p := m.Platform
		if p == nil || p.OS != c.OS || p.Architecture != c.Arch {
			continue
		}
		if c.Variant == "" || p.Variant == c.Variant {
			return m, nil
		}
		if fallback == nil {
			fallback = &list[i]
		}
	}
	if fallback != nil {
		return *fallback, nil
	}
	var have []string
	for _, m := range list {
		if m.Platform != nil && m.Platform.OS != "unknown" {
			have = append(have, m.Platform.OS+"/"+m.Platform.Architecture)
		}
	}
	return descriptor{}, fmt.Errorf("image has no %s/%s variant (available: %s)", c.OS, c.Arch, strings.Join(have, ", "))
}

// Resolve fetches the manifest (selecting the platform from an index) and the config blob.
func (c *Client) Resolve(ctx context.Context, ref Reference) (*manifest, *imageConfigFile, string, error) {
	want := ref.Digest
	b, d, err := c.fetchManifest(ctx, ref, ref.ManifestRef(), want)
	if err != nil {
		return nil, nil, "", err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, nil, "", fmt.Errorf("bad manifest: %w", err)
	}
	if len(m.Manifests) > 0 || m.MediaType == mtOCIIndex || m.MediaType == mtDockerList {
		sel, err := c.pick(m.Manifests)
		if err != nil {
			return nil, nil, "", err
		}
		if _, err := ParseDigest(sel.Digest); err != nil {
			return nil, nil, "", err
		}
		if b, d, err = c.fetchManifest(ctx, ref, sel.Digest, sel.Digest); err != nil {
			return nil, nil, "", err
		}
		m = manifest{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, nil, "", fmt.Errorf("bad manifest: %w", err)
		}
	}
	if len(m.Layers) == 0 || m.Config.Digest == "" {
		return nil, nil, "", errors.New("manifest has no config or layers (unsupported manifest type)")
	}
	if _, err := ParseDigest(m.Config.Digest); err != nil {
		return nil, nil, "", err
	}
	for _, l := range m.Layers {
		if _, err := ParseDigest(l.Digest); err != nil {
			return nil, nil, "", err
		}
	}
	resp, err := c.get(ctx, ref, "/blobs/"+m.Config.Digest, "")
	if err != nil {
		return nil, nil, "", err
	}
	defer resp.Body.Close()
	cb, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, nil, "", err
	}
	if sha(cb) != m.Config.Digest {
		return nil, nil, "", fmt.Errorf("config blob digest mismatch (expected %s); corrupted or tampered response", m.Config.Digest)
	}
	var cfg imageConfigFile
	if err := json.Unmarshal(cb, &cfg); err != nil {
		return nil, nil, "", fmt.Errorf("bad image config: %w", err)
	}
	if len(cfg.RootFS.DiffIDs) != len(m.Layers) {
		return nil, nil, "", fmt.Errorf("image config lists %d diff_ids but manifest has %d layers", len(cfg.RootFS.DiffIDs), len(m.Layers))
	}
	return &m, &cfg, d, nil
}

type imageConfigFile struct {
	Created time.Time `json:"created"`
	Config  struct {
		Entrypoint   []string            `json:"Entrypoint"`
		Cmd          []string            `json:"Cmd"`
		Env          []string            `json:"Env"`
		WorkingDir   string              `json:"WorkingDir"`
		User         string              `json:"User"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"config"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// downloadBlob streams a layer into the blob store (verifying its digest), with retries.
func (c *Client) downloadBlob(ctx context.Context, s *Store, ref Reference, d descriptor, progress func(n int64)) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt) * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err = func() error {
			resp, err := c.get(ctx, ref, "/blobs/"+d.Digest, "")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			var r io.Reader = resp.Body
			if progress != nil {
				r = &countReader{r: r, f: progress}
			}
			// Cap the body at the manifest's declared size: an overlong
			// response would otherwise fill the store's temp blob before
			// digest verification can reject it.
			if d.Size > 0 {
				r = &sizeCappedReader{r: r, max: d.Size}
			}
			_, _, err = s.PutBlob(r, d.Digest)
			return err
		}()
		if err == nil || strings.Contains(err.Error(), "digest mismatch") || errors.Is(err, context.Canceled) {
			return err
		}
	}
	return err
}

type countReader struct {
	r io.Reader
	f func(int64)
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.f(int64(n))
	}
	return n, err
}

// sizeCappedReader rejects bodies longer than the manifest's declared layer
// size (a short body still fails later at digest verification). One byte of
// slack distinguishes an exact-size body from an overlong one.
type sizeCappedReader struct {
	r   io.Reader
	max int64
	n   int64
}

func (c *sizeCappedReader) Read(p []byte) (int, error) {
	if c.n > c.max {
		return 0, fmt.Errorf("layer is longer than the %d bytes the manifest declares", c.max)
	}
	if int64(len(p)) > c.max+1-c.n {
		p = p[:c.max+1-c.n]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.n > c.max {
		return n, fmt.Errorf("layer is longer than the %d bytes the manifest declares (truncated response or tampered registry)", c.max)
	}
	return n, err
}
