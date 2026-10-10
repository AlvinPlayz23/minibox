//go:build linux

// Package image implements the content-addressed blob store, unpacked layer
// store and image records.
package image

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/sys/unix"
)

// Compiled lazily: regexp compilation at package init costs startup time on the `run` hot path.
var hexRe = lazyRe(`^[0-9a-f]{64}$`)

func lazyRe(expr string) func() *regexp.Regexp {
	return sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(expr) })
}

// ParseDigest validates "sha256:<64 hex>" and returns the hex part.
func ParseDigest(d string) (string, error) {
	h, ok := strings.CutPrefix(d, "sha256:")
	if !ok || !hexRe().MatchString(h) {
		return "", fmt.Errorf("invalid digest %q; expected sha256:<64 hex chars>", d)
	}
	return h, nil
}

// ChainID computes the OCI chain ID: diffID for the first layer, else
// sha256(parentChainID + " " + diffID). Both are "sha256:<hex>" strings.
func ChainID(parent, diffID string) string {
	if parent == "" {
		return diffID
	}
	sum := sha256.Sum256([]byte(parent + " " + diffID))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Store is the on-disk image store rooted at $MINIBOX_ROOT.
type Store struct{ Root string }

func (s *Store) blobsDir() string  { return filepath.Join(s.Root, "blobs", "sha256") }
func (s *Store) layersDir() string { return filepath.Join(s.Root, "layers") }

// LinksDir holds short symlinks to layer diff dirs (for the overlayfs option length limit).
func (s *Store) LinksDir() string { return filepath.Join(s.layersDir(), "l") }

// ---- blobs ----

// BlobPath returns the path of a blob (it may not exist).
func (s *Store) BlobPath(digest string) (string, error) {
	h, err := ParseDigest(digest)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.blobsDir(), h), nil
}

// HasBlob reports whether the blob exists.
func (s *Store) HasBlob(digest string) bool {
	p, err := s.BlobPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// PutBlob streams r into the store, verifying it hashes to want (if non-empty).
// Returns the digest and size. Nothing becomes visible unless verification passes.
func (s *Store) PutBlob(r io.Reader, want string) (string, int64, error) {
	bw, err := s.newBlobWriter()
	if err != nil {
		return "", 0, err
	}
	defer bw.abort()
	n, err := io.Copy(bw, r)
	if err != nil {
		return "", 0, err
	}
	d, err := bw.commit(want)
	return d, n, err
}

type blobWriter struct {
	s   *Store
	f   *os.File
	h   hash.Hash
	n   int64
	end bool
}

func (s *Store) newBlobWriter() (*blobWriter, error) {
	if err := os.MkdirAll(s.blobsDir(), 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(s.blobsDir(), ".tmp-")
	if err != nil {
		return nil, err
	}
	return &blobWriter{s: s, f: f, h: sha256.New()}, nil
}

func (w *blobWriter) Write(p []byte) (int, error) {
	w.h.Write(p)
	w.n += int64(len(p))
	return w.f.Write(p)
}

func (w *blobWriter) abort() {
	if !w.end {
		w.f.Close()
		os.Remove(w.f.Name())
	}
}

func (w *blobWriter) commit(want string) (string, error) {
	got := "sha256:" + hex.EncodeToString(w.h.Sum(nil))
	if want != "" && want != got {
		return got, fmt.Errorf("digest mismatch: expected %s, got %s (corrupted or tampered blob; re-pull the image)", want, got)
	}
	if err := w.f.Chmod(0o644); err != nil {
		return got, err
	}
	if err := w.f.Close(); err != nil {
		return got, err
	}
	w.end = true
	dst := filepath.Join(w.s.blobsDir(), strings.TrimPrefix(got, "sha256:"))
	if err := os.Rename(w.f.Name(), dst); err != nil {
		os.Remove(w.f.Name())
		return got, err
	}
	return got, nil
}

// VerifyBlob re-hashes a stored blob.
func (s *Store) VerifyBlob(digest string) error {
	p, err := s.BlobPath(digest)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != digest {
		return fmt.Errorf("blob %s is corrupt (hashes to %s)", digest, got)
	}
	return nil
}

// ---- layers ----

// Layer is an unpacked layer.
type Layer struct {
	ChainID string `json:"chainID"`
	DiffID  string `json:"diffID"`
	Parent  string `json:"parent,omitempty"`
}

func shortName(chainID string) string {
	return strings.TrimPrefix(chainID, "sha256:")[:12]
}

// LayerDir returns <layers>/<chainhex>/diff.
func (s *Store) LayerDir(chainID string) (string, error) {
	h, err := ParseDigest(chainID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.layersDir(), h, "diff"), nil
}

// HasLayer reports whether the layer is already unpacked.
func (s *Store) HasLayer(chainID string) bool {
	d, err := s.LayerDir(chainID)
	if err != nil {
		return false
	}
	_, err = os.Stat(d)
	return err == nil
}

// UnpackLayer extracts an uncompressed layer tar stream on top of parent
// (chain ID, "" for base). The layer is built in a temp dir and renamed into
// place atomically, so a crash never leaves a half-unpacked layer. If the
// same layer already exists the new copy is discarded.
func (s *Store) UnpackLayer(parent string, r io.Reader, opts ExtractOptions) (*Layer, error) {
	return s.UnpackLayerVerified(parent, r, opts, "")
}

// UnpackLayerVerified is UnpackLayer, but if wantDiffID is set the layer is only
// published when the uncompressed stream hashes to it.
func (s *Store) UnpackLayerVerified(parent string, r io.Reader, opts ExtractOptions, wantDiffID string) (*Layer, error) {
	if err := os.MkdirAll(s.layersDir(), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.LinksDir(), 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(s.layersDir(), ".tmp-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	diff := filepath.Join(tmp, "diff")
	if err := os.Mkdir(diff, 0o755); err != nil {
		return nil, err
	}
	h := sha256.New()
	tee := io.TeeReader(r, h)
	if err := ExtractTar(diff, tee, opts); err != nil {
		return nil, err
	}
	// Hash everything after the end-of-archive marker too, so diffID covers the whole stream.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return nil, err
	}
	l := &Layer{DiffID: "sha256:" + hex.EncodeToString(h.Sum(nil)), Parent: parent}
	if wantDiffID != "" && wantDiffID != l.DiffID {
		return nil, fmt.Errorf("layer diffID mismatch: image config says %s but content hashes to %s (corrupted or tampered layer)", wantDiffID, l.DiffID)
	}
	l.ChainID = ChainID(parent, l.DiffID)
	meta, _ := json.Marshal(l)
	if err := os.WriteFile(filepath.Join(tmp, "meta.json"), meta, 0o644); err != nil {
		return nil, err
	}
	final := filepath.Join(s.layersDir(), strings.TrimPrefix(l.ChainID, "sha256:"))
	if err := os.Rename(tmp, final); err != nil {
		if !errors.Is(err, unix.ENOTEMPTY) && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		// Lost a race with an identical unpack: fine, the content is identical.
	}
	if err := s.link(l.ChainID); err != nil {
		return nil, err
	}
	return l, nil
}

func (s *Store) link(chainID string) error {
	dir, _ := s.LayerDir(chainID)
	lp := filepath.Join(s.LinksDir(), shortName(chainID))
	if cur, err := os.Readlink(lp); err == nil {
		if cur == dir {
			return nil
		}
		return fmt.Errorf("short-name collision for layer %s (links to %s)", chainID, cur)
	}
	if err := os.Symlink(dir, lp); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

// LowerDir is one overlay lower layer.
type LowerDir struct{ Dir, Short string }

// LowerDirs returns an image's layers top-most first, as overlayfs wants.
func (s *Store) LowerDirs(img *Image) ([]LowerDir, error) {
	var out []LowerDir
	for i := len(img.Layers) - 1; i >= 0; i-- {
		c := img.Layers[i].ChainID
		d, err := s.LayerDir(c)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(d); err != nil {
			return nil, fmt.Errorf("layer %s of image %s is missing from the store; re-pull or re-load the image", c, img.Name)
		}
		if err := s.link(c); err != nil {
			return nil, err
		}
		out = append(out, LowerDir{Dir: d, Short: filepath.Join(s.LinksDir(), shortName(c))})
	}
	return out, nil
}

// ---- images ----

// Config is the subset of the OCI image config minibox applies.
type Config struct {
	Entrypoint   []string `json:"Entrypoint,omitempty"`
	Cmd          []string `json:"Cmd,omitempty"`
	Env          []string `json:"Env,omitempty"`
	WorkingDir   string   `json:"WorkingDir,omitempty"`
	User         string   `json:"User,omitempty"`
	ExposedPorts []string `json:"ExposedPorts,omitempty"`
}

// ImageLayer ties a compressed blob to its unpacked layer.
type ImageLayer struct {
	Blob    string `json:"blob,omitempty"`
	DiffID  string `json:"diffID"`
	ChainID string `json:"chainID"`
}

// Image is the on-disk image record (images/<registry>/<repo>/<tag>.json).
type Image struct {
	Name    string       `json:"name"` // registry/repo:tag
	Layers  []ImageLayer `json:"layers"`
	Config  Config       `json:"config"`
	Created time.Time    `json:"created"`
	Digest  string       `json:"digest,omitempty"` // manifest digest (pulled images)
	Size    int64        `json:"size,omitempty"`   // compressed layer bytes
}

var nameRe = lazyRe(`^[a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*$`)
var tagRe = lazyRe(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

// imagePath maps a reference to images/<registry>/<repo>/<tag>.json and returns its canonical name.
func (s *Store) imagePath(name string) (string, string, error) {
	ref, err := ParseReference(name)
	if err != nil {
		return "", "", err
	}
	for _, c := range strings.Split(ref.Repo, "/") {
		if c == "." || c == ".." {
			return "", "", fmt.Errorf("invalid image name %q", name)
		}
	}
	file := ref.Tag + ".json"
	if ref.Digest != "" {
		file = "@" + strings.Replace(ref.Digest, ":", "-", 1) + ".json"
	}
	host := strings.ReplaceAll(ref.Registry, ":", "_")
	return filepath.Join(s.Root, "images", host, filepath.FromSlash(ref.Repo), file), ref.Name(), nil
}

// SaveImage writes the image record atomically.
func (s *Store) SaveImage(img *Image, name string) error {
	p, canon, err := s.imagePath(name)
	if err != nil {
		return err
	}
	img.Name = canon
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(img, "", "  ")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// GetImage loads an image record by name.
func (s *Store) GetImage(name string) (*Image, error) {
	p, _, err := s.imagePath(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("image %q not found in %s; load it first with `minibox load`", name, s.Root)
		}
		return nil, err
	}
	var img Image
	if err := json.Unmarshal(b, &img); err != nil {
		return nil, fmt.Errorf("corrupt image record %s: %w", p, err)
	}
	return &img, nil
}

// ---- load ----

// Decompress sniffs the stream and returns an uncompressed reader.
func Decompress(r io.Reader) (io.Reader, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	magic, _ := br.Peek(4)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(br)
	case len(magic) == 4 && magic[0] == 0x28 && magic[1] == 0xb5 && magic[2] == 0x2f && magic[3] == 0xfd:
		zr, err := zstd.NewReader(br, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(256<<20))
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	}
	return br, nil
}

// LoadTar imports a rootfs tarball (plain or gzip) as a single-layer image.
// The input is streamed once: it is hashed and stored as a blob while being
// unpacked, never held in memory.
func (s *Store) LoadTar(r io.Reader, name string, cfg Config) (*Image, error) {
	if _, _, err := s.imagePath(name); err != nil {
		return nil, err
	}
	bw, err := s.newBlobWriter()
	if err != nil {
		return nil, err
	}
	defer bw.abort()
	tee := io.TeeReader(r, bw)
	dr, err := Decompress(tee)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	layer, err := s.UnpackLayer("", dr, DefaultExtractOptions())
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(io.Discard, tee); err != nil { // finish the compressed stream
		return nil, err
	}
	blob, err := bw.commit("")
	if err != nil {
		return nil, err
	}
	if cfg.Env == nil {
		cfg.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	}
	if cfg.Cmd == nil && cfg.Entrypoint == nil {
		cfg.Cmd = []string{"/bin/sh"}
	}
	img := &Image{
		Layers:  []ImageLayer{{Blob: blob, DiffID: layer.DiffID, ChainID: layer.ChainID}},
		Config:  cfg,
		Created: time.Now().UTC(),
	}
	if err := s.SaveImage(img, name); err != nil {
		return nil, err
	}
	return img, nil
}

// NewID returns 64 random hex chars.
func NewID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
