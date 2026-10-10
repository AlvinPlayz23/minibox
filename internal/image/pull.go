//go:build linux

package image

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const pullConcurrency = 3

// lockStore takes the store-wide lock: shared for pulls/runs, exclusive for GC.
func (s *Store) lockStore(exclusive, block bool) (*os.File, error) {
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Root, ".store.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	if !block {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// RLock holds the shared store lock (blocks GC) until the returned func is called.
func (s *Store) RLock() (func(), error) {
	f, err := s.lockStore(false, true)
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Pull fetches ref from its registry into the store. Blobs are verified by digest before
// anything is unpacked, layers are verified by diffID before they are published, and
// everything streams to disk (no layer is held in memory).
func (s *Store) Pull(ctx context.Context, c *Client, name string, log io.Writer) (*Image, error) {
	ref, err := ParseReference(name)
	if err != nil {
		return nil, err
	}
	unlock, err := s.RLock()
	if err != nil {
		return nil, fmt.Errorf("lock store: %w", err)
	}
	defer unlock()
	if log == nil {
		log = io.Discard
	}
	fmt.Fprintf(log, "Resolving %s\n", ref.Name())
	m, cfg, mdigest, err := c.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	// Chain IDs are known up front from the config's diff_ids.
	chains := make([]string, len(m.Layers))
	parent := ""
	for i, d := range cfg.RootFS.DiffIDs {
		if _, err := ParseDigest(d); err != nil {
			return nil, fmt.Errorf("image config diff_id %d: %w", i, err)
		}
		chains[i] = ChainID(parent, d)
		parent = chains[i]
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	sem := make(chan struct{}, pullConcurrency)
	var firstErr error
	var errMu sync.Once
	var total int64
	for i, d := range m.Layers {
		total += d.Size
		wg.Add(1)
		go func(i int, d descriptor) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if err := s.fetchLayer(ctx, c, ref, d, cfg.RootFS.DiffIDs[i], chains, i, log); err != nil {
				errMu.Do(func() { firstErr = fmt.Errorf("layer %d (%s): %w", i+1, shortDigest(d.Digest), err); cancel() })
			}
		}(i, d)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	img := &Image{Config: Config{
		Entrypoint: cfg.Config.Entrypoint, Cmd: cfg.Config.Cmd, Env: cfg.Config.Env,
		WorkingDir: cfg.Config.WorkingDir, User: cfg.Config.User,
	}, Created: cfg.Created, Digest: mdigest, Size: total}
	for p := range cfg.Config.ExposedPorts {
		img.Config.ExposedPorts = append(img.Config.ExposedPorts, p)
	}
	sort.Strings(img.Config.ExposedPorts)
	for i, d := range m.Layers {
		img.Layers = append(img.Layers, ImageLayer{Blob: d.Digest, DiffID: cfg.RootFS.DiffIDs[i], ChainID: chains[i]})
	}
	if img.Created.IsZero() {
		img.Created = time.Now().UTC()
	}
	if err := s.SaveImage(img, name); err != nil {
		return nil, err
	}
	fmt.Fprintf(log, "Digest: %s\nStatus: pulled %s\n", mdigest, img.Name)
	return img, nil
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func (s *Store) fetchLayer(ctx context.Context, c *Client, ref Reference, d descriptor, diffID string, chains []string, i int, log io.Writer) error {
	if s.HasLayer(chains[i]) {
		fmt.Fprintf(log, "%s: already present\n", shortDigest(d.Digest))
		return nil
	}
	if !s.HasBlob(d.Digest) {
		var done int64
		var last atomic.Int64
		err := c.downloadBlob(ctx, s, ref, d, func(n int64) {
			done += n
			if done-last.Load() >= 8<<20 {
				last.Store(done)
				fmt.Fprintf(log, "%s: downloaded %d/%d MB\n", shortDigest(d.Digest), done>>20, d.Size>>20)
			}
		})
		if err != nil {
			return err
		}
	}
	p, _ := s.BlobPath(d.Digest)
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := Decompress(f)
	if err != nil {
		return err
	}
	if rc, ok := r.(io.Closer); ok {
		defer rc.Close()
	}
	parent := ""
	if i > 0 {
		parent = chains[i-1]
	}
	if _, err := s.UnpackLayerVerified(parent, r, DefaultExtractOptions(), diffID); err != nil {
		return err
	}
	fmt.Fprintf(log, "%s: pull complete\n", shortDigest(d.Digest))
	return nil
}

// ListImages returns all image records, sorted by name. A malformed or
// unreadable record is an error: callers (notably GC) must not silently treat
// such images as absent and delete their layers.
func (s *Store) ListImages() ([]*Image, error) {
	var out []*Image
	root := filepath.Join(s.Root, "images")
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if e.IsDir() || !strings.HasSuffix(p, ".json") {
			return nil
		}
		if strings.HasPrefix(e.Name(), ".tmp-") {
			return nil // unfinished atomic save; GC removes these
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read image record %s: %w", p, err)
		}
		var img Image
		if err := json_unmarshal(b, &img); err != nil {
			return fmt.Errorf("corrupt image record %s: %w", p, err)
		}
		if img.Name == "" {
			return fmt.Errorf("corrupt image record %s: missing name", p)
		}
		out = append(out, &img)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// RemoveImage deletes an image record (layers are reclaimed by GC),
// including pre-M6 records (see GetImage).
func (s *Store) RemoveImage(name string) (string, error) {
	p, canon, err := s.imagePath(name)
	if err != nil {
		return "", err
	}
	if err := os.Remove(p); err != nil {
		if !os.IsNotExist(err) {
			return "", err
		}
		removed := false
		for _, legacy := range s.legacyPaths(name) {
			if os.Remove(legacy) == nil {
				removed = true
			}
		}
		if !removed {
			return "", fmt.Errorf("no such image %q; list images with `minibox images`", name)
		}
	}
	// Tidy now-empty directories up to images/.
	for d := filepath.Dir(p); d != filepath.Join(s.Root, "images"); d = filepath.Dir(d) {
		if os.Remove(d) != nil {
			break
		}
	}
	return canon, nil
}

// GCResult reports what GC removed.
type GCResult struct{ Layers, Blobs, Temp int }

// GC removes layers not used by any image, stale temp files, and (with blobs) the compressed
// blobs, which are only needed to re-unpack. It skips (returns nil result, nil error) if a pull is running.
func (s *Store) GC(blobs bool) (*GCResult, error) {
	l, err := s.lockStore(true, false)
	if err != nil {
		if err == unix.EWOULDBLOCK {
			return nil, nil
		}
		return nil, err
	}
	defer l.Close()
	imgs, err := s.ListImages()
	if err != nil {
		return nil, err
	}
	keepLayer := map[string]bool{}
	for _, img := range imgs {
		for _, ly := range img.Layers {
			keepLayer[strings.TrimPrefix(ly.ChainID, "sha256:")] = true
		}
	}
	res := &GCResult{}
	if ents, _ := os.ReadDir(s.layersDir()); ents != nil {
		for _, e := range ents {
			n := e.Name()
			switch {
			case n == "l":
			case strings.HasPrefix(n, ".tmp-"):
				if os.RemoveAll(filepath.Join(s.layersDir(), n)) == nil {
					res.Temp++
				}
			case !keepLayer[n]:
				if err := s.removeLayer(n); err != nil {
					return res, err
				}
				res.Layers++
			}
		}
	}
	// Dangling short links.
	if ents, _ := os.ReadDir(s.LinksDir()); ents != nil {
		for _, e := range ents {
			lp := filepath.Join(s.LinksDir(), e.Name())
			if _, err := os.Stat(lp); err != nil {
				os.Remove(lp)
			}
		}
	}
	if ents, _ := os.ReadDir(s.blobsDir()); ents != nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".tmp-") {
				if os.Remove(filepath.Join(s.blobsDir(), e.Name())) == nil {
					res.Temp++
				}
			} else if blobs {
				if os.Remove(filepath.Join(s.blobsDir(), e.Name())) == nil {
					res.Blobs++
				}
			}
		}
	}
	return res, nil
}

// removeLayer deletes a layer dir. Overlay whiteout char devices and odd modes are fine for RemoveAll as root.
func (s *Store) removeLayer(chainHex string) error {
	return os.RemoveAll(filepath.Join(s.layersDir(), chainHex))
}

func json_unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
