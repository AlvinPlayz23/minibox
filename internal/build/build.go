//go:build linux

package build

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"minibox/internal/container"
	"minibox/internal/image"
	"minibox/internal/network"
	"minibox/internal/security"
	"minibox/internal/state"
)

// Options configures a build.
type Options struct {
	ContextDir string
	Dockerfile string // path to Dockerfile (default ContextDir/Dockerfile)
	Tag        string // target image name
	BuildArgs  map[string]string
	Log        io.Writer
}

// cacheFile maps build-step keys to layers.
type cacheFile map[string]image.ImageLayer

func cachePath(root string) string { return filepath.Join(root, "build-cache.json") }

func loadCache(root string) cacheFile {
	c := cacheFile{}
	if b, err := os.ReadFile(cachePath(root)); err == nil {
		_ = json.Unmarshal(b, &c)
	}
	return c
}

func saveCache(root string, c cacheFile) {
	b, _ := json.Marshal(c)
	tmp := cachePath(root) + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, cachePath(root))
	}
}

func stepKey(parent, step, extra string) string {
	h := sha256.Sum256([]byte(parent + "\n" + step + "\n" + extra))
	return "sha256:" + hex.EncodeToString(h[:])
}

// Build executes the Dockerfile and saves the image as opts.Tag.
func Build(ctx context.Context, opts Options) (*image.Image, error) {
	log := opts.Log
	if log == nil {
		log = io.Discard
	}
	dfPath := opts.Dockerfile
	if dfPath == "" {
		dfPath = filepath.Join(opts.ContextDir, "Dockerfile")
	}
	data, err := os.ReadFile(dfPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dfPath, err)
	}
	insts, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if len(insts) == 0 || insts[0].Name != "FROM" {
		return nil, fmt.Errorf("Dockerfile must start with FROM (line %d)", firstLine(insts))
	}
	root := state.Root()
	st := &image.Store{Root: root}
	unlock, err := st.RLock()
	if err != nil {
		return nil, fmt.Errorf("lock image store: %w", err)
	}
	defer unlock()
	cache := loadCache(root)

	var layers []image.ImageLayer
	var cfg image.Config
	cfg.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	parent := ""
	vars := map[string]string{}
	for k, v := range opts.BuildArgs {
		vars[k] = v
	}
	fromSeen := false
	for _, in := range insts {
		args := Substitute(in.Args, vars)
		switch in.Name {
		case "FROM":
			if fromSeen {
				return nil, fmt.Errorf("line %d: multiple FROMs (multi-stage builds) are not supported; keep a single FROM", in.Line)
			}
			fromSeen = true
			base, _, _ := strings.Cut(args, " ")
			// Strip optional "AS name".
			fields := SplitArgs(args)
			base = fields[0]
			if len(fields) >= 3 && strings.ToUpper(fields[len(fields)-2]) == "AS" {
				base = strings.Join(fields[:len(fields)-2], " ")
			}
			base = Substitute(base, vars)
			if strings.ToLower(base) == "scratch" {
				layers = nil
				cfg = image.Config{Env: cfg.Env}
				parent = ""
				fmt.Fprintf(log, "Step: FROM scratch\n")
				continue
			}
			fmt.Fprintf(log, "Step: FROM %s\n", base)
			img, err := st.GetImage(base)
			if err != nil {
				fmt.Fprintf(log, "Pulling base image %s...\n", base)
				if img, err = st.Pull(ctx, image.NewClient(), base, log); err != nil {
					return nil, fmt.Errorf("line %d: base image: %w", in.Line, err)
				}
			}
			layers = append([]image.ImageLayer(nil), img.Layers...)
			cfg = img.Config
			if len(layers) > 0 {
				parent = layers[len(layers)-1].ChainID
			}
		case "ARG":
			name, def, _ := strings.Cut(args, "=")
			name = strings.TrimSpace(name)
			if name == "" {
				return nil, fmt.Errorf("line %d: bad ARG", in.Line)
			}
			if _, ok := vars[name]; !ok {
				vars[name] = strings.TrimSpace(def)
			}
		case "ENV":
			pairs, err := ParseEnv(args)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			for _, kv := range pairs {
				vars[kv[0]] = kv[1]
				cfg.Env = setEnv(cfg.Env, kv[0], kv[1])
			}
		case "WORKDIR":
			if args == "" {
				return nil, fmt.Errorf("line %d: WORKDIR needs a path", in.Line)
			}
			wd := args
			if !filepath.IsAbs(wd) {
				wd = filepath.Join(cfg.WorkingDir, wd)
				if cfg.WorkingDir == "" {
					wd = filepath.Join("/", args)
				}
			}
			wd = filepath.Clean(wd)
			cfg.WorkingDir = wd
			vars["WORKDIR"] = wd
			// The directory must exist in the image: tiny layer with just the dir.
			key := stepKey(parent, "WORKDIR "+wd, "")
			if l, ok := cache[key]; ok && st.HasLayer(l.ChainID) {
				layers = append(layers, l)
				parent = l.ChainID
				break
			}
			var buf bytes.Buffer
			tw := tar.NewWriter(&buf)
			parts := strings.Split(strings.Trim(wd, "/"), "/")
			for i := range parts {
				d := strings.Join(parts[:i+1], "/") + "/"
				_ = tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755})
			}
			tw.Close()
			l, err := st.UnpackLayer(parent, &buf, image.DefaultExtractOptions())
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			il := image.ImageLayer{DiffID: l.DiffID, ChainID: l.ChainID}
			layers = append(layers, il)
			parent = l.ChainID
			cache[key] = il
		case "USER":
			cfg.User = args
		case "EXPOSE":
			for _, p := range strings.Fields(args) {
				cfg.ExposedPorts = append(cfg.ExposedPorts, p)
			}
		case "CMD", "ENTRYPOINT":
			cmd, err := ParseJSONOrShell(args)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			if in.Name == "CMD" {
				cfg.Cmd = cmd
			} else {
				cfg.Entrypoint = cmd
			}
		case "COPY":
			chown, srcs, dst, err := ParseCopy(args)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			uid, gid := 0, 0
			override := false
			if chown != "" {
				if uid, gid, err = ParseChown(chown); err != nil {
					return nil, fmt.Errorf("line %d: %w", in.Line, err)
				}
				override = true
			}
			pairs, _, err := ContextFiles(opts.ContextDir, srcs, dst, cfg.WorkingDir)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			fhash, err := HashFiles(pairs)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			key := stepKey(parent, "COPY "+strings.Join(srcs, ",")+" "+dst, fhash)
			if l, ok := cache[key]; ok && st.HasLayer(l.ChainID) {
				fmt.Fprintf(log, "Step: COPY (cached)\n")
				layers = append(layers, l)
				parent = l.ChainID
				break
			}
			fmt.Fprintf(log, "Step: COPY %s\n", args)
			pr, pw := io.Pipe()
			go func() { pw.CloseWithError(TarCopy(pw, pairs, uid, gid, override)) }()
			l, err := st.UnpackLayer(parent, pr, image.DefaultExtractOptions())
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			il := image.ImageLayer{DiffID: l.DiffID, ChainID: l.ChainID}
			layers = append(layers, il)
			parent = l.ChainID
			cache[key] = il
		case "RUN":
			cmd, err := ParseJSONOrShell(args)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			key := stepKey(parent, "RUN "+strings.Join(cmd, " "), "")
			if l, ok := cache[key]; ok && st.HasLayer(l.ChainID) {
				fmt.Fprintf(log, "Step: RUN (cached)\n")
				layers = append(layers, l)
				parent = l.ChainID
				break
			}
			fmt.Fprintf(log, "Step: RUN %s\n", args)
			l, err := runLayer(ctx, st, layers, cfg, cmd, log)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", in.Line, err)
			}
			il := image.ImageLayer{DiffID: l.DiffID, ChainID: l.ChainID}
			layers = append(layers, il)
			parent = l.ChainID
			cache[key] = il
		case "LABEL", "MAINTAINER", "STOPSIGNAL", "SHELL", "HEALTHCHECK", "ONBUILD":
			fmt.Fprintf(log, "Step: %s ignored (%s is metadata; not stored)\n", in.Name, in.Name)
		default:
			if in.Name == "ADD" {
				return nil, fmt.Errorf("line %d: ADD is not supported; use COPY (ADD's URL/tar magic is out of scope)", in.Line)
			}
			return nil, fmt.Errorf("line %d: unsupported instruction %q; supported: FROM RUN COPY ENV WORKDIR CMD ENTRYPOINT EXPOSE USER ARG", in.Line, in.Name)
		}
	}
	saveCache(root, cache)
	img := &image.Image{Layers: layers, Config: cfg}
	img.Created = time.Now().UTC()
	if opts.Tag == "" {
		return nil, fmt.Errorf("no target name: use `minibox build -t NAME PATH`")
	}
	if err := st.SaveImage(img, opts.Tag); err != nil {
		return nil, err
	}
	// Re-read to get the canonical name.
	saved, err := st.GetImage(opts.Tag)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(log, "Built %s (%d layer(s))\n", saved.Name, len(layers))
	return saved, nil
}

func firstLine(insts []Instruction) int {
	if len(insts) > 0 {
		return insts[0].Line
	}
	return 1
}

func setEnv(env []string, k, v string) []string {
	prefix := k + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + v
			return env
		}
	}
	return append(env, prefix+v)
}

// runLayer runs cmd in a throwaway container over layers+cfg and returns the new layer
// captured from the container's upper dir.
func runLayer(ctx context.Context, st *image.Store, layers []image.ImageLayer, cfg image.Config, cmd []string, log io.Writer) (*image.Layer, error) {
	tmpName := fmt.Sprintf("minibox-build/tmp:%s", shortID(mustBuildID()))
	tmp := &image.Image{Layers: append([]image.ImageLayer(nil), layers...), Config: cfg}
	if err := st.SaveImage(tmp, tmpName); err != nil {
		return nil, err
	}
	defer st.RemoveImage(tmpName)
	id, err := image.NewID()
	if err != nil {
		return nil, err
	}
	caps, _ := security.ResolveCaps(nil, nil)
	mode, _ := network.DefaultMode()
	c, err := container.Create(container.Config{
		ID: id, Image: tmp.Name, Cmd: cmd, Env: cfg.Env, Workdir: cfg.WorkingDir, User: cfg.User,
		Hostname: "build", Init: true, Caps: caps, Seccomp: true, Network: mode,
	})
	if err != nil {
		return nil, err
	}
	code, serr := c.Supervise(container.Foreground, nil)
	if serr != nil {
		os.RemoveAll(container.Dir(id))
		return nil, serr
	}
	if code != 0 {
		os.RemoveAll(container.Dir(id))
		return nil, fmt.Errorf("RUN exited with code %d", code)
	}
	upper := filepath.Join(container.Dir(id), "upper")
	defer os.RemoveAll(container.Dir(id))
	// Tar the upper dir to a temp file (it can be large; don't buffer in RAM).
	tf, err := os.CreateTemp("", "minibox-build-*.tar")
	if err != nil {
		return nil, err
	}
	tpath := tf.Name()
	if terr := TarUpper(tf, upper); terr != nil {
		tf.Close()
		os.Remove(tpath)
		return nil, terr
	}
	tf.Close()
	f, err := os.Open(tpath)
	if err != nil {
		os.Remove(tpath)
		return nil, err
	}
	defer func() {
		f.Close()
		os.Remove(tpath)
	}()
	parent := ""
	if len(layers) > 0 {
		parent = layers[len(layers)-1].ChainID
	}
	return st.UnpackLayer(parent, f, image.DefaultExtractOptions())
}

func mustBuildID() string {
	id, err := image.NewID()
	if err != nil {
		return "tmp"
	}
	return id
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
