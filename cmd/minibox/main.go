//go:build linux

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"minibox/internal/cgroup"
	"minibox/internal/image"
	"minibox/internal/runtime"
	"minibox/internal/state"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run-raw":
		runRaw(os.Args[2:])
	case "system":
		if len(os.Args) == 3 && os.Args[2] == "prune" {
			n, err := runtime.Prune()
			if err != nil {
				fmt.Fprintf(os.Stderr, "minibox: prune: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("removed %d stale container resource(s) (cgroups, container dirs)\n", n)
			return
		}
		usage()
		os.Exit(2)
	case "load":
		load(os.Args[2:])
	case "init": // hidden: runs inside the new namespaces
		fmt.Fprintf(os.Stderr, "minibox init: %v\n", runtime.Init())
		os.Exit(126)
	case "version":
		fmt.Println("minibox 0.1.0 (M1)")
	default:
		usage()
		os.Exit(2)
	}
}

func runRaw(args []string) {
	fs := flag.NewFlagSet("run-raw", flag.ExitOnError)
	mem := fs.String("memory", "", "memory limit, e.g. 64m")
	cpus := fs.Float64("cpus", 0, "CPU limit, e.g. 0.5")
	pids := fs.Int64("pids-limit", 0, "max number of processes")
	img := fs.String("image", "", "run a loaded image (overlayfs) instead of a ROOTFS directory")
	keep := fs.Bool("keep", false, "keep the container's upper layer after exit")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: minibox run-raw [--memory 64m] [--cpus 0.5] [--pids-limit N] ROOTFS CMD...\n       minibox run-raw --image NAME [flags] [CMD...]")
	}
	fs.Parse(args)
	opts := runtime.RunOptions{Image: *img, Keep: *keep}
	if *img != "" {
		opts.Cmd = fs.Args()
	} else {
		if fs.NArg() < 2 {
			fs.Usage()
			os.Exit(2)
		}
		opts.Rootfs, opts.Cmd = fs.Arg(0), fs.Args()[1:]
	}
	lim := cgroup.Limits{CPUs: *cpus, PidsLimit: *pids}
	if *mem != "" {
		b, err := cgroup.ParseSize(*mem)
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: --memory: %v\n", err)
			os.Exit(2)
		}
		lim.MemoryBytes = b
	}
	opts.Limits = lim
	code, err := runtime.RunRaw(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
		if code == 0 {
			code = 125
		}
	}
	os.Exit(code)
}

func load(args []string) {
	fs := flag.NewFlagSet("load", flag.ExitOnError)
	in := fs.String("i", "-", "input rootfs tarball (plain or gzip), - for stdin")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: minibox load [-i FILE] NAME[:TAG]   (imports a rootfs tarball as a single-layer image)")
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	var r io.Reader = os.Stdin
	if *in != "-" {
		f, err := os.Open(*in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		r = f
	}
	root, err := filepath.Abs(state.Root())
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
		os.Exit(1)
	}
	st := &image.Store{Root: root}
	img, err := st.LoadTar(r, fs.Arg(0), image.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: load: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %s (%s)\n", img.Name, img.Layers[0].DiffID)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: minibox run-raw [flags] (ROOTFS CMD... | --image NAME [CMD...]) | load | system prune | version")
}
