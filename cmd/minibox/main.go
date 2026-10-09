//go:build linux

package main

import (
	"flag"
	"fmt"
	"os"

	"minibox/internal/cgroup"
	"minibox/internal/runtime"
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
			fmt.Printf("removed %d stale cgroup(s)\n", n)
			return
		}
		usage()
		os.Exit(2)
	case "init": // hidden: runs inside the new namespaces
		fmt.Fprintf(os.Stderr, "minibox init: %v\n", runtime.Init(os.Args[2:]))
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
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: minibox run-raw [--memory 64m] [--cpus 0.5] [--pids-limit N] ROOTFS CMD...")
	}
	fs.Parse(args)
	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(2)
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
	code, err := runtime.RunRaw(fs.Arg(0), fs.Args()[1:], lim)
	if err != nil {
		fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
		if code == 0 {
			code = 125
		}
	}
	os.Exit(code)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: minibox run-raw [flags] ROOTFS CMD... | system prune | version")
}
