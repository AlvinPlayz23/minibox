//go:build linux

package main

import (
	"fmt"
	"os"

	"minibox/internal/runtime"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run-raw":
		if len(os.Args) < 4 {
			fmt.Fprintln(os.Stderr, "usage: minibox run-raw ROOTFS CMD...")
			os.Exit(2)
		}
		code, err := runtime.RunRaw(os.Args[2], os.Args[3:])
		if err != nil {
			fmt.Fprintf(os.Stderr, "minibox: %v\n", err)
			if code == 0 {
				code = 125
			}
		}
		os.Exit(code)
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: minibox run-raw ROOTFS CMD... | version")
}
