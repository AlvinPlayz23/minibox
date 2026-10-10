//go:build linux && !amd64 && !arm64

package security

import "errors"

func ApplySeccomp(caps []string) error {
	return errors.New("seccomp profile is only available on amd64 and arm64; use --seccomp unconfined")
}
