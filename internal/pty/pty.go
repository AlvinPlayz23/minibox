//go:build linux

// Package pty allocates pseudo-terminals and handles the host terminal for -t.
package pty

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open allocates a pty pair. The slave is opened O_RDWR|O_NOCTTY.
func Open() (master, slave *os.File, err error) {
	m, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	fail := func(e error) (*os.File, *os.File, error) { unix.Close(m); return nil, nil, e }
	if err := unix.IoctlSetPointerInt(m, unix.TIOCSPTLCK, 0); err != nil {
		return fail(fmt.Errorf("unlockpt: %w", err))
	}
	n, err := unix.IoctlGetInt(m, unix.TIOCGPTN)
	if err != nil {
		return fail(fmt.Errorf("ptsname: %w", err))
	}
	s, err := unix.Open(fmt.Sprintf("/dev/pts/%d", n), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(fmt.Errorf("open pty slave: %w", err))
	}
	return os.NewFile(uintptr(m), "ptmx"), os.NewFile(uintptr(s), "pts"), nil
}

// IsTerminal reports whether fd is a terminal.
func IsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// MakeRaw puts the terminal into raw mode and returns a restore function.
func MakeRaw(fd int) (func(), error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	t := *old
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN], t.Cc[unix.VTIME] = 1, 0
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &t); err != nil {
		return nil, err
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, old) }, nil
}

// CopySize copies the window size of from to the pty master.
func CopySize(from int, master *os.File) {
	ws, err := unix.IoctlGetWinsize(from, unix.TIOCGWINSZ)
	if err != nil {
		return
	}
	_ = unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, ws)
}
