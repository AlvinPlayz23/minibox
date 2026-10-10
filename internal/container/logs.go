//go:build linux

package container

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

const logKeep = 3 // rotated files kept: log.1 (newest) .. log.3

func logMax() int64 {
	if v, err := strconv.ParseInt(os.Getenv("MINIBOX_LOG_MAX"), 10, 64); err == nil && v > 0 {
		return v
	}
	return 10 << 20
}

type logWriter struct {
	path string
	f    *os.File
	size int64
	max  int64
}

func newLogWriter(path string) (*logWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log %s: %w", path, err)
	}
	st, _ := f.Stat()
	return &logWriter{path: path, f: f, size: st.Size(), max: logMax()}, nil
}

func (w *logWriter) Write(p []byte) (int, error) {
	if w.size > 0 && w.size+int64(len(p)) > w.max {
		w.rotate()
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *logWriter) rotate() {
	w.f.Close()
	os.Remove(fmt.Sprintf("%s.%d", w.path, logKeep))
	for i := logKeep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	os.Rename(w.path, w.path+".1")
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil { // keep going: dropping output beats killing the container
		f, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	}
	w.f, w.size = f, 0
}

func (w *logWriter) Close() error { return w.f.Close() }

// Logs writes the container's log (oldest rotated file first) to out; with follow it keeps
// streaming until the container stops. Copy errors are propagated: a failed
// writer must not spin in follow mode nor return a silently truncated log.
func Logs(c *Container, out io.Writer, follow bool) error {
	base := logPath(c.Config.ID)
	for i := logKeep; i >= 1; i-- {
		if f, err := os.Open(fmt.Sprintf("%s.%d", base, i)); err == nil {
			_, cerr := io.Copy(out, f)
			f.Close()
			if cerr != nil {
				return cerr
			}
		}
	}
	f, err := os.Open(base)
	if err != nil {
		if os.IsNotExist(err) {
			if c.Config.Detach {
				return nil
			}
			return fmt.Errorf("container %s has no logs; only detached containers (-d) are logged", short(c.Config.ID))
		}
		return err
	}
	defer f.Close()
	drain := func() error {
		_, err := io.Copy(out, f)
		return err
	}
	for {
		if err := drain(); err != nil {
			return err
		}
		if !follow {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
		// Rotation: the path now names a different file; drain the old one, then switch.
		var a, b syscall.Stat_t
		if syscall.Fstat(int(f.Fd()), &a) == nil && syscall.Stat(base, &b) == nil && a.Ino != b.Ino {
			if err := drain(); err != nil {
				return err
			}
			f.Close()
			if f, err = os.Open(base); err != nil {
				return err
			}
			continue
		}
		_ = c.Refresh()
		if !c.Running() {
			return drain()
		}
	}
}
