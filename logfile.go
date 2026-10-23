package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// rotatingFile is an append-only log file that rotates by size: when a
// write would take it past maxBytes, path is renamed to path.1 (path.1 to
// path.2, …, keeping maxBackups old files) and a fresh path is started.
// Disk use is therefore bounded by about (maxBackups+1) × maxBytes.
//
// The file holds device IDs and client addresses, so it is created 0600.
// Write never fails: a failing log file must not take logging to stderr down
// with it (io.MultiWriter stops at the first error), so errors are reported
// once on stderr and the line is dropped from the file.
type rotatingFile struct {
	mu         sync.Mutex
	path       string
	maxBytes   int64
	maxBackups int
	f          *os.File
	size       int64
	failing    bool // an error was reported; cleared after a good write
}

func openRotatingFile(path string, maxBytes int64, maxBackups int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, maxBytes: maxBytes, maxBackups: maxBackups}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f, r.size = f, fi.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f != nil && r.size > 0 && r.size+int64(len(p)) > r.maxBytes {
		if err := r.rotate(); err != nil {
			r.report("rotate", err)
			// Keep appending to path; try again after another maxBytes
			// rather than on every line.
			if r.f == nil && r.open() == nil {
				r.size = 0
			}
		}
	}
	if r.f == nil {
		if err := r.open(); err != nil {
			r.report("open", err)
			return len(p), nil
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	if err != nil {
		r.report("write", err)
	} else {
		r.failing = false
	}
	return len(p), nil
}

// rotate shifts path.N-1 → path.N … path → path.1 and closes the current
// file; the next write opens a new one.
func (r *rotatingFile) rotate() error {
	if err := r.f.Close(); err != nil {
		r.report("close", err)
	}
	r.f = nil
	if r.maxBackups == 0 {
		return os.Remove(r.path)
	}
	_ = os.Remove(r.backup(r.maxBackups))
	for i := r.maxBackups - 1; i >= 1; i-- {
		if err := os.Rename(r.backup(i), r.backup(i+1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(r.path, r.backup(1))
}

func (r *rotatingFile) backup(i int) string {
	return fmt.Sprintf("%s.%d", r.path, i)
}

// report writes err to stderr once per failure streak (not through log,
// which would come back here).
func (r *rotatingFile) report(op string, err error) {
	if !r.failing {
		fmt.Fprintf(os.Stderr, "log file %s: %s: %v (logging to stderr only until it recovers)\n", r.path, op, err)
		r.failing = true
	}
}

// Close releases the file. A nil *rotatingFile (file logging off) is fine.
func (r *rotatingFile) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// setupLogFile sends the standard logger to stderr and, when path is set,
// also to a rotating file (nil when path is empty). Writes are unbuffered;
// Close only releases the file.
func setupLogFile(path string, maxSizeMB, maxBackups int) (*rotatingFile, error) {
	if path == "" {
		return nil, nil
	}
	f, err := openRotatingFile(path, int64(maxSizeMB)<<20, maxBackups)
	if err != nil {
		return nil, err
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	return f, nil
}
