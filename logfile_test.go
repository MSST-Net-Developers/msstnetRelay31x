package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRotatingFileAppendsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.log")
	if err := os.WriteFile(path, []byte("earlier\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openRotatingFile(path, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("line\n")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "earlier\nline\n" {
		t.Fatalf("content %q", got)
	}
	if f.size != int64(len("earlier\nline\n")) {
		t.Fatalf("size %d", f.size)
	}

	os.Remove(path)
	g, err := openRotatingFile(path, 1<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Windows has no Unix permission bits.
	if perm := fi.Mode().Perm(); runtime.GOOS != "windows" && perm != 0o600 {
		t.Fatalf("log created with mode %o, want 600", perm)
	}
}

func TestRotatingFileRotatesAndKeepsBackups(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.log")
	f, err := openRotatingFile(path, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Each 6-byte line fills more than half the 10-byte limit: one per file.
	for _, l := range []string{"line1\n", "line2\n", "line3\n", "line4\n"} {
		f.Write([]byte(l))
	}
	if got := []string{readFile(t, path), readFile(t, path+".1"), readFile(t, path+".2")}; strings.Join(got, "") != "line4\nline3\nline2\n" {
		t.Fatalf("files %q", got)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatalf("only 2 backups kept: %v", err)
	}
	// A line longer than the limit still goes to an empty file.
	f.Write([]byte(strings.Repeat("x", 20) + "\n"))
	if got := readFile(t, path); len(got) != 21 {
		t.Fatalf("long line: %q", got)
	}
}

func TestRotatingFileWithoutBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.log")
	f, err := openRotatingFile(path, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("line1\n"))
	f.Write([]byte("line2\n"))
	if got := readFile(t, path); got != "line2\n" {
		t.Fatalf("content %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("files: %v", entries)
	}
}

func TestRotatingFileNeverFailsAWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "relay.log")
	f, err := openRotatingFile(path, 1<<20, 1)
	if err != nil {
		t.Fatal(err)
	}
	// The file breaks under the logger: the write is dropped, not failed,
	// so io.MultiWriter still reaches stderr.
	f.f.Close()
	if n, err := f.Write([]byte("lost\n")); n != 5 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if !f.failing {
		t.Fatal("error not reported")
	}
}

func TestSetupLogFile(t *testing.T) {
	if f, err := setupLogFile("", 50, 5); f != nil || err != nil {
		t.Fatalf("off: %v, %v", f, err)
	}
	var off *rotatingFile
	if err := off.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := setupLogFile(filepath.Join(t.TempDir(), "missing", "relay.log"), 50, 5); err == nil {
		t.Fatal("unopenable path accepted")
	}
}
