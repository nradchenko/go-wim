// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// The differential gate: read real WIMs — Microsoft's own and other tools' captures — and require
// every byte to match what wimlib extracts from the same image.
//
// A round trip over this package's own output checks that it agrees with itself, which is a
// weaker claim than it looks: a misreading shared by both halves cancels out and passes. This is
// the check that does not cancel: an independent implementation has no reason to be wrong in the
// same way.
//
// The fixtures cannot be committed — they are Microsoft's media and third-party captures — so
// they come from the environment and the test skips without them.
//
// What this gate does NOT cover, stated because the fixture set looks more complete than it is:
// no WIM in reach carries a named alternate data stream or a reparse point. Checked with `wimdir
// --detailed` on the AIK image, the largest available: 10746 entries, every one a single unnamed
// data stream, and its header's "Relative path junction" attribute is the vacuous RP_FIX flag
// that this package's writer sets too. Those two branches are covered only by the hand-built
// metadata in dentry_test.go.

// TestCrossCheckAgainstWimlib extracts every file from each corpus WIM with wimlib and compares
// it against what this package reads. It opens the WIM as a file rather than a byte slice, so the
// io.ReaderAt path is what gets exercised on a real image.
func TestCrossCheckAgainstWimlib(t *testing.T) {
	// Looked up on PATH rather than at a fixed location: an absolute path is right on one
	// distribution and wrong everywhere else, and the failure is silent — the strongest test
	// here would skip itself on a machine that has wimlib installed somewhere else.
	if _, err := exec.LookPath("wimlib-imagex"); err != nil {
		t.Skip("wimlib-imagex not available; skipping")
	}
	for _, p := range realWIMFixtures(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			crossCheckWIM(t, p)
		})
	}
}

func crossCheckWIM(t *testing.T, path string) {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	rd, err := Open(f, fi.Size())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	for i := 1; i <= len(rd.Images()); i++ {
		im, err := rd.Image(i)
		if err != nil {
			t.Fatalf("Image(%d): %v", i, err)
		}

		// wimlib applies the image to a directory; --no-acls because a POSIX filesystem cannot
		// carry NT security data, which this reader does not surface anyway.
		dir := t.TempDir()
		start := time.Now()
		mustRun(t, "wimlib-imagex", "apply", path, itoa(i), dir, "--no-acls")
		t.Logf("wimlib applied image %d in %v", i, time.Since(start).Round(time.Millisecond))

		want := map[string]int64{}
		if err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil || rel == "." {
				return err
			}
			if d.IsDir() {
				want[filepath.ToSlash(rel)] = -1
				return nil
			}
			// A non-regular entry has no counterpart to compare bytes against.
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			want[filepath.ToSlash(rel)] = info.Size()
			return nil
		}); err != nil {
			t.Fatalf("walk the applied tree: %v", err)
		}

		fsys := im.FS()
		var files, bytesRead int64
		start = time.Now()
		err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == "." {
				return nil
			}
			size, ok := want[p]
			if !ok {
				t.Errorf("%s: read from the WIM but not applied by wimlib", p)
				return nil
			}
			delete(want, p)
			if d.IsDir() {
				if size != -1 {
					t.Errorf("%s: this package says directory, wimlib applied a file", p)
				}
				return nil
			}
			if size == -1 {
				t.Errorf("%s: this package says file, wimlib applied a directory", p)
				return nil
			}

			got, err := fs.ReadFile(fsys, p)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				return nil
			}
			expect, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(p)))
			if err != nil {
				t.Errorf("%s: %v", p, err)
				return nil
			}
			if i := firstDiff(got, expect); i != -1 {
				t.Errorf("%s: differs from wimlib's extraction at byte %d (read %d bytes, wimlib %d)",
					p, i, len(got), len(expect))
			}
			files++
			bytesRead += int64(len(got))
			return nil
		})
		if err != nil {
			t.Fatalf("WalkDir: %v", err)
		}

		for p := range want {
			t.Errorf("%s: applied by wimlib but not read from the WIM", p)
		}

		elapsed := time.Since(start)
		t.Logf("image %d: %d files, %d bytes read and compared in %v (%.1f MB/s decoded)",
			i, files, bytesRead, elapsed.Round(time.Millisecond),
			float64(bytesRead)/1e6/elapsed.Seconds())
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// BenchmarkReadImage measures decode throughput on its own: every file in a corpus image, read
// and discarded, with no oracle and no comparison in the loop.
//
// The number matters for one open decision. This package's LZX decoder walks a canonical Huffman
// code one bit at a time, which needs no decode table and so no allocation; a table-driven
// decoder is several times faster. Whether to write one should rest on a measurement of what the reader
// actually does, which is this.
func BenchmarkReadImage(b *testing.B) {
	dirs := os.Getenv("GOWIM_WIM_CORPUS")
	if dirs == "" {
		b.Skip("set GOWIM_WIM_CORPUS to a colon-separated list of directories holding .wim files")
	}
	var paths []string
	for _, dir := range filepath.SplitList(dirs) {
		matches, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, m := range matches {
			if ext := filepath.Ext(m); ext == ".wim" || ext == ".WIM" {
				paths = append(paths, m)
			}
		}
	}

	for _, p := range paths {
		b.Run(filepath.Base(p), func(b *testing.B) {
			f, err := os.Open(p)
			if err != nil {
				b.Skip(err)
			}
			defer f.Close()
			fi, _ := f.Stat()
			rd, err := Open(f, fi.Size())
			if err != nil {
				b.Fatalf("Open: %v", err)
			}
			im, err := rd.Boot()
			if err != nil {
				b.Fatalf("Boot: %v", err)
			}
			fsys := im.FS()

			b.ResetTimer()
			var total int64
			for b.Loop() {
				total = 0
				err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
					if err != nil || d.IsDir() {
						return err
					}
					data, err := fs.ReadFile(fsys, p)
					total += int64(len(data))
					return err
				})
				if err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(total)
			b.ReportMetric(float64(total)/1e6, "MB/image")
		})
	}
}
