// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Benchmarks shaped to be comparable with wimlib's, so the two numbers mean the same thing.
//
// The trap in comparing them is measuring different work. `wimlib-imagex verify` decompresses
// every stored resource once, sequentially, into a reused buffer and hashes it; a benchmark that
// walks a filesystem and allocates each file separately is measuring the allocator as much as the
// codec. BenchmarkDecodeAllResources therefore does what verify does. BenchmarkReadImage, which
// reads through the fs.FS, stays as the measure of what a caller actually experiences — both
// numbers are real, they answer different questions.

// BenchmarkDecodeAllResources decompresses every file resource in a corpus WIM into one reused
// buffer. This is the like-for-like counterpart to `wimlib-imagex verify`, minus the hashing.
func BenchmarkDecodeAllResources(b *testing.B) {
	dirs := os.Getenv("GOWIM_WIM_CORPUS")
	if dirs == "" {
		b.Skip("set GOWIM_WIM_CORPUS to a colon-separated list of directories holding .wim files")
	}
	for _, dir := range filepath.SplitList(dirs) {
		matches, _ := filepath.Glob(filepath.Join(dir, "*"))
		for _, p := range matches {
			if ext := filepath.Ext(p); ext != ".wim" && ext != ".WIM" {
				continue
			}
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

				var total int64
				var largest uint64
				for _, res := range rd.byHash {
					total += int64(res.uncompressed)
					largest = max(largest, res.uncompressed)
				}
				buf := make([]byte, largest)

				b.ResetTimer()
				for b.Loop() {
					for _, res := range rd.byHash {
						n, err := rd.readResourceAt(res, buf[:res.uncompressed], 0, nil)
						if err != nil && err != io.EOF {
							b.Fatalf("read resource at %#x: %v", res.offset, err)
						}
						if uint64(n) != res.uncompressed {
							b.Fatalf("resource at %#x: read %d of %d bytes", res.offset, n, res.uncompressed)
						}
					}
				}
				b.SetBytes(total)
			})
		}
	}
}

// BenchmarkCaptureTree captures a directory tree, for comparison with `wimlib-imagex capture` on
// the same tree. GOWIM_CAPTURE_THREADS mirrors wimlib's --threads so the two can be compared at
// one thread and at all of them.
func BenchmarkCaptureTree(b *testing.B) {
	dir := os.Getenv("GOWIM_CAPTURE_DIR")
	if dir == "" {
		b.Skip("set GOWIM_CAPTURE_DIR to a directory tree to capture")
	}
	opts := Options{
		Security:    UniformSecurity(testSecurityDescriptor()),
		Compression: CompressLZX,
	}
	if os.Getenv("GOWIM_CAPTURE_THREADS") == "1" {
		opts.Concurrency = 1
	}

	out := filepath.Join(b.TempDir(), "bench.wim")
	b.ResetTimer()
	for b.Loop() {
		if err := CaptureDir(context.Background(), dir, out, ImageInfo{Name: "Image", Boot: true}, opts); err != nil {
			b.Fatalf("CaptureDir: %v", err)
		}
	}
	b.StopTimer()

	if fi, err := os.Stat(out); err == nil {
		b.ReportMetric(float64(fi.Size())/1e6, "MB/wim")
	}
}
