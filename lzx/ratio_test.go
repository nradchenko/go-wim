// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package lzx

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// TestRatio measures the compressor against a directory of real files, chunk by chunk exactly
// as the writer does, and reports the ratio and throughput. It is the feedback loop for parse
// changes: a change that does not move this number is not worth its complexity.
//
//	GOWIM_LZX_CORPUS=<dir> go test -run TestRatio ./internal/wim/lzx/ -v
//
// Set GOWIM_LZX_BASELINE to a previous run's total to print the delta directly.
func TestRatio(t *testing.T) {
	dir := os.Getenv("GOWIM_LZX_CORPUS")
	if dir == "" {
		t.Skip("GOWIM_LZX_CORPUS not set; skipping")
	}

	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)

	c := NewCompressor()
	dst := make([]byte, WindowSize)
	var raw, packed int64
	var chunks, declined int
	start := time.Now()
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for off := 0; off < len(data); off += WindowSize {
			end := off + WindowSize
			if end > len(data) {
				end = len(data)
			}
			src := data[off:end]
			raw += int64(len(src))
			chunks++
			if n, ok := c.Compress(dst, src); ok {
				packed += int64(n)
			} else {
				packed += int64(len(src))
				declined++
			}
		}
	}
	elapsed := time.Since(start)

	t.Logf("%d files, %d chunks (%d stored raw)", len(files), chunks, declined)
	t.Logf("raw %d -> packed %d = %.3f%%", raw, packed, 100*float64(packed)/float64(raw))
	t.Logf("%.1f MiB/s", float64(raw)/elapsed.Seconds()/(1<<20))
	if b := os.Getenv("GOWIM_LZX_BASELINE"); b != "" {
		var base int64
		if _, err := fmt.Sscan(b, &base); err == nil && base > 0 {
			t.Logf("baseline %d -> %+d bytes (%+.3f%%)", base, packed-base,
				100*float64(packed-base)/float64(base))
		}
	}
}
