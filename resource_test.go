// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// resourceFor returns the resource holding data, found the way the format finds one: by the
// SHA-1 of the content. This lets the resource layer be tested on its own, before there is a
// dentry tree to reach a file through.
func resourceFor(t *testing.T, rd *Reader, data []byte) resHdr {
	t.Helper()
	res, ok := rd.byHash[sha1.Sum(data)]
	if !ok {
		t.Fatalf("no resource for %d bytes of content", len(data))
	}
	return res
}

// TestResourceReadsWholeAndInPieces is the resource layer's own gate: whatever the codec, and
// wherever a read starts and ends, the bytes must be the bytes that were captured.
//
// The sub-range half is the point. A read is served by decoding only the chunks it touches and
// copying the wanted part out of them, so the boundaries — a read starting mid-chunk, ending
// mid-chunk, spanning several, or landing exactly on a chunk edge — are where that arithmetic
// goes wrong, and reading whole files would never exercise any of it.
func TestResourceReadsWholeAndInPieces(t *testing.T) {
	src := lzxCaptureFixture()
	big := src["windows/system32/big.txt"].Data // 200000 bytes: seven chunks, last one partial

	for _, tc := range []struct {
		name string
		comp Compression
	}{
		{"uncompressed", CompressNone},
		{"LZX", CompressLZX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions()
			opts.Compression = tc.comp
			rd, err := OpenBytes(captureBytes(t, src, opts))
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			res := resourceFor(t, rd, big)

			whole, err := rd.readResource(res)
			if err != nil {
				t.Fatalf("readResource: %v", err)
			}
			if i := firstDiff(whole, big); i != -1 {
				t.Fatalf("whole read differs at byte %d", i)
			}

			const chunk = DefaultChunkSize
			for _, r := range []struct {
				name     string
				off, len int
			}{
				{"first byte", 0, 1},
				{"within chunk 0", 100, 1000},
				{"up to a chunk edge", 0, chunk},
				{"from a chunk edge", chunk, chunk},
				{"across one edge", chunk - 10, 20},
				{"across several chunks", chunk/2 + 3, 3*chunk + 7},
				{"the partial last chunk", 6 * chunk, len(big) - 6*chunk},
				{"last byte", len(big) - 1, 1},
			} {
				t.Run(r.name, func(t *testing.T) {
					buf := make([]byte, r.len)
					n, err := rd.readResourceAt(res, buf, int64(r.off), nil)
					if err != nil && err != io.EOF {
						t.Fatalf("readResourceAt(%d,%d): %v", r.off, r.len, err)
					}
					if n != r.len {
						t.Fatalf("read %d bytes, want %d", n, r.len)
					}
					if i := firstDiff(buf, big[r.off:r.off+r.len]); i != -1 {
						t.Fatalf("differs at byte %d of the range", i)
					}
				})
			}

			// Random ranges, because the interesting boundaries are not only the ones a
			// person thinks to list.
			rng := rand.New(rand.NewSource(1))
			for i := 0; i < 200; i++ {
				off := rng.Intn(len(big))
				n := 1 + rng.Intn(len(big)-off)
				buf := make([]byte, n)
				got, err := rd.readResourceAt(res, buf, int64(off), nil)
				if err != nil && err != io.EOF {
					t.Fatalf("readResourceAt(%d,%d): %v", off, n, err)
				}
				if got != n || firstDiff(buf, big[off:off+n]) != -1 {
					t.Fatalf("range [%d,%d) came back wrong", off, off+n)
				}
			}
		})
	}
}

// TestResourceReadPastEndReportsEOF pins the io.ReaderAt contract: a read running past the end is
// served short with io.EOF, and one starting at or past the end returns it immediately. A file
// handle is built on this, so getting it wrong turns "the file ended" into a corruption report.
func TestResourceReadPastEndReportsEOF(t *testing.T) {
	data := []byte("nested payload")
	rd, err := OpenBytes(captureBytes(t, fixture(), testOptions()))
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	res := resourceFor(t, rd, data)

	buf := make([]byte, len(data)+10)
	n, err := rd.readResourceAt(res, buf, 0, nil)
	if n != len(data) || err != io.EOF {
		t.Errorf("over-long read: got (%d, %v), want (%d, EOF)", n, err, len(data))
	}
	if n, err := rd.readResourceAt(res, buf, int64(len(data)), nil); n != 0 || err != io.EOF {
		t.Errorf("read at the end: got (%d, %v), want (0, EOF)", n, err)
	}
}

// TestResourceRawStoredChunk covers the format's incompressible-data path: a chunk the codec
// declines is stored verbatim inside an otherwise compressed resource, which a reader recognises
// only by that chunk's stored size equalling its uncompressed size. Treating it as compressed
// would fail to decode a legal image.
//
// The content is deliberately mixed. A resource of nothing but noise does not reach this path at
// all: the writer finds the whole encoding no smaller than the input and stores the resource
// verbatim, with no chunk table and no compressed flag — which is a different path, and the one
// an earlier version of this test was silently exercising instead. Hence the assertion that the
// resource really is chunk-compressed before the chunks are examined.
func TestResourceRawStoredChunk(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	mixed := make([]byte, 0, 3*DefaultChunkSize)
	for i := range 2 * DefaultChunkSize {
		mixed = append(mixed, "the quick brown fox "[i%20])
	}
	noise := make([]byte, DefaultChunkSize)
	rng.Read(noise)
	mixed = append(mixed, noise...)

	opts := testOptions()
	opts.Compression = CompressLZX
	src := fstest.MapFS{"mixed.bin": &fstest.MapFile{Data: mixed}}
	rd, err := OpenBytes(captureBytes(t, src, opts))
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	res := resourceFor(t, rd, mixed)
	if res.flags&flagCompressed == 0 {
		t.Fatal("the resource was stored verbatim, so there are no chunks to check")
	}

	offs, err := rd.chunks(res)
	if err != nil {
		t.Fatalf("chunks: %v", err)
	}
	raw := 0
	for k := 0; k+1 < len(offs); k++ {
		if offs[k+1]-offs[k] == DefaultChunkSize {
			raw++
		}
	}
	if raw == 0 {
		t.Fatal("no chunk was stored raw, so this test is not covering the path it exists for")
	}

	got, err := rd.readResource(res)
	if err != nil {
		t.Fatalf("readResource: %v", err)
	}
	if !bytes.Equal(got, mixed) {
		t.Error("a resource holding raw-stored chunks did not read back")
	}
}

// TestResourceRejectsCorruptChunkTable checks a damaged chunk table is refused rather than
// decoded from wherever the offset happens to point. Each case names ErrCorrupt specifically:
// "this resource is damaged" and "this WIM is a form I do not read" are different answers.
func TestResourceRejectsCorruptChunkTable(t *testing.T) {
	src := lzxCaptureFixture()
	big := src["windows/system32/big.txt"].Data
	opts := testOptions()
	opts.Compression = CompressLZX
	good := captureBytes(t, src, opts)

	find := func(t *testing.T, b []byte) resHdr {
		rd, err := OpenBytes(b)
		if err != nil {
			t.Fatalf("OpenBytes: %v", err)
		}
		return resourceFor(t, rd, big)
	}
	res := find(t, good)

	for _, tc := range []struct {
		name    string
		corrupt func(b []byte)
	}{
		{"chunk offset past the resource", func(b []byte) {
			binary.LittleEndian.PutUint32(b[res.offset:], uint32(res.size)+1<<20)
		}},
		{"chunk offsets out of order", func(b []byte) {
			// Entry 0 is chunk 1's offset; pushing it past chunk 2's inverts the pair.
			second := binary.LittleEndian.Uint32(b[res.offset+4:])
			binary.LittleEndian.PutUint32(b[res.offset:], second+1)
		}},
		{"chunk larger than the chunk size", func(b []byte) {
			binary.LittleEndian.PutUint32(b[res.offset:], DefaultChunkSize+1)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			tc.corrupt(b)
			rd, err := OpenBytes(b)
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			if _, err := rd.readResource(resourceFor(t, rd, big)); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
			}
		})
	}
}

// BenchmarkReadFile reads one multi-chunk file the way a caller does — through the fs.FS, in
// whatever pieces io.ReadAll asks for — so the per-call cost of serving a Read shows up.
func BenchmarkReadFile(b *testing.B) {
	src := lzxCaptureFixture()
	opts := Options{Security: UniformSecurity(testSecurityDescriptor()), Compression: CompressLZX}

	p := filepath.Join(b.TempDir(), "bench.wim")
	f, err := os.Create(p)
	if err != nil {
		b.Fatal(err)
	}
	if err := Capture(context.Background(), f, src, ImageInfo{Name: "Image", Boot: true}, opts); err != nil {
		b.Fatal(err)
	}
	f.Close()
	raw, err := os.ReadFile(p)
	if err != nil {
		b.Fatal(err)
	}
	rd, err := OpenBytes(raw)
	if err != nil {
		b.Fatal(err)
	}
	im, err := rd.Boot()
	if err != nil {
		b.Fatal(err)
	}
	fsys := im.FS()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := fs.ReadFile(fsys, "windows/system32/big.txt"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkReadFileStreaming reads the same file through io.Copy, whose 32 KiB buffer means one
// Read per chunk rather than one for the whole file. This is the shape that shows what serving a
// Read costs, and the shape a caller streaming a large file actually produces.
func BenchmarkReadFileStreaming(b *testing.B) {
	src := lzxCaptureFixture()
	opts := Options{Security: UniformSecurity(testSecurityDescriptor()), Compression: CompressLZX}
	p := filepath.Join(b.TempDir(), "bench.wim")
	f, err := os.Create(p)
	if err != nil {
		b.Fatal(err)
	}
	if err := Capture(context.Background(), f, src, ImageInfo{Name: "Image", Boot: true}, opts); err != nil {
		b.Fatal(err)
	}
	f.Close()
	raw, _ := os.ReadFile(p)
	rd, err := OpenBytes(raw)
	if err != nil {
		b.Fatal(err)
	}
	im, _ := rd.Boot()
	fsys := im.FS()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		h, err := fsys.Open("windows/system32/big.txt")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, h); err != nil {
			b.Fatal(err)
		}
		h.Close()
	}
}
