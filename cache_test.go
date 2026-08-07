// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"sync"
	"testing"
	"testing/fstest"
)

// The one-chunk cache a file handle carries is the newest and most intricate part of the read
// path, and it went in after the gates it has to survive were designed. These cover what the
// gates do not reach: the cache's interaction with a raw-stored chunk, with a decode that fails
// part way, and with the concurrent ReadAt its mutex exists for.

// cachedFile opens name and returns the handle as a *wimFile, which is what carries the cache.
func cachedFile(t *testing.T, fsys fs.FS, name string) *wimFile {
	t.Helper()
	h, err := fsys.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	f, ok := h.(*wimFile)
	if !ok {
		t.Fatalf("open %s returned %T, not a file handle", name, h)
	}
	return f
}

// mixedChunkFixture is content whose chunks are not all compressible: two chunks of repeated text
// and one of noise, so the resource is chunk-compressed overall while holding a raw-stored chunk.
// Reading across that boundary is what exercises the cache against both kinds of chunk.
func mixedChunkFixture() []byte {
	rng := rand.New(rand.NewSource(7))
	out := make([]byte, 0, 3*DefaultChunkSize)
	for i := range 2 * DefaultChunkSize {
		out = append(out, "the quick brown fox "[i%20])
	}
	noise := make([]byte, DefaultChunkSize)
	rng.Read(noise)
	return append(out, noise...)
}

// TestCacheServesRawStoredChunks covers the interaction the cache's comment reasons about but no
// test executed: a raw-stored chunk is served straight from the read scratch, leaving whatever
// decoded chunk the cache holds untouched and still valid.
//
// The reasoning was that dbuf is written only by the decode path. That is the kind of claim that
// is right until someone adds a second writer, so it is executed here rather than argued.
func TestCacheServesRawStoredChunks(t *testing.T) {
	want := mixedChunkFixture()
	opts := testOptions()
	opts.Compression = CompressLZX
	fsys := imageFSFor(t, fstest.MapFS{"mixed.bin": &fstest.MapFile{Data: want}}, opts)

	f := cachedFile(t, fsys, "mixed.bin")
	defer f.Close()
	if f.d.res.flags&flagCompressed == 0 {
		t.Fatal("the resource was stored verbatim, so no chunk path is being covered")
	}

	// Read in small pieces, crossing from the compressible chunks into the raw-stored one and
	// back again, so the cache is used, bypassed, and used again within one handle.
	const piece = 4096
	for _, off := range []int64{
		0, piece, 2 * DefaultChunkSize, 2*DefaultChunkSize + piece, // into the raw chunk
		0, piece, // back to a decoded chunk the cache may still hold
		DefaultChunkSize - piece/2, // straddling a chunk boundary
	} {
		n := int64(piece)
		if off+n > int64(len(want)) {
			n = int64(len(want)) - off
		}
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
		if !bytes.Equal(buf, want[off:off+n]) {
			t.Fatalf("ReadAt(%d,%d) served the wrong bytes — a stale cached chunk?", off, n)
		}
	}

	// And the whole file through the handle still matches.
	whole := make([]byte, len(want))
	if _, err := f.ReadAt(whole, 0); err != nil && err != io.EOF {
		t.Fatalf("ReadAt(whole): %v", err)
	}
	if !bytes.Equal(whole, want) {
		t.Error("reading the whole file through a used cache differs from the captured content")
	}
}

// TestCacheDiscardsPartialDecode covers a decode that fails part way through, leaving the cache's
// buffer holding a partial chunk. The failed read must not leave that behind for the next read to
// serve as though it were sound: a cache that survives its own failure is how corrupt data gets
// returned without an error.
func TestCacheDiscardsPartialDecode(t *testing.T) {
	src := lzxCaptureFixture()
	big := src["windows/system32/big.txt"].Data
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, src, opts)

	rd, err := OpenBytes(b)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	res := resourceFor(t, rd, big)
	offs, err := rd.chunks(res)
	if err != nil {
		t.Fatalf("chunks: %v", err)
	}

	// Corrupt the bytes of chunk 1 only, so chunk 0 still decodes and chunk 1 cannot.
	corrupt := append([]byte(nil), b...)
	for i := offs[1]; i < offs[2]; i++ {
		corrupt[i] ^= 0xff
	}
	rd, err = OpenBytes(corrupt)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	f := cachedFile(t, im.FS(), "windows/system32/big.txt")
	defer f.Close()

	// Chunk 0 is sound and caches.
	first := make([]byte, 1024)
	if _, err := f.ReadAt(first, 0); err != nil {
		t.Fatalf("reading the sound chunk: %v", err)
	}
	// Chunk 1 fails somewhere in its decode.
	second := make([]byte, 1024)
	if _, err := f.ReadAt(second, DefaultChunkSize); err == nil {
		t.Fatal("reading a corrupted chunk returned no error")
	}
	// Reading it again must fail the same way rather than serve whatever the failed decode
	// left behind.
	again := make([]byte, 1024)
	if _, err := f.ReadAt(again, DefaultChunkSize); err == nil {
		t.Fatal("re-reading the corrupted chunk succeeded, so the failed decode was cached")
	}
	// And the sound chunk still reads correctly afterwards.
	after := make([]byte, 1024)
	if _, err := f.ReadAt(after, 0); err != nil {
		t.Fatalf("re-reading the sound chunk after a failure: %v", err)
	}
	if !bytes.Equal(after, big[:1024]) {
		t.Error("the sound chunk came back wrong after a neighbouring chunk failed to decode")
	}
}

// TestCacheConcurrentReadAtOnOneHandle exercises what the cache's mutex exists for. io.ReaderAt
// permits parallel ReadAt calls on one source, and the existing concurrency test uses a separate
// handle per goroutine — so until this ran, the race detector had never seen the guarded path.
func TestCacheConcurrentReadAtOnOneHandle(t *testing.T) {
	want := mixedChunkFixture()
	opts := testOptions()
	opts.Compression = CompressLZX
	fsys := imageFSFor(t, fstest.MapFS{"mixed.bin": &fstest.MapFile{Data: want}}, opts)

	f := cachedFile(t, fsys, "mixed.bin")
	defer f.Close()

	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(g)))
			for range 40 {
				off := int64(rng.Intn(len(want)))
				n := int64(1 + rng.Intn(min(len(want)-int(off), 3*4096)))
				buf := make([]byte, n)
				if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
					t.Errorf("ReadAt(%d,%d): %v", off, n, err)
					return
				}
				if !bytes.Equal(buf, want[off:off+n]) {
					t.Errorf("ReadAt(%d,%d) served the wrong bytes under concurrent reads", off, n)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestCacheDoesNotChangeWhatIsRead is the safety net under the optimisation: for a file read every
// way a caller might read it, a cached handle and an uncached whole-resource read must agree
// byte for byte. The cache is an optimisation, and an optimisation that changes an answer is a
// defect however fast it is.
func TestCacheDoesNotChangeWhatIsRead(t *testing.T) {
	want := mixedChunkFixture()
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, fstest.MapFS{"mixed.bin": &fstest.MapFile{Data: want}}, opts)

	rd, err := OpenBytes(b)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}

	// Uncached: one whole-resource read with no handle in the way.
	uncached, err := rd.readResource(resourceFor(t, rd, want))
	if err != nil {
		t.Fatalf("readResource: %v", err)
	}
	if !bytes.Equal(uncached, want) {
		t.Fatal("the uncached read is already wrong, so this comparison proves nothing")
	}

	for _, piece := range []int{1, 7, 4096, DefaultChunkSize - 1, DefaultChunkSize, DefaultChunkSize + 1} {
		f := cachedFile(t, im.FS(), "mixed.bin")
		got := make([]byte, 0, len(want))
		buf := make([]byte, piece)
		for {
			n, err := f.Read(buf)
			got = append(got, buf[:n]...)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("piece %d: %v", piece, err)
			}
			if n == 0 {
				t.Fatalf("piece %d: Read returned 0 bytes and no error", piece)
			}
		}
		f.Close()
		if i := firstDiff(got, uncached); i != -1 {
			t.Errorf("read in %d-byte pieces: differs from the uncached read at byte %d", piece, i)
		}
	}
}
