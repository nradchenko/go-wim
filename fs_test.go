// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"maps"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// imageFSFor captures src and returns the boot image's fs.FS, which is the whole point of the
// reader: what went in as a tree comes back as one.
func imageFSFor(t *testing.T, src fs.FS, opts Options) fs.FS {
	t.Helper()
	rd, err := OpenBytes(captureBytes(t, src, opts))
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	return im.FS()
}

// TestFSRoundTrip is the reader's primary gate: capture a tree, read it back through the fs.FS,
// and require the same file set with the same bytes. It runs in both codecs, because the
// uncompressed form is the one no external parser checks — go-winio refuses every uncompressed
// WIM outright, so the writer's own tests patch the header to get it read at all.
func TestFSRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		comp Compression
	}{
		{"uncompressed", CompressNone},
		{"LZX", CompressLZX},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := lzxCaptureFixture()
			opts := testOptions()
			opts.Compression = tc.comp
			fsys := imageFSFor(t, src, opts)

			// Every path in the source tree, with directories marked, must come back — and
			// nothing else with it.
			want := map[string]string{".": "<dir>"}
			maps.Copy(want, fixtureContents)
			for _, name := range []string{"windows/system32/big.txt", "windows/system32/code.bin"} {
				want[name] = string(src[name].Data)
			}

			got := map[string]string{}
			err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					got[p] = "<dir>"
					return nil
				}
				b, err := fs.ReadFile(fsys, p)
				if err != nil {
					return err
				}
				got[p] = string(b)

				// A file's declared size must agree with what reading it produces, since a
				// caller listing an image sees the one and a caller extracting sees the other.
				fi, err := fs.Stat(fsys, p)
				if err != nil {
					return err
				}
				if fi.Size() != int64(len(b)) {
					t.Errorf("%s: Stat says %d bytes, read %d", p, fi.Size(), len(b))
				}
				return nil
			})
			if err != nil {
				t.Fatalf("WalkDir: %v", err)
			}

			for _, p := range slices.Sorted(maps.Keys(want)) {
				switch g, ok := got[p]; {
				case !ok:
					t.Errorf("%s is missing from the image", p)
				case g != want[p]:
					t.Errorf("%s: content differs (%d bytes read, %d captured)", p, len(g), len(want[p]))
				}
			}
			for _, p := range slices.Sorted(maps.Keys(got)) {
				if _, ok := want[p]; !ok {
					t.Errorf("%s is in the image but not in the source tree", p)
				}
			}
		})
	}
}

// TestFSSatisfiesTestFS runs the standard library's own conformance suite, which checks the
// things a hand-written test forgets: that Open, Stat, ReadDir and ReadDirFile agree with each
// other, that partial ReadDir(n) walks a directory exactly once, that listings are sorted, and
// that a bad path is refused rather than resolved.
func TestFSSatisfiesTestFS(t *testing.T) {
	fsys := imageFSFor(t, lzxCaptureFixture(), testOptions())
	var names []string
	err := fs.WalkDir(fsys, ".", func(p string, _ fs.DirEntry, err error) error {
		if err == nil && p != "." {
			names = append(names, p)
		}
		return err
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if err := fstest.TestFS(fsys, names...); err != nil {
		t.Error(err)
	}
}

// TestFSNonASCIINames covers names outside ASCII, which a dentry stores as UTF-16 and this
// package has to bring back as the same Go string.
func TestFSNonASCIINames(t *testing.T) {
	src := fstest.MapFS{
		"Программы/файл.txt":   &fstest.MapFile{Data: []byte("cyrillic")},
		"日本語/テスト.bin":          &fstest.MapFile{Data: []byte("japanese")},
		"emoji \U0001f600.txt": &fstest.MapFile{Data: []byte("astral")},
	}
	fsys := imageFSFor(t, src, testOptions())
	for name, f := range src {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !bytes.Equal(b, f.Data) {
			t.Errorf("%s: content differs", name)
		}
	}
}

// TestFSListingDoesNotDecodeContent pins the laziness the design depends on: walking and statting
// an image must not decompress any file body. The check is the bytes actually pulled from the
// backing — a listing that decoded content would read the whole image, not its metadata.
func TestFSListingDoesNotDecodeContent(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, lzxCaptureFixture(), opts)

	counting := &countingReaderAt{r: bytes.NewReader(b)}
	rd, err := Open(counting, int64(len(b)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	fsys := im.FS()

	if err := fs.WalkDir(fsys, ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		_, err = fs.Stat(fsys, p)
		return err
	}); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	afterWalk := counting.bytes()

	// The metadata resource is read whole, and the walk is served from it. What must not have
	// happened is a read of the file resources, which in this fixture are the bulk of the image.
	if afterWalk > int64(len(b))/2 {
		t.Errorf("walking read %d of the image's %d bytes; a listing should read metadata only",
			afterWalk, len(b))
	}

	if _, err := fs.ReadFile(fsys, "windows/system32/big.txt"); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if counting.bytes() == afterWalk {
		t.Error("reading a file pulled no further bytes, so the walk had already read it")
	}
}

// TestFSDanglingHashListsButDoesNotRead covers a dentry naming a stream the blob table does not
// hold. A reader may leave such a file with no data and so serve it as empty; this one does not.
// The file is listed, because listing a
// damaged image is exactly when it is wanted, and reading it fails naming the missing content —
// never silently returning zero bytes that are indistinguishable from a genuinely empty file.
func TestFSDanglingHashListsButDoesNotRead(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())

	// Point one blob-table entry's hash at content the image does not hold, which orphans the
	// dentries that name the original hash.
	tbl := readResHdr(b, hdrLookupTableOff)
	found := false
	for i := 0; i < int(tbl.size/blobEntrySize); i++ {
		o := int(tbl.offset) + i*blobEntrySize
		if res := readResHdr(b, o); res.flags&flagMetadata != 0 {
			continue
		}
		b[o+blobHashOffset] ^= 0xff
		found = true
		break
	}
	if !found {
		t.Fatal("no file blob to orphan")
	}

	rd, err := OpenBytes(b)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	fsys := im.FS()

	// Every name still lists, including the orphaned one.
	var listed, unreadable int
	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		listed++
		if d.IsDir() {
			return nil
		}
		if _, err := fs.ReadFile(fsys, p); err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Errorf("%s: got %v, want it to be %v", p, err, ErrCorrupt)
			}
			unreadable++
		}
		return nil
	}); err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if listed != len(fixtureContents)+1 { // +1 for the root
		t.Errorf("listed %d entries, want %d", listed, len(fixtureContents)+1)
	}
	if unreadable == 0 {
		t.Error("every file read back, so nothing was actually orphaned")
	}
}

// TestFSEmptyFileIsEmptyNotMissing is the other half of the dangling-hash rule: a zero-length
// file is recorded with an all-zero hash and no blob entry at all, which must read as empty
// rather than as content the WIM has lost.
func TestFSEmptyFileIsEmptyNotMissing(t *testing.T) {
	fsys := imageFSFor(t, fixture(), testOptions())
	b, err := fs.ReadFile(fsys, "windows/zero.dat")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(b) != 0 {
		t.Errorf("read %d bytes from a zero-length file", len(b))
	}
	fi, err := fs.Stat(fsys, "windows/zero.dat")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if fi.Size() != 0 {
		t.Errorf("Stat says %d bytes", fi.Size())
	}
}

// TestFSTimestampsRoundTrip checks the capture's recorded time comes back. The writer stores one
// FILETIME in all three of a dentry's time fields, so the modification time is what a reader can
// meaningfully report.
func TestFSTimestampsRoundTrip(t *testing.T) {
	stamp := time.Date(2003, 3, 25, 12, 0, 0, 0, time.UTC)
	opts := testOptions()
	opts.Timestamp = stamp
	fsys := imageFSFor(t, fixture(), opts)

	fi, err := fs.Stat(fsys, "readme.txt")
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !fi.ModTime().Equal(stamp) {
		t.Errorf("ModTime is %v, want %v", fi.ModTime(), stamp)
	}
}

// TestFSRejectsMalformedTree checks a damaged metadata resource is refused rather than walked
// into. Each case is a single field, so what is being tested is that specific guard.
func TestFSRejectsMalformedTree(t *testing.T) {
	// An uncompressed capture, so the metadata can be edited in place.
	opts := testOptions()
	opts.Compression = CompressNone
	good := captureBytes(t, fixture(), opts)

	metaOf := func(t *testing.T, b []byte) resHdr {
		t.Helper()
		rd, err := OpenBytes(b)
		if err != nil {
			t.Fatalf("OpenBytes: %v", err)
		}
		return rd.metas[0]
	}
	meta := metaOf(t, good)
	if meta.flags&flagCompressed != 0 {
		t.Fatal("the metadata resource is compressed, so it cannot be edited in place")
	}
	// The root dentry sits at the 8-aligned end of the security table.
	secTotal := binary.LittleEndian.Uint32(good[meta.offset:])
	root := meta.offset + uint64(align8(int(secTotal)))

	for _, tc := range []struct {
		name    string
		corrupt func(b []byte)
	}{
		{"security table shorter than its own header", func(b []byte) {
			binary.LittleEndian.PutUint32(b[meta.offset:], 4)
		}},
		{"security table past the metadata", func(b []byte) {
			binary.LittleEndian.PutUint32(b[meta.offset:], uint32(meta.uncompressed)+8)
		}},
		{"security table claims impossible descriptor count", func(b []byte) {
			binary.LittleEndian.PutUint32(b[meta.offset+4:], 1<<20)
		}},
		{"dentry shorter than its fixed header", func(b []byte) {
			binary.LittleEndian.PutUint64(b[root:], 40)
		}},
		{"dentry longer than the metadata", func(b []byte) {
			binary.LittleEndian.PutUint64(b[root:], meta.uncompressed+8)
		}},
		{"subdir offset points at the dentry itself", func(b []byte) {
			// A cycle: the root's children include the root, for as deep as the parse allows.
			binary.LittleEndian.PutUint64(b[root+dentrySubdirOffset:], root-meta.offset)
		}},
		{"name length overruns the dentry", func(b []byte) {
			length := binary.LittleEndian.Uint64(b[root:])
			binary.LittleEndian.PutUint16(b[root+dentryNameLength:], uint16(length))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			tc.corrupt(b)
			rd, err := OpenBytes(b)
			if err != nil {
				if !errors.Is(err, ErrCorrupt) {
					t.Fatalf("Open: got %v, want it to be %v", err, ErrCorrupt)
				}
				return
			}
			im, err := rd.Boot()
			if err != nil {
				t.Fatalf("Boot: %v", err)
			}
			if _, err := fs.ReadDir(im.FS(), "."); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
			}
		})
	}
}

// TestFSConcurrentReads exercises the contract the package documents: a Reader is safe for
// concurrent use. Several goroutines read the same and different files at once, which is what a
// parallel tree walk does, and what the memoized chunk tables have to survive.
func TestFSConcurrentReads(t *testing.T) {
	src := lzxCaptureFixture()
	opts := testOptions()
	opts.Compression = CompressLZX
	fsys := imageFSFor(t, src, opts)

	names := []string{
		"windows/system32/big.txt",
		"windows/system32/code.bin",
		"readme.txt",
		"windows/system32/config/note.txt",
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name := names[i%len(names)]
			b, err := fs.ReadFile(fsys, name)
			if err != nil {
				t.Errorf("%s: %v", name, err)
				return
			}
			if want := src[name].Data; !bytes.Equal(b, want) {
				t.Errorf("%s: content differs under concurrent reads", name)
			}
		}()
	}
	wg.Wait()
}

// countingReaderAt counts the bytes served, so a test can assert on how much of an image an
// operation actually touched.
type countingReaderAt struct {
	r  io.ReaderAt
	mu sync.Mutex
	n  int64
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.mu.Lock()
	c.n += int64(n)
	c.mu.Unlock()
	return n, err
}

func (c *countingReaderAt) bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
