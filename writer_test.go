// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	winio "github.com/Microsoft/go-winio/wim"
)

// The writer is checked against two independent readers: go-winio's WIM parser, which needs no
// external tool and so runs everywhere, and wimlib, which verifies every resource's SHA-1 and
// can apply the image back to a tree. Neither shares code with the writer.

// fixture is an in-memory tree covering the shapes a capture has to get right: nesting,
// duplicate content that must be stored once, a zero-length file, and an empty directory.
func fixture() fstest.MapFS {
	return fstest.MapFS{
		"readme.txt":                       &fstest.MapFile{Data: []byte("a plain file\n")},
		"windows/system32/example.dll":     &fstest.MapFile{Data: []byte("MZ payload one")},
		"windows/system32/config/note.txt": &fstest.MapFile{Data: []byte("nested payload")},
		"windows/inf/notes":                &fstest.MapFile{Data: []byte("MZ payload one")}, // duplicate of example.dll
		"windows/zero.dat":                 &fstest.MapFile{Data: []byte{}},
		"empty":                            &fstest.MapFile{Mode: fs.ModeDir},
	}
}

// fixtureContents is what a reader must see, with directories marked.
var fixtureContents = map[string]string{
	"readme.txt":                       "a plain file\n",
	"empty":                            "<dir>",
	"windows":                          "<dir>",
	"windows/inf":                      "<dir>",
	"windows/inf/notes":                "MZ payload one",
	"windows/system32":                 "<dir>",
	"windows/system32/config":          "<dir>",
	"windows/system32/config/note.txt": "nested payload",
	"windows/system32/example.dll":     "MZ payload one",
	"windows/zero.dat":                 "",
}

func testOptions() Options {
	return Options{Security: UniformSecurity(testSecurityDescriptor()), Compression: CompressNone}
}

func testImage() ImageInfo {
	return ImageInfo{
		Name: "Image",
		Boot: true,
		Windows: &WindowsInfo{
			Arch:       ArchIntel,
			Version:    Version{Major: 5, Minor: 1, Build: 2600, SPBuild: 5512},
			SystemRoot: "WINDOWS",
		},
	}
}

// captureFile captures src to a file and returns its path.
func captureFile(t *testing.T, src fs.FS, opts Options) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.wim")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := Capture(context.Background(), f, src, testImage(), opts); err != nil {
		t.Fatalf("Capture: %v", err)
	}
	return p
}

// goWinioReader parses a capture with go-winio.
//
// go-winio refuses any WIM whose header chunk size is not 0x8000, unconditionally — including
// every uncompressed WIM wimlib writes, which record 0. The field only describes how compressed
// resources are chunked and is inert when none are, so the test patches it for the reader
// rather than making the writer emit a value wimlib does not. The shipped header value is
// pinned separately, against real images, by TestCaptureHeaderMatchesReferenceImages.
func goWinioReader(t *testing.T, b []byte) *winio.Reader {
	t.Helper()
	patched := make([]byte, len(b))
	copy(patched, b)
	binary.LittleEndian.PutUint32(patched[hdrChunkSizeOff:], DefaultChunkSize)
	r, err := winio.NewReader(bytes.NewReader(patched))
	if err != nil {
		t.Fatalf("go-winio could not parse the capture: %v", err)
	}
	return r
}

// captureBytes captures src and returns the finished WIM.
func captureBytes(t *testing.T, src fs.FS, opts Options) []byte {
	t.Helper()
	b, err := os.ReadFile(captureFile(t, src, opts))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCaptureReadsBackWithGoWinio walks a capture with an independent WIM parser and checks the
// tree, the file contents, and the security descriptor each dentry resolves to.
func TestCaptureReadsBackWithGoWinio(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())

	r := goWinioReader(t, b)
	if len(r.Image) != 1 {
		t.Fatalf("images = %d, want 1", len(r.Image))
	}
	if got := r.Image[0].Name; got != "Image" {
		t.Errorf("image name = %q, want %q", got, "Image")
	}
	root, err := r.Image[0].Open()
	if err != nil {
		t.Fatalf("open image: %v", err)
	}

	got := make(map[string]string)
	var walk func(prefix string, f *winio.File) error
	walk = func(prefix string, f *winio.File) error {
		children, err := f.Readdir()
		if err != nil {
			return err
		}
		for _, c := range children {
			p := path.Join(prefix, c.Name)
			if !bytes.Equal(c.SecurityDescriptor, testSecurityDescriptor()) {
				t.Errorf("%s: security descriptor = %x, want the captured one", p, c.SecurityDescriptor)
			}
			if c.IsDir() {
				got[p] = "<dir>"
				if err := walk(p, c); err != nil {
					return err
				}
				continue
			}
			rc, err := c.Open()
			if err != nil {
				return err
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return err
			}
			got[p] = string(data)
		}
		return nil
	}
	if err := walk("", root); err != nil {
		t.Fatalf("walk image: %v", err)
	}

	for p, want := range fixtureContents {
		if g, ok := got[p]; !ok {
			t.Errorf("%s: missing from the image", p)
		} else if g != want {
			t.Errorf("%s = %q, want %q", p, g, want)
		}
	}
	for p := range got {
		if _, ok := fixtureContents[p]; !ok {
			t.Errorf("%s: unexpected entry in the image", p)
		}
	}
}

// TestCaptureHeaderMatchesReferenceImages pins the header fields against the values both
// wimlib's captures and Microsoft's imagex write.
func TestCaptureHeaderMatchesReferenceImages(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())

	if string(b[0:8]) != wimMagic {
		t.Fatalf("magic = %q", b[0:8])
	}
	for _, c := range []struct {
		name string
		off  int
		want uint32
	}{
		{"cbSize", hdrSizeOff, headerSize},
		{"version", hdrVersionOff, wimVersion},
		// An uncompressed capture matches wimlib's uncompressed header: no codec, no chunk
		// size. This is the shape proven to boot while the LZX codec does not exist.
		{"flags", hdrFlagsOff, hdrFlagRPFix},
		{"chunk size", hdrChunkSizeOff, 0},
		{"image count", hdrImageCountOff, 1},
		{"boot index", hdrBootIndexOff, 1},
	} {
		if got := binary.LittleEndian.Uint32(b[c.off:]); got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, got, c.want)
		}
	}
	if got := binary.LittleEndian.Uint16(b[hdrPartNumberOff:]); got != 1 {
		t.Errorf("part number = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint16(b[hdrTotalPartsOff:]); got != 1 {
		t.Errorf("total parts = %d, want 1", got)
	}
	// The boot-metadata header must name the same resource as the bootable image's own entry.
	boot := readResHdr(b, hdrBootMetaOff)
	_, meta, err := findMetadataResource(b)
	if err != nil {
		t.Fatal(err)
	}
	if boot != meta {
		t.Errorf("boot metadata %+v does not match the image's metadata resource %+v", boot, meta)
	}
	// No integrity table is written.
	if got := readResHdr(b, hdrIntegrityOff); got != (resHdr{}) {
		t.Errorf("integrity table = %+v, want none", got)
	}
	// The LZX header value is pinned for when the codec lands: it is what both wimlib's
	// captures and Microsoft's imagex write, measured from images known to boot.
	if got := uint32(hdrFlagRPFix | hdrFlagCompressed | hdrFlagCompressLZX); got != 0x40082 {
		t.Errorf("LZX header flags = %#x, want %#x", got, 0x40082)
	}
}

// TestCaptureLZX checks an LZX capture end to end: the header declares the codec, the metadata
// resource is compressed along with everything else, every resource decodes back to the bytes its
// recorded hash names, and the image is smaller than storing it raw.
//
// The metadata assertion is the load-bearing one. A loader takes the metadata's compression
// from the WIM header, not from that resource's own flag, so an image declaring LZX while
// storing raw metadata is legal, passes wimlib's verifier, and decodes to garbage.
func TestCaptureLZX(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, lzxCaptureFixture(), opts)

	if got := binary.LittleEndian.Uint32(b[hdrFlagsOff:]); got != hdrFlagRPFix|hdrFlagCompressed|hdrFlagCompressLZX {
		t.Errorf("header flags = %#x, want %#x", got, hdrFlagRPFix|hdrFlagCompressed|hdrFlagCompressLZX)
	}
	if got := binary.LittleEndian.Uint32(b[hdrChunkSizeOff:]); got != DefaultChunkSize {
		t.Errorf("chunk size = %d, want %d", got, DefaultChunkSize)
	}

	_, meta, err := findMetadataResource(b)
	if err != nil {
		t.Fatal(err)
	}
	if meta.flags&flagCompressed == 0 {
		t.Errorf("metadata resource flags = %#x, want the compressed bit set", meta.flags)
	}

	// Every resource, metadata included, must decode back to what the blob table records.
	compressed, stored := verifyResources(t, b, DefaultChunkSize)
	t.Logf("wrote %d compressed and %d stored resources", compressed, stored)
	if compressed < 2 {
		t.Errorf("only %d compressed resources; the capture is not exercising the codec", compressed)
	}

	// And it has to actually pay: the same tree stored raw is the thing to beat.
	plain := captureBytes(t, lzxCaptureFixture(), testOptions())
	if len(b) >= len(plain) {
		t.Errorf("LZX capture is %d bytes, no smaller than the uncompressed %d", len(b), len(plain))
	}
	t.Logf("LZX %d bytes vs uncompressed %d (%.1f%%)", len(b), len(plain), 100*float64(len(b))/float64(len(plain)))
}

// TestCaptureRejectsBadChunkSize checks a chunk size the codec cannot code against is refused.
// Left unchecked the failure is silent and reads as success: a chunk past the LZX window is
// declined and stored raw, yet a resource of those can still be a few bytes shorter than its
// input and so earn the compressed flag. Before the guard, a 200 KB compressible file captured
// at a 65536 chunk size came out at 98% of its original size, marked compressed.
func TestCaptureRejectsBadChunkSize(t *testing.T) {
	for _, size := range []int{65536, 131072, 30000, -1} {
		opts := testOptions()
		opts.Compression = CompressLZX
		opts.ChunkSize = size

		p := filepath.Join(t.TempDir(), "out.wim")
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		err = Capture(context.Background(), f, fixture(), testImage(), opts)
		f.Close()
		if !errors.Is(err, ErrChunkSize) {
			t.Errorf("Capture with ChunkSize %d = %v, want ErrChunkSize", size, err)
		}
	}

	// A smaller power of two is legal and still round-trips, so the guard rejects the
	// unusable rather than merely the unusual.
	opts := testOptions()
	opts.Compression = CompressLZX
	opts.ChunkSize = 4096
	b := captureBytes(t, lzxCaptureFixture(), opts)
	if got := binary.LittleEndian.Uint32(b[hdrChunkSizeOff:]); got != 4096 {
		t.Errorf("chunk size = %d, want 4096", got)
	}
	verifyResources(t, b, 4096)
}

// TestCaptureConcurrencyIsDeterministic checks the worker count changes only how long a capture
// takes, never what it produces. Chunks finish out of order under any real scheduling, so this
// is what keeps a capture reproducible — and run under -race it also covers the Compressors,
// which carry a match finder and coding scratch and must never be shared between workers.
func TestCaptureConcurrencyIsDeterministic(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX

	opts.Concurrency = 1
	want := captureBytes(t, lzxCaptureFixture(), opts)

	for _, n := range []int{2, 3, 8, 64} {
		opts.Concurrency = n
		got := captureBytes(t, lzxCaptureFixture(), opts)
		if !bytes.Equal(got, want) {
			t.Errorf("capture with %d workers differs from a single worker (first difference at byte %d)",
				n, firstDiff(got, want))
		}
	}

	// And the parallel output must still be readable, not merely stable.
	opts.Concurrency = 8
	verifyResources(t, captureBytes(t, lzxCaptureFixture(), opts), DefaultChunkSize)
}

// failAfter is a WriteSeeker that fails once it has accepted n bytes, standing in for a full
// disk or a broken pipe partway through a capture.
type failAfter struct {
	buf     []byte
	pos     int64
	written int
	limit   int
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.written+len(p) > f.limit {
		return 0, errors.New("device full")
	}
	f.written += len(p)
	end := f.pos + int64(len(p))
	if int64(len(f.buf)) < end {
		f.buf = append(f.buf, make([]byte, end-int64(len(f.buf)))...)
	}
	copy(f.buf[f.pos:], p)
	f.pos = end
	return len(p), nil
}

func (f *failAfter) Seek(off int64, whence int) (int64, error) {
	if whence != io.SeekStart {
		return 0, errors.New("unsupported seek")
	}
	f.pos = off
	return off, nil
}

// TestWriterFailureIsSticky checks a Writer that has failed mid-capture stays failed. Without
// this, bytes no blob-table entry describes are already on disk while the blobs recorded before
// the failure remain in the dedup map — so a retried AddImage would double-count their
// reference counts, and a Close would seal a WIM that parses fine and is wrong.
func TestWriterFailureIsSticky(t *testing.T) {
	dst := &failAfter{limit: headerSize + 64}
	w := NewWriter(dst, testOptions())

	first := w.AddImage(context.Background(), lzxCaptureFixture(), testImage())
	if first == nil {
		t.Fatal("AddImage onto a failing writer succeeded")
	}
	if retry := w.AddImage(context.Background(), lzxCaptureFixture(), testImage()); retry == nil {
		t.Error("AddImage after a failure succeeded; the failure must be sticky")
	} else if !errors.Is(retry, first) {
		t.Errorf("retry reported %v, want the original failure %v", retry, first)
	}
	if err := w.Close(); err == nil {
		t.Error("Close after a failure succeeded; it would seal an incomplete WIM")
	}
}

// TestCaptureMetadataAlwaysCompressed checks the metadata resource carries the compressed flag
// under an LZX header even for a tree so small that compressing it does not pay. A loader takes
// the metadata's compression from the header, so this must not depend on whether the encoding
// happened to come out smaller.
func TestCaptureMetadataAlwaysCompressed(t *testing.T) {
	trees := map[string]fstest.MapFS{
		"one empty file": {"a": &fstest.MapFile{}},
		"one short file": {"a": &fstest.MapFile{Data: []byte("x")}},
		"bare directory": {"d": &fstest.MapFile{Mode: fs.ModeDir}},
	}
	opts := testOptions()
	opts.Compression = CompressLZX
	for name, src := range trees {
		b := captureBytes(t, src, opts)
		_, meta, err := findMetadataResource(b)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if meta.flags&flagCompressed == 0 {
			t.Errorf("%s: metadata flags = %#x, want the compressed bit set", name, meta.flags)
		}
		verifyResources(t, b, DefaultChunkSize)
	}
}

// TestCaptureRejectsOverlongName checks a name too long for a dentry's 16-bit length field is
// refused. A real filesystem caps a component far below this, but a capture reads an arbitrary
// fs.FS, and a wrapped length would yield a structurally valid image holding a corrupt dentry.
func TestCaptureRejectsOverlongName(t *testing.T) {
	src := fstest.MapFS{strings.Repeat("n", 40000): &fstest.MapFile{Data: []byte("x")}}
	p := filepath.Join(t.TempDir(), "out.wim")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = Capture(context.Background(), f, src, testImage(), testOptions())
	if err == nil {
		t.Fatal("capture of an overlong name succeeded")
	}
	if !strings.Contains(err.Error(), "name is") {
		t.Errorf("error = %v, want it to name the length problem", err)
	}
}

// lzxCaptureFixture is a tree with enough compressible bulk to be worth coding, unlike the
// handful of short strings the structural fixture carries.
func lzxCaptureFixture() fstest.MapFS {
	src := fixture()
	text := make([]byte, 200000)
	for i := range text {
		text[i] = byte("the quick brown fox jumps over the lazy dog "[i%43])
	}
	src["windows/system32/big.txt"] = &fstest.MapFile{Data: text}

	code := make([]byte, 90000)
	for i := range code {
		code[i] = byte(i * 7)
	}
	for i := 0; i+5 < len(code); i += 24 {
		code[i] = 0xe8
		binary.LittleEndian.PutUint32(code[i+1:], uint32(i*13%80000))
	}
	src["windows/system32/code.bin"] = &fstest.MapFile{Data: code}
	return src
}

// TestCaptureDeduplicatesAndSkipsEmptyFiles checks the blob table holds one entry per distinct
// non-empty stream, plus the metadata: a zero-length file is recorded by an all-zero hash and
// no resource, and identical content is stored once.
func TestCaptureDeduplicatesAndSkipsEmptyFiles(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())

	tbl := readResHdr(b, hdrLookupTableOff)
	n := int(tbl.size) / blobEntrySize
	var files, metas int
	var offsets []uint64
	for i := 0; i < n; i++ {
		e := int(tbl.offset) + i*blobEntrySize
		res := readResHdr(b, e)
		offsets = append(offsets, res.offset)
		if res.flags&flagMetadata != 0 {
			metas++
		} else {
			files++
		}
	}
	// Three distinct non-empty contents in the fixture; zero.dat contributes none.
	if files != 3 || metas != 1 {
		t.Errorf("blob table has %d file resources and %d metadata, want 3 and 1", files, metas)
	}
	if !sort.SliceIsSorted(offsets, func(i, j int) bool { return offsets[i] < offsets[j] }) {
		t.Errorf("blob-table entries are not ordered by offset: %v", offsets)
	}
}

// TestCaptureEmptyDirectoryHasChildList guards the trap that a zero subdirectory offset would
// point a reader at offset 0 of the metadata — the security table — rather than at nothing.
func TestCaptureEmptyDirectoryHasChildList(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())
	_, res, err := findMetadataResource(b)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := metadataBytes(b, res)
	if err != nil {
		t.Fatal(err)
	}

	off, ok := findDentry(t, meta, "empty")
	if !ok {
		t.Fatal(`no "empty" dentry in the metadata`)
	}
	if sub := binary.LittleEndian.Uint64(meta[off+dentrySubdirOffset:]); sub == 0 {
		t.Error(`empty directory has subdir offset 0; it must point at a list holding only its terminator`)
	}

	// And the behaviour that depends on it: an independent reader lists it as empty rather
	// than failing or inventing entries.
	r := goWinioReader(t, b)
	root, err := r.Image[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	children, err := root.Readdir()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range children {
		if c.Name != "empty" {
			continue
		}
		sub, err := c.Readdir()
		if err != nil {
			t.Fatalf("read empty directory: %v", err)
		}
		if len(sub) != 0 {
			t.Errorf("empty directory lists %d entries", len(sub))
		}
	}
}

// findDentry returns the offset of the first dentry named name, walking the tree the way a
// reader does.
func findDentry(t *testing.T, meta []byte, name string) (int, bool) {
	t.Helper()
	total := binary.LittleEndian.Uint32(meta[0:4])
	var walk func(p int) (int, bool)
	walk = func(p int) (int, bool) {
		for {
			ln := binary.LittleEndian.Uint64(meta[p : p+8])
			if ln == 0 {
				return 0, false
			}
			nl := int(binary.LittleEndian.Uint16(meta[p+dentryNameLength:]))
			var got string
			if nl > 0 {
				u := make([]uint16, nl/2)
				for i := range u {
					u[i] = binary.LittleEndian.Uint16(meta[p+dentryName+2*i:])
				}
				got = string(utf16Decode(u))
			}
			if got == name {
				return p, true
			}
			attr := binary.LittleEndian.Uint32(meta[p+dentryAttributes:])
			sub := binary.LittleEndian.Uint64(meta[p+dentrySubdirOffset:])
			if attr&dirAttr != 0 && sub != 0 {
				if off, ok := walk(int(sub)); ok {
					return off, true
				}
			}
			p += align8(int(ln))
		}
	}
	return walk(align8(int(total)))
}

func utf16Decode(u []uint16) []rune {
	out := make([]rune, 0, len(u))
	for _, c := range u {
		out = append(out, rune(c))
	}
	return out
}

// TestCaptureIsReproducible checks that capturing the same tree twice produces the same bytes —
// the derived GUID and the tree's own timestamps are the only things that could vary.
func TestCaptureIsReproducible(t *testing.T) {
	a := captureBytes(t, fixture(), testOptions())
	b := captureBytes(t, fixture(), testOptions())
	if !bytes.Equal(a, b) {
		t.Errorf("two captures of the same tree differ (first difference at byte %d)", firstDiff(a, b))
	}
}

// TestCaptureRequiresSecurity checks the empty-security-table image is refused at capture time
// rather than at boot.
func TestCaptureRequiresSecurity(t *testing.T) {
	p := filepath.Join(t.TempDir(), "out.wim")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = Capture(context.Background(), f, fixture(), testImage(), Options{})
	if !errors.Is(err, ErrNoSecurity) {
		t.Errorf("Capture with no Security = %v, want ErrNoSecurity", err)
	}
}

// TestCaptureRejectsSymlink checks a symlink is an error rather than being followed, which
// would duplicate a file or escape the capture root.
func TestCaptureRejectsSymlink(t *testing.T) {
	src := fstest.MapFS{
		"real.txt": &fstest.MapFile{Data: []byte("x")},
		"link.txt": &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("real.txt")},
	}
	p := filepath.Join(t.TempDir(), "out.wim")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = Capture(context.Background(), f, src, testImage(), testOptions())
	if err == nil {
		t.Fatal("Capture of a tree with a symlink succeeded, want an error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("symlink")) {
		t.Errorf("error = %v, want it to name the symlink", err)
	}
}

// TestCaptureVerifiesWithWimlib runs wimlib over a native capture: verify checks every
// resource's SHA-1 against its blob-table entry, and apply round-trips the image back to a tree.
func TestCaptureVerifiesWithWimlib(t *testing.T) {
	for _, tool := range []string{"wimlib-imagex", "wimapply"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available; skipping", tool)
		}
	}
	out := captureFile(t, fixture(), testOptions())
	mustRun(t, "wimlib-imagex", "verify", out)

	dir := filepath.Join(t.TempDir(), "applied")
	mustRun(t, "wimapply", out, "1", dir)

	got := make(map[string]string)
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			got[filepath.ToSlash(rel)] = "<dir>"
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		got[filepath.ToSlash(rel)] = string(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	for p, want := range fixtureContents {
		if g, ok := got[p]; !ok {
			t.Errorf("%s: missing from the applied tree", p)
		} else if g != want {
			t.Errorf("%s = %q, want %q", p, g, want)
		}
	}
	for p := range got {
		if _, ok := fixtureContents[p]; !ok {
			t.Errorf("%s: unexpected entry in the applied tree", p)
		}
	}
}
