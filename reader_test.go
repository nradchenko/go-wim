// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

// captureImages writes a WIM holding one image per entry and returns its bytes. Several images
// in one WIM is otherwise untested territory for the reader, and it is where the two orderings
// it relies on — the XML's INDEX attribute and the blob table's metadata-resource order — could
// disagree without anything noticing.
func captureImages(t *testing.T, opts Options, images ...struct {
	src  fs.FS
	info ImageInfo
}) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "multi.wim")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWriter(f, opts)
	for _, im := range images {
		if err := w.AddImage(context.Background(), im.src, im.info); err != nil {
			t.Fatalf("AddImage %q: %v", im.info.Name, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestReaderImagesRoundTrip checks the identity a capture recorded comes back unchanged, for one
// image and for several. ImageInfo is the writer's own input type, which is what makes this the
// sharpest assertion available: what went in must come out, field for field.
func TestReaderImagesRoundTrip(t *testing.T) {
	second := ImageInfo{
		Name:        "Second",
		Description: "the one that is not bootable",
		Windows:     &WindowsInfo{Arch: ArchAMD64, Version: Version{Major: 5, Minor: 2, Build: 3790, SPBuild: 3959, SPLevel: 2}, SystemRoot: "WINDOWS"},
	}
	type image = struct {
		src  fs.FS
		info ImageInfo
	}

	for _, tc := range []struct {
		name string
		want []ImageInfo
		wim  func(t *testing.T) []byte
	}{
		{
			name: "one image",
			want: []ImageInfo{testImage()},
			wim:  func(t *testing.T) []byte { return captureBytes(t, fixture(), testOptions()) },
		},
		{
			name: "two images",
			want: []ImageInfo{testImage(), second},
			wim: func(t *testing.T) []byte {
				return captureImages(t, testOptions(),
					image{fixture(), testImage()},
					image{fstest.MapFS{"only.txt": &fstest.MapFile{Data: []byte("second")}}, second})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd, err := OpenBytes(tc.wim(t))
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			got := rd.Images()
			if len(got) != len(tc.want) {
				t.Fatalf("Images() returned %d image(s), want %d", len(got), len(tc.want))
			}
			for i := range tc.want {
				if !sameImageInfo(got[i], tc.want[i]) {
					t.Errorf("image %d:\n got %+v (windows %+v)\nwant %+v (windows %+v)",
						i+1, got[i], got[i].Windows, tc.want[i], tc.want[i].Windows)
				}
			}

			// The bootable image is named twice — by header index and by a copy of its
			// metadata reshdr — and Boot resolves both to the same image.
			boot, err := rd.Boot()
			if err != nil {
				t.Fatalf("Boot: %v", err)
			}
			if boot.Index() != 1 {
				t.Errorf("Boot() returned image %d, want 1", boot.Index())
			}
			if got := boot.Info().Name; got != tc.want[0].Name {
				t.Errorf("Boot() named %q, want %q", got, tc.want[0].Name)
			}
			if _, err := rd.Image(len(tc.want) + 1); err == nil {
				t.Error("Image past the last one returned no error")
			}
		})
	}
}

func sameImageInfo(a, b ImageInfo) bool {
	if a.Name != b.Name || a.Description != b.Description || a.Boot != b.Boot {
		return false
	}
	if (a.Windows == nil) != (b.Windows == nil) {
		return false
	}
	return a.Windows == nil || *a.Windows == *b.Windows
}

// TestReaderRejectsMalformedHeaders checks each refusal reports the kind of failure it is, not
// merely that something went wrong: "this is not a WIM", "this is a WIM I decline to read" and
// "this WIM contradicts itself" are three different answers for a caller.
func TestReaderRejectsMalformedHeaders(t *testing.T) {
	good := captureBytes(t, fixture(), testOptions())

	for _, tc := range []struct {
		name    string
		want    error
		corrupt func(b []byte)
	}{
		{"bad magic", ErrNotWIM, func(b []byte) { b[0] = 'X' }},
		{"header size", ErrUnsupported, func(b []byte) { binary.LittleEndian.PutUint32(b[hdrSizeOff:], 212) }},
		{"version", ErrUnsupported, func(b []byte) { binary.LittleEndian.PutUint32(b[hdrVersionOff:], 0x000E0000) }},
		{"split WIM", ErrUnsupported, func(b []byte) { binary.LittleEndian.PutUint16(b[hdrTotalPartsOff:], 2) }},
		{"XPRESS", ErrUnsupported, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed|hdrFlagCompressXPRESS)
			binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], DefaultChunkSize)
		}},
		{"LZMS", ErrUnsupported, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed|hdrFlagCompressLZMS)
			binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], DefaultChunkSize)
		}},
		{"compressed with no codec", ErrCorrupt, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed)
		}},
		{"chunk size over the window", ErrUnsupported, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed|hdrFlagCompressLZX)
			binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], 1<<20)
		}},
		{"chunk size not a power of two", ErrUnsupported, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed|hdrFlagCompressLZX)
			binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], 24576)
		}},
		{"chunk size with the sign bit set", ErrUnsupported, func(b []byte) {
			// 0x80000000 is positive in a 64-bit int and caught by the window bound, but on a
			// 32-bit build it reads back negative: it passes both the window and the
			// power-of-two terms, and the allocation that follows panics. Only the chunk <= 0
			// term refuses it on every architecture.
			binary.LittleEndian.PutUint32(b[hdrFlagsOff:], hdrFlagCompressed|hdrFlagCompressLZX)
			binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], 0x80000000)
		}},
		{"image count disagrees with the blob table", ErrCorrupt, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrImageCountOff:], 2)
		}},
		{"boot index past the last image", ErrCorrupt, func(b []byte) {
			binary.LittleEndian.PutUint32(b[hdrBootIndexOff:], 4)
		}},
		{"compressed blob table", ErrUnsupported, func(b []byte) {
			b[hdrLookupTableOff+7] |= flagCompressed
		}},
		{"blob table outside the WIM", ErrCorrupt, func(b []byte) {
			binary.LittleEndian.PutUint64(b[hdrLookupTableOff+8:], 1<<40)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			tc.corrupt(b)
			_, err := OpenBytes(b)
			if err == nil {
				t.Fatal("no error")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want it to be %v", err, tc.want)
			}
		})
	}
}

// TestReaderRejectsSolidAndSpannedResources covers the two resource forms that are refused by
// name. Both are legal WIM, neither is readable here, and a reader that ignored the flags would
// treat a solid resource's LZMS block as an ordinary LZX one and decode nonsense from it.
func TestReaderRejectsSolidAndSpannedResources(t *testing.T) {
	for _, tc := range []struct {
		name string
		flag byte
	}{
		{"solid", flagSolid},
		{"spanned", flagSpanned},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := captureBytes(t, fixture(), testOptions())
			// Flag the first blob-table entry, whichever resource it describes.
			tbl := readResHdr(b, hdrLookupTableOff)
			b[int(tbl.offset)+7] |= tc.flag

			_, err := OpenBytes(b)
			if !errors.Is(err, ErrUnsupported) {
				t.Fatalf("got %v, want it to be %v", err, ErrUnsupported)
			}
		})
	}
}

// TestReaderSkipsSupersededMetadata covers the shape Microsoft's own images are in: updating an
// image writes a new metadata resource and clears the old entry's reference count instead of
// rewriting the blob table, so a WIM declaring one image can hold several metadata resources.
// The Windows AIK's WinPE image holds four for its one image. Counting them all would refuse
// that image; picking the first would read a superseded version of it as though it were current.
//
// The stale entry here is made by re-flagging a file blob rather than by splicing a new entry in,
// which would move every offset after the blob table.
func TestReaderSkipsSupersededMetadata(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())
	tbl := readResHdr(b, hdrLookupTableOff)
	live := readResHdr(b, hdrBootMetaOff)

	found := false
	for i := 0; i < int(tbl.size/blobEntrySize); i++ {
		o := int(tbl.offset) + i*blobEntrySize
		res := readResHdr(b, o)
		if res.flags&flagMetadata != 0 || res.offset == live.offset {
			continue
		}
		b[o+7] |= flagMetadata                               // now metadata-flagged...
		binary.LittleEndian.PutUint32(b[o+resHdrSize+2:], 0) // ...with no references: superseded
		found = true
		break
	}
	if !found {
		t.Fatal("no file blob to re-flag as a superseded metadata resource")
	}

	rd, err := OpenBytes(b)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	if n := len(rd.Images()); n != 1 {
		t.Fatalf("Images() returned %d, want 1", n)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if im.meta.offset != live.offset {
		t.Errorf("Boot resolved the metadata at %#x, want the live one at %#x", im.meta.offset, live.offset)
	}
}

// TestReaderBootDisagreementIsReported covers a WIM naming two different boot images: the header
// carries a copy of the boot image's metadata reshdr, and the boot index names an image. When
// they disagree the image is two different images depending on who reads it — a loader takes the
// reshdr, everything else takes the index — so Boot refuses rather than picking one. Image and
// Images keep working, because inspecting a WIM in that state is exactly when you would want to.
func TestReaderBootDisagreementIsReported(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())
	binary.LittleEndian.PutUint64(b[hdrBootMetaOff+8:], 0xdead0000)

	rd, err := OpenBytes(b)
	if err != nil {
		t.Fatalf("OpenBytes: %v", err)
	}
	if _, err := rd.Boot(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Boot: got %v, want it to be %v", err, ErrCorrupt)
	}
	if _, err := rd.Image(1); err != nil {
		t.Errorf("Image(1) failed on a WIM whose only fault is its boot pointers: %v", err)
	}
	if len(rd.Images()) != 1 {
		t.Errorf("Images() returned %d entries, want 1", len(rd.Images()))
	}
}

// TestReaderReadsUncompressedAndLZX checks both storage forms parse, since the header's codec
// decides how every resource below it is read. The uncompressed form matters on its own: go-winio
// cannot read one at all, so it is the form no external parser has ever checked this writer on.
func TestReaderReadsUncompressedAndLZX(t *testing.T) {
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
			rd, err := OpenBytes(captureBytes(t, lzxCaptureFixture(), opts))
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			im, err := rd.Boot()
			if err != nil {
				t.Fatalf("Boot: %v", err)
			}
			// The metadata resource is the reader's first real decode: it is chunked exactly
			// as file content is, and nothing else can be read until it comes back whole.
			meta, err := rd.readResource(im.meta)
			if err != nil {
				t.Fatalf("read metadata: %v", err)
			}
			if len(meta) != int(im.meta.uncompressed) {
				t.Fatalf("metadata read %d bytes, resource declares %d", len(meta), im.meta.uncompressed)
			}
		})
	}
}

// TestMetadataAndXMLStorageOnRealImages records how real images actually store the two resources
// the reader locates from the header, rather than assuming it.
//
// This exists because the rule the reader follows was arrived at by reasoning: a resource's own
// COMPRESSED flag decides how it is stored, and the header supplies only the codec and the chunk
// size. The opposite rule — take the metadata's compression from the header — is a constraint on
// writers, and following it as a reader would fail on a legal image. No tool in
// reach reports these flags (`wiminfo` does not), so the values are pinned here.
//
// It is a measurement, not a gate: it asserts only the invariant the reader depends on, and logs
// what it saw. A future image storing the metadata raw is a fact to learn, not a failure.
func TestMetadataAndXMLStorageOnRealImages(t *testing.T) {
	for _, p := range realWIMFixtures(t) {
		t.Run(filepath.Base(p), func(t *testing.T) {
			b, err := os.ReadFile(p)
			if err != nil {
				t.Skipf("cannot read %s: %v", p, err)
			}
			rd, err := OpenBytes(b)
			if err != nil {
				t.Fatalf("OpenBytes: %v", err)
			}
			for i := 1; i <= len(rd.metas); i++ {
				res := rd.metas[i-1]
				t.Logf("image %d metadata: %d stored / %d uncompressed, compressed=%v",
					i, res.size, res.uncompressed, res.flags&flagCompressed != 0)
				if _, err := rd.readResource(res); err != nil {
					t.Errorf("image %d metadata does not read: %v", i, err)
				}
			}
			t.Logf("XML: %d stored / %d uncompressed, compressed=%v",
				rd.xmlRes.size, rd.xmlRes.uncompressed, rd.xmlRes.flags&flagCompressed != 0)
			if len(rd.Images()) != rd.imageCount {
				t.Errorf("XML described %d images, header declares %d", len(rd.Images()), rd.imageCount)
			}
		})
	}
}

// realWIMFixtures returns the WIMs this package is checked against that cannot be committed:
// Microsoft's own, and captures by other tools. Their paths come from the environment, so a
// checkout without them skips rather than fails.
func realWIMFixtures(t *testing.T) []string {
	t.Helper()
	dirs := os.Getenv("GOWIM_WIM_CORPUS")
	if dirs == "" {
		t.Skip("set GOWIM_WIM_CORPUS to a colon-separated list of directories holding .wim files")
	}
	var out []string
	for _, dir := range filepath.SplitList(dirs) {
		matches, err := filepath.Glob(filepath.Join(dir, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range matches {
			if ext := filepath.Ext(m); ext == ".wim" || ext == ".WIM" {
				out = append(out, m)
			}
		}
	}
	if len(out) == 0 {
		t.Skipf("no .wim files under %s", dirs)
	}
	return out
}

// TestReaderRejectsRaggedBlobTable covers a blob table whose size is not a whole number of
// entries. Dividing and reading what fits would drop the remainder silently — and the remainder
// can be an image's metadata resource, so the image would come back missing or absent entirely
// rather than reported as damaged.
func TestReaderRejectsRaggedBlobTable(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())
	tbl := readResHdr(b, hdrLookupTableOff)
	writeResHdr(b, hdrLookupTableOff, tbl.size-1, tbl.flags, tbl.offset, tbl.uncompressed)

	if _, err := OpenBytes(b); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
	}
}

// TestReaderRejectsImplausibleUncompressedSize covers a resource declaring far more uncompressed
// bytes than the bytes it stores could describe. maxResourceSize alone does not catch it: a WIM of
// a few hundred bytes may declare 64 GiB and be believed, and the allocation happens while Open is
// still parsing — so an image that never gets as far as being inspected can still exhaust memory.
// The blob table is deliberately not covered here: it is read by its stored size, which is
// already checked against the length of the WIM, and its uncompressed field is never used. An
// earlier version of this test asserted an error there and was wrong about the code, not the
// other way round.
func TestReaderRejectsImplausibleUncompressedSize(t *testing.T) {
	b := captureBytes(t, fixture(), testOptions())
	res := readResHdr(b, hdrXMLOff)
	writeResHdr(b, hdrXMLOff, res.size, res.flags, res.offset, 48<<30)

	_, err := OpenBytes(b)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
	}
}

// TestReaderRejectsImplausibleMetadataSize is the same guard reached through an image's metadata
// resource, which is read when the tree is first walked rather than at Open.
func TestReaderRejectsImplausibleMetadataSize(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, fixture(), opts)

	tbl := readResHdr(b, hdrLookupTableOff)
	for i := 0; i < int(tbl.size/blobEntrySize); i++ {
		o := int(tbl.offset) + i*blobEntrySize
		res := readResHdr(b, o)
		if res.flags&flagMetadata == 0 {
			continue
		}
		writeResHdr(b, o, res.size, res.flags, res.offset, 48<<30)
		break
	}

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
}
