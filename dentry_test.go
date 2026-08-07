// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
	"unicode/utf16"
)

// The tests here build metadata resources by hand rather than by capturing a tree.
//
// They exist because this package's writer cannot produce the shapes they cover. It emits no
// alternate data streams and no reparse points, so a round trip over its own output — however
// thorough — leaves
// the parse's two hardest branches untouched: where the next sibling begins when a dentry carries
// stream entries, and what a directory reparse point means. Neither can be reached from a fixture
// either: the Windows AIK image, the largest real WIM in reach, was checked with `wimdir
// --detailed` and carries exactly one unnamed data stream per entry and no reparse points.
//
// Hand-built metadata is weaker evidence than a real capture, and is recorded as such. It is
// still the difference between a branch that is reasoned about and one that is executed.

// metaBuilder lays out a metadata resource: a security table, then a dentry tree.
type metaBuilder struct {
	buf []byte
}

// entry describes one dentry to emit.
type entry struct {
	name       string
	attributes uint32
	hash       [20]byte
	streams    []stream // emitted after the dentry, which is where the next sibling then starts
	rawStreams [][]byte // emitted verbatim in place of streams, for testing the on-disk layout
	children   []entry  // for a directory
}

// stream is one alternate-stream entry: its own length, a hash, and a name.
type stream struct {
	name string
	hash [20]byte
}

// newMetaBuilder starts a metadata resource with a one-descriptor security table, which is the
// shape a real capture has and the shape the tree offset is computed from.
func newMetaBuilder() *metaBuilder {
	sd := testSecurityDescriptor()
	total := 8 + 8 + len(sd)
	buf := make([]byte, align8(total))
	binary.LittleEndian.PutUint32(buf[0:], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:], 1)
	binary.LittleEndian.PutUint64(buf[8:], uint64(len(sd)))
	copy(buf[16:], sd)
	return &metaBuilder{buf: buf}
}

// build emits the root and its descendants and returns the finished resource. Child lists are
// written after the list that names them, which is the layout the writer produces.
func (m *metaBuilder) build(root entry) []byte {
	m.writeList([]entry{root})
	return m.buf
}

// writeList emits one child list — the dentries, then the 8-byte terminator — and returns where
// it began. Each directory's own children are emitted afterwards, so its subdir offset is
// back-patched once their list has a home.
func (m *metaBuilder) writeList(entries []entry) uint64 {
	at := uint64(len(m.buf))
	type patch struct {
		offset   uint64 // where this dentry's subdir field is
		children []entry
	}
	var pending []patch

	for _, e := range entries {
		off := uint64(len(m.buf))
		name16 := utf16.Encode([]rune(e.name))
		length := align8(dentryFixedSize + 2*len(name16) + 2)

		d := make([]byte, length)
		binary.LittleEndian.PutUint64(d[0:], uint64(length))
		binary.LittleEndian.PutUint32(d[dentryAttributes:], e.attributes)
		binary.LittleEndian.PutUint64(d[dentryWriteTime:], fileTime(builderTime))
		copy(d[dentryHash:], e.hash[:])
		nstreams := len(e.streams) + len(e.rawStreams)
		binary.LittleEndian.PutUint16(d[dentryStreamCount:], uint16(nstreams))
		binary.LittleEndian.PutUint16(d[dentryNameLength:], uint16(2*len(name16)))
		for i, u := range name16 {
			binary.LittleEndian.PutUint16(d[dentryName+2*i:], u)
		}
		m.buf = append(m.buf, d...)

		// Stream entries sit between this dentry and the next, which is the layout a reader
		// has to step over to find the sibling.
		for _, s := range e.streams {
			n16 := utf16.Encode([]rune(s.name))
			slen := align8(streamEntryHeader + 2*len(n16) + 2)
			sb := make([]byte, slen)
			binary.LittleEndian.PutUint64(sb[streamLength:], uint64(slen))
			// streamReserved stays zero.
			copy(sb[streamHash:], s.hash[:])
			binary.LittleEndian.PutUint16(sb[streamNameLength:], uint16(2*len(n16)))
			for i, u := range n16 {
				binary.LittleEndian.PutUint16(sb[streamName+2*i:], u)
			}
			m.buf = append(m.buf, sb...)
		}
		for _, raw := range e.rawStreams {
			m.buf = append(m.buf, raw...)
		}

		if e.attributes&attrDirectory != 0 {
			pending = append(pending, patch{offset: off, children: e.children})
		}
	}
	m.buf = append(m.buf, make([]byte, 8)...) // the list terminator

	for _, p := range pending {
		at := m.writeList(p.children)
		binary.LittleEndian.PutUint64(m.buf[p.offset+dentrySubdirOffset:], at)
	}
	return at
}

// builderTime is the timestamp every hand-built dentry carries. Its value does not matter; that
// every dentry has one does, since a zero FILETIME reads back as the zero time.
var builderTime = time.Date(2003, 3, 25, 12, 0, 0, 0, time.UTC)

// hashOf makes a distinct, non-zero hash for a test stream.
func hashOf(b byte) [20]byte {
	var h [20]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// readerWithBlobs builds a Reader holding the given streams, so a hand-built tree can resolve
// against a blob table without a WIM around it.
func readerWithBlobs(blobs map[[20]byte]uint64) *Reader {
	rd := &Reader{byHash: make(map[[20]byte]resHdr)}
	for h, size := range blobs {
		rd.byHash[h] = resHdr{size: size, uncompressed: size}
	}
	return rd
}

// TestParseStepsOverAlternateStreams is the branch a round trip cannot reach. A dentry carrying
// alternate data streams is followed by those stream entries, and only then by its sibling.
// Stepping by the dentry's own length instead lands inside the stream table and reads its bytes
// as a dentry — which does not fail, it silently produces a garbage name, so a reader that gets
// this wrong looks like it is working.
func TestParseStepsOverAlternateStreams(t *testing.T) {
	unnamed, ads, plain := hashOf(1), hashOf(2), hashOf(3)
	root := entry{
		attributes: attrDirectory,
		children: []entry{
			{
				name: "hasads.txt",
				// The unnamed stream's hash lives in the stream table, not the dentry, which
				// is how a file with alternate streams records its own content.
				streams: []stream{{name: "", hash: unnamed}, {name: "Zone.Identifier", hash: ads}},
			},
			{name: "plain.txt", hash: plain},
		},
	}
	md := newMetaBuilder().build(root)
	rd := readerWithBlobs(map[[20]byte]uint64{unnamed: 11, ads: 22, plain: 33})

	got, err := rd.parseMetadata(md)
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if len(got.children) != 2 {
		var names []string
		for _, c := range got.children {
			names = append(names, c.name)
		}
		t.Fatalf("root has %d children %q, want 2 — the sibling after a dentry with streams was missed",
			len(got.children), names)
	}
	withADS, plainFile := got.children[0], got.children[1]
	if withADS.name != "hasads.txt" || plainFile.name != "plain.txt" {
		t.Fatalf("children are %q and %q", withADS.name, plainFile.name)
	}
	// The unnamed stream is the file's content, so its size is the one to report.
	if !withADS.hasData || withADS.size != 11 {
		t.Errorf("the file's unnamed stream did not resolve: hasData=%v size=%d", withADS.hasData, withADS.size)
	}
	if !plainFile.hasData || plainFile.size != 33 {
		t.Errorf("the plain file did not resolve: hasData=%v size=%d", plainFile.hasData, plainFile.size)
	}
}

// TestParseDoesNotFollowDirectoryReparsePoint checks a directory reparse point is listed as an
// empty directory rather than walked into. Its subdir field is not a child list — it is part of
// the reparse data — so following it reads whatever those bytes happen to be.
func TestParseDoesNotFollowDirectoryReparsePoint(t *testing.T) {
	root := entry{
		attributes: attrDirectory,
		children: []entry{
			{
				name:       "junction",
				attributes: attrDirectory | attrReparsePoint,
				children:   []entry{{name: "unreachable.txt", hash: hashOf(9)}},
			},
			{name: "real", attributes: attrDirectory, children: []entry{{name: "inside.txt", hash: hashOf(8)}}},
		},
	}
	md := newMetaBuilder().build(root)
	rd := readerWithBlobs(map[[20]byte]uint64{hashOf(9): 1, hashOf(8): 2})

	got, err := rd.parseMetadata(md)
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if len(got.children) != 2 {
		t.Fatalf("root has %d children, want 2", len(got.children))
	}
	junction, ordinary := got.children[0], got.children[1]
	if junction.name != "junction" || ordinary.name != "real" {
		t.Fatalf("children are %q and %q", junction.name, ordinary.name)
	}
	if len(junction.children) != 0 {
		t.Errorf("the reparse point was followed: it lists %d children", len(junction.children))
	}
	if len(ordinary.children) != 1 {
		t.Errorf("the ordinary directory lists %d children, want 1", len(ordinary.children))
	}
}

// TestParseRejectsUnaddressableNames covers names that cannot be path components. A name holding
// a separator would be reachable only as some other path, so Open and ReadDir would disagree
// about what the image contains — and a walk could be steered outside it.
func TestParseRejectsUnaddressableNames(t *testing.T) {
	for _, name := range []string{"a/b", ".", "..", ""} {
		t.Run("name "+name, func(t *testing.T) {
			md := newMetaBuilder().build(entry{
				attributes: attrDirectory,
				children:   []entry{{name: name, hash: hashOf(4)}},
			})
			rd := readerWithBlobs(map[[20]byte]uint64{hashOf(4): 5})
			if _, err := rd.parseMetadata(md); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
			}
		})
	}
}

// TestParseRejectsMalformedStreamEntries checks the stream table is bounded like everything else:
// a stream entry shorter than its own header, or running past the metadata, would otherwise
// advance the walk to an arbitrary offset.
func TestParseRejectsMalformedStreamEntries(t *testing.T) {
	root := entry{
		attributes: attrDirectory,
		children: []entry{
			{name: "hasads.txt", streams: []stream{{name: "", hash: hashOf(1)}}},
			{name: "plain.txt", hash: hashOf(3)},
		},
	}
	good := newMetaBuilder().build(root)
	rd := readerWithBlobs(map[[20]byte]uint64{hashOf(1): 11, hashOf(3): 33})

	// Locate the stream entry: it follows the first child dentry.
	tree, err := treeOffset(good)
	if err != nil {
		t.Fatal(err)
	}
	rootLen := binary.LittleEndian.Uint64(good[tree:])
	childList := binary.LittleEndian.Uint64(good[tree+dentrySubdirOffset:])
	_ = rootLen
	streamAt := childList + binary.LittleEndian.Uint64(good[childList:])

	for _, tc := range []struct {
		name string
		set  uint64
	}{
		{"stream entry shorter than its header", 8},
		{"stream entry past the metadata", uint64(len(good)) + 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint64(b[streamAt:], tc.set)
			if _, err := rd.parseMetadata(b); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
			}
		})
	}
}

// TestParseRejectsDuplicateNames covers two children of one directory sharing a name. NTFS does
// not permit it, so no real capture produces it — but a path lookup binary-searches the sorted
// children, so one of the two would simply be unreachable: listed, and impossible to open. A tree
// that contradicts itself that way is refused rather than half-served.
func TestParseRejectsDuplicateNames(t *testing.T) {
	md := newMetaBuilder().build(entry{
		attributes: attrDirectory,
		children: []entry{
			{name: "same.txt", hash: hashOf(1)},
			{name: "same.txt", hash: hashOf(2)},
		},
	})
	rd := readerWithBlobs(map[[20]byte]uint64{hashOf(1): 1, hashOf(2): 2})
	if _, err := rd.parseMetadata(md); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
	}
}

// TestParseRejectsTwoRootDentries covers a metadata resource opening with more than the one
// nameless root. Taking the first would make which dentry is the root depend on the name sort
// applied to that list, so a malformed image would yield a different tree instead of an error.
func TestParseRejectsTwoRootDentries(t *testing.T) {
	m := newMetaBuilder()
	m.writeList([]entry{
		{attributes: attrDirectory},
		{attributes: attrDirectory, name: "second-root"},
	})
	if _, err := readerWithBlobs(nil).parseMetadata(m.buf); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
	}
}

// TestStreamEntryLayoutIsAsDocumented pins the on-disk layout of an alternate-stream entry
// against bytes written out literally, rather than against the constants the parser uses.
//
// This exists because the constants and the fixture that exercised them were once wrong in the
// same way, and so agreed: the parser read the hash at +8 and the name length at +28 — a 30-byte
// header — while bounding entries at 38, and the hand-built fixture was written from the same
// wrong offsets, so every test passed. Building the entry here from an explicit byte layout is
// what makes the two independent: this blob is written from the format, not from the code.
func TestStreamEntryLayoutIsAsDocumented(t *testing.T) {
	// le64 length | le64 reserved | u8 hash[20] | le16 name_nbytes | utf16 name
	//      8      +       8       +     20      +        2         = 38 bytes
	want := hashOf(0x5a)
	raw := make([]byte, 40)                    // 38 rounded up to the 8-byte alignment
	binary.LittleEndian.PutUint64(raw[0:], 40) // length, including padding
	binary.LittleEndian.PutUint64(raw[8:], 0)  // reserved
	copy(raw[16:36], want[:])                  // hash
	binary.LittleEndian.PutUint16(raw[36:], 0) // name_nbytes: unnamed, so this is the file's own

	if streamEntryHeader != 38 {
		t.Fatalf("streamEntryHeader is %d; the documented fixed part is 38 bytes", streamEntryHeader)
	}

	md := newMetaBuilder().build(entry{
		attributes: attrDirectory,
		children: []entry{
			{name: "withads.txt", rawStreams: [][]byte{raw}},
			{name: "after.txt", hash: hashOf(0x77)},
		},
	})
	rd := readerWithBlobs(map[[20]byte]uint64{want: 4242, hashOf(0x77): 7})

	root, err := rd.parseMetadata(md)
	if err != nil {
		t.Fatalf("parseMetadata: %v", err)
	}
	if len(root.children) != 2 {
		t.Fatalf("root has %d children, want 2 — the entry after a stream was missed", len(root.children))
	}
	withADS := root.children[1] // "withads.txt" sorts after "after.txt"
	if withADS.name != "withads.txt" {
		t.Fatalf("children are %q and %q", root.children[0].name, root.children[1].name)
	}
	// Reading the hash at the wrong offset yields zero, which resolves to an empty file — the
	// silent failure this whole test exists to make loud.
	if !withADS.hasData {
		t.Fatal("the unnamed stream did not resolve: the hash was read at the wrong offset")
	}
	if withADS.size != 4242 {
		t.Errorf("resolved to %d bytes, want 4242", withADS.size)
	}
}

// TestParseRejectsWrappingOffsets covers offsets and lengths near 2**64. The natural way to bound
// them — off+n > len(md) — wraps to a small number and passes, after which the read panics rather
// than reporting a corrupt image. A single crafted subdir offset is enough to do it, so this is
// reachable from any untrusted image through Image.FS().
func TestParseRejectsWrappingOffsets(t *testing.T) {
	good := newMetaBuilder().build(entry{
		attributes: attrDirectory,
		children: []entry{
			{name: "dir", attributes: attrDirectory, children: []entry{{name: "f.txt", hash: hashOf(1)}}},
			{name: "hasads.txt", streams: []stream{{name: "", hash: hashOf(2)}}},
		},
	})
	rd := readerWithBlobs(map[[20]byte]uint64{hashOf(1): 1, hashOf(2): 2})

	tree, err := treeOffset(good)
	if err != nil {
		t.Fatal(err)
	}
	childList := binary.LittleEndian.Uint64(good[tree+dentrySubdirOffset:])
	dirLen := binary.LittleEndian.Uint64(good[childList:])

	for _, tc := range []struct {
		name string
		at   uint64
		set  uint64
	}{
		{"subdir offset", childList + dentrySubdirOffset, ^uint64(0)},
		{"dentry length", childList, ^uint64(0) - 3},
		{"stream entry length", childList + dirLen + binary.LittleEndian.Uint64(good[childList+dirLen:]), ^uint64(0) - 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), good...)
			if tc.at+8 > uint64(len(b)) {
				t.Skipf("fixture too small to place a %s at %d", tc.name, tc.at)
			}
			binary.LittleEndian.PutUint64(b[tc.at:], tc.set)
			// A panic here is the defect; errors.Is checks the fix reports rather than crashes.
			if _, err := rd.parseMetadata(b); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("got %v, want it to be %v", err, ErrCorrupt)
			}
		})
	}
}
