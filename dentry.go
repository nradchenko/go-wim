// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
)

// Bounds on the shape of a dentry tree. A metadata resource is untrusted input the moment this
// package reads a WIM it did not write, and the tree is a graph of offsets that the format does
// not require to be acyclic: a subdir offset may point anywhere, including back at an ancestor.
//
// The depth cap alone is not enough. A tree whose subdir offsets branch into shared subtrees fans
// out exponentially while staying shallow, so the node cap is what actually bounds the work; the
// depth cap bounds the recursion.
const (
	maxTreeDepth = 64
	maxTreeNodes = 1 << 20
)

// File attributes the tree parse acts on.
const (
	attrDirectory    = 0x00000010
	attrReparsePoint = 0x00000400
)

// Field offsets within an alternate-stream entry, and the size of its fixed part.
//
// These are named and the size is *derived* from them because getting them wrong is silent: a
// stream entry read at the wrong offsets yields a zero hash, which resolves to a legitimately
// empty file rather than to an error. An earlier version of this parse read the name length at
// +28 and the hash at +8 — the layout of a 30-byte header — while bounding entries at 38 bytes.
// The two facts contradicted each other and nothing noticed, because the hand-built test fixture
// was written from the same wrong offsets and so agreed with the bug. Deriving the size from the
// last field's offset makes that particular contradiction impossible to write down.
const (
	streamLength      = 0  // le64: the entry's own length
	streamReserved    = 8  // le64: reserved, always zero
	streamHash        = 16 // 20 bytes: SHA-1 of this stream
	streamNameLength  = 36 // le16: the stream name's length in bytes
	streamName        = streamNameLength + 2
	streamEntryHeader = streamName // everything before the name
)

// Field offsets within a dentry that only the reader needs. The rest are in metadata.go, shared
// with the writer that emits them.
const (
	dentryStreamCount = 96
	dentryShortName   = 98
)

// dentry is one file or directory in an image's tree, as read from the metadata resource.
type dentry struct {
	name       string
	attributes uint32
	written    uint64 // FILETIME; the writer records one time in all three fields
	size       uint64
	hash       [20]byte
	res        resHdr
	hasData    bool
	// missing marks a dentry whose hash names a stream the blob table does not hold. The file
	// is listed — a damaged image is exactly when listing is wanted — but reading it fails
	// rather than returning the zero bytes it is not known to have.
	missing  bool
	children []*dentry
}

func (d *dentry) isDir() bool { return d.attributes&attrDirectory != 0 }

// alignUp8 rounds n up to a multiple of 8, saturating rather than wrapping: a length near 2**64
// would otherwise round to a small number and pass a bound it should fail.
func alignUp8(n uint64) uint64 {
	if n > ^uint64(0)-7 {
		return ^uint64(0)
	}
	return (n + 7) &^ 7
}

// tree returns the image's dentry tree, parsing the metadata resource on first use.
func (im *Image) tree() (*dentry, error) {
	im.once.Do(func() {
		var md []byte
		if md, im.loadErr = im.rd.readResource(im.meta); im.loadErr != nil {
			im.loadErr = fmt.Errorf("wim: image %d metadata: %w", im.index, im.loadErr)
			return
		}
		im.root, im.loadErr = im.rd.parseMetadata(md)
		if im.loadErr != nil {
			im.loadErr = fmt.Errorf("wim: image %d: %w", im.index, im.loadErr)
		}
	})
	return im.root, im.loadErr
}

// parseMetadata reads the security table's extent and then the dentry tree that follows it.
func (rd *Reader) parseMetadata(md []byte) (*dentry, error) {
	off, err := treeOffset(md)
	if err != nil {
		return nil, err
	}
	p := &metaParser{rd: rd, md: md}
	list, err := p.list(off, 0, true)
	if err != nil {
		return nil, err
	}
	// The metadata opens with exactly one dentry — the nameless root — and its own terminator.
	// Accepting more and taking the first would make which dentry is the root depend on the sort
	// above, so a malformed list would silently produce a different tree rather than an error.
	if len(list) != 1 {
		return nil, fmt.Errorf("wim: metadata opens with %d dentries, want exactly one root: %w",
			len(list), ErrCorrupt)
	}
	root := list[0]
	if !root.isDir() {
		return nil, fmt.Errorf("wim: metadata root is not a directory (attributes %#x): %w",
			root.attributes, ErrCorrupt)
	}
	return root, nil
}

// treeOffset validates the security table and returns where the dentry tree begins: the 8-aligned
// end of that table.
//
// The table's recorded length is load-bearing rather than informational, which is why it is
// checked rather than trusted. A length of zero rounds to zero, which would put the root dentry
// on top of the security table and parse its first bytes as a dentry length — yielding a tree
// that is structurally plausible and entirely wrong. It is the same offset-zero trap the writer
// guards from the other side, where an empty directory must still point at a real child list
// because offset zero is the security table.
func treeOffset(md []byte) (uint64, error) {
	if len(md) < 8 {
		return 0, fmt.Errorf("wim: metadata is %d bytes, too short for a security table: %w",
			len(md), ErrCorrupt)
	}
	total := uint64(binary.LittleEndian.Uint32(md[0:4]))
	count := uint64(binary.LittleEndian.Uint32(md[4:8]))
	if total < 8 {
		return 0, fmt.Errorf("wim: security table declares %d bytes, less than its own header: %w",
			total, ErrCorrupt)
	}
	// The table carries one 8-byte length per descriptor before the descriptors themselves, so
	// a total that cannot hold the length array describes a table that cannot exist.
	if count > (total-8)/8 {
		return 0, fmt.Errorf("wim: security table declares %d descriptors in %d bytes: %w",
			count, total, ErrCorrupt)
	}
	off := uint64(align8(int(total)))
	if off > uint64(len(md)) {
		return 0, fmt.Errorf("wim: security table ends at %d, past the %d-byte metadata: %w",
			off, len(md), ErrCorrupt)
	}
	return off, nil
}

// metaParser carries the state a tree walk needs beyond its own recursion.
type metaParser struct {
	rd    *Reader
	md    []byte
	nodes int
}

// fits reports whether n bytes at off lie inside the metadata.
//
// Every bound in this file goes through it, because the obvious form does not work here: an
// offset read from the image can be near 2**64, so `off+n > len(md)` wraps to a small number and
// passes — after which the read panics instead of reporting a corrupt image. A subdir offset of
// 0xFFFFFFFFFFFFFFFF is enough to do it. Subtracting on the known-good side cannot wrap.
func (p *metaParser) fits(off, n uint64) bool {
	total := uint64(len(p.md))
	return off <= total && n <= total-off
}

// list parses one directory's child list: dentries laid end to end, terminated by an 8-byte zero.
//
// The subtle part is where the next sibling begins. A dentry's recorded length covers its fixed
// header and its names, but a file with alternate data streams carries those stream entries after
// it, and the next dentry follows them. Stepping by the dentry length alone lands in the middle
// of a stream table and reads its bytes as a dentry — which does not fail, it produces garbage
// names. This package's writer emits no alternate streams, so no round trip over its own output
// can catch this; it is here because real captures do carry them.
func (p *metaParser) list(off uint64, depth int, isRoot bool) ([]*dentry, error) {
	if depth > maxTreeDepth {
		return nil, fmt.Errorf("wim: dentry tree deeper than %d: %w", maxTreeDepth, ErrCorrupt)
	}
	var out []*dentry
	for {
		if !p.fits(off, 8) {
			return nil, fmt.Errorf("wim: dentry list at %d runs past the metadata: %w", off, ErrCorrupt)
		}
		length := binary.LittleEndian.Uint64(p.md[off:])
		if length == 0 {
			// The list's terminator. Children are sorted here, once, because io/fs requires a
			// directory listing in name order and because sorted children let a path lookup
			// binary-search each component. The WIM's own order is not guaranteed to be either
			// — a capture made by walking a tree lexically comes out sorted, but nothing
			// requires that of an image from elsewhere.
			sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
			// Two children of one directory cannot share a name. NTFS does not permit it, so no
			// real capture produces it; what it would produce here is one of the two being
			// unreachable, since a path lookup binary-searches and finds whichever it lands on.
			// A tree where a listed name cannot be opened is worse than a refused one.
			for i := 1; i < len(out); i++ {
				if out[i].name == out[i-1].name {
					return nil, fmt.Errorf("wim: directory holds two entries named %q: %w",
						out[i].name, ErrCorrupt)
				}
			}
			return out, nil
		}
		// The step to the next entry is the length rounded up to 8: the format aligns dentries,
		// and a producer may record the unpadded length. Every image measured stores it already
		// aligned, so this is a no-op on all of them — but an unaligned one would otherwise
		// desynchronise the whole sibling list into garbage names rather than fail.
		step := alignUp8(length)
		if length < dentryFixedSize || step < length || !p.fits(off, step) {
			return nil, fmt.Errorf("wim: dentry at %d declares %d bytes: %w", off, length, ErrCorrupt)
		}
		p.nodes++
		if p.nodes > maxTreeNodes {
			return nil, fmt.Errorf("wim: dentry tree holds more than %d entries: %w", maxTreeNodes, ErrCorrupt)
		}

		d := &dentry{
			attributes: binary.LittleEndian.Uint32(p.md[off+dentryAttributes:]),
			written:    binary.LittleEndian.Uint64(p.md[off+dentryWriteTime:]),
		}
		subdir := binary.LittleEndian.Uint64(p.md[off+dentrySubdirOffset:])
		nameLen := uint64(binary.LittleEndian.Uint16(p.md[off+dentryNameLength:]))
		shortLen := uint64(binary.LittleEndian.Uint16(p.md[off+dentryShortName:]))
		streams := int(binary.LittleEndian.Uint16(p.md[off+dentryStreamCount:]))
		copy(d.hash[:], p.md[off+dentryHash:off+dentryHash+20])

		// The name, its terminator and the short name all live inside the recorded length.
		namesAt := off + dentryName
		if nameLen+2+shortLen > length-dentryName {
			return nil, fmt.Errorf("wim: dentry at %d: a %d-byte name does not fit in %d bytes: %w",
				off, nameLen, length, ErrCorrupt)
		}
		var err error
		if d.name, err = dentryName16(p.md[namesAt:namesAt+nameLen], off, isRoot); err != nil {
			return nil, err
		}

		// Alternate streams follow the dentry, and the next sibling follows them.
		next := off + step
		for i := 0; i < streams; i++ {
			if !p.fits(next, streamEntryHeader) {
				return nil, fmt.Errorf("wim: stream entry at %d runs past the metadata: %w", next, ErrCorrupt)
			}
			slen := binary.LittleEndian.Uint64(p.md[next+streamLength:])
			sstep := alignUp8(slen)
			if slen < streamEntryHeader || sstep < slen || !p.fits(next, sstep) {
				return nil, fmt.Errorf("wim: stream entry at %d declares %d bytes: %w", next, slen, ErrCorrupt)
			}
			// A file with alternate streams records its unnamed stream among them rather than
			// in the dentry, leaving the dentry hash zero. The unnamed one comes first.
			if i == 0 && binary.LittleEndian.Uint16(p.md[next+streamNameLength:]) == 0 && d.hash == ([20]byte{}) {
				copy(d.hash[:], p.md[next+streamHash:next+streamHash+20])
			}
			next += sstep
		}

		p.resolve(d)
		// A directory reparse point is a link to elsewhere: its subdir offset is not a child
		// list, and following it would leave the image. It is listed as an empty directory.
		if d.attributes&(attrDirectory|attrReparsePoint) == attrDirectory && subdir != 0 {
			if d.children, err = p.list(subdir, depth+1, false); err != nil {
				return nil, err
			}
		}
		out = append(out, d)
		off = next
	}
}

// resolve attaches the stream a dentry names, and records when there is none to attach.
//
// An all-zero hash is how the format encodes an empty file, so it is one — not a lookup failure.
// A hash naming a stream the blob table does not hold is a different thing entirely: the file's
// content is not in this WIM. Leaving such a dentry with no data — which is what a reader
// optimised for serving a mounted image tends to do — makes it read back as zero bytes, and that
// is indistinguishable from a genuinely empty file: it answers the question with data loss rather
// than with an error.
func (p *metaParser) resolve(d *dentry) {
	if d.isDir() || d.hash == ([20]byte{}) {
		return
	}
	res, ok := p.rd.byHash[d.hash]
	if !ok {
		d.missing = true
		return
	}
	d.res = res
	d.hasData = true
	d.size = res.uncompressed
}

// dentryName16 decodes a dentry's UTF-16 name and refuses one that cannot be a path component.
//
// A name holding a separator, or naming one of the relative directories, would be addressable
// only as some other path — so Open and ReadDir would disagree about what the tree contains, and
// a walk could be steered out of the image. The root's name is empty, and only the root's.
func dentryName16(b []byte, off uint64, isRoot bool) (string, error) {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	name := string(utf16.Decode(u))
	switch {
	case name == "":
		if !isRoot {
			return "", fmt.Errorf("wim: dentry at %d has no name: %w", off, ErrCorrupt)
		}
	case isRoot:
		return "", fmt.Errorf("wim: the root dentry at %d is named %q: %w", off, name, ErrCorrupt)
	case name == "." || name == "..", strings.ContainsRune(name, '/'):
		return "", fmt.Errorf("wim: dentry at %d is named %q, which is not a path component: %w",
			off, name, ErrCorrupt)
	}
	return name, nil
}
