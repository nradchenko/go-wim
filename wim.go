// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

// Package wim reads and writes Windows Imaging (.wim) files.
//
// Writing captures a file tree into a WIM: walking the tree, deduplicating streams by SHA-1, and
// emitting the dentry tree, the security table, the blob table, and the XML — with no external
// imaging tool involved. Resources are stored uncompressed or LZX-compressed; the codec lives
// in the lzx subpackage and is usable on its own.
//
// Reading goes the other way and presents an image as an [io/fs.FS]:
//
//	rd, err := wim.Open(f, size)
//	im, err := rd.Boot()
//	data, err := fs.ReadFile(im.FS(), "windows/system32/ntoskrnl.exe")
//
// so anything already written against a filesystem works against a WIM unchanged. Reads are
// served from the chunks they touch rather than by expanding the image, which is what makes
// listing one cheap and reading one file out of a large one cheaper still.
//
// Two properties of the format are load-bearing and easy to get wrong, and this package refuses
// rather than lets you discover them at boot. A loader takes the metadata resource's compression
// from the WIM header rather than from that resource's own flag, so an image declaring a codec
// must compress its metadata too — the mismatch is legal, verifies clean under other tools, and
// produces an image Windows will not boot. And every dentry needs a security ID: an image whose
// dentries carry -1, which is what a POSIX capture naturally produces, is rejected at mount,
// which is why Options.Security has no default.
//
// Both of those constrain what is written. The reader is deliberately more permissive: it takes
// each resource's storage from that resource's own flag, so it reads images a loader would
// refuse. A WIM this package reads is therefore not necessarily one Windows will boot — writing
// it here is what makes it that.
package wim

import (
	"encoding/binary"
	"fmt"
)

// wimMagic is the 8-byte WIM file signature.
const wimMagic = "MSWIM\x00\x00\x00"

const (
	// flagMetadata marks a blob-table resource as an image's metadata resource.
	flagMetadata = 0x02
	// flagCompressed marks a resource as stored in chunk-compressed form.
	flagCompressed = 0x04
	// dirAttr is the FILE_ATTRIBUTE_DIRECTORY bit in a dentry's attributes.
	dirAttr = 0x10

	// resHdrSize is the size of a WIM resource header (reshdr): a 7-byte in-WIM size, a
	// 1-byte flags, an 8-byte in-WIM offset, and an 8-byte uncompressed size.
	resHdrSize = 24
	// blobEntrySize is the size of a blob-table (lookup-table) entry: a reshdr, a 2-byte
	// part number, a 4-byte reference count, and a 20-byte SHA-1.
	blobEntrySize = 50
	// blobHashOffset is the offset of the SHA-1 within a blob-table entry (after the
	// reshdr, part number, and reference count).
	blobHashOffset = resHdrSize + 2 + 4
	// lookupTableHdrOffset is the offset of the blob-table (lookup-table) reshdr in the
	// WIM header.
	lookupTableHdrOffset = 48
)

// resHdr is a decoded WIM resource header.
type resHdr struct {
	size         uint64 // stored (in-WIM) size
	flags        byte
	offset       uint64 // in-WIM byte offset
	uncompressed uint64 // uncompressed size
}

// readResHdr decodes the resource header at offset o. The size is a 7-byte field packed
// against the 1-byte flags, so it is read from the 8-byte window with the flags byte
// masked off.
func readResHdr(b []byte, o int) resHdr {
	return resHdr{
		size:         binary.LittleEndian.Uint64(b[o:o+8]) & 0x00ff_ffff_ffff_ffff,
		flags:        b[o+7],
		offset:       binary.LittleEndian.Uint64(b[o+8 : o+16]),
		uncompressed: binary.LittleEndian.Uint64(b[o+16 : o+24]),
	}
}

// writeResHdr encodes a resource header at offset o, preserving the 7-byte-size /
// 1-byte-flags packing.
func writeResHdr(b []byte, o int, size uint64, flags byte, offset, uncompressed uint64) {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], size)
	copy(b[o:o+7], tmp[:7])
	b[o+7] = flags
	binary.LittleEndian.PutUint64(b[o+8:o+16], offset)
	binary.LittleEndian.PutUint64(b[o+16:o+24], uncompressed)
}

// align8 rounds n up to a multiple of 8, the alignment WIM metadata regions use.
func align8(n int) int { return (n + 7) &^ 7 }

// findMetadataResource returns the blob-table entry offset and decoded resource header of
// the image's metadata resource. The blob table is described by the reshdr at
// lookupTableHdrOffset and is an array of blobEntrySize-byte entries.
//
// This and metadataBytes are the read side of the format. The writer does not need them —
// nothing here reads a WIM back — but the tests do, to check what was written against an
// independent parse, and a reader is what this package grows next: inspecting a built image,
// and reading a WIM-based Windows source.
func findMetadataResource(w []byte) (entOff int, res resHdr, err error) {
	if len(w) < lookupTableHdrOffset+resHdrSize || string(w[0:8]) != wimMagic {
		return 0, resHdr{}, fmt.Errorf("wim: not a WIM (bad magic)")
	}
	tbl := readResHdr(w, lookupTableHdrOffset)
	// The blob table is read as a flat array of blobEntrySize-byte entries, so its size
	// field must be the uncompressed on-disk size. wimlib writes it uncompressed for the
	// captures this assembles; guard the assumption rather than silently misread a
	// compressed table as raw entries.
	if tbl.flags&flagCompressed != 0 {
		return 0, resHdr{}, fmt.Errorf("wim: compressed blob table is not supported")
	}
	base, n := int(tbl.offset), int(tbl.size)/blobEntrySize
	for i := 0; i < n; i++ {
		e := base + i*blobEntrySize
		// The whole entry must fit: callers write the repointed reshdr and SHA-1 up to
		// e+blobEntrySize, not just the reshdr.
		if e < 0 || e+blobEntrySize > len(w) {
			break
		}
		if r := readResHdr(w, e); r.flags&flagMetadata != 0 {
			return e, r, nil
		}
	}
	return 0, resHdr{}, fmt.Errorf("wim: no metadata resource in blob table")
}

// metadataBytes returns the resource's uncompressed metadata slice, bounds-checked without
// overflowing (offset+uncompressed can wrap for a crafted reshdr).
func metadataBytes(w []byte, res resHdr) ([]byte, error) {
	if res.offset > uint64(len(w)) || res.uncompressed > uint64(len(w))-res.offset {
		return nil, fmt.Errorf("wim: metadata resource %#x+%#x out of bounds", res.offset, res.uncompressed)
	}
	return w[res.offset : res.offset+res.uncompressed], nil
}
