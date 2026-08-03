// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import "encoding/binary"

// dentryFixedSize is a dentry's fixed header, from its 8-byte length through the file-name
// length field; the UTF-16 name and its terminator follow.
const dentryFixedSize = 102

// Field offsets within a dentry, from the start of its 8-byte length prefix.
const (
	dentryAttributes   = 8
	dentrySecurityID   = 12
	dentrySubdirOffset = 16
	dentryCreationTime = 40
	dentryAccessTime   = 48
	dentryWriteTime    = 56
	dentryHash         = 64
	dentryNameLength   = 100
	dentryName         = 102
)

// encodeMetadata builds an image's metadata resource: the security table, then the dentry tree
// laid out after it.
//
// The tree's shape follows what wimlib and imagex write, and what a reader expects: the root is
// a single nameless dentry sitting at the 8-aligned end of the security data, followed by that
// list's terminator; the root's children start after it, and every directory's children are a
// list of dentries ending in an 8-byte zero.
func encodeMetadata(c *captured) ([]byte, error) {
	if len(c.security) == 0 {
		return nil, ErrNoSecurity
	}
	sec := encodeSecurityTable(c.security)

	// Lay the tree out first: a dentry records its children by metadata-relative offset, so
	// every offset has to be known before any dentry can be written.
	pos := len(sec)
	c.root.dentryOff = pos
	pos += dentryLen(c.root) + 8 // the root's own list: the root dentry and its terminator

	queue := []*node{c.root}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		// Every directory gets a child list, empty ones included. A zero subdirectory offset
		// would send a reader to offset 0 of the metadata — the security table — so an empty
		// directory points at a list holding nothing but its terminator, as wimlib's does.
		d.subdirOffset = uint64(pos)
		for _, ch := range d.children {
			ch.dentryOff = pos
			pos += dentryLen(ch)
		}
		pos += 8
		for _, ch := range d.children {
			if ch.isDir {
				queue = append(queue, ch)
			}
		}
	}

	buf := make([]byte, pos)
	copy(buf, sec)
	putDentry(buf, c.root)
	var emit func(*node)
	emit = func(d *node) {
		for _, ch := range d.children {
			putDentry(buf, ch)
			if ch.isDir {
				emit(ch)
			}
		}
	}
	emit(c.root)
	return buf, nil
}

// dentryLen is a dentry's stored length: the fixed header, the UTF-16 name, and the name's
// terminator, rounded to 8. The length is stored already rounded — a reader steps by it — so
// the rounding is part of the value, not just of the layout.
func dentryLen(n *node) int {
	return align8(dentryFixedSize + 2*len(n.name16) + 2)
}

// putDentry writes n's dentry at the offset assigned to it. Everything not set here — the two
// unused words, the reparse/hard-link field, the stream count, the short name, the name
// terminator, and the padding to 8 — is zero, which is what a capture without alternate
// streams, hard links, or 8.3 names means.
func putDentry(buf []byte, n *node) {
	o := n.dentryOff
	binary.LittleEndian.PutUint64(buf[o:], uint64(dentryLen(n)))
	binary.LittleEndian.PutUint32(buf[o+dentryAttributes:], n.attrs)
	binary.LittleEndian.PutUint32(buf[o+dentrySecurityID:], n.secID)
	binary.LittleEndian.PutUint64(buf[o+dentrySubdirOffset:], n.subdirOffset)
	// A capture has no separate creation or access time to record, so all three carry the
	// file's modification time — as wimlib's capture of the same tree does.
	binary.LittleEndian.PutUint64(buf[o+dentryCreationTime:], n.filetime)
	binary.LittleEndian.PutUint64(buf[o+dentryAccessTime:], n.filetime)
	binary.LittleEndian.PutUint64(buf[o+dentryWriteTime:], n.filetime)
	copy(buf[o+dentryHash:o+dentryHash+20], n.hash[:])
	binary.LittleEndian.PutUint16(buf[o+dentryNameLength:], uint16(2*len(n.name16)))
	for i, u := range n.name16 {
		binary.LittleEndian.PutUint16(buf[o+dentryName+2*i:], u)
	}
}

// encodeSecurityTable serialises the descriptors as a metadata security block: the block's
// length and entry count, then each descriptor's length, then the descriptors, padded to 8.
// The recorded length excludes that padding; the dentry tree begins at the 8-aligned end.
func encodeSecurityTable(sds [][]byte) []byte {
	total := 8 + 8*len(sds)
	for _, sd := range sds {
		total += len(sd)
	}
	buf := make([]byte, align8(total))
	binary.LittleEndian.PutUint32(buf[0:], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:], uint32(len(sds)))
	off := 8
	for _, sd := range sds {
		binary.LittleEndian.PutUint64(buf[off:], uint64(len(sd)))
		off += 8
	}
	for _, sd := range sds {
		off += copy(buf[off:], sd)
	}
	return buf
}

// encodeBlobTable serialises the blob table: one entry per stored resource, each a resource
// header, the part number, the reference count, and the stream's SHA-1.
func encodeBlobTable(entries []blobEntry) []byte {
	buf := make([]byte, len(entries)*blobEntrySize)
	for i, e := range entries {
		o := i * blobEntrySize
		writeResHdr(buf, o, e.res.size, e.res.flags, e.res.offset, e.res.uncompressed)
		binary.LittleEndian.PutUint16(buf[o+resHdrSize:], 1) // part number; this WIM is not split
		binary.LittleEndian.PutUint32(buf[o+resHdrSize+2:], e.refs)
		copy(buf[o+blobHashOffset:o+blobEntrySize], e.hash[:])
	}
	return buf
}
