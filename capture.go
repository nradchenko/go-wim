// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"context"
	"crypto/sha1"
	"fmt"
	"io"
	"io/fs"
	"path"
	"time"
	"unicode/utf16"
)

// attrNormal is FILE_ATTRIBUTE_NORMAL. A tree captured on a POSIX filesystem carries no
// Windows attributes of its own, so a file is NORMAL and a directory is dirAttr — what wimlib
// records for the same tree.
const attrNormal = 0x00000080

// maxNameBytes is the longest name a dentry can record, its length field being 16 bits.
const maxNameBytes = 0xffff

// node is one captured file or directory. The offsets are filled in by encodeMetadata, which
// lays the dentry tree out before writing it.
type node struct {
	name     string
	name16   []uint16 // the name as UTF-16, which is how a dentry stores it
	isDir    bool
	attrs    uint32
	secID    uint32
	size     int64
	hash     [20]byte // all zero for a directory or an empty file
	filetime uint64
	children []*node

	dentryOff    int
	subdirOffset uint64
}

// capturedBlob is one unique file stream to be written as a resource. Its path is kept so the
// write pass can re-read the file — capturing hashes it, writing stores it — and its hash so
// that pass can confirm it is still reading the bytes it hashed.
type capturedBlob struct {
	path string
	size int64
	hash [20]byte
	refs uint32
}

// captured is a source tree walked and hashed, ready to be written.
type captured struct {
	root       *node
	blobs      []capturedBlob
	security   [][]byte
	dirCount   int
	fileCount  int
	totalBytes int64
	created    uint64
	modified   uint64
}

// capture walks src, hashing every file and deduplicating identical ones, and returns the tree
// plus the unique blobs to store. Entries are visited in lexical order, so the capture — and
// therefore the WIM — is reproducible for a given tree.
func capture(ctx context.Context, src fs.FS, opts Options) (*captured, error) {
	c := &captured{}
	secIndex := make(map[string]uint32)
	blobIndex := make(map[[20]byte]int)
	dirs := make(map[string]*node)

	err := fs.WalkDir(src, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}

		// A symlink has no WIM representation here, and following one would either duplicate a
		// file or escape the capture root — so it is an error rather than a silent decision.
		typ := d.Type()
		switch {
		case typ&fs.ModeSymlink != 0:
			return fmt.Errorf("wim: %s: symlinks cannot be captured", p)
		case !d.IsDir() && !typ.IsRegular():
			return fmt.Errorf("wim: %s: cannot capture irregular file (mode %s)", p, typ)
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		name := path.Base(p)
		if p == "." {
			name = "" // the root dentry is nameless
		}
		name16 := utf16.Encode([]rune(name))
		// A dentry records its name length in 16 bits. A real filesystem caps a path
		// component far below this, but src is an arbitrary fs.FS, and a name that wrapped
		// the field would produce a structurally valid image holding a corrupt dentry.
		if 2*len(name16) > maxNameBytes {
			return fmt.Errorf("wim: %s: name is %d UTF-16 bytes, over the %d a dentry can record",
				p, 2*len(name16), maxNameBytes)
		}
		n := &node{name: name, name16: name16, isDir: d.IsDir()}
		if n.isDir {
			n.attrs = dirAttr
			c.dirCount++
		} else {
			n.attrs = attrNormal
			c.fileCount++
		}

		n.filetime = fileTime(info.ModTime())
		if !opts.Timestamp.IsZero() {
			n.filetime = fileTime(opts.Timestamp)
		}
		if n.filetime > c.modified {
			c.modified = n.filetime
		}

		// Descriptors are deduplicated by content: a build that gives every file the same
		// descriptor gets a one-entry security table. A missing descriptor is refused here
		// rather than recorded as the no-descriptor sentinel — a partially secured image
		// verifies clean and then fails at mount, the failure this package exists to prevent.
		sd := opts.Security(p, d)
		if sd == nil {
			return fmt.Errorf("wim: %s: %w", p, ErrNoSecurity)
		}
		id, ok := secIndex[string(sd)]
		if !ok {
			id = uint32(len(c.security))
			secIndex[string(sd)] = id
			c.security = append(c.security, sd)
		}
		n.secID = id

		if !n.isDir {
			n.size = info.Size()
			c.totalBytes += n.size
			// A zero-length file is recorded with an all-zero hash and no blob-table entry;
			// only a file with content becomes a resource.
			if n.size > 0 {
				if n.hash, err = hashFile(src, p); err != nil {
					return err
				}
				if i, ok := blobIndex[n.hash]; ok {
					c.blobs[i].refs++
				} else {
					blobIndex[n.hash] = len(c.blobs)
					c.blobs = append(c.blobs, capturedBlob{path: p, size: n.size, hash: n.hash, refs: 1})
				}
			}
		}

		if p == "." {
			c.root = n
		} else {
			parent, ok := dirs[path.Dir(p)]
			if !ok {
				return fmt.Errorf("wim: %s: parent directory not visited", p)
			}
			parent.children = append(parent.children, n)
		}
		if n.isDir {
			dirs[p] = n
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if c.root == nil || !c.root.isDir {
		return nil, fmt.Errorf("wim: capture root is not a directory")
	}
	c.created = c.root.filetime
	return c, nil
}

// hashFile returns the SHA-1 of a file's contents, streamed rather than read whole: a WIM
// identifies every stream by this hash, and it is what deduplication matches on.
func hashFile(src fs.FS, p string) ([20]byte, error) {
	var out [20]byte
	f, err := src.Open(p)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := sha1.New()
	if _, err := io.Copy(h, f); err != nil {
		return out, fmt.Errorf("wim: hash %s: %w", p, err)
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// filetimeEpochDelta is the number of 100-nanosecond ticks between the FILETIME epoch
// (1601-01-01) and the Unix epoch.
const filetimeEpochDelta = 116444736000000000

// fileTime converts t to a Windows FILETIME. A time before the FILETIME epoch — which a
// synthetic filesystem's zero ModTime is — clamps to zero rather than wrapping.
func fileTime(t time.Time) uint64 {
	ticks := t.Unix()*10000000 + int64(t.Nanosecond())/100 + filetimeEpochDelta
	if ticks < 0 {
		return 0
	}
	return uint64(ticks)
}
