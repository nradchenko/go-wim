// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// FS presents the image's file tree as a read-only fs.FS, implementing fs.ReadDirFS and
// fs.StatFS as well, so a caller walks, stats and reads it exactly as it would any other
// filesystem.
//
// Paths are matched exactly, including case. A WIM stores names in the case the capture saw, and
// Windows would match them case-insensitively; that is a property of the filesystem the image
// came from rather than of the format, and folding it in here would make Open succeed on paths
// this tree does not contain. A caller wanting Windows' own matching wraps this.
//
// FS never fails: an image whose metadata cannot be parsed reports that from the first operation
// on it, rather than making every caller handle an error from a method that has nothing else to
// go wrong.
func (im *Image) FS() fs.FS { return &imageFS{im: im} }

type imageFS struct{ im *Image }

// Open opens the named file for reading. Reading a directory is an error, as it is for os.Open.
func (f *imageFS) Open(name string) (fs.File, error) {
	d, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	if d.isDir() {
		return &wimDir{fs: f, d: d, name: name}, nil
	}
	// A dentry naming a stream the WIM does not hold is reported here rather than at parse
	// time, so a damaged image can still be listed — which is when listing is most wanted.
	if d.missing {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fmt.Errorf(
			"content (SHA-1 %x) is not in this WIM: %w", d.hash, ErrCorrupt)}
	}
	return &wimFile{fs: f, d: d, name: name, cache: newChunkCache()}, nil
}

// Stat returns the named file's metadata without reading or decompressing any of its content.
func (f *imageFS) Stat(name string) (fs.FileInfo, error) {
	d, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return fileInfo{d: d, name: name}, nil
}

// ReadDir returns the named directory's entries, sorted by name.
func (f *imageFS) ReadDir(name string) ([]fs.DirEntry, error) {
	d, err := f.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	if !d.isDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrInvalid}
	}
	return dirEntries(d), nil
}

// lookup resolves a slash-separated path to its dentry, walking one component at a time. The
// children of each directory are held in name order, so each step is a binary search rather than
// a scan.
func (f *imageFS) lookup(op, name string) (*dentry, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	root, err := f.im.tree()
	if err != nil {
		return nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	d := root
	if name == "." {
		return d, nil
	}
	for rest := name; rest != ""; {
		var comp string
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			comp, rest = rest[:i], rest[i+1:]
		} else {
			comp, rest = rest, ""
		}
		if !d.isDir() {
			return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		child := findChild(d, comp)
		if child == nil {
			return nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		d = child
	}
	return d, nil
}

// findChild returns d's child named name, or nil.
func findChild(d *dentry, name string) *dentry {
	i := sort.Search(len(d.children), func(i int) bool { return d.children[i].name >= name })
	if i < len(d.children) && d.children[i].name == name {
		return d.children[i]
	}
	return nil
}

func dirEntries(d *dentry) []fs.DirEntry {
	out := make([]fs.DirEntry, len(d.children))
	for i, c := range d.children {
		out[i] = fileInfo{d: c, name: c.name}
	}
	return out
}

// wimFile is an open file. It reads through the resource layer, so only the chunks a read
// touches are decoded: opening a file in a 200 MB image and reading its first bytes decodes one
// chunk, not the file and not the image.
type wimFile struct {
	fs    *imageFS
	d     *dentry
	name  string
	off   int64
	cache *chunkCache
}

func (f *wimFile) Stat() (fs.FileInfo, error) { return fileInfo{d: f.d, name: f.name}, nil }
func (f *wimFile) Close() error               { return nil }

func (f *wimFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.off)
	f.off += int64(n)
	return n, err
}

// ReadAt reads at an absolute offset, leaving the file's own position alone. It is the operation
// the format actually supports — every chunk is found by offset — and Read is built on it.
func (f *wimFile) ReadAt(p []byte, off int64) (int, error) {
	if !f.d.hasData {
		// An empty file has no resource at all: its hash is all zero and the blob table holds
		// no entry for it. That is the format's encoding of emptiness, not a missing stream.
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	return f.fs.im.rd.readResourceAt(f.d.res, p, off, f.cache)
}

// wimDir is an open directory. It carries the read position ReadDir(n) advances, which is what
// distinguishes reading a directory in pieces from reading it whole.
type wimDir struct {
	fs   *imageFS
	d    *dentry
	name string
	pos  int
}

func (d *wimDir) Stat() (fs.FileInfo, error) { return fileInfo{d: d.d, name: d.name}, nil }
func (d *wimDir) Close() error               { return nil }

func (d *wimDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}

// ReadDir implements fs.ReadDirFile. With n <= 0 it returns every remaining entry and no error;
// with n > 0 it returns at most n and reports io.EOF once they are exhausted.
func (d *wimDir) ReadDir(n int) ([]fs.DirEntry, error) {
	all := dirEntries(d.d)
	if d.pos >= len(all) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}
	rest := all[d.pos:]
	if n > 0 && n < len(rest) {
		rest = rest[:n]
	}
	d.pos += len(rest)
	return rest, nil
}

// fileInfo serves as both fs.FileInfo and fs.DirEntry: a WIM dentry holds everything either
// needs, so there is nothing to look up between them.
type fileInfo struct {
	d    *dentry
	name string
}

func (i fileInfo) Name() string {
	// The root dentry is nameless in the format; as a path it is ".".
	if i.d.name != "" {
		return i.d.name
	}
	return "."
}

func (i fileInfo) Size() int64        { return int64(i.d.size) }
func (i fileInfo) IsDir() bool        { return i.d.isDir() }
func (i fileInfo) Type() fs.FileMode  { return i.Mode().Type() }
func (i fileInfo) Sys() any           { return nil }
func (i fileInfo) ModTime() time.Time { return fileTimeToTime(i.d.written) }

// Info implements fs.DirEntry. The information is already in hand, so it cannot fail.
func (i fileInfo) Info() (fs.FileInfo, error) { return i, nil }

// Mode reports a read-only file or directory. A WIM records Windows attributes, which do not map
// onto permission bits; what is true of every entry here is that this filesystem cannot be
// written to.
func (i fileInfo) Mode() fs.FileMode {
	if i.d.isDir() {
		return fs.ModeDir | 0o555
	}
	return 0o444
}

// fileTimeToTime converts a Windows FILETIME — 100-nanosecond ticks since 1601 — to a time.Time.
// A zero FILETIME is the zero time rather than the year 1601, which is what a capture of a
// filesystem with no timestamp to record produces.
func fileTimeToTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	ticks := int64(ft) - filetimeEpochDelta
	return time.Unix(ticks/10000000, (ticks%10000000)*100).UTC()
}
