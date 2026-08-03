// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nradchenko/go-wim/lzx"
)

// WIM header constants, measured from real images rather than taken from a specification: both
// wimlib's captures and Microsoft's own imagex write version 0x00010D00, and an LZX image
// carries COMPRESSED|RP_FIX|LZX with a 32768-byte chunk size.
const (
	headerSize = 208
	wimVersion = 0x00010D00

	hdrFlagCompressed  = 0x00000002
	hdrFlagRPFix       = 0x00000080
	hdrFlagCompressLZX = 0x00040000
)

// Header field offsets.
const (
	hdrSizeOff       = 8
	hdrVersionOff    = 12
	hdrFlagsOff      = 16
	hdrChunkSizeOff  = 20
	hdrGUIDOff       = 24
	hdrPartNumberOff = 40
	hdrTotalPartsOff = 42
	hdrImageCountOff = 44
	hdrXMLOff        = 72
	hdrBootMetaOff   = 96
	hdrBootIndexOff  = 120
	// The integrity reshdr follows the boot index directly — there is no padding word
	// between them, which the header's own size confirms: 124 + 24 + 60 unused = 208.
	// (go-winio's header struct carries a spurious padding field and so totals 212; it
	// never reads the integrity descriptor, so its offset error is invisible there.)
	hdrIntegrityOff   = 124
	hdrLookupTableOff = lookupTableHdrOffset
)

// ErrNoSecurity reports a capture with no security descriptors. An image whose dentries carry
// no security ID is what a POSIX filesystem naturally yields — there is no NT security data to
// read — and it is what Windows rejects at mount, so it is refused at capture time rather than
// discovered when the image is used.
var ErrNoSecurity = errors.New("wim: Options.Security is required (an image with no security table is rejected by Windows)")

// ErrChunkSize reports a chunk size the codec cannot code against.
//
// It is refused because the failure is otherwise silent and looks like success: the LZX window
// is one chunk, so a chunk larger than the window is declined by the codec and stored raw, and
// a resource of those can still come out a few bytes shorter than its input — earning the
// compressed flag while holding almost entirely uncompressed data. The image is well formed,
// reads back correctly, and is neither compressed nor readable by anything expecting the
// standard chunk size.
var ErrChunkSize = errors.New("wim: ChunkSize must be a power of two no larger than the LZX window")

// Compression selects the codec a WIM's file resources are stored with.
type Compression int

const (
	// CompressLZX stores resources as LZX-compressed chunks. It is the codec WIMs of this
	// version carry, and the only one this package implements; XPRESS is not written.
	CompressLZX Compression = iota
	// CompressNone stores every resource uncompressed. Useful for tests and for inspecting
	// a capture; a whole PE image stored this way is legal but large.
	CompressNone
)

// SecurityFunc returns the self-relative NT security descriptor to record for the captured
// file at path — slash-separated and relative to the capture root, with "." for the root
// itself. It must return one for every file: a dentry left without a security ID carries -1,
// which is the wimlib-on-Linux shape Windows rejects at mount, and a capture holding even a
// few of them verifies clean and fails at boot. Returning nil is therefore an error, not a
// way to skip a file.
//
// The writer deduplicates descriptors by content, so returning the same bytes for every file
// costs exactly one security-table entry.
type SecurityFunc func(path string, d fs.DirEntry) []byte

// UniformSecurity returns a SecurityFunc that assigns sd to every captured file — the shape a
// PE build wants, where one system descriptor covers the whole image.
func UniformSecurity(sd []byte) SecurityFunc {
	return func(string, fs.DirEntry) []byte { return sd }
}

// Options configure a Writer. Security is required; the rest default to LZX, 32768-byte chunks,
// and timestamps taken from the captured tree.
type Options struct {
	// Compression is the codec for file resources. Defaults to CompressLZX.
	Compression Compression

	// ChunkSize is the uncompressed size of one chunk of a compressed resource. Defaults to
	// DefaultChunkSize, which is what real images carry; setting anything else is for tests.
	// It must be a power of two no larger than the LZX window, which is what the codec can
	// code a chunk against (see ErrChunkSize).
	ChunkSize int

	// Security assigns a security descriptor to each captured file. It has no default: see
	// ErrNoSecurity.
	Security SecurityFunc

	// Timestamp, when non-zero, is recorded as every dentry's creation, access, and write
	// time in place of the source tree's own times. Set it for a byte-reproducible capture
	// of a tree whose timestamps vary.
	Timestamp time.Time

	// GUID is the WIM's identifier. A zero GUID is derived from the image's own content,
	// keeping a capture reproducible; wimlib randomises it.
	GUID [16]byte

	// Concurrency bounds the chunk compressions in flight. Zero means one per CPU. Chunks are
	// independent by construction — each resets the window, the trees and the recent offsets —
	// so this is the cheapest speed available, and the output is byte-identical whatever the
	// value: results are placed by chunk index, never in completion order.
	Concurrency int
}

// concurrency is how many chunks to compress at once.
func (o Options) concurrency() int {
	if o.Concurrency > 0 {
		return o.Concurrency
	}
	return runtime.GOMAXPROCS(0)
}

func (o Options) chunk() int {
	if o.ChunkSize == 0 {
		return DefaultChunkSize
	}
	return o.ChunkSize
}

// blobEntry is one stored resource's blob-table entry.
type blobEntry struct {
	res  resHdr
	hash [20]byte
	refs uint32
}

// imageEntry is one written image: its metadata resource, and what its XML entry needs.
type imageEntry struct {
	info       ImageInfo
	res        resHdr
	hash       [20]byte
	dirCount   int
	fileCount  int
	totalBytes int64
	created    uint64
	modified   uint64
}

// Writer builds a WIM into dst. Resources are written as they are captured and the header,
// blob table, and XML are finalised by Close, so dst must be seekable — the header carries
// offsets that are only known once every image has been written.
//
// A Writer holds one blob table across every image it writes, which is the whole reason it is
// a type rather than a function: identical files, within an image or across images, are stored
// once and referenced by SHA-1.
type Writer struct {
	dst  io.WriteSeeker
	opts Options
	pos  int64

	started bool
	closed  bool
	// err is sticky: once a write fails the WIM on disk is incomplete and its recorded
	// offsets no longer describe it, so every later call reports the same failure rather
	// than building on the wreckage.
	err error

	blobs  []blobEntry
	byHash map[[20]byte]int
	images []imageEntry

	// comps holds one Compressor per worker, grown as needed and reused across resources: a
	// Compressor carries a match-finder and coding scratch worth several hundred kilobytes,
	// and it is not safe to share, so workers never touch the same one.
	comps []*lzx.Compressor
}

// NewWriter returns a Writer that builds a WIM into dst. Nothing is written until the first
// AddImage; Close must be called to produce a valid file.
func NewWriter(dst io.WriteSeeker, opts Options) *Writer {
	return &Writer{dst: dst, opts: opts, byHash: make(map[[20]byte]int)}
}

// AddImage captures the tree rooted at src as a new image described by info, appending its file
// resources and metadata resource to the WIM. Files are deduplicated against everything already
// written. Symlinks in src are an error rather than being followed, so a capture cannot silently
// duplicate a file or escape its root.
func (w *Writer) AddImage(ctx context.Context, src fs.FS, info ImageInfo) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return errors.New("wim: Writer is closed")
	}
	if w.opts.Security == nil {
		return ErrNoSecurity
	}
	if n := w.opts.chunk(); n <= 0 || n > lzx.WindowSize || n&(n-1) != 0 {
		return fmt.Errorf("%w: got %d, want a power of two up to %d", ErrChunkSize, n, lzx.WindowSize)
	}
	if info.Boot {
		for _, im := range w.images {
			if im.info.Boot {
				return errors.New("wim: more than one image marked bootable")
			}
		}
	}

	c, err := capture(ctx, src, w.opts)
	if err != nil {
		return err // nothing written yet, so the Writer is still usable
	}
	// From here on the Writer is mutating the output, and a failure leaves it inconsistent:
	// bytes are on disk that no blob-table entry describes, and the blobs recorded so far
	// would be double-counted by a retry. Every failure past this point is sticky.
	return w.fail(w.addImage(ctx, src, info, c))
}

// fail records err as the Writer's sticky failure and returns it.
func (w *Writer) fail(err error) error {
	if err != nil && w.err == nil {
		w.err = err
	}
	return err
}

// addImage writes a captured tree's resources and metadata. Its failures are sticky; see
// AddImage.
func (w *Writer) addImage(ctx context.Context, src fs.FS, info ImageInfo, c *captured) error {
	if err := w.start(); err != nil {
		return err
	}

	for i := range c.blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := &c.blobs[i]
		// A stream already stored — by an earlier image, or by an earlier file in this one —
		// is referenced again rather than written twice.
		if j, ok := w.byHash[b.hash]; ok {
			w.blobs[j].refs += b.refs
			continue
		}
		data, err := fs.ReadFile(src, b.path)
		if err != nil {
			return err
		}
		// The hash recorded during the capture pass is written into the blob table and into
		// every dentry referencing this stream, so it has to describe the bytes actually
		// stored. Re-hashing catches a file edited between the two passes — a length check
		// alone would miss an in-place edit and produce an image that verifies as
		// well-formed and fails only when something validates the stream.
		if sha1.Sum(data) != b.hash {
			return fmt.Errorf("wim: %s changed under the capture (hashed %x, now %x)",
				b.path, b.hash, sha1.Sum(data))
		}
		res, err := w.writeResource(data, 0)
		if err != nil {
			return fmt.Errorf("wim: write %s: %w", b.path, err)
		}
		w.byHash[b.hash] = len(w.blobs)
		w.blobs = append(w.blobs, blobEntry{res: res, hash: b.hash, refs: b.refs})
	}

	meta, err := encodeMetadata(c)
	if err != nil {
		return err
	}
	// The metadata resource is compressed with everything else, and must be: a loader takes
	// its compression from the WIM header rather than from this resource's own flag, so an
	// image declaring a codec while storing raw metadata parses as garbage. writeResource
	// enforces that; it is not left to whether compressing happened to pay.
	res, err := w.writeResource(meta, flagMetadata)
	if err != nil {
		return fmt.Errorf("wim: write metadata: %w", err)
	}
	w.images = append(w.images, imageEntry{
		info:       info,
		res:        res,
		hash:       sha1.Sum(meta),
		dirCount:   c.dirCount,
		fileCount:  c.fileCount,
		totalBytes: c.totalBytes,
		created:    c.created,
		modified:   c.modified,
	})
	return nil
}

// Close writes the blob table and the XML data, rewrites the header now that their offsets are
// known, and releases the Writer. It does not close dst.
func (w *Writer) Close() error {
	if w.err != nil {
		return w.err // an earlier failure left the output incomplete; do not seal it
	}
	if w.closed {
		return errors.New("wim: Writer already closed")
	}
	if len(w.images) == 0 {
		return errors.New("wim: no images added")
	}
	w.closed = true

	// The blob table lists every stored resource: the file streams and each image's metadata.
	// Entries are ordered by in-WIM offset, which is what Microsoft's imagex writes; wimlib
	// leaves them unordered and both are read, so ordering is a choice rather than a
	// requirement, and offset order keeps a sequential reader's scan monotonic in the file.
	entries := make([]blobEntry, 0, len(w.blobs)+len(w.images))
	entries = append(entries, w.blobs...)
	for _, im := range w.images {
		entries = append(entries, blobEntry{res: im.res, hash: im.hash, refs: 1})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].res.offset < entries[j].res.offset })

	tblBytes := encodeBlobTable(entries)
	tbl, err := w.writeStored(bytes.NewReader(tblBytes), int64(len(tblBytes)), 0)
	if err != nil {
		return w.fail(fmt.Errorf("wim: write blob table: %w", err))
	}

	// The WIM's own <TOTALBYTES> is everything written before the XML, which is exactly the
	// offset the XML resource lands at.
	xmlBytes := buildXML(w.images, w.pos)
	xmlRes, err := w.writeStored(bytes.NewReader(xmlBytes), int64(len(xmlBytes)), 0)
	if err != nil {
		return w.fail(fmt.Errorf("wim: write xml: %w", err))
	}

	if _, err := w.dst.Seek(0, io.SeekStart); err != nil {
		return w.fail(err)
	}
	if _, err := w.dst.Write(w.header(tbl, xmlRes)); err != nil {
		return w.fail(err)
	}
	return nil
}

// start reserves the header, which is written for real by Close once it holds the offsets the
// header has to carry. It seeks to the start of dst first: every resource offset a WIM records
// is absolute, and Close rewrites the header at absolute 0, so a WIM must begin at offset 0 of
// whatever it is written to.
func (w *Writer) start() error {
	if w.started {
		return nil
	}
	if _, err := w.dst.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := w.dst.Write(make([]byte, headerSize)); err != nil {
		return err
	}
	w.pos = headerSize
	w.started = true
	return nil
}

// writeStored stores size bytes from r verbatim at the current position and returns its
// resource header. The blob table and the XML are written this way whatever the WIM's codec is:
// a reader locates them from the header and reads them as they lie, so they are never chunked.
func (w *Writer) writeStored(r io.Reader, size int64, flags byte) (resHdr, error) {
	off := w.pos
	n, err := io.Copy(w.dst, r)
	w.pos += n
	if err != nil {
		return resHdr{}, err
	}
	if n != size {
		return resHdr{}, fmt.Errorf("wim: resource is %d bytes, expected %d (source changed under the capture?)", n, size)
	}
	return resHdr{size: uint64(n), flags: flags, offset: uint64(off), uncompressed: uint64(n)}, nil
}

// writeResource stores a file stream or an image's metadata as a resource, compressing it when
// the WIM declares a codec. A resource that does not come out smaller is stored verbatim
// instead, which is why a compressed WIM still holds plain resources.
func (w *Writer) writeResource(data []byte, flags byte) (resHdr, error) {
	body := data
	if w.opts.Compression == CompressLZX && len(data) > 0 {
		enc, smaller := w.compressResource(data)
		// A resource that does not come out smaller is stored verbatim — except an image's
		// metadata, which is compressed whether or not it pays. A loader takes the
		// metadata's compression from the WIM header, not from this flag, so storing it raw
		// under a header that declares a codec yields an image that verifies clean and does
		// not boot. A few wasted bytes is the right trade against that.
		if smaller || flags&flagMetadata != 0 {
			body = enc
			flags |= flagCompressed
		}
	}
	off := w.pos
	n, err := w.dst.Write(body)
	w.pos += int64(n)
	if err != nil {
		return resHdr{}, err
	}
	return resHdr{
		size:         uint64(len(body)),
		flags:        flags,
		offset:       uint64(off),
		uncompressed: uint64(len(data)),
	}, nil
}

// compressResource encodes data as a chunked compressed resource: a table of chunk offsets
// followed by the chunks. The table holds one entry per chunk after the first — the first
// always begins where the table ends — and each offset is relative to the table's end.
//
// A chunk the codec declines is stored raw, which a reader detects by its stored size equalling
// its uncompressed size; that is the format's incompressible-data path, not an error.
//
// The encoding is returned whether or not it is smaller, along with whether it is: the caller
// decides, because one resource — an image's metadata — must be compressed even when that
// costs bytes.
func (w *Writer) compressResource(data []byte) (body []byte, smaller bool) {
	chunk := w.opts.chunk()
	nchunks := (len(data) + chunk - 1) / chunk
	entry := 4
	if len(data) > 0xffffffff {
		entry = 8
	}

	table := make([]byte, (nchunks-1)*entry)
	encoded := w.encodeChunks(data, chunk, nchunks)

	chunks := make([]byte, 0, len(data))
	for i, e := range encoded {
		if i > 0 {
			// Where this chunk begins, measured from the end of the table.
			off := uint64(len(chunks))
			if entry == 4 {
				binary.LittleEndian.PutUint32(table[(i-1)*4:], uint32(off))
			} else {
				binary.LittleEndian.PutUint64(table[(i-1)*8:], off)
			}
		}
		chunks = append(chunks, e...)
	}

	body = append(table, chunks...)
	return body, len(body) < len(data)
}

// encodeChunks returns each chunk in the form it will be stored, compressed where that is
// smaller and the raw bytes where it is not.
//
// Chunks are compressed in parallel — they share no coding state, which is what makes a chunk
// independently decodable in the first place — but each result is placed at its own index, so
// the assembled resource does not depend on the order they finish in.
func (w *Writer) encodeChunks(data []byte, chunk, nchunks int) [][]byte {
	encoded := make([][]byte, nchunks)

	workers := w.opts.concurrency()
	if workers > nchunks {
		workers = nchunks
	}
	// Grown before the workers start: they index this slice concurrently and must not append.
	for len(w.comps) < workers {
		w.comps = append(w.comps, lzx.NewCompressor())
	}

	if workers <= 1 {
		scratch := make([]byte, chunk)
		for i := range encoded {
			encoded[i] = encodeChunk(w.comps[0], scratch, data, chunk, i)
		}
		return encoded
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	for k := 0; k < workers; k++ {
		wg.Add(1)
		go func(c *lzx.Compressor) {
			defer wg.Done()
			scratch := make([]byte, chunk)
			for {
				i := int(next.Add(1)) - 1
				if i >= nchunks {
					return
				}
				encoded[i] = encodeChunk(c, scratch, data, chunk, i)
			}
		}(w.comps[k])
	}
	wg.Wait()
	return encoded
}

// encodeChunk returns chunk i of data as it will be stored. A chunk the codec declines is
// returned as the input bytes themselves — data is not modified while this runs, so the raw
// case needs no copy; only a compressed chunk is copied out of the reusable scratch.
func encodeChunk(c *lzx.Compressor, scratch, data []byte, chunk, i int) []byte {
	end := (i + 1) * chunk
	if end > len(data) {
		end = len(data)
	}
	src := data[i*chunk : end]
	n, ok := c.Compress(scratch, src)
	if !ok {
		return src
	}
	return append([]byte(nil), scratch[:n]...)
}

// header renders the 208-byte WIM header.
func (w *Writer) header(tbl, xmlRes resHdr) []byte {
	b := make([]byte, headerSize)
	copy(b, wimMagic)
	binary.LittleEndian.PutUint32(b[hdrSizeOff:], headerSize)
	binary.LittleEndian.PutUint32(b[hdrVersionOff:], wimVersion)

	// RP_FIX records that reparse-point fixups were applied. A capture holds no reparse
	// points, so it is vacuously true — and it is what both wimlib and imagex set, so the
	// header matches the images known to boot.
	flags := uint32(hdrFlagRPFix)
	chunk := uint32(0)
	if w.opts.Compression == CompressLZX {
		flags |= hdrFlagCompressed | hdrFlagCompressLZX
		chunk = uint32(w.opts.chunk())
	}
	binary.LittleEndian.PutUint32(b[hdrFlagsOff:], flags)
	binary.LittleEndian.PutUint32(b[hdrChunkSizeOff:], chunk)

	guid := w.guid()
	copy(b[hdrGUIDOff:hdrGUIDOff+16], guid[:])
	binary.LittleEndian.PutUint16(b[hdrPartNumberOff:], 1)
	binary.LittleEndian.PutUint16(b[hdrTotalPartsOff:], 1)
	binary.LittleEndian.PutUint32(b[hdrImageCountOff:], uint32(len(w.images)))

	writeResHdr(b, hdrLookupTableOff, tbl.size, tbl.flags, tbl.offset, tbl.uncompressed)
	writeResHdr(b, hdrXMLOff, xmlRes.size, xmlRes.flags, xmlRes.offset, xmlRes.uncompressed)

	// A bootable image is named twice: by index, and by a copy of its metadata resource
	// header, which is what a loader reads to find the image without walking the blob table.
	for i, im := range w.images {
		if im.info.Boot {
			writeResHdr(b, hdrBootMetaOff, im.res.size, im.res.flags, im.res.offset, im.res.uncompressed)
			binary.LittleEndian.PutUint32(b[hdrBootIndexOff:], uint32(i+1))
			break
		}
	}
	// The integrity table at hdrIntegrityOff stays zero: no integrity table is written.
	return b
}

// guid returns the WIM's identifier: the caller's, or one derived from the content so that
// capturing the same tree twice produces the same file. It is not an RFC 4122 UUID and does not
// claim to be — a WIM's GUID only has to distinguish one image from another.
func (w *Writer) guid() [16]byte {
	if w.opts.GUID != ([16]byte{}) {
		return w.opts.GUID
	}
	h := sha1.New()
	for _, b := range w.blobs {
		h.Write(b.hash[:])
	}
	for _, im := range w.images {
		h.Write(im.hash[:])
	}
	var g [16]byte
	copy(g[:], h.Sum(nil))
	return g
}

// Capture writes src to dst as a single-image WIM. It is NewWriter + AddImage + Close.
func Capture(ctx context.Context, dst io.WriteSeeker, src fs.FS, info ImageInfo, opts Options) error {
	w := NewWriter(dst, opts)
	if err := w.AddImage(ctx, src, info); err != nil {
		return err
	}
	return w.Close()
}

// CaptureDir captures the directory dir into a new WIM file at out, replacing it if it exists.
// A failed capture leaves no partial file behind.
func CaptureDir(ctx context.Context, dir, out string, info ImageInfo, opts Options) error {
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	if err := Capture(ctx, f, os.DirFS(dir), info, opts); err != nil {
		f.Close()
		os.Remove(out)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(out)
		return err
	}
	return nil
}
