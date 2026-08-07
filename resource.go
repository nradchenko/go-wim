// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/nradchenko/go-wim/lzx"
)

// maxResourceSize caps a resource's declared uncompressed size. A WIM this package reads may be
// one it did not write, and every chunk-table computation below derives a count and an
// allocation from that field: the cap keeps a malformed size from driving a huge allocation or
// overflowing the arithmetic. It is far above any real WIM member and well clear of the 32-bit
// overflow points.
const maxResourceSize = 64 << 30

// A resource's storage is decided by its own flags, never by the WIM header. The header says
// which codec and what chunk size; whether a given resource used them is the flagCompressed bit
// on that resource.
//
// This is worth stating because the writer's rule runs the other way and is easy to carry across.
// Some readers take the metadata resource's compression from the header without consulting that
// resource's flag, which is why an image declaring a codec must compress its metadata: that is a
// constraint on what may be written. Applied to reading it would be a defect — a raw-stored
// metadata resource is legal, other tools produce it, and decoding it as LZX would fail on a WIM
// that reads perfectly well here. The consequence to keep in view is that this reader accepts
// images stricter consumers reject, so a successful read is not a validity check.

// chunkTable holds a compressed resource's chunk boundaries, computed once and shared. offs[k]
// is the absolute WIM offset of chunk k and offs[len-1] is the resource's end, so chunk k
// occupies [offs[k], offs[k+1]).
type chunkTable struct {
	once sync.Once
	offs []uint64
	err  error
}

// chunks returns res's chunk boundaries, reading the table on first use and reusing it after.
// The table is memoized per resource because it is otherwise re-read on every Read: a file read
// in 32 KiB pieces would parse its own table once per piece.
func (rd *Reader) chunks(res resHdr) ([]uint64, error) {
	rd.mu.Lock()
	t := rd.tables[res.offset]
	if t == nil {
		t = &chunkTable{}
		rd.tables[res.offset] = t
	}
	rd.mu.Unlock()

	t.once.Do(func() { t.offs, t.err = rd.readChunkTable(res) })
	return t.offs, t.err
}

// readChunkTable decodes the offset table at the head of a compressed resource.
//
// The table holds one entry per chunk after the first — chunk 0 always begins where the table
// ends — and each entry is that chunk's offset measured from the table's end. Entries are 4
// bytes, or 8 for a resource whose uncompressed size does not fit in 32 bits.
func (rd *Reader) readChunkTable(res resHdr) ([]uint64, error) {
	if err := rd.plausibleSize(res); err != nil {
		return nil, err
	}

	chunk := uint64(rd.chunkSize)
	nchunks := int((res.uncompressed + chunk - 1) / chunk)
	if nchunks == 0 {
		return []uint64{res.offset, res.offset + res.size}, nil
	}

	entry := 4
	if res.uncompressed > 0xffffffff {
		entry = 8
	}
	tblBytes := uint64(nchunks-1) * uint64(entry)
	if tblBytes > res.size {
		return nil, fmt.Errorf("wim: resource at %#x: %d-byte chunk table does not fit in %d stored bytes: %w",
			res.offset, tblBytes, res.size, ErrCorrupt)
	}

	tbl := make([]byte, tblBytes)
	if _, err := rd.r.ReadAt(tbl, int64(res.offset)); err != nil {
		return nil, fmt.Errorf("wim: read chunk table at %#x: %w", res.offset, err)
	}

	offs := make([]uint64, nchunks+1)
	base := res.offset + tblBytes
	offs[0] = base
	for i := 1; i < nchunks; i++ {
		var v uint64
		if entry == 4 {
			v = uint64(binary.LittleEndian.Uint32(tbl[(i-1)*4:]))
		} else {
			v = binary.LittleEndian.Uint64(tbl[(i-1)*8:])
		}
		offs[i] = base + v
	}
	offs[nchunks] = res.offset + res.size

	// Every chunk must lie inside the resource, in order, and hold no more than one chunk's
	// worth of bytes — a compressed chunk that does not pay is stored raw at exactly its
	// uncompressed size, so nothing legitimately exceeds it. This is what turns a corrupted
	// offset into a rejection instead of a decode of whatever the offset happens to address.
	for i := 0; i < nchunks; i++ {
		if offs[i] < base || offs[i] > offs[i+1] || offs[i+1] > res.offset+res.size {
			return nil, fmt.Errorf("wim: resource at %#x: chunk %d spans [%#x,%#x) outside the resource: %w",
				res.offset, i, offs[i], offs[i+1], ErrCorrupt)
		}
		if offs[i+1]-offs[i] > chunk {
			return nil, fmt.Errorf("wim: resource at %#x: chunk %d stores %d bytes, over the %d-byte chunk size: %w",
				res.offset, i, offs[i+1]-offs[i], chunk, ErrCorrupt)
		}
	}
	return offs, nil
}

// chunkCache holds one decoded chunk, so a run of reads that all land in it decodes it once.
//
// This is worth its complexity because of how callers actually read. A read is served by decoding
// every chunk it touches, so a caller asking for less than a chunk at a time — io.Copy's buffer
// is 32 KiB, and to an io.Discard-like destination 8 KiB — decodes the same 32 KiB chunk for each
// piece of it. Measured on a 200 KB file read through io.Copy: 7.3x the time and 6x the
// allocation of the same file read in one call, purely in re-decoding.
//
// The cache belongs to a file handle rather than to the Reader: it is bounded by construction
// (one chunk per open file), and it is what makes sequential reading — the common case — cost one
// decode per chunk. The mutex is what lets ReadAt stay usable concurrently on one handle, as
// io.ReaderAt specifies; those calls serialise rather than race.
//
// A cache holds chunks of one resource and carries no resource identity, because a handle is
// bound to one dentry and so to one resource for its whole life. Anything sharing a cache across
// resources would serve one resource's chunk for another's, so don't.
type chunkCache struct {
	mu   sync.Mutex
	idx  int    // index of the cached chunk, -1 when there is none
	data []byte // the decoded chunk
	raw  []byte // scratch for reading the stored chunk
}

func newChunkCache() *chunkCache { return &chunkCache{idx: -1} }

// readResourceAt fills p from res starting at the uncompressed offset off, decoding only the
// chunks that offset range touches. cache may be nil, in which case nothing is retained between
// calls; a caller reading a resource once has nothing to gain from it.
//
// It returns io.EOF exactly as io.ReaderAt specifies: a short read at the end of the resource
// comes with io.EOF, and an off at or past the end returns it immediately.
func (rd *Reader) readResourceAt(res resHdr, p []byte, off int64, cache *chunkCache) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("wim: negative offset %d", off)
	}
	if err := rd.plausibleSize(res); err != nil {
		return 0, err
	}
	if uint64(off) >= res.uncompressed {
		return 0, io.EOF
	}
	// A read running past the end is served short and reports EOF, rather than being refused.
	short := false
	if uint64(off)+uint64(len(p)) > res.uncompressed {
		p = p[:res.uncompressed-uint64(off)]
		short = true
	}
	if len(p) == 0 {
		return 0, nil
	}

	var n int
	var err error
	if res.flags&flagCompressed == 0 {
		n, err = rd.readStoredAt(res, p, off)
	} else {
		n, err = rd.readChunkedAt(res, p, off, cache)
	}
	if err != nil {
		return n, err
	}
	if short {
		return n, io.EOF
	}
	return n, nil
}

// readStoredAt serves a resource held verbatim. Its stored and uncompressed sizes must agree —
// they describe the same bytes — and a resource where they do not is malformed rather than
// something to read as far as it goes.
func (rd *Reader) readStoredAt(res resHdr, p []byte, off int64) (int, error) {
	if res.size != res.uncompressed {
		return 0, fmt.Errorf("wim: uncompressed resource at %#x stores %d bytes for %d uncompressed: %w",
			res.offset, res.size, res.uncompressed, ErrCorrupt)
	}
	n, err := rd.r.ReadAt(p, int64(res.offset)+off)
	// io.ReaderAt permits EOF alongside a full read, so that one is not a failure. Any other
	// error is: suppressing it because the byte count happened to come out right would turn a
	// failing backing into a silent success.
	if errors.Is(err, io.EOF) && n == len(p) {
		err = nil
	}
	return n, err
}

// readChunkedAt serves a chunk-compressed resource, decoding each chunk the range touches and
// copying out the wanted part of it. When cache is non-nil, a chunk it already holds is used as
// it stands, and the last chunk decoded is left there for the next call.
func (rd *Reader) readChunkedAt(res resHdr, p []byte, off int64, cache *chunkCache) (int, error) {
	offs, err := rd.chunks(res)
	if err != nil {
		return 0, err
	}
	chunk := int64(rd.chunkSize)
	nchunks := len(offs) - 1

	// Scratch for this call, or the cache's own buffers when there is one. Either way both are
	// reused across the chunks a single read spans.
	var cbuf, dbuf []byte
	if cache != nil {
		cache.mu.Lock()
		defer cache.mu.Unlock()
		if cache.raw == nil {
			cache.raw, cache.data = make([]byte, chunk), make([]byte, chunk)
		}
		cbuf, dbuf = cache.raw, cache.data
	} else {
		cbuf, dbuf = make([]byte, chunk), make([]byte, chunk)
	}

	produced := 0
	for k := int(off / chunk); k < nchunks && produced < len(p); k++ {
		csize := int(offs[k+1] - offs[k])
		usize := int(chunk)
		if k == nchunks-1 {
			usize = int(res.uncompressed - uint64(nchunks-1)*uint64(chunk))
		}
		if usize <= 0 || usize > int(chunk) || csize > int(chunk) {
			return produced, fmt.Errorf("wim: resource at %#x: chunk %d is %d stored / %d uncompressed bytes: %w",
				res.offset, k, csize, usize, ErrCorrupt)
		}

		var data []byte
		switch {
		case cache != nil && cache.idx == k:
			data = dbuf[:usize] // already decoded by an earlier read
		default:
			if _, err := rd.r.ReadAt(cbuf[:csize], int64(offs[k])); err != nil {
				return produced, fmt.Errorf("wim: read chunk %d at %#x: %w", k, offs[k], err)
			}
			if csize == usize {
				// The format's incompressible-data path: the chunk is stored raw, which the
				// writer emits whenever a chunk does not come out smaller. It is not cached —
				// the cache holds decoded chunks, and this one shares the read scratch.
				// dbuf is untouched here, so a chunk it already holds stays valid.
				data = cbuf[:csize]
				break
			}
			if err := lzx.Decompress(dbuf[:usize], cbuf[:csize]); err != nil {
				if cache != nil {
					cache.idx = -1 // dbuf now holds a partial decode
				}
				return produced, fmt.Errorf("wim: decode chunk %d at %#x: %w", k, offs[k], err)
			}
			data = dbuf[:usize]
			if cache != nil {
				cache.idx = k
			}
		}

		base := int64(k) * chunk
		from := int64(0)
		if off > base {
			from = off - base
		}
		produced += copy(p[produced:], data[from:])
	}
	if produced < len(p) {
		return produced, fmt.Errorf("wim: resource at %#x: %d of %d bytes available from offset %d: %w",
			res.offset, produced, len(p), off, ErrCorrupt)
	}
	return produced, nil
}

// plausibleSize reports whether a resource's declared uncompressed size could be produced by the
// bytes it actually stores, so a size read from the image cannot drive an allocation unrelated to
// it. maxResourceSize alone is far too loose for that: a few-hundred-byte WIM may declare 64 GiB
// and be believed, and readResource would try to allocate it while Open is still parsing the XML.
//
// The bound comes from the format rather than from a guess. A stored resource holds exactly its
// uncompressed bytes. A compressed one carries a chunk table of one entry — at least 4 bytes —
// per chunk after the first, and that table has to fit in the stored size, which caps how many
// chunks (and so how many uncompressed bytes) the resource can possibly describe.
func (rd *Reader) plausibleSize(res resHdr) error {
	switch {
	case res.uncompressed > maxResourceSize:
		return fmt.Errorf("wim: resource at %#x declares %d uncompressed bytes: %w",
			res.offset, res.uncompressed, ErrCorrupt)
	case res.flags&flagCompressed == 0:
		if res.size != res.uncompressed {
			return fmt.Errorf("wim: uncompressed resource at %#x stores %d bytes for %d uncompressed: %w",
				res.offset, res.size, res.uncompressed, ErrCorrupt)
		}
	default:
		if rd.chunkSize == 0 {
			return fmt.Errorf("wim: resource at %#x is compressed but the WIM declares no codec: %w",
				res.offset, ErrCorrupt)
		}
		if maxChunks := res.size/4 + 1; res.uncompressed > maxChunks*uint64(rd.chunkSize) {
			return fmt.Errorf("wim: resource at %#x declares %d uncompressed bytes, more than %d stored bytes can describe: %w",
				res.offset, res.uncompressed, res.size, ErrCorrupt)
		}
	}
	return nil
}

// readResource returns a resource's whole uncompressed contents. It is used for the parts of a
// WIM that are consumed as a unit — the blob table, the XML, an image's metadata — never for
// file content, which is read through the fs.FS a chunk at a time.
func (rd *Reader) readResource(res resHdr) ([]byte, error) {
	if err := rd.plausibleSize(res); err != nil {
		return nil, err
	}
	if res.offset > uint64(rd.size) || res.size > uint64(rd.size)-res.offset {
		return nil, fmt.Errorf("wim: resource %#x+%#x lies outside the %d-byte WIM: %w",
			res.offset, res.size, rd.size, ErrCorrupt)
	}
	buf := make([]byte, res.uncompressed)
	if len(buf) == 0 {
		return buf, nil
	}
	if _, err := rd.readResourceAt(res, buf, 0, nil); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}
