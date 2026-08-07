// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sync"
	"unicode/utf16"

	"github.com/nradchenko/go-wim/lzx"
)

// The three error kinds a reader distinguishes. They are kept apart because they mean different
// things to a caller: the input is not a WIM at all, it is a WIM this package declines to read,
// or it is a WIM whose contents contradict themselves. Collapsing them would make "we cannot
// read this" indistinguishable from "this file is damaged".
var (
	// ErrNotWIM reports input that is not a WIM: too short, or without the signature.
	ErrNotWIM = errors.New("wim: not a WIM file")
	// ErrUnsupported reports a well-formed WIM in a form this package does not read — another
	// codec, a solid or split image — as opposed to a damaged one.
	ErrUnsupported = errors.New("wim: unsupported WIM")
	// ErrCorrupt reports a WIM whose structure contradicts itself. Every bound this package
	// checks reports through it, so a caller can tell a damaged image from an unreadable one.
	ErrCorrupt = errors.New("wim: corrupt WIM")
)

// Header flag bits beyond those the writer sets. A compressed WIM names exactly one codec; the
// two this package does not implement are recognised so they can be refused by name rather than
// read as LZX and decoded into nonsense.
const (
	hdrFlagCompressXPRESS = 0x00020000
	hdrFlagCompressLZMS   = 0x00080000
)

// Resource flags beyond metadata and compressed. A solid resource packs several streams into one
// LZMS-compressed block and a spanned one continues in another part of a split WIM; neither is
// read here, and both are refused rather than misread as an ordinary resource.
const (
	flagSpanned = 0x08
	flagSolid   = 0x10
)

// Reader reads a WIM: its images, and through them their file trees.
//
// A Reader is safe for concurrent use, and so must be the io.ReaderAt it was opened over — a
// tree walk fans out across files, and each read seeks independently.
type Reader struct {
	r    io.ReaderAt
	size int64

	chunkSize  int // 0 for an uncompressed WIM
	imageCount int
	bootIndex  int
	bootMeta   resHdr
	blobTable  resHdr
	xmlRes     resHdr

	byHash map[[20]byte]resHdr // file streams, by SHA-1
	metas  []resHdr            // image metadata resources, in blob-table order
	infos  []ImageInfo         // from the XML, indexed as the images are

	mu     sync.Mutex
	tables map[uint64]*chunkTable // per-resource chunk tables, memoized
	images map[int]*Image         // parsed image trees, memoized
}

// Open reads the WIM held in r, whose length is size.
//
// r must support random access and be safe for concurrent use: the format is offset-indexed —
// the blob table, the metadata resource and every chunk of every file are found by offset — so
// reading one file never costs a scan of the image, and several may be read at once.
func Open(r io.ReaderAt, size int64) (*Reader, error) {
	rd := &Reader{
		r:      r,
		size:   size,
		byHash: make(map[[20]byte]resHdr),
		tables: make(map[uint64]*chunkTable),
		images: make(map[int]*Image),
	}
	if err := rd.readHeader(); err != nil {
		return nil, err
	}
	if err := rd.readBlobTable(); err != nil {
		return nil, err
	}
	if err := rd.readXML(); err != nil {
		return nil, err
	}
	return rd, nil
}

// OpenBytes reads a WIM already held in memory. It is the convenience form of Open for a WIM
// pulled out of an archive or an image, where the bytes are in hand already.
func OpenBytes(b []byte) (*Reader, error) {
	return Open(bytes.NewReader(b), int64(len(b)))
}

// readHeader parses and validates the 208-byte header. Everything it rejects, it rejects here:
// past this point the reader trusts the codec, the chunk size and the image count.
func (rd *Reader) readHeader() error {
	if rd.size < headerSize {
		return fmt.Errorf("wim: %d bytes is shorter than a WIM header: %w", rd.size, ErrNotWIM)
	}
	b := make([]byte, headerSize)
	if _, err := rd.r.ReadAt(b, 0); err != nil {
		return fmt.Errorf("wim: read header: %w", err)
	}
	if string(b[0:8]) != wimMagic {
		return fmt.Errorf("wim: bad signature %q: %w", b[0:8], ErrNotWIM)
	}
	if n := binary.LittleEndian.Uint32(b[hdrSizeOff:]); n != headerSize {
		return fmt.Errorf("wim: header declares %d bytes, not %d: %w", n, headerSize, ErrUnsupported)
	}
	if v := binary.LittleEndian.Uint32(b[hdrVersionOff:]); v != wimVersion {
		return fmt.Errorf("wim: version %#x, not %#x: %w", v, wimVersion, ErrUnsupported)
	}
	// A split WIM's resources continue in other parts, which this reader has no way to reach:
	// reading part 1 alone would serve truncated files rather than fail.
	part := binary.LittleEndian.Uint16(b[hdrPartNumberOff:])
	total := binary.LittleEndian.Uint16(b[hdrTotalPartsOff:])
	if part != 1 || total != 1 {
		return fmt.Errorf("wim: split WIM (part %d of %d): %w", part, total, ErrUnsupported)
	}

	flags := binary.LittleEndian.Uint32(b[hdrFlagsOff:])
	chunk := int(binary.LittleEndian.Uint32(b[hdrChunkSizeOff:]))
	if flags&hdrFlagCompressed != 0 {
		switch {
		case flags&hdrFlagCompressXPRESS != 0:
			return fmt.Errorf("wim: XPRESS compression: %w", ErrUnsupported)
		case flags&hdrFlagCompressLZMS != 0:
			return fmt.Errorf("wim: LZMS compression: %w", ErrUnsupported)
		case flags&hdrFlagCompressLZX == 0:
			return fmt.Errorf("wim: compressed with no codec named (flags %#x): %w", flags, ErrCorrupt)
		}
		if chunk == 0 {
			chunk = DefaultChunkSize
		}
		// The same bound the writer refuses on the way out, and for the same reason: one chunk
		// is coded against one LZX window, so a larger chunk cannot be decoded at all, and a
		// non-power-of-two is the silently-wrong case ErrChunkSize documents.
		//
		// The chunk <= 0 term is not redundant. int is 32 bits on a 32-bit build, where a header
		// chunk size of 0x80000000 reads back negative: it passes both other terms, and the
		// make([]byte, chunk) that follows panics instead of reporting a bad image.
		if chunk <= 0 || chunk > lzx.WindowSize || chunk&(chunk-1) != 0 {
			return fmt.Errorf("wim: %d-byte chunks: %w", chunk, ErrUnsupported)
		}
		rd.chunkSize = chunk
	}

	rd.imageCount = int(binary.LittleEndian.Uint32(b[hdrImageCountOff:]))
	rd.bootIndex = int(binary.LittleEndian.Uint32(b[hdrBootIndexOff:]))
	rd.bootMeta = readResHdr(b, hdrBootMetaOff)
	rd.blobTable = readResHdr(b, hdrLookupTableOff)
	rd.xmlRes = readResHdr(b, hdrXMLOff)
	return nil
}

// readBlobTable indexes every stored resource: file streams by SHA-1, and each image's metadata
// resource in the order the table lists them, which is the order images are numbered.
func (rd *Reader) readBlobTable() error {
	h := rd.blobTable
	// The table is read as a flat array of fixed-size entries, so it has to lie there as one.
	// wimlib and imagex both write it uncompressed; a compressed one is refused rather than
	// misread as entries.
	if h.flags&flagCompressed != 0 {
		return fmt.Errorf("wim: compressed blob table: %w", ErrUnsupported)
	}
	if h.offset > uint64(rd.size) || h.size > uint64(rd.size)-h.offset {
		return fmt.Errorf("wim: blob table %#x+%#x lies outside the %d-byte WIM: %w",
			h.offset, h.size, rd.size, ErrCorrupt)
	}
	// The table is an array of fixed-size entries, so a size that is not a whole number of them
	// describes something this is not. Dividing and reading what fits would silently drop the
	// remainder — including, potentially, an image's metadata resource.
	if h.size%blobEntrySize != 0 {
		return fmt.Errorf("wim: blob table is %d bytes, not a multiple of the %d-byte entry: %w",
			h.size, blobEntrySize, ErrCorrupt)
	}
	n := int(h.size / blobEntrySize)
	if n == 0 {
		return fmt.Errorf("wim: empty blob table: %w", ErrCorrupt)
	}

	tbl := make([]byte, n*blobEntrySize)
	if _, err := rd.r.ReadAt(tbl, int64(h.offset)); err != nil {
		return fmt.Errorf("wim: read blob table: %w", err)
	}

	stale := 0
	for i := 0; i < n; i++ {
		o := i * blobEntrySize
		res := readResHdr(tbl, o)
		switch {
		case res.flags&flagSolid != 0:
			return fmt.Errorf("wim: solid resource at %#x: %w", res.offset, ErrUnsupported)
		case res.flags&flagSpanned != 0:
			return fmt.Errorf("wim: spanned resource at %#x: %w", res.offset, ErrUnsupported)
		}
		if res.offset > uint64(rd.size) || res.size > uint64(rd.size)-res.offset {
			return fmt.Errorf("wim: resource %#x+%#x lies outside the %d-byte WIM: %w",
				res.offset, res.size, rd.size, ErrCorrupt)
		}

		if res.flags&flagMetadata != 0 {
			// A metadata resource with no references is a superseded one: re-capturing or
			// updating an image writes a new metadata resource and leaves the old entry in
			// the table with its reference count cleared, rather than rewriting the table.
			// Microsoft's own images carry these — the Windows AIK's WinPE image declares one
			// image and holds four metadata resources, three of them dropped to zero — so
			// counting every metadata-flagged entry as an image means refusing that image, or
			// worse, reading an earlier version of it as though it were the current one.
			if binary.LittleEndian.Uint32(tbl[o+resHdrSize+2:]) == 0 {
				stale++
				continue
			}
			rd.metas = append(rd.metas, res)
			continue
		}
		var hash [20]byte
		copy(hash[:], tbl[o+blobHashOffset:o+blobEntrySize])
		// An all-zero hash is the empty stream's, not a content key: indexing it would make
		// every empty file resolve to whichever resource carried it.
		if hash != ([20]byte{}) {
			if _, dup := rd.byHash[hash]; !dup {
				rd.byHash[hash] = res
			}
		}
	}

	// Image i is the i-th metadata resource in table order, so a count that disagrees with the
	// header leaves Image(i) indexing an array unrelated to the numbering the caller uses.
	if len(rd.metas) != rd.imageCount {
		return fmt.Errorf("wim: header declares %d image(s), blob table holds %d live metadata resource(s) (%d superseded): %w",
			rd.imageCount, len(rd.metas), stale, ErrCorrupt)
	}
	if rd.bootIndex < 0 || rd.bootIndex > rd.imageCount {
		return fmt.Errorf("wim: boot index %d, with %d image(s): %w", rd.bootIndex, rd.imageCount, ErrCorrupt)
	}
	return nil
}

// readXML parses the XML resource into one ImageInfo per image.
func (rd *Reader) readXML() error {
	raw, err := rd.readResource(rd.xmlRes)
	if err != nil {
		return fmt.Errorf("wim: read XML: %w", err)
	}
	doc, err := decodeXMLText(raw)
	if err != nil {
		return err
	}

	var parsed xmlWIM
	dec := xml.NewDecoder(bytes.NewReader(doc))
	// The text has already been decoded to UTF-8, so any encoding a declaration names has been
	// dealt with; pass the bytes through rather than letting the decoder refuse a label.
	dec.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := dec.Decode(&parsed); err != nil {
		return fmt.Errorf("wim: parse XML: %w", err)
	}

	rd.infos = make([]ImageInfo, rd.imageCount)
	seen := make([]bool, rd.imageCount+1)
	for _, im := range parsed.Images {
		if im.Index < 1 || im.Index > rd.imageCount {
			return fmt.Errorf("wim: XML names image %d, with %d image(s): %w", im.Index, rd.imageCount, ErrCorrupt)
		}
		if seen[im.Index] {
			return fmt.Errorf("wim: XML names image %d twice: %w", im.Index, ErrCorrupt)
		}
		seen[im.Index] = true
		rd.infos[im.Index-1] = im.info()
	}
	// Bootability is the header's to state — it is what a loader reads — so it is applied here
	// rather than taken from the XML, which carries no such element anyway.
	if rd.bootIndex > 0 {
		rd.infos[rd.bootIndex-1].Boot = true
	}
	return nil
}

// Images returns one entry per image, in the WIM's own order: element 0 is image 1.
func (rd *Reader) Images() []ImageInfo {
	out := make([]ImageInfo, len(rd.infos))
	copy(out, rd.infos)
	return out
}

// Image returns image i, numbered as the WIM numbers it: the first image is 1.
func (rd *Reader) Image(i int) (*Image, error) {
	if i < 1 || i > len(rd.metas) {
		return nil, fmt.Errorf("wim: no image %d (the WIM holds %d)", i, len(rd.metas))
	}
	rd.mu.Lock()
	defer rd.mu.Unlock()
	if im := rd.images[i]; im != nil {
		return im, nil
	}
	im := &Image{rd: rd, index: i, info: rd.infos[i-1], meta: rd.metas[i-1]}
	rd.images[i] = im
	return im, nil
}

// Boot returns the image the header marks bootable, or the sole image of a WIM that marks none.
//
// A bootable image is named twice — by index, and by a copy of its metadata resource header that
// a loader reads directly — and the two are cross-checked here. On disagreement the image is
// reported as corrupt rather than one of the two being preferred silently: the header's copy is
// what a loader would boot and the index is what every other tool would show, so the image is
// two different images depending on who reads it. Only Boot fails, so an image in that state can
// still be listed and inspected through Image.
func (rd *Reader) Boot() (*Image, error) {
	if rd.bootIndex == 0 {
		if len(rd.metas) != 1 {
			return nil, fmt.Errorf("wim: no boot image, and %d images to choose from", len(rd.metas))
		}
		return rd.Image(1)
	}
	if rd.bootMeta.offset != 0 && rd.bootMeta.offset != rd.metas[rd.bootIndex-1].offset {
		return nil, fmt.Errorf("wim: boot index %d names the metadata at %#x, the header points at %#x: %w",
			rd.bootIndex, rd.metas[rd.bootIndex-1].offset, rd.bootMeta.offset, ErrCorrupt)
	}
	return rd.Image(rd.bootIndex)
}

// Image is one image inside a WIM: its identity, and its file tree.
//
// The tree is parsed on first use rather than at Open: listing a WIM's images should not cost the
// decode of every image's metadata, and most callers want one image out of the WIM.
type Image struct {
	rd    *Reader
	index int
	info  ImageInfo
	meta  resHdr

	once    sync.Once
	root    *dentry
	loadErr error
}

// Info returns the image's identity as the WIM's XML records it.
func (im *Image) Info() ImageInfo { return im.info }

// Index returns the image's number within the WIM, counting from 1.
func (im *Image) Index() int { return im.index }

// decodeXMLText converts a WIM's XML resource to UTF-8 text. The resource is UTF-16 little
// endian led by a byte order mark, and the mark is part of the stored bytes rather than
// something the reader may assume away.
func decodeXMLText(raw []byte) ([]byte, error) {
	if len(raw) < 2 {
		return nil, fmt.Errorf("wim: XML resource is %d bytes: %w", len(raw), ErrCorrupt)
	}
	if len(raw)%2 != 0 {
		return nil, fmt.Errorf("wim: XML resource is %d bytes, not a whole number of UTF-16 units: %w",
			len(raw), ErrCorrupt)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if u[0] == 0xfeff {
		u = u[1:]
	}
	return []byte(string(utf16.Decode(u))), nil
}

// The XML document a WIM carries, in the shape this reader takes from it: the identity a caller
// chose at capture. The computed elements beside them — DIRCOUNT, FILECOUNT, TOTALBYTES, the
// timestamps — describe the capture rather than the image's identity, and are left unparsed
// until something needs them.
type xmlWIM struct {
	XMLName xml.Name   `xml:"WIM"`
	Images  []xmlImage `xml:"IMAGE"`
}

type xmlImage struct {
	Index       int         `xml:"INDEX,attr"`
	Name        string      `xml:"NAME"`
	Description string      `xml:"DESCRIPTION"`
	Windows     *xmlWindows `xml:"WINDOWS"`
}

type xmlWindows struct {
	Arch       *int        `xml:"ARCH"`
	SystemRoot string      `xml:"SYSTEMROOT"`
	Version    *xmlVersion `xml:"VERSION"`
}

type xmlVersion struct {
	Major   int `xml:"MAJOR"`
	Minor   int `xml:"MINOR"`
	Build   int `xml:"BUILD"`
	SPBuild int `xml:"SPBUILD"`
	SPLevel int `xml:"SPLEVEL"`
}

// info converts a parsed <IMAGE> to the ImageInfo a caller passed at capture. Boot is not set
// here: it is the header's to state.
func (x xmlImage) info() ImageInfo {
	info := ImageInfo{Name: x.Name, Description: x.Description}
	if w := x.Windows; w != nil {
		win := &WindowsInfo{SystemRoot: w.SystemRoot}
		if w.Arch != nil {
			win.Arch = Arch(*w.Arch)
		}
		if v := w.Version; v != nil {
			win.Version = Version{
				Major: v.Major, Minor: v.Minor, Build: v.Build,
				SPBuild: v.SPBuild, SPLevel: v.SPLevel,
			}
		}
		info.Windows = win
	}
	return info
}
