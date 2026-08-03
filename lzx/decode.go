// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package lzx

import "encoding/binary"

// bitReader consumes the LZX bitstream. Bits are taken MSB-first from a 32-bit accumulator
// refilled one 16-bit little-endian word at a time, which is the order the stream is written.
// pos is the offset of the next word to feed; the bits still buffered always come from bytes
// before pos, so an uncompressed block's raw read at pos is correct once the buffered bits are
// dropped.
type bitReader struct {
	in        []byte
	pos       int
	acc       uint32
	nbits     uint8
	unaligned bool // the previous uncompressed block had an odd length
	err       bool
}

// feed pulls one word into the accumulator. Past the end of input it feeds zeros rather than
// failing: a correct stream never depends on those bits, and padding keeps a truncated chunk
// terminating instead of looping.
func (b *bitReader) feed() {
	var w uint16
	switch {
	case b.pos+2 <= len(b.in):
		w = binary.LittleEndian.Uint16(b.in[b.pos:])
		b.pos += 2
	case b.pos < len(b.in):
		w = uint16(b.in[b.pos]) // dangling final byte, high half zero
		b.pos = len(b.in)
	}
	b.acc |= uint32(w) << (16 - b.nbits)
	b.nbits += 16
}

// bits consumes the next n bits, MSB-first. n must not exceed 16.
func (b *bitReader) bits(n uint8) uint16 {
	if n == 0 {
		return 0
	}
	if b.nbits < n {
		b.feed()
	}
	v := uint16(b.acc >> (32 - n))
	b.acc <<= n
	b.nbits -= n
	return v
}

// huffman is a canonical decode table: symbols ordered by (code length, symbol), with the
// count of symbols at each length.
type huffman struct {
	maxBits uint8
	count   [maxTreePath + 1]uint16
	symbol  [mainCodeCount]uint16
}

// build fills the table from per-symbol code lengths, where 0 means the symbol is absent. An
// all-zero set is legal — a block whose matches never use the length tree leaves it empty —
// and yields maxBits 0, which only errors if a symbol is then decoded from it. A set that is
// over- or under-subscribed is corrupt.
func (h *huffman) build(lens []byte) error {
	for i := range h.count {
		h.count[i] = 0
	}
	h.maxBits = 0
	for _, l := range lens {
		if l > maxTreePath {
			return ErrCorrupt
		}
		h.count[l]++
		if l > h.maxBits {
			h.maxBits = l
		}
	}
	if h.maxBits == 0 {
		return nil
	}

	left := 1
	for l := 1; l <= maxTreePath; l++ {
		left <<= 1
		left -= int(h.count[l])
		if left < 0 {
			return ErrCorrupt // over-subscribed
		}
	}
	if left != 0 {
		return ErrCorrupt // incomplete
	}

	var offs [maxTreePath + 2]uint16
	for l := 1; l < maxTreePath; l++ {
		offs[l+1] = offs[l] + h.count[l]
	}
	for i, l := range lens {
		if l != 0 {
			h.symbol[offs[l]] = uint16(i)
			offs[l]++
		}
	}
	return nil
}

// sym decodes one symbol, one bit at a time.
func (b *bitReader) sym(h *huffman) int {
	if h.maxBits == 0 {
		b.err = true
		return 0
	}
	code, first, index := 0, 0, 0
	for l := uint8(1); l <= h.maxBits; l++ {
		code |= int(b.bits(1))
		cnt := int(h.count[l])
		if code-first < cnt {
			return int(h.symbol[index+code-first])
		}
		index += cnt
		first = (first + cnt) << 1
		code <<= 1
	}
	b.err = true
	return 0
}

// readTree reads one tree's code lengths, which are delta-coded against the previous block's
// lengths through a 20-symbol pre-tree. lens is updated in place.
func (b *bitReader) readTree(lens []byte) error {
	var pretreeLens [pretreeCount]byte
	for i := range pretreeLens {
		pretreeLens[i] = byte(b.bits(4))
	}
	var pt huffman
	if err := pt.build(pretreeLens[:]); err != nil {
		return err
	}

	for i := 0; i < len(lens); {
		c := b.sym(&pt)
		if b.err {
			return ErrCorrupt
		}
		switch {
		case c <= 16: // a delta from the previous length
			lens[i] = byte((int(lens[i]) + 17 - c) % 17)
			i++
		case c == 17, c == 18: // a run of zero lengths
			var run int
			if c == 17 {
				run = int(b.bits(4)) + 4
			} else {
				run = int(b.bits(5)) + 20
			}
			if i+run > len(lens) {
				return ErrCorrupt
			}
			for j := 0; j < run; j++ {
				lens[i+j] = 0
			}
			i += run
		case c == 19: // a run of equal lengths
			run := int(b.bits(1)) + 4
			if i+run > len(lens) {
				return ErrCorrupt
			}
			c = b.sym(&pt)
			if b.err || c > 16 {
				return ErrCorrupt
			}
			l := byte((int(lens[i]) + 17 - c) % 17)
			for j := 0; j < run; j++ {
				lens[i+j] = l
			}
			i += run
		default:
			return ErrCorrupt
		}
	}
	return nil
}

// decoder holds the state one chunk is decoded with: the trees, the code lengths they are
// rebuilt from block to block, and the three recent match offsets.
type decoder struct {
	b        bitReader
	mainLens [mainCodeCount]byte
	lenLens  [lenCodeCount]byte
	main     huffman
	length   huffman
	aligned  huffman
	recent   [3]uint32
}

// readTrees reads a block's trees: the aligned-offset tree for an aligned block, then the main
// tree in its two halves, then the length tree.
func (d *decoder) readTrees(readAligned bool) error {
	if readAligned {
		var alignedLens [alignedCount]byte
		for i := range alignedLens {
			alignedLens[i] = byte(d.b.bits(3))
		}
		if err := d.aligned.build(alignedLens[:]); err != nil {
			return err
		}
	}
	if err := d.b.readTree(d.mainLens[:mainCodeSplit]); err != nil {
		return err
	}
	if err := d.b.readTree(d.mainLens[mainCodeSplit:]); err != nil {
		return err
	}
	if err := d.main.build(d.mainLens[:]); err != nil {
		return err
	}
	if err := d.b.readTree(d.lenLens[:]); err != nil {
		return err
	}
	return d.length.build(d.lenLens[:])
}

// readBlockHeader reads the 3-bit block type and the block's size, which is either the full
// window (a 1-bit flag) or an explicit 16-bit count. An uncompressed block additionally
// realigns the stream and carries its three recent offsets literally.
func (d *decoder) readBlockHeader() (blockType byte, size int, err error) {
	// Restore 2-byte alignment after a previous odd-length uncompressed block.
	if d.b.unaligned {
		if d.b.pos < len(d.b.in) {
			d.b.pos++
		}
		d.b.unaligned = false
	}

	blockType = byte(d.b.bits(3))
	if d.b.bits(1) != 0 {
		size = WindowSize
	} else {
		size = int(d.b.bits(16))
		if size > WindowSize {
			return 0, 0, ErrCorrupt
		}
	}

	switch blockType {
	case blkVerbatim, blkAligned:
	case blkUncompressed:
		// Realign to a 16-bit boundary, dropping the partial word — or one full padding
		// word when none remains — then read the three recent offsets, each stored as a
		// 32-bit value of which only the low half is used.
		n := d.b.nbits
		if n == 0 {
			n = 16
		}
		d.b.bits(n)
		if d.b.pos+12 > len(d.b.in) {
			return 0, 0, ErrCorrupt
		}
		for i := 0; i < 3; i++ {
			d.recent[i] = uint32(binary.LittleEndian.Uint16(d.b.in[d.b.pos+4*i:]))
		}
		d.b.pos += 12
	default:
		return 0, 0, ErrCorrupt
	}
	return blockType, size, nil
}

// readCompressed decodes a verbatim or aligned block into window[start:end].
func (d *decoder) readCompressed(window []byte, start, end int, useAligned bool) error {
	i := start
	for i < end {
		sym := d.b.sym(&d.main)
		if d.b.err {
			return ErrCorrupt
		}
		if sym < 256 { // a literal byte
			window[i] = byte(sym)
			i++
			continue
		}

		matchLen := (sym - 256) % 8
		slot := (sym - 256) / 8
		if matchLen == 7 { // a long length, extended by the length tree
			matchLen += d.b.sym(&d.length)
			if d.b.err {
				return ErrCorrupt
			}
		}
		matchLen += minMatch

		var offset uint32
		if slot < 3 { // one of the recent offsets, promoted to most recent
			offset = d.recent[slot]
			d.recent[slot] = d.recent[0]
			d.recent[0] = offset
		} else {
			if slot >= len(footerBits) {
				return ErrCorrupt
			}
			bits := footerBits[slot]
			var verbatim, aligned uint32
			if bits > 0 {
				if useAligned && bits >= 3 {
					verbatim = uint32(d.b.bits(bits-3)) * 8
					aligned = uint32(d.b.sym(&d.aligned))
					if d.b.err {
						return ErrCorrupt
					}
				} else {
					verbatim = uint32(d.b.bits(bits))
				}
			}
			offset = basePosition[slot] + verbatim + aligned - minMatch
			d.recent[2] = d.recent[1]
			d.recent[1] = d.recent[0]
			d.recent[0] = offset
		}

		if offset == 0 || int(offset) > i || matchLen > end-i {
			return ErrCorrupt
		}
		for e := i + matchLen; i < e; i++ {
			window[i] = window[i-int(offset)]
		}
	}
	return nil
}

// readBlock decodes one block into window at start and returns how many bytes it produced.
func (d *decoder) readBlock(window []byte, start int) (int, error) {
	blockType, size, err := d.readBlockHeader()
	if err != nil {
		return 0, err
	}
	if start+size > len(window) {
		return 0, ErrCorrupt
	}

	if blockType == blkUncompressed {
		if size%2 == 1 {
			d.b.unaligned = true
		}
		if d.b.pos+size > len(d.b.in) {
			return 0, ErrCorrupt
		}
		copy(window[start:start+size], d.b.in[d.b.pos:])
		d.b.pos += size
		return size, nil
	}

	if err := d.readTrees(blockType == blkAligned); err != nil {
		return 0, err
	}
	if err := d.readCompressed(window, start, start+size, blockType == blkAligned); err != nil {
		return 0, err
	}
	return size, nil
}

// Decompress decodes one compressed chunk from src into dst, whose length must be the chunk's
// exact uncompressed size — a WIM records that size rather than coding it into the stream.
func Decompress(dst, src []byte) error {
	if len(dst) == 0 {
		return nil
	}
	if len(dst) > WindowSize {
		return ErrCorrupt
	}

	d := &decoder{b: bitReader{in: src}, recent: [3]uint32{1, 1, 1}}
	for n := 0; n < len(dst); {
		produced, err := d.readBlock(dst, n)
		if err != nil {
			return err
		}
		if produced <= 0 {
			return ErrCorrupt // no forward progress
		}
		n += produced
	}

	decodeE8(dst)
	return nil
}

// decodeE8 reverses the Intel E8 (x86 CALL) branch translation applied before compression. A
// WIM applies it per chunk against a zero base, so the current-position guard never trips and
// the values are relative to the chunk start.
func decodeE8(b []byte) {
	if len(b) < e8MinLength {
		return
	}
	for i := 0; i+e8MinLength < len(b); i++ {
		if b[i] != 0xe8 {
			continue
		}
		pos := int32(i)
		v := int32(binary.LittleEndian.Uint32(b[i+1:]))
		if v >= -pos && v < e8FileSize {
			rel := v + e8FileSize
			if v >= 0 {
				rel = v - pos
			}
			binary.LittleEndian.PutUint32(b[i+1:], uint32(rel))
		}
		i += 4
	}
}
