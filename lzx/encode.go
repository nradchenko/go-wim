// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package lzx

import "encoding/binary"

// The encoder emits exactly one block per chunk. A chunk resets the trees anyway, so the
// cross-block length deltas a multi-block stream would save are not available, and one block
// keeps the tree-writing side free of state. It never emits an uncompressed block either: a
// chunk that does not compress is reported as such and the caller stores it raw, which is the
// same saving with none of the block-type bookkeeping.

// Match-finder tuning. The window is one chunk, so the structures are small and the chain
// bound matters more for time than for ratio.
const (
	hashBits  = 15
	hashSize  = 1 << hashBits
	minLength = 3    // shortest match the finder emits; the format allows 2, which rarely pays
	maxChain  = 64   // hash-chain entries examined per position
	goodMatch = 1024 // a match at least this long ends the search early
)

// pretree symbols above the 0..16 length deltas.
const (
	pretreeZeroShort = 17 // a run of 4..19 zero lengths
	pretreeZeroLong  = 18 // a run of 20..51 zero lengths
	pretreeSame      = 19 // a run of 4..5 equal lengths
)

// Code-length limits. The main and length trees write their lengths through the pre-tree, which
// codes values 0..16; the aligned tree and the pre-tree itself write raw 3- and 4-bit fields.
const (
	mainLenLimit    = maxTreePath
	alignedLenLimit = 7
	pretreeLenLimit = 15
)

// bitWriter is the inverse of bitReader: bits accumulate MSB-first and leave as 16-bit
// little-endian words.
type bitWriter struct {
	out   []byte
	acc   uint32
	nbits uint8
}

// write appends the low n bits of v, most significant first. n must not exceed 16.
func (w *bitWriter) write(v uint32, n uint8) {
	if n == 0 {
		return
	}
	v &= (1 << n) - 1
	w.acc |= v << (32 - w.nbits - n)
	w.nbits += n
	for w.nbits >= 16 {
		word := uint16(w.acc >> 16)
		w.out = append(w.out, byte(word), byte(word>>8))
		w.acc <<= 16
		w.nbits -= 16
	}
}

// flush emits the final partial word, zero-padded. A reader past the end of input feeds zeros,
// so the padding is never mistaken for data.
func (w *bitWriter) flush() {
	if w.nbits > 0 {
		word := uint16(w.acc >> 16)
		w.out = append(w.out, byte(word), byte(word>>8))
		w.acc = 0
		w.nbits = 0
	}
}

// token is one coded element: a literal, or a match already resolved to its position slot and
// extra offset bits.
type token struct {
	sym    int    // main-tree symbol
	lenSym int    // length-tree symbol, or -1 when the length fits in the main symbol
	slot   int    // position slot, or -1 for a literal
	extra  uint32 // offset bits below the slot's base
}

// Compressor holds the match-finder and coding scratch reused across chunks.
type Compressor struct {
	head [hashSize]int32
	prev [WindowSize]int32
	buf  [WindowSize]byte // the chunk after E8 translation; src is never modified

	tokens      []token
	mainFreq    [mainCodeCount]uint32
	lenFreq     [lenCodeCount]uint32
	alignedFreq [alignedCount]uint32

	w bitWriter
}

// NewCompressor returns a Compressor ready to use.
func NewCompressor() *Compressor { return &Compressor{} }

// Compress encodes src, which must be at most WindowSize bytes, into dst and returns the
// number of bytes written. It reports ok=false — writing nothing — when the encoding would not
// be smaller than src, which is the signal to store the chunk raw. A caller must handle that
// case: it is how the format carries incompressible data, and it is not an error.
func (c *Compressor) Compress(dst, src []byte) (n int, ok bool) {
	if len(src) == 0 || len(src) > WindowSize {
		return 0, false
	}

	// E8 translation rewrites the data, so it runs on a private copy.
	data := c.buf[:len(src)]
	copy(data, src)
	encodeE8(data)

	c.findMatches(data)
	c.countFrequencies()

	mainLens := assignLengths(c.mainFreq[:], mainLenLimit)
	lenLens := assignLengths(c.lenFreq[:], mainLenLimit)
	alignedLens := assignLengths(c.alignedFreq[:], alignedLenLimit)
	useAligned := c.alignedPays(alignedLens)

	c.w.out = c.w.out[:0]
	c.w.acc, c.w.nbits = 0, 0
	c.emitBlock(len(src), mainLens, lenLens, alignedLens, useAligned)
	c.w.flush()

	if len(c.w.out) >= len(src) || len(c.w.out) > len(dst) {
		return 0, false
	}
	return copy(dst, c.w.out), true
}

// findMatches turns the chunk into tokens, tracking the three recent offsets exactly as a
// decoder does so that a match at a recent offset can be coded in the cheap slots 0..2.
func (c *Compressor) findMatches(data []byte) {
	c.tokens = c.tokens[:0]
	for i := range c.head {
		c.head[i] = 0 // 0 means empty; positions are stored biased by one
	}
	recent := [3]uint32{1, 1, 1}

	pos := 0
	for pos < len(data) {
		length, offset := c.longestMatch(data, pos, recent)

		// Lazy matching: if the next position starts a strictly longer match, emit this
		// byte as a literal and take that one instead.
		if length >= minLength && pos+1 < len(data) {
			if nextLen, _ := c.longestMatch(data, pos+1, recent); nextLen > length {
				length = 0
			}
		}

		if length < minLength {
			c.tokens = append(c.tokens, token{sym: int(data[pos]), lenSym: -1, slot: -1})
			c.insert(data, pos)
			pos++
			continue
		}

		c.tokens = append(c.tokens, c.matchToken(length, offset, &recent))
		for e := pos + length; pos < e; pos++ {
			c.insert(data, pos)
		}
	}
}

// matchToken resolves a match to its coded form and applies the recent-offset update the
// decoder will mirror.
func (c *Compressor) matchToken(length int, offset uint32, recent *[3]uint32) token {
	t := token{lenSym: -1}

	slot := -1
	for i := 0; i < 3; i++ {
		if recent[i] == offset {
			slot = i
			break
		}
	}
	if slot >= 0 {
		// Promote the reused offset, exactly as the decoder does.
		recent[slot] = recent[0]
		recent[0] = offset
	} else {
		adjusted := offset + minMatch
		slot = positionSlot(adjusted)
		t.extra = adjusted - basePosition[slot]
		recent[2] = recent[1]
		recent[1] = recent[0]
		recent[0] = offset
	}
	t.slot = slot

	short := length - minMatch
	if short >= 7 {
		t.lenSym = short - 7
		short = 7
	}
	t.sym = 256 + slot*8 + short
	return t
}

// positionSlot returns the slot whose base is the largest not exceeding adjusted.
func positionSlot(adjusted uint32) int {
	slot := len(basePosition) - 1
	for basePosition[slot] > adjusted {
		slot--
	}
	return slot
}

// hash3 hashes the three bytes at b into a chain bucket.
func hash3(b []byte) uint32 {
	v := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	return (v * 2654435761) >> (32 - hashBits)
}

// insert records position pos in the chain for the bytes starting there.
func (c *Compressor) insert(data []byte, pos int) {
	if pos+minLength > len(data) {
		return
	}
	h := hash3(data[pos:])
	c.prev[pos] = c.head[h]
	c.head[h] = int32(pos + 1)
}

// longestMatch returns the longest match for the bytes at pos, preferring a recent offset when
// it ties: a recent offset costs three bits rather than a slot plus its extra bits.
func (c *Compressor) longestMatch(data []byte, pos int, recent [3]uint32) (length int, offset uint32) {
	if pos+minLength > len(data) {
		return 0, 0
	}
	maxLen := len(data) - pos
	if maxLen > maxMatch {
		maxLen = maxMatch
	}

	for _, r := range recent {
		if int(r) > pos || r == 0 {
			continue
		}
		if n := matchLen(data, pos, pos-int(r), maxLen); n > length {
			length, offset = n, r
		}
	}

	h := hash3(data[pos:])
	for cur, n := int(c.head[h])-1, 0; cur >= 0 && n < maxChain; n++ {
		off := uint32(pos - cur)
		if off == 0 || off > WindowSize {
			break
		}
		if l := matchLen(data, pos, cur, maxLen); l > length {
			length, offset = l, off
			if l >= goodMatch || l >= maxLen {
				break
			}
		}
		cur = int(c.prev[cur]) - 1
	}
	return length, offset
}

// matchLen returns how many bytes agree between the strings at a and b, capped at max.
func matchLen(data []byte, a, b, max int) int {
	n := 0
	for n < max && data[a+n] == data[b+n] {
		n++
	}
	return n
}

// countFrequencies tallies the symbols the tokens will emit.
func (c *Compressor) countFrequencies() {
	for i := range c.mainFreq {
		c.mainFreq[i] = 0
	}
	for i := range c.lenFreq {
		c.lenFreq[i] = 0
	}
	for i := range c.alignedFreq {
		c.alignedFreq[i] = 0
	}
	for _, t := range c.tokens {
		c.mainFreq[t.sym]++
		if t.lenSym >= 0 {
			c.lenFreq[t.lenSym]++
		}
		if t.slot >= 3 && footerBits[t.slot] >= 3 {
			c.alignedFreq[t.extra&7]++
		}
	}
}

// alignedPays reports whether coding the low three offset bits through the aligned tree costs
// less than writing them raw, counting the tree's own 24-bit header.
func (c *Compressor) alignedPays(alignedLens []byte) bool {
	raw, coded := 0, alignedCount*3
	for sym, n := range c.alignedFreq {
		if n == 0 {
			continue
		}
		l := int(alignedLens[sym])
		if l == 0 {
			return false // the symbol occurs but has no code; verbatim is the safe choice
		}
		raw += int(n) * 3
		coded += int(n) * l
	}
	return coded < raw
}

// emitBlock writes the block header, the trees, and the tokens.
func (c *Compressor) emitBlock(size int, mainLens, lenLens, alignedLens []byte, useAligned bool) {
	blockType := blkVerbatim
	if useAligned {
		blockType = blkAligned
	}
	c.w.write(uint32(blockType), 3)
	if size == WindowSize {
		c.w.write(1, 1)
	} else {
		c.w.write(0, 1)
		c.w.write(uint32(size), 16)
	}

	if useAligned {
		for _, l := range alignedLens {
			c.w.write(uint32(l), 3)
		}
	}
	// The main tree is written in two halves, then the length tree. Every chunk starts with
	// all lengths zero, so each is a delta against zero.
	c.writeTree(mainLens[:mainCodeSplit])
	c.writeTree(mainLens[mainCodeSplit:])
	c.writeTree(lenLens)

	mainCodes := canonicalCodes(mainLens)
	lenCodes := canonicalCodes(lenLens)
	alignedCodes := canonicalCodes(alignedLens)

	for _, t := range c.tokens {
		c.w.write(mainCodes[t.sym], mainLens[t.sym])
		if t.slot < 0 {
			continue
		}
		if t.lenSym >= 0 {
			c.w.write(lenCodes[t.lenSym], lenLens[t.lenSym])
		}
		bits := footerBits[t.slot]
		if bits == 0 {
			continue
		}
		if useAligned && bits >= 3 {
			c.w.write(t.extra>>3, bits-3)
			c.w.write(alignedCodes[t.extra&7], alignedLens[t.extra&7])
		} else {
			c.w.write(t.extra, bits)
		}
	}
}

// writeTree emits one tree's code lengths through the pre-tree: each length as a delta from the
// previous block's (zero here), with runs of zeros and of equal values coded by the run
// symbols. The pre-tree's own lengths precede it as twenty 4-bit fields.
func (c *Compressor) writeTree(lens []byte) {
	type item struct{ sym, extraBits, extraVal int }
	var items []item
	var freq [pretreeCount]uint32

	delta := func(l byte) int { return (17 - int(l)) % 17 }

	for i := 0; i < len(lens); {
		if lens[i] == 0 {
			run := 1
			for i+run < len(lens) && lens[i+run] == 0 {
				run++
			}
			for run >= 20 {
				n := run
				if n > 51 {
					n = 51
				}
				items = append(items, item{pretreeZeroLong, 5, n - 20})
				freq[pretreeZeroLong]++
				i += n
				run -= n
			}
			for run >= 4 {
				n := run
				if n > 19 {
					n = 19
				}
				items = append(items, item{pretreeZeroShort, 4, n - 4})
				freq[pretreeZeroShort]++
				i += n
				run -= n
			}
			for ; run > 0; run-- {
				items = append(items, item{delta(0), 0, 0})
				freq[delta(0)]++
				i++
			}
			continue
		}

		run := 1
		for i+run < len(lens) && lens[i+run] == lens[i] {
			run++
		}
		// The equal-run symbol carries 4 or 5 repeats and is followed by the value itself.
		for run >= 4 {
			n := 4
			if run >= 5 {
				n = 5
			}
			items = append(items, item{pretreeSame, 1, n - 4}, item{delta(lens[i]), 0, 0})
			freq[pretreeSame]++
			freq[delta(lens[i])]++
			i += n
			run -= n
		}
		for ; run > 0; run-- {
			items = append(items, item{delta(lens[i]), 0, 0})
			freq[delta(lens[i])]++
			i++
		}
	}

	pretreeLens := assignLengths(freq[:], pretreeLenLimit)
	pretreeCodes := canonicalCodes(pretreeLens)
	for _, l := range pretreeLens {
		c.w.write(uint32(l), 4)
	}
	for _, it := range items {
		c.w.write(pretreeCodes[it.sym], pretreeLens[it.sym])
		if it.extraBits > 0 {
			c.w.write(uint32(it.extraVal), uint8(it.extraBits))
		}
	}
}

// encodeE8 applies the Intel E8 (x86 CALL) branch translation decodeE8 reverses. The two ranges
// are the inverse of the decoder's two cases, and together they cover exactly the values the
// decoder would transform — so a value left alone here is one the decoder also leaves alone.
func encodeE8(b []byte) {
	if len(b) < e8MinLength {
		return
	}
	for i := 0; i+e8MinLength < len(b); i++ {
		if b[i] != 0xe8 {
			continue
		}
		pos := int32(i)
		x := int32(binary.LittleEndian.Uint32(b[i+1:]))
		switch {
		case x >= -pos && x < e8FileSize-pos:
			binary.LittleEndian.PutUint32(b[i+1:], uint32(x+pos))
		case x >= e8FileSize-pos && x < e8FileSize:
			binary.LittleEndian.PutUint32(b[i+1:], uint32(x-e8FileSize))
		}
		i += 4
	}
}
