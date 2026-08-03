// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package lzx

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"testing"

	winiolzx "github.com/Microsoft/go-winio/wim/lzx"
)

// roundTrip compresses src and decodes it back with both our decoder and go-winio's, which
// share no code with the encoder. A chunk the encoder declines to compress is not a failure —
// that is the format's incompressible-data path — but it is reported so a case meant to
// exercise compression cannot pass by silently declining.
func roundTrip(t *testing.T, name string, src []byte) (compressed bool) {
	t.Helper()

	dst := make([]byte, len(src))
	n, ok := (&Compressor{}).Compress(dst, src)
	if !ok {
		return false
	}
	if n >= len(src) {
		t.Errorf("%s: compressed to %d bytes, not smaller than %d", name, n, len(src))
		return false
	}

	got := make([]byte, len(src))
	if err := Decompress(got, dst[:n]); err != nil {
		t.Errorf("%s: our decoder rejected our own output: %v", name, err)
		return true
	}
	if !bytes.Equal(got, src) {
		t.Errorf("%s: round trip through our decoder changed the data (first difference at %d)",
			name, firstDiff(got, src))
		return true
	}

	// go-winio decodes the same bytes independently; agreeing with it means the stream is
	// the format rather than merely our own convention.
	r, err := winiolzx.NewReader(bytes.NewReader(dst[:n]), len(src))
	if err != nil {
		t.Errorf("%s: go-winio rejected our output: %v", name, err)
		return true
	}
	other, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Errorf("%s: go-winio failed to decode our output: %v", name, err)
		return true
	}
	if !bytes.Equal(other, src) {
		t.Errorf("%s: go-winio decoded our output differently (first difference at %d)",
			name, firstDiff(other, src))
	}
	return true
}

func firstDiff(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	return -1
}

// TestRoundTripShapes covers the input shapes whose handling differs: the E8 length threshold,
// the full window, data that compresses enormously, and data that cannot compress at all.
func TestRoundTripShapes(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	random := func(n int) []byte {
		b := make([]byte, n)
		rnd.Read(b)
		return b
	}
	repeat := func(n int, pattern string) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = pattern[i%len(pattern)]
		}
		return b
	}

	cases := []struct {
		name         string
		data         []byte
		mustCompress bool
	}{
		{"one byte", []byte{'a'}, false},
		{"below the E8 threshold", []byte("123456789"), false},
		{"exactly the E8 threshold", []byte("1234567890"), false},
		{"tiny repetitive", repeat(64, "ab"), false},
		{"repetitive", repeat(30000, "the quick brown fox "), true},
		{"all zeros, full window", make([]byte, WindowSize), true},
		{"incompressible", random(WindowSize), false},
		{"full window repetitive", repeat(WindowSize, "abcdefgh"), true},
		{"one below the window", repeat(WindowSize-1, "abcdefgh"), true},
		{"one above minimum match", []byte("aaa"), false},
	}
	for _, c := range cases {
		got := roundTrip(t, c.name, c.data)
		if c.mustCompress && !got {
			t.Errorf("%s: declined to compress; the case is meant to exercise the encoder", c.name)
		}
	}
}

// TestRoundTripE8 covers the Intel E8 translation, including the boundary values where the
// encoder's two ranges meet — a displacement that lands wrong there decodes to different bytes.
func TestRoundTripE8(t *testing.T) {
	for _, v := range []int32{
		0, 1, -1, 1000, -1000, e8FileSize - 1, e8FileSize, e8FileSize + 1,
		-e8FileSize, 0x7fffffff, -0x80000000,
	} {
		// Repeat the call site so positions vary: the translation is position-dependent, so
		// one displacement exercises a different branch at each offset.
		data := make([]byte, 4096)
		for i := range data {
			data[i] = byte(i)
		}
		for i := 0; i+5 < len(data); i += 32 {
			data[i] = 0xe8
			binary.LittleEndian.PutUint32(data[i+1:], uint32(v))
		}
		roundTrip(t, fmt.Sprintf("e8 displacement %d", v), data)
	}
}

// TestRoundTripAlignedBlocks feeds the encoder offsets whose low three bits are all zero, which
// is what makes an aligned-offset block cheaper than a verbatim one, and checks the encoder
// actually chooses it — otherwise the aligned path would go untested here.
func TestRoundTripAlignedBlocks(t *testing.T) {
	const record = 512
	blocks := make([][]byte, 16)
	seeded := rand.New(rand.NewSource(2))
	for i := range blocks {
		blocks[i] = make([]byte, record)
		seeded.Read(blocks[i])
	}
	pick := rand.New(rand.NewSource(3))
	data := make([]byte, 0, WindowSize)
	for len(data) < WindowSize-record {
		b := append([]byte(nil), blocks[pick.Intn(len(blocks))]...)
		b[pick.Intn(record)] = byte(len(data))
		data = append(data, b...)
	}

	if !roundTrip(t, "aligned", data) {
		t.Fatal("aligned fixture declined to compress")
	}

	// Confirm the encoder took the aligned branch rather than passing by luck. The block type
	// is the first three bits of the stream, and the stream is 16-bit little-endian words
	// filled most-significant-bit first — so those bits are the top of the second byte.
	dst := make([]byte, len(data))
	if _, ok := (&Compressor{}).Compress(dst, data); !ok {
		t.Fatal("aligned fixture declined to compress")
	}
	if blockType := dst[1] >> 5; blockType != blkAligned {
		t.Errorf("block type = %d, want %d (aligned); the aligned path is untested",
			blockType, blkAligned)
	}
}

// TestRoundTripRandomised runs many pseudo-random inputs of mixed structure through the round
// trip. Structure is varied deliberately: uniform random data never produces matches, so a
// literal-only encoder would pass a purely random test.
func TestRoundTripRandomised(t *testing.T) {
	rnd := rand.New(rand.NewSource(11))
	alphabet := []byte("abcdefghijklmnop\x00\xff\xe8\xe8")
	for i := 0; i < 300; i++ {
		n := 1 + rnd.Intn(WindowSize)
		data := make([]byte, n)
		switch rnd.Intn(4) {
		case 0:
			rnd.Read(data)
		case 1:
			for j := range data {
				data[j] = alphabet[rnd.Intn(len(alphabet))]
			}
		case 2: // runs, which produce long matches at short offsets
			for j := 0; j < len(data); {
				b := byte(rnd.Intn(256))
				run := 1 + rnd.Intn(200)
				for k := 0; k < run && j < len(data); k++ {
					data[j] = b
					j++
				}
			}
		case 3: // a small vocabulary repeated at varied distances
			vocab := make([]byte, 1024)
			rnd.Read(vocab)
			for j := 0; j < len(data); {
				off := rnd.Intn(len(vocab) - 64)
				run := 8 + rnd.Intn(56)
				for k := 0; k < run && j < len(data); k++ {
					data[j] = vocab[off+k]
					j++
				}
			}
		}
		roundTrip(t, fmt.Sprintf("random case %d (%d bytes)", i, n), data)
	}
}

// TestAssignLengthsIsComplete checks the code-length assignment always produces a code a
// decoder accepts: within the limit, and neither over- nor under-subscribed. An incomplete code
// is not a ratio problem, it is a stream a decoder rejects outright.
func TestAssignLengthsIsComplete(t *testing.T) {
	// Each alphabet is paired with the limit it is actually coded under. The pairing matters:
	// a limit of L can only describe a complete code over at most 2^L symbols, so testing a
	// large alphabet against a small limit would be asking for something that cannot exist.
	alphabets := []struct {
		size  int
		limit int
	}{
		{alignedCount, alignedLenLimit},
		{pretreeCount, pretreeLenLimit},
		{lenCodeCount, mainLenLimit},
		{mainCodeCount, mainLenLimit},
	}

	rnd := rand.New(rand.NewSource(13))
	for i := 0; i < 2000; i++ {
		a := alphabets[rnd.Intn(len(alphabets))]
		// The alphabet is always whole — that is how the encoder calls this — and only the
		// frequencies vary, including the none-used and one-used edges.
		n, limit := a.size, a.limit
		freq := make([]uint32, n)
		used := 0
		for j := range freq {
			switch rnd.Intn(4) {
			case 0: // absent
			case 1:
				freq[j] = 1
				used++
			case 2:
				freq[j] = uint32(1 + rnd.Intn(1000))
				used++
			case 3: // heavily skewed, which is what drives depth past the limit
				freq[j] = uint32(1) << uint(rnd.Intn(30))
				used++
			}
		}
		lens := assignLengths(freq, limit)

		var h huffman
		if err := h.build(lens); err != nil {
			t.Fatalf("case %d (%d symbols, %d used, limit %d): decoder rejects the code: %v",
				i, n, used, limit, err)
		}
		for s, l := range lens {
			if int(l) > limit {
				t.Fatalf("case %d: symbol %d has length %d, over the limit %d", i, s, l, limit)
			}
			if freq[s] > 0 && l == 0 && used > 1 {
				t.Fatalf("case %d: symbol %d occurs %d times but has no code", i, s, freq[s])
			}
		}
	}
}
