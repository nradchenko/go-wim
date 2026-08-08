// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nradchenko/go-wim/lzx"
)

// The LZX decoder is checked against wimlib's compressor, which is an entirely independent
// implementation, and the check needs no oracle beyond the WIM itself: every resource's SHA-1
// is recorded in the blob table, so decoding a resource and hashing it either reproduces the
// recorded hash or does not.

// chunkTableEntrySize is 4 while a resource's uncompressed size fits in 32 bits, 8 above.
func chunkTableEntrySize(uncompressed uint64) int {
	if uncompressed <= 0xffffffff {
		return 4
	}
	return 8
}

// readCompressedResource decodes a chunk-compressed resource out of w and returns its
// uncompressed bytes. A compressed resource is a table of chunk offsets followed by the chunks:
// the table holds one entry per chunk after the first, each offset relative to the table's end,
// and a chunk whose stored size equals its uncompressed size is stored raw rather than coded.
func readCompressedResource(w []byte, res resHdr, chunkSize int) ([]byte, error) {
	if res.offset > uint64(len(w)) || res.size > uint64(len(w))-res.offset {
		return nil, fmt.Errorf("resource %#x+%#x out of bounds", res.offset, res.size)
	}
	body := w[res.offset : res.offset+res.size]

	nchunks := int((res.uncompressed + uint64(chunkSize) - 1) / uint64(chunkSize))
	if nchunks == 0 {
		return nil, nil
	}
	entry := chunkTableEntrySize(res.uncompressed)
	base := (nchunks - 1) * entry
	if base > len(body) {
		return nil, fmt.Errorf("chunk table (%d bytes) past the resource (%d)", base, len(body))
	}

	// offsets[i] is where chunk i starts; the first follows the table directly, and a
	// trailing sentinel gives the last chunk its length.
	offsets := make([]int, nchunks+1)
	offsets[0] = base
	for i := 1; i < nchunks; i++ {
		var off uint64
		if entry == 4 {
			off = uint64(binary.LittleEndian.Uint32(body[(i-1)*4:]))
		} else {
			off = binary.LittleEndian.Uint64(body[(i-1)*8:])
		}
		offsets[i] = base + int(off)
	}
	offsets[nchunks] = len(body)

	out := make([]byte, 0, res.uncompressed)
	for i := 0; i < nchunks; i++ {
		start, end := offsets[i], offsets[i+1]
		if start < base || end < start || end > len(body) {
			return nil, fmt.Errorf("chunk %d spans %d..%d, outside the resource", i, start, end)
		}
		want := chunkSize
		if rem := int(res.uncompressed) - i*chunkSize; rem < chunkSize {
			want = rem
		}
		if end-start == want { // stored raw: the format's incompressible-data path
			out = append(out, body[start:end]...)
			continue
		}
		dst := make([]byte, want)
		if err := lzx.Decompress(dst, body[start:end]); err != nil {
			return nil, fmt.Errorf("chunk %d: %w", i, err)
		}
		out = append(out, dst...)
	}
	return out, nil
}

// verifyResources decodes every resource in w and checks it against the SHA-1 its blob-table
// entry records. It returns how many resources were compressed and how many were stored raw,
// so a caller can assert the corpus actually exercised the decoder.
func verifyResources(t *testing.T, w []byte, chunkSize int) (compressed, stored int) {
	t.Helper()
	tbl := readResHdr(w, hdrLookupTableOff)
	n := int(tbl.size) / blobEntrySize
	for i := 0; i < n; i++ {
		e := int(tbl.offset) + i*blobEntrySize
		if e+blobEntrySize > len(w) {
			t.Fatalf("blob entry %d past the end of the WIM", i)
		}
		res := readResHdr(w, e)
		var want [20]byte
		copy(want[:], w[e+blobHashOffset:])

		var got []byte
		var err error
		if res.flags&flagCompressed != 0 {
			got, err = readCompressedResource(w, res, chunkSize)
			compressed++
		} else {
			if res.offset+res.size > uint64(len(w)) {
				t.Fatalf("resource %d out of bounds", i)
			}
			got = w[res.offset : res.offset+res.size]
			stored++
		}
		if err != nil {
			t.Errorf("resource %d (flags %#x, %d -> %d bytes): %v",
				i, res.flags, res.size, res.uncompressed, err)
			continue
		}
		if uint64(len(got)) != res.uncompressed {
			t.Errorf("resource %d decoded to %d bytes, want %d", i, len(got), res.uncompressed)
			continue
		}
		// The metadata resource's recorded hash is the one field a writer may leave stale,
		// so only file resources are hash-checked; their hash is the stream's identity.
		if res.flags&flagMetadata != 0 {
			continue
		}
		if sha1.Sum(got) != want {
			t.Errorf("resource %d (%d -> %d bytes) decoded to the wrong bytes: sha1 %x, want %x",
				i, res.size, res.uncompressed, sha1.Sum(got), want)
		}
	}
	return compressed, stored
}

// lzxFixture writes a tree chosen to exercise the decoder rather than merely run it: a long
// run of x86 CALL opcodes (the E8 translation), highly repetitive data (long matches and
// aligned-offset blocks), incompressible random data (blocks or whole chunks stored raw), and
// a file past the chunk size (a multi-chunk resource with a chunk table).
func lzxFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Synthetic x86: a CALL with a plausible relative displacement every 16 bytes.
	calls := make([]byte, 40000)
	for i := 0; i+5 < len(calls); i += 16 {
		calls[i] = 0xe8
		binary.LittleEndian.PutUint32(calls[i+1:], uint32(i*7%100000))
	}
	write("calls.bin", calls)

	repetitive := make([]byte, 100000)
	for i := range repetitive {
		repetitive[i] = "the quick brown fox "[i%20]
	}
	write("repetitive.txt", repetitive)

	// Deterministic pseudo-random bytes: incompressible, so LZX cannot shrink them.
	rnd := rand.New(rand.NewSource(1))
	incompressible := make([]byte, 70000)
	rnd.Read(incompressible)
	write("random.bin", incompressible)

	// Matches at long, irregularly spaced distances, which is what drives an encoder to emit
	// aligned-offset blocks — the branch that splits an offset into verbatim high bits and a
	// Huffman-coded low three. Without this the whole aligned path goes untested: a decoder
	// mutated to misscale those high bits still passes on the files above, and is caught here.
	// The distances are all multiples of the record size, so the low three bits of every
	// offset are zero — a skew an encoder can only exploit with an aligned-offset block. Data
	// whose match distances are merely long but uniformly distributed does not do it: the
	// aligned tree does not pay, the encoder stays verbatim, and the path goes untested.
	const record = 512
	blocks := make([][]byte, 16)
	seeded := rand.New(rand.NewSource(2))
	for i := range blocks {
		blocks[i] = make([]byte, record)
		seeded.Read(blocks[i])
	}
	pick := rand.New(rand.NewSource(3))
	aligned := make([]byte, 0, 400*record)
	for i := 0; i < 400; i++ {
		b := append([]byte(nil), blocks[pick.Intn(len(blocks))]...)
		b[pick.Intn(record)] = byte(i) // perturb, so it is not one enormous match
		aligned = append(aligned, b...)
	}
	write("aligned.bin", aligned)

	write("short.txt", []byte("small"))
	write("empty.bin", nil)
	return dir
}

// TestDecodeLZXFromWimlib decodes a wimlib-compressed WIM with our decoder and checks every
// resource against its recorded SHA-1. wimlib's compressor is independent of everything here,
// so agreeing with it on real LZX streams is what validates the decoder.
func TestDecodeLZXFromWimlib(t *testing.T) {
	if _, err := exec.LookPath("wimcapture"); err != nil {
		t.Skip("wimcapture not available; skipping")
	}
	out := filepath.Join(t.TempDir(), "lzx.wim")
	mustRun(t, "wimcapture", lzxFixture(t), out, "LZX", "--compress=LZX",
		fmt.Sprintf("--chunk-size=%d", DefaultChunkSize))

	w, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(w[hdrChunkSizeOff:]); got != DefaultChunkSize {
		t.Fatalf("fixture chunk size = %d, want %d", got, DefaultChunkSize)
	}

	compressed, stored := verifyResources(t, w, DefaultChunkSize)
	t.Logf("decoded %d compressed and %d stored resources", compressed, stored)
	// Guard against the check passing vacuously: the fixture must produce real LZX streams.
	if compressed < 3 {
		t.Errorf("only %d compressed resources; the fixture is not exercising the decoder", compressed)
	}
}

// TestDecodeLZXCorpus sweeps a directory of real WIMs named by GOWIM_CORPUS, decoding
// every resource and checking it against its recorded hash. Real Windows binaries cover far
// more of the format than any synthetic fixture; the environment gate keeps it opt-in because
// the corpus is not part of the repository.
func TestDecodeLZXCorpus(t *testing.T) {
	dir := os.Getenv("GOWIM_CORPUS")
	if dir == "" {
		t.Skip("GOWIM_CORPUS not set; skipping")
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.wim"))
	if err != nil || len(entries) == 0 {
		t.Skipf("no WIMs under %s; skipping", dir)
	}

	var files, compressed, stored int
	for _, p := range entries {
		w, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(w) < headerSize || string(w[0:8]) != wimMagic {
			continue
		}
		chunk := int(binary.LittleEndian.Uint32(w[hdrChunkSizeOff:]))
		if chunk == 0 {
			chunk = DefaultChunkSize // an uncompressed WIM records none
		}
		t.Run(filepath.Base(p), func(t *testing.T) {
			c, s := verifyResources(t, w, chunk)
			compressed += c
			stored += s
		})
		files++
	}
	t.Logf("swept %d WIMs: %d compressed and %d stored resources", files, compressed, stored)
}
