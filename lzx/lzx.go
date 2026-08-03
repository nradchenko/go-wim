// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

// Package lzx implements the WIM variant of the LZX compression algorithm, in both
// directions: a compressor for building WIMs and a decompressor the round-trip tests check it
// against.
//
// The WIM variant differs from the cabinet variant in compress/lzx.go, and the two do not
// share code: a WIM chunk is a self-contained stream over a fixed 32768-byte window, opening
// directly at a block header — there is no cabinet-style file preamble, the block size is a
// 1-bit "full window" flag or a 16-bit count rather than a 24-bit field, and the Intel E8
// call translation is unconditional at a fixed magic file size rather than negotiated.
//
// Reimplemented from the documented LZX format, with the MIT-licensed go-winio WIM reader
// (github.com/microsoft/go-winio, wim/lzx, Copyright (c) 2015 Microsoft) consulted as a format
// reference only; no go-winio source is incorporated. The same reference and the same standing
// as compress/lzx.go and pe-wimmf's reader/lzx.c, which independently agree on this framing.
package lzx

import "errors"

// WindowSize is the LZX window a WIM chunk is coded against, and so the largest chunk this
// codec handles. Each chunk resets the window, the Huffman trees, and the recent-offset state,
// which is what lets a reader decode any chunk without the ones before it.
const WindowSize = 32768

// Alphabet sizes. The main tree covers the 256 literals plus one symbol per (position slot,
// short length) pair — 30 slots for a 32768-byte window, 8 lengths each.
const (
	mainCodeCount = 256 + 30*8
	mainCodeSplit = 256
	lenCodeCount  = 249
	pretreeCount  = 20
	alignedCount  = 8

	// maxTreePath is the longest permitted Huffman code.
	maxTreePath = 16

	// minMatch is the shortest encodable match, which is why a match length is stored
	// biased by it.
	minMatch = 2
	// maxMatch is the longest: the 7 lengths the main symbol encodes directly, extended by
	// the length tree's 249 symbols.
	maxMatch = minMatch + 7 + lenCodeCount - 1
)

// Block types.
const (
	blkVerbatim     = 1
	blkAligned      = 2
	blkUncompressed = 3
)

// e8FileSize is the magic file size the Intel E8 call translation is performed against. A WIM
// applies the translation per chunk with a zero base, so this constant is the whole of it.
const e8FileSize = 12000000

// e8MinLength is the shortest buffer the translation touches.
const e8MinLength = 10

// footerBits is the number of offset bits carried directly for each position slot, and
// basePosition the window offset each slot starts at.
var (
	footerBits = [31]byte{
		0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
		7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14,
	}
	basePosition = [31]uint32{
		0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192,
		256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
		12288, 16384, 24576, 32768,
	}
)

// ErrCorrupt is returned when a chunk cannot be decoded.
var ErrCorrupt = errors.New("lzx: data corrupt")

// Compressor and Decompress are defined in encode.go and decode.go.
