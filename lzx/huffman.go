// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package lzx

import "sort"

// assignLengths returns a canonical Huffman code length per symbol from the symbols'
// frequencies, with 0 for a symbol that does not occur. No length exceeds limit, and the code
// is always complete — a decoder rejects an over- or under-subscribed set, so completeness is
// a correctness requirement here rather than a quality one.
//
// freq must be a whole alphabet of at least two symbols, and limit must be able to describe it
// (a limit of L covers at most 2^L symbols). Every alphabet here satisfies both: the smallest
// is the 8-symbol aligned tree at limit 7. A single-symbol alphabet has no complete code at
// all, which is why the one-used-symbol case below borrows a second symbol rather than
// standing alone.
//
// Lengths come from an ordinary Huffman construction, then are clamped to the limit and
// repaired back to completeness. The repair is what makes the limit safe: clamping alone
// leaves the code over-subscribed, and a frequency distribution skewed enough to need it does
// occur — a 496-symbol alphabet over a 32768-byte chunk can reach depths past 16.
func assignLengths(freq []uint32, limit int) []byte {
	lens := make([]byte, len(freq))

	var used []int
	for i, f := range freq {
		if f > 0 {
			used = append(used, i)
		}
	}
	switch len(used) {
	case 0:
		// No symbol occurs. An all-zero tree is legal: the block simply never decodes one.
		return lens
	case 1:
		// A one-symbol code cannot be complete, so a second symbol is given a length too.
		// Which one is arbitrary — it is never emitted.
		lens[used[0]] = 1
		other := 0
		if used[0] == 0 {
			other = 1
		}
		if other < len(lens) {
			lens[other] = 1
		}
		return lens
	}

	huffmanLengths(freq, used, lens)
	clampLengths(lens, used, limit)
	return lens
}

// huffmanLengths fills in the unlimited Huffman code length of every used symbol, by repeatedly
// merging the two lowest-weight nodes. Nodes are kept in two queues — the leaves in increasing
// frequency, and the internal nodes in creation order, which is already increasing — so the
// next-smallest node is the front of one or the other and no heap is needed.
func huffmanLengths(freq []uint32, used []int, lens []byte) {
	leaves := append([]int(nil), used...)
	sort.Slice(leaves, func(i, j int) bool {
		if freq[leaves[i]] != freq[leaves[j]] {
			return freq[leaves[i]] < freq[leaves[j]]
		}
		return leaves[i] < leaves[j]
	})

	// An internal node's children, and its weight. Leaves are encoded as ^symbol so the two
	// kinds can share one child array.
	type node struct {
		weight      uint64
		left, right int
	}
	nodes := make([]node, 0, len(leaves))

	li, ni := 0, 0
	next := func() (weight uint64, ref int) {
		if li < len(leaves) && (ni >= len(nodes) || uint64(freq[leaves[li]]) <= nodes[ni].weight) {
			w, r := uint64(freq[leaves[li]]), ^leaves[li]
			li++
			return w, r
		}
		w, r := nodes[ni].weight, ni
		ni++
		return w, r
	}
	for (len(leaves)-li)+(len(nodes)-ni) > 1 {
		w1, r1 := next()
		w2, r2 := next()
		nodes = append(nodes, node{weight: w1 + w2, left: r1, right: r2})
	}

	// Walk down from the root, recording each leaf's depth.
	var walk func(ref, depth int)
	walk = func(ref, depth int) {
		if ref < 0 {
			if depth == 0 {
				depth = 1
			}
			lens[^ref] = byte(depth)
			return
		}
		walk(nodes[ref].left, depth+1)
		walk(nodes[ref].right, depth+1)
	}
	walk(len(nodes)-1, 0)
}

// clampLengths caps every length at limit and then restores completeness, which clamping
// breaks. Completeness is measured as the Kraft sum scaled to 1<<limit: a complete code sums to
// exactly that, an over-subscribed one exceeds it.
func clampLengths(lens []byte, used []int, limit int) {
	for _, s := range used {
		if int(lens[s]) > limit {
			lens[s] = byte(limit)
		}
	}

	total := uint64(0)
	one := uint64(1) << uint(limit)
	for _, s := range used {
		total += one >> uint(lens[s])
	}

	// Over-subscribed: lengthening a symbol halves its contribution. Deepening the shallowest
	// symbols first costs the fewest bits overall.
	order := append([]int(nil), used...)
	sort.Slice(order, func(i, j int) bool {
		if lens[order[i]] != lens[order[j]] {
			return lens[order[i]] < lens[order[j]]
		}
		return order[i] < order[j]
	})
	for total > one {
		moved := false
		for _, s := range order {
			if int(lens[s]) < limit {
				total -= one >> uint(lens[s]+1)
				lens[s]++
				moved = true
				break
			}
		}
		if !moved {
			return // every symbol is already at the limit; cannot happen for a real alphabet
		}
	}

	// Under-subscribed: shortening a symbol doubles its contribution, so take the deepest
	// symbol that still fits in the remaining slack.
	for total < one {
		best := -1
		for _, s := range used {
			if lens[s] <= 1 {
				continue
			}
			if total+(one>>uint(lens[s])) > one {
				continue
			}
			if best == -1 || lens[s] > lens[best] {
				best = s
			}
		}
		if best == -1 {
			return
		}
		total += one >> uint(lens[best])
		lens[best]--
	}
}

// canonicalCodes returns each symbol's code, in the same canonical order a decoder assigns:
// symbols are ordered by (length, symbol) and given consecutive codes within a length. The code
// is returned MSB-first in its low len bits, which is the order the bitstream carries it.
func canonicalCodes(lens []byte) []uint32 {
	var count [maxTreePath + 2]uint32
	for _, l := range lens {
		count[l]++
	}
	// Absent symbols must not seed the first length's code. Leaving them counted offsets
	// every code by count[0]<<len — which a writer masking to the code length happens to
	// discard, so the bug is invisible in the stream and plain in the returned values.
	count[0] = 0

	var next [maxTreePath + 2]uint32
	code := uint32(0)
	for l := 1; l <= maxTreePath; l++ {
		code = (code + count[l-1]) << 1
		next[l] = code
	}
	codes := make([]uint32, len(lens))
	for i, l := range lens {
		if l != 0 {
			codes[i] = next[l]
			next[l]++
		}
	}
	return codes
}
