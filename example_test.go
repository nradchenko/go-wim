// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim_test

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"testing/fstest"

	"github.com/nradchenko/go-wim"
	"github.com/nradchenko/go-wim/lzx"
)

// A security descriptor is opaque to this package; a real caller supplies one its target
// Windows accepts. This is a minimal self-relative descriptor so the examples run.
var descriptor = []byte{
	0x01, 0x00, 0x00, 0x80, // revision, sbz, SE_SELF_RELATIVE
	0x14, 0x00, 0x00, 0x00, // owner offset
	0x20, 0x00, 0x00, 0x00, // group offset
	0x00, 0x00, 0x00, 0x00, // no SACL
	0x00, 0x00, 0x00, 0x00, // no DACL
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, // S-1-5-18
	0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, // S-1-5-18
}

// Capture a directory into a bootable single-image WIM.
func ExampleCaptureDir() {
	err := wim.CaptureDir(context.Background(), "tree", "out.wim",
		wim.ImageInfo{
			Name: "Image",
			Boot: true,
			Windows: &wim.WindowsInfo{
				Arch:    wim.ArchIntel,
				Version: wim.Version{Major: 5, Minor: 1, Build: 2600},
			},
		},
		wim.Options{Security: wim.UniformSecurity(descriptor)},
	)
	if err != nil {
		log.Fatal(err)
	}
}

// Capture an in-memory tree, which is all a Writer needs — any fs.FS will do.
func ExampleCapture() {
	src := fstest.MapFS{
		"boot.ini":            &fstest.MapFile{Data: []byte("[boot loader]\n")},
		"system32/kernel.dll": &fstest.MapFile{Data: []byte("MZ...")},
	}

	out, err := os.CreateTemp("", "example-*.wim")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(out.Name())
	defer out.Close()

	err = wim.Capture(context.Background(), out, src,
		wim.ImageInfo{Name: "Image"},
		wim.Options{
			Security: wim.UniformSecurity(descriptor),
			// Deduplicated by content, so one descriptor for every file costs one entry.
			Compression: wim.CompressLZX,
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("captured")
	// Output: captured
}

// Give different files different descriptors.
func ExampleSecurityFunc() {
	security := func(_ string, d fs.DirEntry) []byte {
		if d.IsDir() {
			return directoryDescriptor
		}
		return descriptor
	}
	_ = wim.Options{Security: security}
}

var directoryDescriptor = descriptor

// Compress and decompress a single chunk with the codec directly.
func ExampleCompressor() {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = "the quick brown fox "[i%20]
	}

	packed := make([]byte, len(data))
	n, ok := (&lzx.Compressor{}).Compress(packed, data)
	if !ok {
		// Not an error: the chunk did not get smaller, so a caller stores it raw. That is
		// how the format carries incompressible data.
		log.Fatal("declined")
	}

	round := make([]byte, len(data))
	if err := lzx.Decompress(round, packed[:n]); err != nil {
		log.Fatal(err)
	}
	// The exact compressed size is deliberately not asserted: it is a property of the parse,
	// and improving the parse should not break an example.
	fmt.Printf("compressed: %t, round trip ok: %t\n", n < len(data), string(round) == string(data))
	// Output: compressed: true, round trip ok: true
}
