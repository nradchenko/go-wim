// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

// DefaultChunkSize is the uncompressed size of one chunk of a compressed resource, and the
// value every WIM of this version in the wild uses. It is also the LZX window, which is why the
// codec cannot code a larger one.
const DefaultChunkSize = 32768

// The types here describe one image's entry in a WIM's XML data — the UTF-16 document a WIM
// carries after its blob table. Only what a caller chooses is modelled: the counts, sizes, and
// timestamps in that document are computed from the capture itself and are not settable.

// ImageInfo describes an image being captured.
type ImageInfo struct {
	// Name is the image's <NAME>. It is what wimlib and DISM show as the image's identity.
	Name string
	// Description is the image's optional <DESCRIPTION>.
	Description string
	// Boot marks this image bootable: it becomes the WIM's boot index, and the header's
	// boot-metadata resource points at this image's metadata. A loader reads the image the
	// boot index names.
	Boot bool
	// Windows, when non-nil, adds the <WINDOWS> block describing the Windows installation
	// the image holds.
	Windows *WindowsInfo
}

// WindowsInfo is an image's <WINDOWS> block. Zero fields are omitted from the XML.
type WindowsInfo struct {
	Arch       Arch
	Version    Version
	SystemRoot string
}

// Arch is the processor architecture recorded in <WINDOWS><ARCH>, using Windows' own
// PROCESSOR_ARCHITECTURE numbering.
type Arch int

// The architectures a WIM of this vintage records.
const (
	ArchIntel Arch = 0 // x86
	ArchAMD64 Arch = 9 // x64
)

// Version is a Windows build version, recorded in <WINDOWS><VERSION>, in the four parts that
// element carries: 5.1.2600.5512 is one such version.
type Version struct {
	Major   int
	Minor   int
	Build   int
	SPBuild int
	SPLevel int
}
