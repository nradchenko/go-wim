// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"strings"
	"unicode/utf16"
)

// buildXML renders the WIM's XML data: one <IMAGE> per image, then the WIM's own total. The
// element order follows what wimlib and imagex emit. wimTotalBytes is the offset the XML
// resource itself is written at — which is the header, every resource, and the blob table, and
// is what both writers record there.
func buildXML(images []imageEntry, wimTotalBytes int64) []byte {
	var b strings.Builder
	b.WriteString("<WIM>")
	for i, im := range images {
		fmt.Fprintf(&b, `<IMAGE INDEX="%d">`, i+1)
		writeElem(&b, "NAME", im.info.Name)
		if im.info.Description != "" {
			writeElem(&b, "DESCRIPTION", im.info.Description)
		}
		fmt.Fprintf(&b, "<DIRCOUNT>%d</DIRCOUNT>", im.dirCount)
		fmt.Fprintf(&b, "<FILECOUNT>%d</FILECOUNT>", im.fileCount)
		fmt.Fprintf(&b, "<TOTALBYTES>%d</TOTALBYTES>", im.totalBytes)
		// Hard links are not captured, so no bytes are saved by them.
		b.WriteString("<HARDLINKBYTES>0</HARDLINKBYTES>")
		writeTimeElem(&b, "CREATIONTIME", im.created)
		writeTimeElem(&b, "LASTMODIFICATIONTIME", im.modified)
		if w := im.info.Windows; w != nil {
			b.WriteString("<WINDOWS>")
			if w.SystemRoot != "" {
				writeElem(&b, "SYSTEMROOT", w.SystemRoot)
			}
			fmt.Fprintf(&b, "<ARCH>%d</ARCH>", int(w.Arch))
			if v := w.Version; v != (Version{}) {
				fmt.Fprintf(&b, "<VERSION><MAJOR>%d</MAJOR><MINOR>%d</MINOR><BUILD>%d</BUILD><SPBUILD>%d</SPBUILD><SPLEVEL>%d</SPLEVEL></VERSION>",
					v.Major, v.Minor, v.Build, v.SPBuild, v.SPLevel)
			}
			b.WriteString("</WINDOWS>")
		}
		b.WriteString("</IMAGE>")
	}
	fmt.Fprintf(&b, "<TOTALBYTES>%d</TOTALBYTES></WIM>", wimTotalBytes)
	return utf16LE(b.String())
}

// writeElem writes a text element, escaping the text — an image name is caller-supplied and
// may hold characters XML reserves.
func writeElem(b *strings.Builder, name, text string) {
	fmt.Fprintf(b, "<%s>", name)
	_ = xml.EscapeText(b, []byte(text))
	fmt.Fprintf(b, "</%s>", name)
}

// writeTimeElem writes a FILETIME as the split high/low hex words the schema uses.
func writeTimeElem(b *strings.Builder, name string, ft uint64) {
	fmt.Fprintf(b, "<%s><HIGHPART>0x%08X</HIGHPART><LOWPART>0x%08X</LOWPART></%s>",
		name, uint32(ft>>32), uint32(ft), name)
}

// utf16LE encodes s as the little-endian UTF-16 the XML resource is stored in, led by a byte
// order mark. The mark is part of the resource, and is counted in its recorded size.
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2+2*len(u))
	binary.LittleEndian.PutUint16(out, 0xfeff)
	for i, c := range u {
		binary.LittleEndian.PutUint16(out[2+2*i:], c)
	}
	return out
}
