# go-wim

A native Go library for reading and writing Windows Imaging (`.wim`) files.

```go
err := wim.CaptureDir(ctx, "tree", "out.wim", wim.ImageInfo{Name: "Image", Boot: true},
    wim.Options{Security: wim.UniformSecurity(sd)})
```

Writing walks a file tree, deduplicates streams by SHA-1, and emits the dentry tree, the security
table, the blob table and the XML. Resources are stored uncompressed or LZX-compressed. The LZX
codec is in [`lzx`](lzx), works in both directions, and is usable on its own.

Reading presents an image as an [`fs.FS`](https://pkg.go.dev/io/fs#FS):

```go
rd, err := wim.Open(f, size)   // or wim.OpenBytes(b)
im, err := rd.Boot()           // or rd.Image(1), rd.Images()
data, err := fs.ReadFile(im.FS(), "windows/system32/ntoskrnl.exe")
```

so anything already written against a filesystem — `fs.WalkDir`, `fs.Stat`, `http.FS` — works
against a WIM unchanged. A read decodes only the chunks it touches, so listing an image costs its
metadata rather than its contents, and pulling one file out of a large image costs that file.
Paths are matched exactly, including case; wrap the `fs.FS` if you want Windows' own
case-insensitive matching.

What this aims at is a **correct, dependency-free implementation, not a fast one** — no
subprocess, no cgo, no imaging tool on the build host. It does not try to match wimlib's
throughput, and [Performance](#performance) says plainly where that costs you.

## Why

Go could read a WIM but not write one, and the LZX variant the format uses had no Go
implementation in either direction. That variant is distinct from the cabinet LZX that Go and C
libraries do implement: a fixed 32 KiB window, a different block-size encoding, per-chunk resets
of the window, the Huffman trees and the recent-offset state, and an unconditional Intel E8
filter at a fixed magic size. A cabinet decoder misreads a WIM chunk from its first field on.

The per-chunk reset is the interesting property: it is what lets a reader decode any chunk of a
resource without the ones before it, which is what makes a WIM randomly accessible.

## Two things the format will let you get wrong

Both are legal per the format, pass verification under other tools, and produce an image Windows
cannot use — one unreadable, one unmountable. This package refuses them instead.

**Some readers take the metadata resource's compression from the header rather than from its own
flag.** They decode the metadata with the codec the header names, without consulting that
resource's compressed bit. An image declaring LZX while storing its metadata raw is therefore
well-formed and passes `wimlib-imagex verify`, and yet its metadata decodes to garbage in such a
reader — the file list, and with it everything the image contains, becomes unreadable. That is not
hypothetical: we shipped one, and it failed late and silently, with nothing in the image pointing
at the cause. So a compressed image always compresses its metadata here, even when that costs
bytes.

**Every dentry needs a security ID.** A capture from a POSIX filesystem has no NT security data
to read, and the natural result is `security_id = -1` throughout — which Windows rejects at
mount. `Options.Security` therefore has no default, and a `SecurityFunc` returning nil for any
file is an error rather than a way to skip it. What belongs *in* a descriptor is not this
package's business; it treats them as opaque bytes and deduplicates them by content.

## Compatibility

This writes the general-purpose WIM format: **version 0x00010D00**, non-solid, LZX-compressed or
uncompressed, 32 KiB chunks — the same format `install.wim` and `boot.wim` have used across
Windows releases. The header it emits is byte-for-byte identical to the one Microsoft's own
imagex writes.

Deliberately not written, all optional: LZMS and solid resources (the `.esd` format), XPRESS,
integrity tables, reparse points, hard links, short names, alternate data streams, extended
attributes.

The reader accepts the same format and is refused by name outside it — XPRESS, LZMS, solid or
spanned resources, and split WIMs each report what they are rather than failing obscurely. It
does handle constructs the writer never emits, because real images carry them: alternate data
streams are stepped over to find the next entry, a directory reparse point is listed but never
followed, and a metadata resource whose reference count has been cleared is recognised as a
superseded image rather than counted as a live one. That last one is not hypothetical — the
Windows AIK's WinPE image declares one image and carries four metadata resources.

A damaged image stays inspectable. A file whose content the image does not actually hold is listed
with everything else and fails only when opened, naming what is missing — rather than reading back
as the empty file it would otherwise be indistinguishable from.

The reader is deliberately more permissive than the strictest consumers of the format. It takes
each resource's storage from that resource's own flag rather than from the WIM header, which is
the more literal reading of what is on disk — and which means it will read images that something
else rejects, the metadata case above among them. A successful read here says the image parses,
not that every other tool will accept it.

Verification status, stated precisely:

| | |
|---|---|
| header and structures match Microsoft imagex's output | measured |
| every resource verified and applied back by wimlib | measured |
| parsed by go-winio's independent reader | measured |
| a written image boots a Windows installation | measured |
| read by DISM/WIMGAPI | inferred from format identity |
| reader byte-identical to wimlib on a real image | measured — a Windows PE image, ~8,600 files, ~770 MB |
| reader round-trips this package's own captures | measured — both codecs |
| reader handles alternate streams and reparse points | measured on hand-built metadata only |

Booting has been exercised on one Windows release and one architecture, so read that row as
"this works" rather than "this works everywhere". The last row follows from emitting the
documented version with the documented codec, and from the header matching imagex's byte for
byte — but it has not been exercised directly, so it is listed as an inference rather than a
result.

Read the alternate-streams row precisely: none of the images tested against carries a named
alternate data stream or a reparse point, so those two branches are exercised by hand-built
metadata rather than by a real capture. That is weaker evidence, and it is listed as what it is.

## Performance

**Speed is not a goal of this package, and the numbers below are not a competitive claim.** What
it sets out to be is a *native* implementation: correct, verified against wimlib, and usable from
a Go program with no subprocess, no cgo, and no imaging tool on the build host. Matching a mature
C implementation with a decade of optimisation behind it is not something it attempts, and where
it falls short it falls short — the measurements are published so you can tell whether it fits
your use, not to suggest it competes.

So: if you are extracting or capturing whole images in bulk and throughput is what matters, use
wimlib. If you want a WIM read or written from Go without depending on it, this is that, and the
numbers tell you what it costs you.

The gaps are understood rather than mysterious, and are recorded here because knowing *which*
part is slow is worth more than a single figure — see the notes under each table.

Measured against wimlib on a Windows PE image of roughly 8,600 files and about 770 MB
uncompressed, on a current multi-core desktop, with everything in cache so no disk is in the loop.
Figures are rounded; treat them as the shape of the difference rather than as a benchmark to
reproduce. Both sides were checked to be doing the same work: the image carries no integrity
table, so `wimverify` decompresses and hashes every resource, and `user ≈ real` on its runs
confirms it is single-threaded.

**Decoding**, resource for resource (one reused buffer, no per-file allocation, no hashing):

| | throughput | |
|---|---|---|
| wimlib `verify` (decompress + SHA-1) | **~570 MB/s** | 1 core |
| go-wim, resource by resource | **~70 MB/s** | 1 core, roughly 8x slower |
| go-wim, through the `fs.FS` | ~50 MB/s | adds per-file allocation and the tree walk |

**Encoding** the same tree, LZX, 32 KiB chunks:

| | wimlib | go-wim | |
|---|---|---|---|
| 1 thread | ~26 s | **~26 s** | parity |
| all cores | ~3.4 s | ~8.8 s | roughly 2.5x slower |
| output | ~166 MB | ~172 MB | about 4% larger |

Read those three rows as three different findings. Single-threaded compression is **at parity** —
the LZX encoder is competitive. Parallel compression is not, and the arithmetic says why: solving
for the serial fraction gives wimlib a little over a second of non-parallel work against go-wim's
seven, so what limits the all-cores run is the path around the codec, not the codec. Capturing
hashes every file and the write pass re-reads and re-hashes it; that is serial, and it is where
the difference lives.

Decoding is the weakest column. A CPU profile puts **about three quarters of the time in Huffman
symbol decoding**: the decoder walks a canonical code one bit at a time, so a nine-bit symbol
costs nine iterations where a table-driven decoder costs one lookup. That shape was inherited from
a setting where a decode table would have cost heap that was not available. Building the
trees is *not* the cost — it is under 1% of runtime — so the usual objection to table-driven
decoding does not apply here.

It is worth knowing the ceiling before anyone acts on that: the remaining quarter is match copying
and the Intel E8 filter, so even an infinitely fast symbol decoder would only reach about 4x, and a
realistic one lands in the low hundreds of MB/s. It would close most of this gap, not all of it.

Whether any of it matters depends on what you read. Whole-image extraction: about 770 MB takes
some 16 seconds against wimlib's 1.5. Inspecting an image: it does not — dumping a registry hive
out of one takes tens of milliseconds and listing an image rather less, because a read decodes
only the chunks it touches.

## Determinism

The same tree produces the same bytes. Timestamps come from the tree or from
`Options.Timestamp`, the GUID is derived from the image's content rather than randomised, and
chunk results are placed by index rather than as workers finish — so `Options.Concurrency`
changes only how long a capture takes.

## Testing

There is **no CI** yet. The suite runs locally and is worth running:

```sh
go test ./...          # round trips against an independent reader
go test -race ./...    # the parallel compression path
```

Coverage leans on implementations that share no code with this one:

- **go-winio's WIM parser** reads back what the writer produces — no external tool needed, so
  this runs anywhere.
- **wimlib**, when `wimcapture`/`wimapply`/`wimlib-imagex` are on `PATH`, verifies every
  resource's SHA-1 and round-trips an image back to a tree. Tests skip cleanly without it.
- Two environment-gated sweeps for bulk validation: `GOWIM_CORPUS=<dir of .wim files>`
  decodes every resource in a corpus and checks it against its recorded hash, and
  `GOWIM_LZX_CORPUS=<dir>` measures the compressor's ratio and throughput against real files.

## Compression

Roughly 4.5% larger than wimlib on the same input (41.1% of raw against 39.3%), at about 80% of
its single-threaded speed, and parallel across cores. The difference is the parse strategy —
greedy with lazy matching here, near-optimal in wimlib — not the framing: the Huffman trees are
1.67% of output, and deeper match search buys 0.14%. Closing it needs a real optimal parser.

## Provenance

An independent reimplementation from the documented WIM format.

- The MIT-licensed [go-winio](https://github.com/microsoft/go-winio) WIM reader (Copyright (c)
  Microsoft Corporation) was consulted as a **format reference only**; no go-winio source is
  incorporated. It is also a test dependency, used as an independent reader.
- The LZX decoder, and the metadata parse the reader is built on, were ported from the author's
  own C implementations in [pe-wimmf](https://github.com/nradchenko/pe-wimmf) (`reader/lzx.c`,
  `reader/wimcore.c`). That project is Apache-2.0 and remains so; its sole copyright holder is the
  author of this package, who licenses these ports under MIT here. No third-party code is carried
  across.
- **wimlib is used only as a black-box oracle at test time.** It is GPL, and is neither linked
  into nor distributed with this software.
- Field values and structure layouts were measured from real images — wimlib's captures and
  Microsoft imagex's — rather than assumed.

No Microsoft binaries or Windows files are included in this repository.

## License

Copyright © 2026 Nikita Radchenko

Licensed under the [MIT License](LICENSE).

The library has no runtime dependencies; [go-winio](https://github.com/microsoft/go-winio) (MIT)
is used by the tests only.

## Disclaimer

go-wim is **not affiliated with, endorsed by, or derived from the code of** Microsoft. Windows
is a trademark of Microsoft Corporation.
