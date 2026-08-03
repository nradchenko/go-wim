# go-wim

A native Go library for writing Windows Imaging (`.wim`) files.

```go
err := wim.CaptureDir(ctx, "tree", "out.wim", wim.ImageInfo{Name: "Image", Boot: true},
    wim.Options{Security: wim.UniformSecurity(sd)})
```

It walks a file tree, deduplicates streams by SHA-1, and emits the dentry tree, the security
table, the blob table and the XML. Resources are stored uncompressed or LZX-compressed. The LZX
codec is in [`lzx`](lzx), works in both directions, and is usable on its own.

This package **writes**. It parses enough of the format internally to place what it emits, and
the tests parse the output back, but there is no reader API.

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

**The metadata resource's compression follows the header, not its own flag.** A reader takes the
codec from the WIM header and decodes the metadata with it, without consulting that resource's
own compressed bit. An image declaring LZX while storing its metadata raw is therefore
well-formed and passes `wimlib-imagex verify`, yet its metadata decodes to garbage — the file
list, and with it everything the image contains, is unreadable. So a compressed image always
compresses its metadata, even when that costs bytes.

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

Verification status, stated precisely:

| | |
|---|---|
| header and structures match Microsoft imagex's output | measured |
| every resource verified and applied back by wimlib | measured |
| parsed by go-winio's independent reader | measured |
| a written image boots a Windows installation | measured |
| read by DISM/WIMGAPI | inferred from format identity |

Booting has been exercised on one Windows release and one architecture, so read that row as
"this works" rather than "this works everywhere". The last row follows from emitting the
documented version with the documented codec, and from the header matching imagex's byte for
byte — but it has not been exercised directly, so it is listed as an inference rather than a
result.

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
- The LZX decoder here was ported from the author's own C decoder in
  [pe-wimmf](https://github.com/nradchenko/pe-wimmf), which is Apache-2.0 and remains so in that
  repository; this port is MIT by the same author.
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
