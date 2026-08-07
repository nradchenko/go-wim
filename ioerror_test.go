// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"errors"
	"io"
	"io/fs"
	"testing"
)

// The backing an image is read from can fail — a network filesystem, a failing disk, a truncated
// download. Every ErrCorrupt path is exercised elsewhere; these check the other axis, that a
// failing io.ReaderAt is reported rather than absorbed. It is the axis where a mistake is silent:
// an error dropped because the byte count happened to look right yields a short file, not a
// failure.

var errBacking = errors.New("backing failed")

// failingReaderAt serves the first n bytes' worth of reads and fails every one after that, so a
// test can put the failure at a chosen stage of the parse.
type failingReaderAt struct {
	b     []byte
	after int // number of successful ReadAt calls before failing
	calls int
}

func (f *failingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	f.calls++
	if f.calls > f.after {
		return 0, errBacking
	}
	if off >= int64(len(f.b)) {
		return 0, io.EOF
	}
	n := copy(p, f.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// TestBackingFailurePropagates walks the failure through each stage of opening and reading an
// image. The stages are found by counting reads rather than named individually, so this keeps
// covering them if the parse changes what it reads and when.
func TestBackingFailurePropagates(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX
	b := captureBytes(t, lzxCaptureFixture(), opts)

	// How many reads a complete open-and-read takes, so the failure can be placed inside it.
	counter := &failingReaderAt{b: b, after: 1 << 30}
	rd, err := Open(counter, int64(len(b)))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	im, err := rd.Boot()
	if err != nil {
		t.Fatalf("Boot: %v", err)
	}
	if _, err := fs.ReadFile(im.FS(), "windows/system32/big.txt"); err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	total := counter.calls
	if total < 4 {
		t.Fatalf("a full read took %d ReadAt calls, too few to place a failure inside", total)
	}

	for after := range total {
		f := &failingReaderAt{b: b, after: after}
		rd, err := Open(f, int64(len(b)))
		if err != nil {
			if !errors.Is(err, errBacking) {
				t.Errorf("failing after %d reads: Open gave %v, want it to be %v", after, err, errBacking)
			}
			continue
		}
		im, err := rd.Boot()
		if err != nil {
			if !errors.Is(err, errBacking) {
				t.Errorf("failing after %d reads: Boot gave %v, want it to be %v", after, err, errBacking)
			}
			continue
		}
		got, err := fs.ReadFile(im.FS(), "windows/system32/big.txt")
		if err == nil {
			t.Errorf("failing after %d of %d reads: the file read back whole (%d bytes) with no error",
				after, total, len(got))
			continue
		}
		if !errors.Is(err, errBacking) {
			t.Errorf("failing after %d reads: ReadFile gave %v, want it to be %v", after, err, errBacking)
		}
	}
}

// TestTruncatedWIMIsRefused covers the other shape a damaged backing takes: the bytes are there,
// there are just not enough of them. Each cut lands in a different structure, and none may read
// back as a valid but smaller image.
func TestTruncatedWIMIsRefused(t *testing.T) {
	opts := testOptions()
	opts.Compression = CompressLZX
	good := captureBytes(t, lzxCaptureFixture(), opts)

	for _, frac := range []int{2, 4, 8, 16, 64} {
		b := good[:len(good)/frac]
		rd, err := OpenBytes(b)
		if err != nil {
			continue // refused at open, which is the expected outcome for most cuts
		}
		im, err := rd.Boot()
		if err != nil {
			continue
		}
		// If it opened, no file may read back as content: the resources are past the cut.
		err = fs.WalkDir(im.FS(), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if _, err := fs.ReadFile(im.FS(), p); err != nil {
				return err
			}
			return nil
		})
		if err == nil {
			t.Errorf("a WIM truncated to 1/%d of its length read back completely", frac)
		}
	}
}
