// Copyright 2026 Nikita Radchenko
// SPDX-License-Identifier: MIT

package wim

import (
	"encoding/binary"
	"os/exec"
	"testing"
)

// testSecurityDescriptor is a minimal well-formed self-relative NT security descriptor: owner
// and group LocalSystem, no ACLs.
//
// It is a test fixture, not a recommendation. This package treats a descriptor as opaque bytes
// and takes no view on what should be in one — what a given Windows build requires of the
// descriptors in an image is the caller's business, and callers author their own.
func testSecurityDescriptor() []byte {
	// S-1-5-18: revision 1, one sub-authority, 6-byte big-endian authority 5, sub-authority 18.
	sid := make([]byte, 12)
	sid[0], sid[1], sid[7] = 1, 1, 5
	binary.LittleEndian.PutUint32(sid[8:], 18)

	const headerLen = 20 // revision, sbz, control, then four offsets
	sd := make([]byte, headerLen, headerLen+2*len(sid))
	sd[0] = 1                                        // revision
	binary.LittleEndian.PutUint16(sd[2:], 0x8000)    // SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(sd[4:], headerLen) // owner
	binary.LittleEndian.PutUint32(sd[8:], headerLen+uint32(len(sid)))
	// SACL and DACL offsets stay zero: absent, which is not the same as empty.
	return append(append(sd, sid...), sid...)
}

// mustRun runs an external tool and fails the test with its output if it errors.
func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// firstDiff returns the index of the first byte where a and b differ, or -1.
func firstDiff(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}
