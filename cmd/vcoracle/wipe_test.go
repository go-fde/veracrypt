package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/go-fde/veracrypt"
)

// retaining wraps the stand-in so that the test keeps the buffers the XTS
// tool hands back: openHeader returns the master keys as a slice of one.
func retaining(dumpOut string, dumpErr error) (tools, *[][]byte) {
	var kept [][]byte
	base := aesOnly()
	tl := base
	tl.xts = func(c string, key, n, data []byte, decrypt bool) ([]byte, error) {
		out, err := base.xts(c, key, n, data, decrypt)
		if len(out) == 448 {
			kept = append(kept, out)
		}
		return out, err
	}
	if dumpErr == nil {
		tl.dump = func(string) (string, error) { return dumpOut, nil }
	}
	return tl, &kept
}

// A backup header with other (but well-formed) master keys is a FAIL, and its
// keys are wiped too.
func TestBackupWithOtherMasterKeysFails(t *testing.T) {
	base := aesOnly()
	tl := base
	n := 0
	var kept [][]byte
	tl.xts = func(c string, key, nonce, data []byte, decrypt bool) ([]byte, error) {
		out, err := base.xts(c, key, nonce, data, decrypt)
		if err == nil && len(out) == 448 {
			n++
			if n == 2 {
				out[192] ^= 1
				binary.BigEndian.PutUint32(out[8:], crc32.ChecksumIEEE(out[192:448]))
				binary.BigEndian.PutUint32(out[188:], crc32.ChecksumIEEE(out[:188]))
			}
			kept = append(kept, out)
		}
		return out, err
	}
	v := check(tl, t.TempDir(), []byte("a-passphrase-long-enough"), chainIndex(t, veracrypt.AES), kdf{veracrypt.Argon2id, ""})
	if v.status != "FAIL" || !strings.Contains(v.detail, "other master keys") {
		t.Fatalf("got %+v, want FAIL other master keys", v)
	}
	for i, b := range kept {
		if !bytes.Equal(b[192:448], make([]byte, 256)) {
			t.Errorf("master keys of header %d left in memory", i)
		}
	}
}

// The master keys of both headers are wiped on success and on a failure after
// they were found (cryptsetup's output does not parse).
func TestMasterKeysWipedOnEveryPath(t *testing.T) {
	pass := []byte("a-passphrase-long-enough")
	zero := make([]byte, 256)
	k := kdf{veracrypt.Argon2id, ""}

	tl, kept := retaining("", bytes.ErrTooLarge)
	if v := check(tl, t.TempDir(), pass, chainIndex(t, veracrypt.AES), k); v.status != "OK" {
		t.Fatal(v)
	}
	if len(*kept) != 2 {
		t.Fatalf("%d header buffers", len(*kept))
	}
	for i, b := range *kept {
		if !bytes.Equal(b[192:448], zero) {
			t.Errorf("success: master keys of header %d left in memory", i)
		}
	}

	tl, kept = retaining("garbage", nil)
	if v := check(tl, t.TempDir(), pass, chainIndex(t, veracrypt.AES), k); v.status != "FAIL" {
		t.Fatal(v)
	}
	if len(*kept) != 2 {
		t.Fatalf("%d header buffers", len(*kept))
	}
	for i, b := range *kept {
		if !bytes.Equal(b[192:448], zero) {
			t.Errorf("failure: master keys of header %d left in memory", i)
		}
	}
}
