package veracrypt

import (
	"errors"
	"testing"

	"github.com/go-encryptions/kdfbudget"
)

// countDerives replaces deriveKey with a counter for the test's duration.
// With real set, the real derivation still runs; otherwise it returns a key
// that opens nothing, so an allowed Argon2id run costs no time.
func countDerives(t *testing.T, real bool) *int {
	t.Helper()
	n := new(int)
	old := deriveKey
	deriveKey = func(v kdfVariant, pool, salt []byte, pim int) []byte {
		*n++
		if real {
			return v.derive(pool, salt, pim)
		}
		return make([]byte, headerKeyLen)
	}
	t.Cleanup(func() { deriveKey = old })
	return n
}

// TestBudgetArgon2idPIM: the default MaxPIM of 2000 asks Argon2id for 1982
// passes over 1 GiB, four times kdfbudget's DefaultMaxWork. It was exempt
// from MaxIterations and ran in full; now it is refused before deriving.
func TestBudgetArgon2idPIM(t *testing.T) {
	img, _ := buildVolume(t, defaultVol(t))
	n := countDerives(t, false)
	b := kdfbudget.Default()
	_, err := openImg(t, img, Options{Password: []byte("pw"), KDF: Argon2id, PIM: 2000,
		Limits: Limits{Budget: b}})
	if !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongSecret) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
	if *n != 0 || b.Spent() != 0 {
		t.Fatalf("derivations %d, spent %d; a refusal must spend nothing", *n, b.Spent())
	}
	// Without a Budget in Limits the default applies all the same.
	if _, err := openImg(t, img, Options{Password: []byte("pw"), KDF: Argon2id, PIM: 2000}); !errors.Is(err, ErrLimit) || *n != 0 {
		t.Fatalf("nil Budget: err = %v after %d derivations", err, *n)
	}
}

// TestBudgetBoundary: one unit short refuses, the exact budget opens.
func TestBudgetBoundary(t *testing.T) {
	img, plain := buildVolume(t, defaultVol(t))
	o := Options{Password: []byte("pw"), TrueCryptOnly: true, KDF: SHA512}
	// PBKDF2-SHA-512, 1000 iterations, 3 output blocks of the 192-byte key:
	// 3 charges of 2 * 2 * 1000.
	const want = 3 * 2 * 2 * 1000
	n := countDerives(t, true)

	short := kdfbudget.Default()
	short.MaxWork = want - 1
	o.Limits.Budget = short
	if _, err := openImg(t, img, o); !errors.Is(err, ErrLimit) {
		t.Fatalf("one unit short: %v, want ErrLimit", err)
	}
	if *n != 0 {
		t.Fatalf("%d derivations on a refusal", *n)
	}

	exact := kdfbudget.Default()
	exact.MaxWork = want
	o.Limits.Budget = exact
	d, err := openImg(t, img, o)
	if err != nil {
		t.Fatalf("exact budget: %v", err)
	}
	if string(readAll(t, d)) != string(plain) || exact.Spent() != want || *n != 1 {
		t.Fatalf("spent %d of %d, %d derivations", exact.Spent(), want, *n)
	}
}

// TestBudgetArgon2idBoundary: the same boundary for Argon2id, whose charge is
// one run of passes * memKiB blocks (derivation stubbed: 1 GiB is not run).
func TestBudgetArgon2idBoundary(t *testing.T) {
	img, _ := buildVolume(t, defaultVol(t))
	n := countDerives(t, false)
	const pim = 2000
	want := uint64(pim-18) * (1 << 20) * kdfbudget.Argon2BlockCost
	o := Options{Password: []byte("pw"), KDF: Argon2id, PIM: pim}

	b := kdfbudget.Unlimited()
	b.MaxWork = want - 1
	o.Limits.Budget = b
	if _, err := openImg(t, img, o); !errors.Is(err, ErrLimit) || *n != 0 {
		t.Fatalf("one short: %v after %d derivations", err, *n)
	}
	b = kdfbudget.Unlimited()
	b.MaxWork = want
	o.Limits.Budget = b
	// Allowed: the key is stubbed, so the header does not open, and that is a
	// wrong secret, not a limit.
	if _, err := openImg(t, img, o); !errors.Is(err, ErrWrongSecret) || *n != 1 || b.Spent() != want {
		t.Fatalf("exact: %v, %d derivations, spent %d of %d", err, *n, b.Spent(), want)
	}
}

// TestBudgetHiddenSharesOne: a hidden-volume open tries two header offsets
// and both drain the same budget.
func TestBudgetHiddenSharesOne(t *testing.T) {
	img, _ := buildVolume(t, defaultVol(t)) // no hidden header: both trials miss
	const one = 3 * 2 * 2 * 1000
	o := Options{Password: []byte("pw"), TrueCryptOnly: true, KDF: SHA512, Hidden: true}
	n := countDerives(t, true)

	b := kdfbudget.Default()
	b.MaxWork = 2 * one
	o.Limits.Budget = b
	if _, err := openImg(t, img, o); !errors.Is(err, ErrWrongSecret) || *n != 2 || b.Spent() != 2*one {
		t.Fatalf("two headers: %v, %d derivations, spent %d", err, *n, b.Spent())
	}

	*n = 0
	b = kdfbudget.Default()
	b.MaxWork = 2*one - 1 // the second header does not fit what the first left
	o.Limits.Budget = b
	if _, err := openImg(t, img, o); !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongSecret) || *n != 1 {
		t.Fatalf("shared budget: %v, %d derivations", err, *n)
	}

	// Every open without a Budget starts from a fresh Default.
	*n = 0
	o.Limits.Budget = nil
	for range 3 {
		if _, err := openImg(t, img, o); !errors.Is(err, ErrWrongSecret) {
			t.Fatal(err)
		}
	}
}

// TestBudgetSkipsAndContinues: a refused variant is skipped, a cheaper one
// after it still runs; if none opens, the answer is ErrLimit.
func TestBudgetSkipsAndContinues(t *testing.T) {
	img, plain := buildVolume(t, defaultVol(t))
	countDerives(t, true)
	b := kdfbudget.Default()
	b.MaxWork = 3 * 2 * 2 * 1000 // the first variants (RIPEMD-160 x 2000: 10 blocks) do not fit
	d, err := openImg(t, img, Options{Password: []byte("pw"), TrueCryptOnly: true,
		Limits: Limits{Budget: b}})
	if err != nil {
		t.Fatalf("skip and continue: %v", err)
	}
	if string(readAll(t, d)) != string(plain) || d.Header().KDF != "pbkdf2-sha512-1000" {
		t.Fatalf("opened with %s", d.Header().KDF)
	}
	// A wrong password with a skipped variant is not a wrong secret.
	b = kdfbudget.Default()
	b.MaxWork = 3 * 2 * 2 * 1000
	if _, err := openImg(t, img, Options{Password: []byte("nope"), TrueCryptOnly: true,
		Limits: Limits{Budget: b}}); !errors.Is(err, ErrLimit) || errors.Is(err, ErrWrongSecret) {
		t.Fatalf("wrong password, skipped variant: %v, want ErrLimit", err)
	}
}

// TestPIMCeiling: VeraCrypt's own maxima hold however high MaxPIM goes.
func TestPIMCeiling(t *testing.T) {
	img, _ := buildVolume(t, defaultVol(t))
	n := countDerives(t, false)
	for name, o := range map[string]Options{
		"MAX_PIM_VALUE + 1":      {PIM: 2147469, Limits: Limits{MaxPIM: 1 << 30}},
		"MAX_BOOT_PIM_VALUE + 1": {PIM: 65536, System: true, Limits: Limits{MaxPIM: 1 << 30}},
	} {
		o.Password = []byte("pw")
		o.Limits.Budget = kdfbudget.Unlimited()
		if _, err := openImg(t, img, o); !errors.Is(err, ErrLimit) {
			t.Errorf("%s: %v, want ErrLimit", name, err)
		}
	}
	if *n != 0 {
		t.Fatalf("%d derivations", *n)
	}
}

// TestCostWide: the PBKDF2 iteration count of a large PIM does not fit 32 bits.
func TestCostWide(t *testing.T) {
	v := variant(t, "pbkdf2-sha512-500000")
	if iter, _ := v.cost(5_000_000); iter != 15000+1000*5_000_000 {
		t.Fatalf("iterations %d", iter)
	}
}

// TestChargeBlocks: one charge per output block of the 192-byte key.
func TestChargeBlocks(t *testing.T) {
	for _, c := range []struct {
		kdf    KDF
		blocks uint64
	}{{SHA512, 3}, {Whirlpool, 3}, {Streebog, 3}, {SHA256, 6}, {BLAKE2s, 6}, {RIPEMD160, 10}, {SHA1, 10}} {
		cost, _ := hashCost(c.kdf)
		v := kdfVariant{kdf: c.kdf, iter: 1000}
		b := kdfbudget.Unlimited()
		if err := v.charge(b, 0); err != nil {
			t.Fatal(err)
		}
		if want := c.blocks * 2 * cost * 1000; b.Spent() != want {
			t.Errorf("%s: spent %d, want %d", c.kdf, b.Spent(), want)
		}
	}
}
