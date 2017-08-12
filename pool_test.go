package hmacr

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestPoolHMAC(t *testing.T) {

	pools := make(map[crypto.Hash]*Pool)

	for i, tt := range hmacTests {

		pool, ok := pools[tt.cryptoHash]
		if !ok {
			pool = NewPool(tt.hash)
			pools[tt.cryptoHash] = pool
		}
		h := pool.Get(tt.key)

		if s := h.Size(); s != tt.size {
			t.Errorf("Size: got %v, want %v", s, tt.size)
		}
		if b := h.BlockSize(); b != tt.blocksize {
			t.Errorf("BlockSize: got %v, want %v", b, tt.blocksize)
		}
		for j := 0; j < 2; j++ {
			h.Write(tt.in)
			// Repetitive Sum() calls should return the same value
			for k := 0; k < 2; k++ {
				sum := fmt.Sprintf("%x", h.Sum(nil))
				if sum != tt.out {
					t.Errorf("test %d.%d.%d: have %s want %s\n", i, j, k, sum, tt.out)
				}
			}

			// Second iteration: make sure reset works.
			h.Reset()
		}

		pool.Put(h)
	}
}

func TestPoolHKDF(t *testing.T) {
	var buf [3 * sha256.Size]byte
	var secret, salt, info [sha256.Size]byte

	pool := NewPool(sha256.New)

	pool.HKDF(buf[:], secret[:], salt[:], info[:])
}

func BenchmarkPoolHKDF(b *testing.B) {

	var buf [3 * sha256.Size]byte
	var secret, salt, info [sha256.Size]byte

	pool := NewPool(sha256.New)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	for i := 0; i < b.N; i++ {
		pool.HKDF(buf[:], secret[:], salt[:], info[:])
	}

}

func BenchmarkPoolHKDFAwkwardSize(b *testing.B) {
	// Not a multiple of sha256.Size
	var buf [3*sha256.Size - 1]byte
	var secret, salt, info [sha256.Size]byte

	pool := NewPool(sha256.New)

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(buf)))

	for i := 0; i < b.N; i++ {
		pool.HKDF(buf[:], secret[:], salt[:], info[:])
	}

}
