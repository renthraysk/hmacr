package hmacr

import (
	"crypto/subtle"
	"hash"
)

// HMAC extension of hash.Hash interface with SetKey and ClearKey methods.
type HMAC interface {
	hash.Hash

	ClearKey()
	SetKey(key []byte)
}

type hmacr struct {
	inner hash.Hash
	outer hash.Hash
	ipad  []byte
	opad  []byte
}

// New create a new HMAC with given key.
func New(h func() hash.Hash, key []byte) HMAC {
	inner := h()
	n := inner.BlockSize()
	b := make([]byte, 2*n, 2*n+inner.Size())
	r := &hmacr{
		inner: inner,
		outer: h(),
		ipad:  b[:n:n],
		opad:  b[n:],
	}
	r.SetKey(key)
	return r
}

func (r *hmacr) Size() int {
	return r.inner.Size()
}

func (r *hmacr) BlockSize() int {
	return r.inner.BlockSize()
}

func (r *hmacr) ClearKey() {
	for i := range r.ipad {
		r.ipad[i] = 0
	}
	for i := range r.opad {
		r.opad[i] = 0
	}
	r.inner.Reset()
	r.outer.Reset()
}

func (r *hmacr) SetKey(key []byte) {
	for i := range r.ipad {
		r.ipad[i] = 0
	}
	r.inner.Reset()
	if len(key) > r.inner.BlockSize() {
		r.inner.Write(key)
		r.inner.Sum(r.ipad[:0])
		r.inner.Reset()
	} else {
		copy(r.ipad, key)
	}
	copy(r.opad, r.ipad)
	for i := range r.ipad {
		r.ipad[i] ^= 0x36
	}
	for i := range r.opad {
		r.opad[i] ^= 0x5C
	}
	r.inner.Write(r.ipad)
}

func (r *hmacr) Reset() {
	r.inner.Reset()
	r.inner.Write(r.ipad)
}

func (r *hmacr) Write(in []byte) (int, error) {
	return r.inner.Write(in)
}

func (r *hmacr) Sum(in []byte) []byte {
	r.outer.Reset()
	r.outer.Write(r.inner.Sum(r.opad))
	return r.outer.Sum(in)
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(mac1, mac2 []byte) bool {
	// We don't have to be constant time if the lengths of the MACs are
	// different as that suggests that a completely different hash function
	// was used.
	return subtle.ConstantTimeCompare(mac1, mac2) == 1
}
