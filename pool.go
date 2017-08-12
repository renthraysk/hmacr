package hmacr

import (
	"hash"
	"sync"
)

// Pool is a pool of HMAC resources for a specific hash.
type Pool struct {
	pool sync.Pool
}

// NewPool creates a pool of HMAC resources with specified hash, h.
func NewPool(h func() hash.Hash) *Pool {
	return &Pool{sync.Pool{New: func() interface{} { return New(h, nil) }}}
}

// Get retrieves a HMAC from pool of resources and initialised with given key.
func (pool *Pool) Get(key []byte) HMAC {
	r := pool.pool.Get().(HMAC)
	r.SetKey(key)
	return r
}

// Put release a MAC back to the pool. Attempts to scrub the key used.
func (pool *Pool) Put(m HMAC) {
	m.ClearKey()
	pool.pool.Put(m)
}

// HMAC using pooled HMAC resources.
func (pool *Pool) HMAC(in, key []byte, data ...[]byte) []byte {
	mac := pool.Get(key)
	for _, d := range data {
		mac.Write(d)
	}
	in = mac.Sum(in)
	pool.Put(mac)
	return in
}

// HKDF using pooled HMAC resources.
func (pool *Pool) HKDF(p, secret, salt, info []byte) (int, error) {
	mac := pool.Get(salt)
	n, err := hkdfIntern(mac, p, secret, info)
	pool.Put(mac)
	return n, err
}

// PBKDF2 using pooled HMAC resources.
func (pool *Pool) PBKDF2(p, password, salt []byte, iter int) (int, error) {
	mac := pool.Get(password)
	n, err := pbkdf2Intern(mac, p, salt, iter)
	pool.Put(mac)
	return n, err
}
