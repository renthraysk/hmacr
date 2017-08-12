package hmacr

import (
	"errors"
	"hash"
)

// HKDF fills byte slice, p, with the secret keying material to expand with optional salt and info.
func HKDF(h func() hash.Hash, p, secret, salt, info []byte) (int, error) {
	return hkdfIntern(New(h, salt), p, secret, info)
}

func hkdfIntern(mac HMAC, p, secret, info []byte) (int, error) {

	n := len(p)
	if n == 0 {
		return 0, nil
	}
	s := mac.Size()
	if n > s*255 {
		return 0, errors.New("hkdf: exceeds maximum amount of entropy")
	}

	/* Need space for a mac result
	p's len is > 0 and if a multiple of the mac output size can work without needing make()
	*/
	var tmp []byte
	r := n % s
	if r == 0 {
		tmp = p[:s]
		n -= s // ensures have a mac.Sum todo after loop
	} else {
		tmp = make([]byte, s)
		n -= r
	}
	mac.Write(secret)
	mac.SetKey(mac.Sum(tmp[:0]))
	mac.Write(info)
	b := byte(0x01)
	tmp[0] = b
	mac.Write(tmp[:1])
	i := 0
	for i < n {
		mac.Sum(p[:i])
		mac.Reset()
		mac.Write(p[i : i+s])
		mac.Write(info)
		b++
		i += s
		// p[i] is safe, as Sum() or copy() will overwrite
		p[i] = b
		mac.Write(p[i : i+1])
	}
	if r == 0 {
		mac.Sum(p[:i])
		return i + s, nil
	}
	return i + copy(p[i:], mac.Sum(tmp[:0])), nil
}
