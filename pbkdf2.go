package hmacr

import "hash"

// PBKDF2 fills byte slice, p, with PBKDF2 result from password, salt and iteration count.
func PBKDF2(h func() hash.Hash, p, password, salt []byte, iter int) (int, error) {
	return pbkdf2Intern(New(h, password), p, salt, iter)
}

func pbkdf2Intern(mac HMAC, p, salt []byte, iter int) (int, error) {

	n := len(p)
	s := mac.Size()
	b := 0

	// Ensure minimum of 4 bytes
	tmp := make([]byte, s+4)
	for i := 0; i < n; i += s {
		mac.Reset()
		mac.Write(salt)
		b++
		tmp[0] = byte(b >> 24)
		tmp[1] = byte(b >> 16)
		tmp[2] = byte(b >> 8)
		tmp[3] = byte(b)
		mac.Write(tmp[:4])
		mac.Sum(tmp[:0])

		nn := copy(p[i:], tmp[:s])
		q := p[i : i+nn]
		for j := 2; j <= iter; j++ {
			mac.Reset()
			mac.Write(tmp[:s])
			mac.Sum(tmp[:0])
			for k := 0; k < nn; k++ {
				q[k] ^= tmp[k]
			}
		}
	}
	return n, nil
}
