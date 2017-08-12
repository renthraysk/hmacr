# HMACr

Equivalent to golang.org/crypto/hmac, but with added SetKey(key []byte)/ClearKey() methods.
Allowing the same HMAC to be reused in HMAC based KDFs algorithms, for example HKDF().
Using a pool of HMACs, permits a maximum of one allocation per HKDF() call. 