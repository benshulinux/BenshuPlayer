// Package crypto implements the BenshuPlayer protocol ciphers.
//
// Every primitive here is re-implemented cleanly from the published
// protocol documentation; nothing is copied from the vendor binary.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Hardcoded symmetric material, identical across all released clients.
const (
	// PBKDFPassword is the PBKDF2 password embedded in every client.
	PBKDFPassword = "1981rlkRLK86tGnF8aGepr689dGWnrwU"
	// PBKDFSalt is the PBKDF2 salt.
	PBKDFSalt = "benshushu_salt"
	// PBKDFIters is the PBKDF2 iteration count.
	PBKDFIters = 65536
	// UniversalIV is the fixed AES-CBC IV used protocol-wide.
	UniversalIV = "4589benshu155889"
)

// ServerPublicKeyPEM is the RSA public key every client uses to wrap the
// 16-byte login session key (RFC 8017 PKCS#1 v1.5, padding mode 4).
const ServerPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9w4R1qJe0zKvLtJ6g4Q/
e7YOHcax6fgHAn2gFZKYOBedAT6cc750PCQ5XvhPgmueqxkXUayyL8WOGCun0e3E
Z2fV7iQMs9q3rL1PviQ8DDGcPz35T8iao/0xGza6H9SwwY4C3gGVetWCL7PkMN7e
PGcoD7LkJT0gKESqNvODAIP3thkFE28qW+lU8LeXEd8rTcyoiVnk7i+8i6Cn6KL3
iLV4dDDs9+ryhN0ufWbq9+oJijQdBdeG6mKfRM2oS6d1hGy215RrE3GMvWq5kawi
CPHMdmS2ctXtg+cu7u7pnjFU8v4xXE8cJKE1SnBpiwcuC/MplCiP92ZnriIxSxPy
1QIDAQAB
-----END PUBLIC KEY-----`

// UniversalKey returns the protocol-wide AES-256 key.
func UniversalKey() []byte {
	return PBKDF2SHA256([]byte(PBKDFPassword), []byte(PBKDFSalt), PBKDFIters, 32)
}

// PBKDF2SHA256 derives a key with PBKDF2-HMAC-SHA256 (RFC 2898), matching
// OpenSSL's PKCS5_PBKDF2_HMAC with SHA-256 as the vendor binary uses.
func PBKDF2SHA256(password, salt []byte, iters, keyLen int) []byte {
	return pbkdf2Key(password, salt, iters, keyLen, sha256.New)
}

// pbkdf2Key is the standard PBKDF2 construction (FIPS PUB 180-4 / RFC 2898).
// Implemented in-repo to keep the client dependency-free.
func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// U_1 = PRF(password, salt || INT_32_BE(block))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		t := dk[len(dk)-hashLen:]
		copy(u, t)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for x := range t {
				t[x] ^= u[x]
			}
		}
	}
	return dk[:keyLen]
}

var ivBytes = []byte(UniversalIV)

// PadPKCS7 appends PKCS#7 padding to b for the given block size.
func PadPKCS7(b []byte, blockSize int) []byte {
	n := blockSize - len(b)%blockSize
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// UnpadPKCS7 removes PKCS#7 padding, validating it.
func UnpadPKCS7(b []byte, blockSize int) ([]byte, error) {
	if len(b) == 0 || len(b)%blockSize != 0 {
		return nil, errors.New("crypto: invalid padded length")
	}
	n := int(b[len(b)-1])
	if n == 0 || n > blockSize || n > len(b) {
		return nil, errors.New("crypto: invalid padding")
	}
	for _, x := range b[len(b)-n:] {
		if int(x) != n {
			return nil, errors.New("crypto: invalid padding")
		}
	}
	return b[:len(b)-n], nil
}

// AESCBCEncrypt encrypts plaintext with AES-256-CBC under key and returns
// the Base64 of the PKCS7-padded ciphertext. The IV is the protocol-wide
// fixed IV.
func AESCBCEncrypt(key, plaintext []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("crypto: AES key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := PadPKCS7(plaintext, block.BlockSize())
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, ivBytes).CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(out), nil
}

// AESCBCDecrypt decrypts the Base64 ciphertext with AES-256-CBC under key,
// validating and stripping PKCS#7 padding.
func AESCBCDecrypt(key []byte, b64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("crypto: base64: %w", err)
	}
	return AESCBCDecryptRaw(key, ct)
}

// AESCBCDecryptRaw decrypts raw ciphertext bytes with AES-256-CBC under
// key, validating and stripping PKCS#7 padding (the .xpdf body path).
func AESCBCDecryptRaw(key, ct []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: AES key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%block.BlockSize() != 0 {
		return nil, errors.New("crypto: ciphertext not a multiple of block size")
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, ivBytes).CryptBlocks(out, ct)
	return UnpadPKCS7(out, block.BlockSize())
}

// NewSessionKey generates a random 16-byte session key (server-wrapped RSA
// blob payload) and returns its 32-char hex form.
func NewSessionKey() (hexKey string, raw []byte, err error) {
	raw = make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, raw); err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(raw), raw, nil
}

// RSAPublicKey parses the embedded server public key.
func RSAPublicKey() (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(ServerPublicKeyPEM))
	if block == nil {
		return nil, errors.New("crypto: bad PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("crypto: not an RSA public key")
	}
	return rsaPub, nil
}

// RSAPKCS1v15Encrypt is misnamed for history: the vendor binary actually
// uses RSA-OAEP. Pinned at 0x33c585: `mov r8d, 0x4` = RSA_PKCS1_OAEP_PADDING
// (OpenSSL constants: 1=PKCS1v1.5, 4=OAEP-SHA1). The plaintext is the
// 32-char hex session key (call site 0x335313). A v1.5 blob decrypts to
// garbage server-side, which silently disables key issuance.
func RSAPKCS1v15Encrypt(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, msg, nil)
}
