// Package xpdf implements the BenshuPlayer .xpdf ebook container:
// a 64-byte little-endian header followed by an AES-256-CBC body.
//
// Pinned by disassembly of sub_310510 (the local-file open path):
//   - header: magic / 0 / cipher CRC16 / cipher len / plain CRC16 /
//     valid len / courseId (u64 LE each)
//   - body key = PBKDF2-HMAC-SHA256(password = ebookKey plaintext
//     (32-char hex course key from get/course), salt = "benshushu_salt",
//     65536, 32), fixed IV "4589benshu155889", PKCS#7 padding
//   - the plaintext is exactly validLen bytes and starts with "%PDF"
package xpdf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"benshuplayer/internal/crypto"
)

// Magic is the container magic in the first u64 of the header.
const Magic uint64 = 0xFFBB599BFDCE3846

// HeaderLen is the fixed header size in bytes.
const HeaderLen = 64

// Header is the parsed 64-byte container header.
type Header struct {
	CipherCRC uint16 // qChecksum of the ciphertext body
	CipherLen uint64 // body length (file size - 64)
	PlainCRC  uint16 // qChecksum of the plaintext
	ValidLen  uint64 // plaintext length (PDF size, PKCS#7 stripped)
	CourseID  uint64 // course the book belongs to (get/course/{id})
}

// ParseHeader parses and validates the 64-byte header.
func ParseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderLen {
		return h, fmt.Errorf("xpdf: header too short (%d bytes, want %d)", len(b), HeaderLen)
	}
	hdr := b[:HeaderLen]
	if binary.LittleEndian.Uint64(hdr[0:]) != Magic {
		return h, fmt.Errorf("xpdf: bad magic 0x%X", binary.LittleEndian.Uint64(hdr[0:]))
	}
	h.CipherCRC = binary.LittleEndian.Uint16(hdr[16:])
	h.CipherLen = binary.LittleEndian.Uint64(hdr[24:])
	h.PlainCRC = binary.LittleEndian.Uint16(hdr[32:])
	h.ValidLen = binary.LittleEndian.Uint64(hdr[40:])
	h.CourseID = binary.LittleEndian.Uint64(hdr[48:])
	return h, nil
}

// FileKey derives the AES-256 body key from the decrypted ebookKey
// (the 32-char hex course key).
func FileKey(ebookKeyPlain string) []byte {
	return crypto.PBKDF2SHA256([]byte(ebookKeyPlain), []byte(crypto.PBKDFSalt), crypto.PBKDFIters, 32)
}

// DecryptBody decrypts the body with the derived key and verifies the
// result against the header (validLen and %PDF magic). The qChecksum
// fields are not checked: Qt's qChecksum has variant drift across
// releases, and length+magic is the authoritative verification.
func DecryptBody(key, body []byte, h Header) ([]byte, error) {
	if uint64(len(body)) != h.CipherLen {
		return nil, fmt.Errorf("xpdf: body is %d bytes, header says %d", len(body), h.CipherLen)
	}
	pt, err := crypto.AESCBCDecryptRaw(key, body)
	if err != nil {
		return nil, fmt.Errorf("xpdf: decrypt: %w", err)
	}
	if uint64(len(pt)) != h.ValidLen {
		return nil, fmt.Errorf("xpdf: plaintext is %d bytes, header says %d", len(pt), h.ValidLen)
	}
	if !bytes.HasPrefix(pt, []byte("%PDF")) {
		return nil, fmt.Errorf("xpdf: plaintext does not start with %%PDF (wrong key?)")
	}
	return pt, nil
}
