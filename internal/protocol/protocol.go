// Package protocol implements the BenshuPlayer client-server protocol:
// transport defaults, request/response envelope types, and the two-layer
// AES field decryption used on sensitive response fields.
//
// The protocol itself is reverse-engineered and documented at
// /home/ubuntu/benshu/protocol-spec.md; this package is a clean-room Go
// implementation of that specification.
package protocol

import (
	"encoding/json"
	"fmt"

	"benshuplayer/internal/crypto"
)

// Transport defaults, identical to the stock client.
const (
	DefaultServerURL = "https://benshulinux.org:8443"
	Version          = "2.402"

	// UserAgentLogin is the login-chain User-Agent; every other request
	// uses Go's default (Qt's default is "Mozilla/5.0" — see Client).
	TokenHeader = "satoken"
)

// Envelope is the top-level JSON wrapper every endpoint returns.
// Fields in Data may be Base64(AES-256-CBC) blobs; see DecryptField.
type Envelope struct {
	Code int             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// Course is one entry of GET /api/common/get/courses/{studentId}.
type Course struct {
	ID                       int    `json:"id"`
	CourseName               string `json:"courseName"`
	VideoCount               *int   `json:"videoCount"`
	RelatedCourse            string `json:"relatedCourse"`
	DownloadURL              string `json:"downloadUrl"`
	EBookKey                 string `json:"ebookKey"` // empty on the list endpoint
	AccessStartDateByStudent string `json:"accessStartDateByStudent"`
	AccessEndDateByStudend   string `json:"accessEndDateByStudend"`
	AccessExpiredByStudent   bool   `json:"accessExpiredByStudent"`
}

// CourseDetail is the singular GET /api/common/get/course/{id} response
// data object. EBookKey is double-layer encrypted (see DecryptEBookKey);
// the plaintext lands in the running client only while a book is open.
type CourseDetail struct {
	ID            int    `json:"id"`
	CourseName    string `json:"courseName"`
	EBookKey      string `json:"ebookKey"`
	CourseID      int    `json:"courseId"`
	RelatedCourse string `json:"relatedCourse"`
	DownloadURL   string `json:"downloadUrl"`
}

// Video is one entry of GET /api/common/get/videos/{courseId}/{index}.
type Video struct {
	ID         int    `json:"id"`
	CourseID   int    `json:"courseId"`
	FileName   string `json:"fileName"`
	FileCode   string `json:"fileCode"`
	VideoIndex int    `json:"videoIndex"`
	UploadDate string `json:"uploadDate"`
	// PlayerKey is the CENC AES-128-CTR content key, double-layer
	// encrypted (see DecryptPlayerKey). 32 hex chars when decrypted.
	PlayerKey string `json:"playerKey"`
}

// LoginRequest is the POST /api/common/login body. Credentials and
// machineId go in plaintext (TLS is the only protection, same as the
// stock client); data is the RSA-wrapped 32-char hex session key. Field
// order matches the stock client's JSON byte-for-byte (data first).
type LoginRequest struct {
	Data      string `json:"data"` // Base64(RSA_PKCS1v15(hex(sessionKey)))
	MachineID string `json:"machineId"`
	Password  string `json:"password"`
	PhoneNo   string `json:"phoneNo"`
}

// LoginData is the decrypted/parsed login response `data` object.
type LoginData struct {
	ID            int    `json:"id"`
	NickName      string `json:"nickName"`
	PhoneNo       string `json:"phoneNo"`  // AES-encrypted echo
	Password      string `json:"password"` // AES-encrypted echo
	RegisterDate  string `json:"registerDate"`
	ExpireType    *int   `json:"expireType"`
	StartDate     string `json:"startDate"`
	EndDate       string `json:"endDate"`
	Status        int    `json:"status"`
	TokenName     string `json:"tokenName"`
	TokenValue    string `json:"tokenValue"`
	Version       string `json:"version"`
	LM            string `json:"lm"` // AES-encrypted md5(/usr/bin/BenshuPlayer)
	WM            string `json:"wm"`
	MM            string `json:"mm"`
	AM            string `json:"am"`
	LastLoginTime string `json:"lastLoginTime"`
	Comments      string `json:"comments"`
}

// DecryptField decrypts a single-layer AES field (password, lm/wm/mm/am)
// with the protocol-wide universal key.
func DecryptField(b64 string) ([]byte, error) {
	return crypto.AESCBCDecrypt(crypto.UniversalKey(), b64)
}

// DecryptEBookKey unwraps the double-layer ebookKey field from the singular
// get/course/{id} endpoint. The construction is isomorphic to the playerKey
// envelope (same helper sub_33B990 + inner universal-key layer, pinned by
// disassembly at call site 0x34d778 in the get/course handler):
//
//	L1: key = PBKDF2-HMAC-SHA256(hex(sessionKey), "benshushu_salt", 65536, 32)
//	    innerB64 = AES-256-CBC(key, fixedIV)(ebookKey ciphertext)
//	L2: plain = AES-256-CBC(K, fixedIV)(Base64(innerB64))
//
// where sessionKey is the 16-byte random key generated at login (the value
// wrapped by RSA in the login `data` field; the vendor client keeps its hex
// form in the manager object's +0x30 QString). The returned plaintext is the
// 32-char hex course key.
func DecryptEBookKey(ebookKeyB64, sessionKeyHex string) ([]byte, error) {
	key1 := crypto.PBKDF2SHA256([]byte(sessionKeyHex), []byte(crypto.PBKDFSalt), crypto.PBKDFIters, 32)
	innerB64, err := crypto.AESCBCDecrypt(key1, ebookKeyB64)
	if err != nil {
		return nil, fmt.Errorf("ebookKey L1: %w", err)
	}
	key2, err := crypto.AESCBCDecrypt(crypto.UniversalKey(), string(innerB64))
	if err != nil {
		return nil, fmt.Errorf("ebookKey L2: %w", err)
	}
	return key2, nil
}

// DecryptPlayerKey strips the two encryption layers from a playerKey field
// and returns the 32-char hex CENC content key (the value ffmpeg takes as
// -decryption_key).
//
// Layer 1 (outer, sub_33B990 as called from the get/videos handler at
// 0x348b89), pinned by disassembly of sub_33B990 + sub_339D10:
//
//	key = PBKDF2-HMAC-SHA256(password = UTF8(*(manager+0x30)) = hex(sessionKey),
//	                        salt    = "benshushu_salt",   // sub_351A10 constant
//	                        iters   = 65536, dklen = 32)
//	out  = Base64( AES-256-CBC(key, "4589benshu155889")(innerCipher, PKCS7) )
//
// Layer 2 (inner, sub_339DD0): key = the protocol-wide universal key K
// (PKCS5_PBKDF2_HMAC(pass="1981rlkRLK86tGnF8aGepr689dGWnrwU",
// salt="benshushu_salt", 65536, 32)); out = the 32-char hex content key.
//
// sessionKey is the 16-byte random value generated at login (RSA-wrapped
// into the login `data` field). The vendor client derives the L1 password
// from its hex form at login time (sub_335040 stores QString(hex(SK)) into
// manager+0x30; the manager+0xa0 slot that also reaches sub_33B990 is the
// RSA key object and is a dead argument there). The server knows SK after
// unwrapping `data`, which is how it encrypts these envelopes.
func DecryptPlayerKey(playerKeyB64, sessionKeyHex string) ([]byte, error) {
	key1 := crypto.PBKDF2SHA256([]byte(sessionKeyHex), []byte(crypto.PBKDFSalt), crypto.PBKDFIters, 32)
	innerB64, err := crypto.AESCBCDecrypt(key1, playerKeyB64)
	if err != nil {
		return nil, fmt.Errorf("playerKey L1: %w", err)
	}
	key2, err := crypto.AESCBCDecrypt(crypto.UniversalKey(), string(innerB64))
	if err != nil {
		return nil, fmt.Errorf("playerKey L2: %w", err)
	}
	return key2, nil
}

// SessionKeyHex returns the hex form of the current session key — the L1
// password used by the vendor client for every playerKey/ebookKey envelope.
// Empty until a login has been performed (BuildLogin generates the key).
func SessionKeyHex(raw []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, c := range raw {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0xf]
	}
	return string(out)
}
