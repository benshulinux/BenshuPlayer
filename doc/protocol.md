# Protocol reference (verified against the stock client)

Technical documentation for what `benshuplayer` replicates on the wire
and why. Usage instructions live in the root `README.md`.

## Wire-level parity with the stock client

- **TLS fingerprint (JA3)**: the ClientHello is replayed byte-exactly from
  a capture of the real player (`internal/tlsfingerprint/clienthello.bin`,
  tcpdump of `/usr/bin/BenshuPlayer` dialing production). Locked by
  `TestJA3MatchesCaptured` — a raw-socket server captures our hello and
  compares the computed JA3 string to the target. Verified end-to-end
  against the production Cloudflare edge.
- **HTTP/1.1 only**: Qt5 has no HTTP/2; pinned via `ForceAttemptHTTP2=false`
  plus no ALPN in the hello. Locked by `TestHTTP1Only`.
- **20s timeout, no retry** — same as the stock client's QTimer behavior.
- **Backup-server failover is intentionally NOT implemented**: the stock
  client auto-switches to `backup_url` on protocol errors (-212). This CLI
  leaves server selection to the user via `-server <url>` on every
  subcommand — explicit over automatic, no hidden state.

## Protocol facts (verified)

- **Transport**: `https://benshulinux.org:8443`, JSON bodies, `satoken`
  header (+ cookie) after login, 20s timeout, no retry, no cert pinning.
- **machineId** = first 32 hex chars of SHA-256 over the UTF-8 bytes of
  `/etc/machine-id`. Verified byte-for-byte against captured traffic.
- **Universal key** `K = PBKDF2-HMAC-SHA256("1981rlkRLK86tGnF8aGepr689dGWnrwU",
  "benshushu_salt", 65536, 32)`, fixed IV `4589benshu155889`, AES-256-CBC +
  PKCS#7. Field-level encryption of `password`/`phoneNo`/`lm`/`wm`/`mm`/`am`
  decrypts offline with K — verified against real captures.
- **Login `data` field**: the 32-char hex form of a fresh 16-byte random
  session key, wrapped with the embedded RSA-2048 public key using
  **RSA-OAEP (SHA-1)** — `RSA_public_encrypt(..., 4)`; OpenSSL 4 =
  RSA_PKCS1_OAEP_PADDING, not v1.5 — Base64 → 256 bytes / 344 chars.
  Pinned at sub_33C510 (`mov r8d,0x4` @0x33c585) + sub_335040 (input =
  UTF8(hex) @0x335313). A v1.5 blob silently disables key issuance
  (login still returns 200 but get/videos yields playerKey=None).
- **playerKey** is double-layered (same construction for `ebookKey`):
  - L1: `PBKDF2(hex(sessionKey), "benshushu_salt", 65536)` where sessionKey
    is the 16-byte login random (the value RSA-wrapped in `data`; the
    vendor client stores `QString(hex(SK))` in manager+0x30 at login,
    sub_335040). Salt + fixed IV are embedded constants
    (`benshushu_salt` / `4589benshu155889`); the manager+0xa0 slot that
    reaches the decryptor is the RSA key object — a dead argument.
    Pinned by disassembly of sub_33B990/sub_339D10 at call site 0x348b89.
  - L2: the universal key K.
  - Output: 32-char hex CENC content key (ffmpeg `-decryption_key`).
  - The stock client therefore knows the L1 key from the moment it logs
    in — `BenshuPlayer login` prints the session key; passing it as
    `-sk` alongside `-token` decrypts the envelopes end to end
    (`video`/`course`/`xpdf` server paths); a `-token`-only session
    cannot.

## .xpdf ebook container (verified)

- 64-byte little-endian header: `magic 0xFFBB599BFDCE3846` / 0 / cipher
  CRC16 / cipher len (= file size − 64) / plain CRC16 / valid len /
  courseId (u64 each; CRC16 = Qt `qChecksum`).
- Body: AES-256-CBC, key = `PBKDF2-HMAC-SHA256(pass = ebookKey plaintext,
  salt = "benshushu_salt", 65536, 32)`, fixed IV `4589benshu155889`,
  PKCS#7. Plaintext = exactly validLen bytes, starts with `%PDF`.
- Pinned by disassembly of sub_310510 (local-file open path): header
  parse → magic check → qChecksum → course permission (sub_3496D0) →
  ebookKey fetch (sub_34DA40) → sub_33B990 with UTF8(ebookKey plaintext)
  as the PBKDF2 password. The manager+0xa0 slot rides along as the same
  dead argument as in the playerKey chain.

## testdata

- `playerkey_vectors.json` — two (ct, key) pairs from the user's own
  sessions; structure anchors only (L1 key material is runtime-only).
- `crypto_vectors.json` — K hex + PBKDF2 reference values.

## Boundary

Internal assessment material. Point it only at a mock server or your own
logged-in sessions; never at third-party infrastructure without
authorization. This repo contains no secrets beyond what the stock client
itself ships (the hardcoded key material and public key are public facts
of the binary).
