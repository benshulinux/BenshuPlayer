# benshuplayer

Clean-room, open-source Go client for the BenshuPlayer course server
protocol. Implements the client-server protocol layer only: login, course
listing, video metadata, playback reporting. No vendor code, no DRM
bypass, no binary patching.

## Install

```sh
make            # builds ./BenshuPlayer and ./xpdf2pdf
make install    # installs to /usr/local/bin (override with PREFIX=...)
```

Or with plain Go:

```sh
go build -o BenshuPlayer ./cmd/benshuplayer
go build -o xpdf2pdf ./cmd/xpdf2pdf
```

Requires Go 1.21+ and one third-party dependency
(`github.com/refraction-networking/utls` for TLS-fingerprint replay).
Everything else is stdlib.

## Make targets

| Target | What it does |
|---|---|
| `make` / `make build` | build `./BenshuPlayer` and `./xpdf2pdf` |
| `make test` | run the offline test suite |
| `make selfcheck` | crypto self-test (no network) |
| `make vet` / `make fmt` | static checks / formatting |
| `make install` / `make uninstall` | install both binaries to `$(PREFIX)/bin` |
| `make clean` | remove the built binaries |

## Commands

```
BenshuPlayer login   -phone <phone> -password <pass> [-server <url>]          # prints token + sessionKeyHex
BenshuPlayer courses -student <id> -token <satoken> [-server <url>]
BenshuPlayer course  -id <id> -token <satoken> [-sk <hex>] [-server <url>]
BenshuPlayer video   -course <id> -index <n> [-url <uri>]                 # cache lookup, no credentials
                     [-token <satoken> [-sk <hex>]] [-server <url>]
BenshuPlayer xpdf    -file <book.xpdf> [-course <id>] [-out <book.pdf>] [-url <uri>]
                     [-token <satoken> [-sk <hex>]] [-server <url>]
BenshuPlayer locate  -file <video.rlk> [-url <uri>]                       # filename -> candidate rlk/{course}/{index}
BenshuPlayer report  -course <id> -index <n> -sec <s> [-student <id>] [-token <satoken>] [-server <url>]
BenshuPlayer selfcheck
xpdf2pdf             -file <book.xpdf> -key <32hex> [-out <book.pdf>]
```

| Flag | Meaning |
|---|---|
| `-server` | server base URL (default `https://benshulinux.org:8443`) |
| `-machineid` | machine id (default: derived from `/etc/machine-id`) |
| `-token` | `satoken` from `BenshuPlayer login` — required by every command except `login` and cache lookups |
| `-phone` / `-password` | credentials — accepted by `login` ONLY (the server keeps a login session; re-logging in per command trips it) |
| `-student` | student id (default: parsed from the login response) |
| `-sk` | sessionKeyHex from `login` — pair with `-token` to decrypt key envelopes on the server path |
| `-index` | video index (1-based) |
| `-url` | cache source: http(s) URL or local JSON file path (identical format) |
| `-out` | output path (xpdf commands; default: input with `.pdf` suffix) |

Proxy: standard `https_proxy` env vars work (CONNECT tunnel).

## Examples

Log in once (prints the satoken and the session key hex for later use).
When `-phone` / `-password` are omitted, login becomes interactive
(password is not echoed):

```sh
$ BenshuPlayer login
phone: 13443586709
password: **************      <- typed without echo
machineid: [736164d0de1efa466cc541970b1de6c2]   <- Enter keeps the default
login response:
{
  "id": 1180,
  "nickName": "奔跑吧Linux社区",
  ...
  "registerDate": "2019-06-19 09:30:00",
  "expireType": null,
  "tokenName": "satoken",
  "tokenValue": "f08bfb44-62b2-482a-b67f-63ad9f252a34",
  "version": "2.402",
  ...
}
token:  f08bfb44-62b2-482a-b67f-63ad9f252a34
sessionKeyHex: dcda99647288cd0ca3925a45e7078e85
courses: 6
```

When the server requires SMS verification, login pauses for a code
(`r` re-sends, 6 digits submit):

```sh
$ BenshuPlayer login
phone: 13443586709
password: **************      <- typed without echo
sms code sent (30 min valid)
sms: r                       <- re-send the code
sms code re-sent
sms: 123456                  <- submit the 6-digit code
token:  f08bfb44-62b2-482a-b67f-63ad9f252a34
sessionKeyHex: dcda99647288cd0ca3925a45e7078e85
```

Every command prints the full server-returned struct as indented JSON
(encrypted fields stay ciphertext; see [doc/protocol.md](doc/protocol.md)
for the field semantics). Client-computed values — the decrypted keys —
are printed separately after the dump.

List courses:

```sh
$ BenshuPlayer courses -student 9014 -token f08bfb44-...
courses:
[
  {
    "id": 3,
    "courseName": "Sample Course",
    "videoCount": 20,
    "relatedCourse": "[...]",
    ...
  }
]
```

Convert a `.rlk` to MP4 — cache first (no credentials), server on miss:

```sh
# cache hit: no credentials needed
$ BenshuPlayer video -course 3 -index 1 -url ./kv.json
cache hit: course 3 index 1 (sample-course-video.mp4)
playerKey(plaintext):  767734721bae783367df263bbd87a350
ffmpeg -decryption_key 767734721bae783367df263bbd87a350 -i <file>.rlk -c copy out.mp4
```

Fetch a video key straight from the server (reuse the login session;
`-sk` carries the session key so the envelope can be decrypted):

```sh
$ BenshuPlayer video -course 3 -index 1 -token f08bfb44-... -sk dcda99647288cd0ca3925a45e7078e85
video:
{
  "id": 262,
  "courseId": 3,
  "fileName": "sample-course-video.mp4",
  "fileCode": "",
  "videoIndex": 1,
  "uploadDate": "",
  "playerKey": "c9c1DEIJIYuwuzubbNfC473R0Aa1b2c3d4e5f60718..."
}
playerKey(plaintext):  cafd9a4acf8a8490ea07e8253c549090
ffmpeg -decryption_key cafd9a4acf8a8490ea07e8253c549090 -i <file>.rlk -c copy out.mp4
```

Find the course/index of a downloaded `.rlk` by filename (substring
match against the server-side display names, same semantics as the
stock player):

```sh
$ BenshuPlayer locate -file '00-course-intro.rlk'
rlk/3/1  (course-intro.mp4)
```

Convert a `.xpdf` ebook to PDF (course id comes from the file header;
key resolution: cache first, server on miss):

```sh
# cache hit: no credentials needed
$ BenshuPlayer xpdf -file "book1.xpdf" -url ./kv.json
cache hit: xpdf/course/3 (Sample Course)
xpdf -> pdf: "book1.pdf" (1234567 bytes, course 3)

# cache miss: server path (reuse the login session)
$ BenshuPlayer xpdf -file "book1.xpdf" -token f08bfb44-... -sk dcda99647288cd0ca3925a45e7078e85
course:
{
  "id": 3,
  "courseName": "Sample Course",
  "ebookKey": "otbBjWojFV8TXaVGlAxhZUCJJLbwCY36wVuUx0CBwacX=...",
  ...
}
ebookKey(plaintext, course key): cafd9a4acf8a8490ea07e8253c549090
xpdf -> pdf: "book1.pdf" (1234567 bytes, course 3)
```

Standalone decryptor binary (`make build` produces both `BenshuPlayer`
and `xpdf2pdf`). `xpdf2pdf` is network-free: `.xpdf` + 32-hex course key
→ PDF, for offline conversion with a key you already hold:

```sh
$ xpdf2pdf -file "book1.xpdf" -key cafd9a4acf8a8490ea07e8253c549090
xpdf -> pdf: "book1.pdf" (1234567 bytes, course 3)
```

Report playback progress:

```sh
$ BenshuPlayer report -course 3 -index 1 -sec 60 -student 1180 -token f08bfb44-...
report_watch: ok
```

Offline self-check (no network):

```sh
$ BenshuPlayer selfcheck
```

## Notes

- **One session per account at a time**: logging in with a new session
  invalidates the previous one (the server kicks older `satoken`s). Don't
  run the player and this client against the same account simultaneously.
  This is also why only `login` takes `-phone/-password`: every other command
  reuses the session via `-token`.
- **`-token` alone cannot decrypt**: the playerKey/ebookKey envelopes are
  encrypted with a per-login session key. Pair `-token` with
  `-sk <sessionKeyHex>` from the login output.
- **Empty playerKey** = free/preview video; the stock player plays those
  without a key. Not an error.

## Documentation

- [doc/protocol.md](doc/protocol.md) — wire-level parity, protocol facts,
  key hierarchy, test vectors.
- `go test ./...` — offline tests: crypto vectors + captured-fixture
  replay (no network).

## License

[GPL-2.0](LICENSE).

## Boundary

Internal assessment material. Point it only at a mock server or your own
logged-in sessions; never at third-party infrastructure without
authorization.
