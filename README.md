# benshu-client

Clean-room, open-source Go client for the BenshuPlayer course server
protocol. Implements the client-server protocol layer only: login, course
listing, video metadata, playback reporting. No vendor code, no DRM
bypass, no binary patching.

## Install

```sh
make            # builds ./benshu-client
make install    # installs to /usr/local/bin (override with PREFIX=...)
```

Or with plain Go:

```sh
go build -o benshu-client ./cmd/benshu-client
```

Requires Go 1.21+ and one third-party dependency
(`github.com/refraction-networking/utls` for TLS-fingerprint replay).
Everything else is stdlib.

## Make targets

| Target | What it does |
|---|---|
| `make` / `make build` | build `./benshu-client` |
| `make test` | run the offline test suite |
| `make selfcheck` | crypto self-test (no network) |
| `make vet` / `make fmt` | static checks / formatting |
| `make install` / `make uninstall` | install to `$(PREFIX)/bin` |
| `make clean` | remove the built binary |

## Commands

```
benshu-client login   -phone <phone> -pass <pass> [-server <url>]
benshu-client courses -student <id> [-token <satoken>] [-server <url>]
benshu-client course  -id <id> [-token <satoken> | -phone <phone> -pass <pass>] [-server <url>]
benshu-client video   -course <id> -index <n> [-token <satoken> | -phone <phone> -pass <pass>] [-server <url>]
benshu-client xpdf    -file <book.xpdf> [-course <id>] [-out <book.pdf>] [-token <satoken> [-sk <hex>] | -phone <phone> -pass <pass>] [-server <url>]
benshu-client report  -course <id> -index <n> -sec <s> [-student <id>] [-token <satoken>] [-server <url>]
benshu-client selfcheck
```

| Flag | Meaning |
|---|---|
| `-server` | server base URL (default `https://benshulinux.org:8443`) |
| `-machineid` | machine id (default: derived from `/etc/machine-id`) |
| `-token` | `satoken` from a previous login; skips login (no key decryption) |
| `-phone` / `-pass` | credentials; log in in-process so keys can be decrypted |
| `-student` | student id (default: parsed from the login response) |
| `-sk` | session key hex (32 chars) to pair with `-token` for key decryption |
| `-index` | video index (1-based) |

Proxy: standard `https_proxy` env vars work (CONNECT tunnel).

## Examples

Log in (prints the satoken and student id):

```sh
$ benshu-client login -phone 13443586709 -pass '...'
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
courses: 6 门
```

Every command prints the full server-returned struct as indented JSON
(encrypted fields stay ciphertext; see [doc/protocol.md](doc/protocol.md)
for the field semantics). Client-computed values — the decrypted keys —
are printed separately after the dump.

List courses:

```sh
$ benshu-client courses -student 1180 -token f08bfb44-...
courses:
[
  {
    "id": 3,
    "courseName": "示例课程",
    "videoCount": 20,
    "relatedCourse": "[...]",
    ...
  }
]
```

Fetch a video and get its ffmpeg key (in-process login decrypts the
envelope):

```sh
$ benshu-client video -course 3 -index 1 -phone 13443586709 -pass '...'
login ok: token=f08bfb44-... (sessionKeyHex=dcda99647288cd0ca3925a45e7078e85)
video:
{
  "id": 262,
  "courseId": 3,
  "fileName": "示例课程视频.mp4",
  "fileCode": "",
  "videoIndex": 1,
  "uploadDate": "",
  "playerKey": "c9c1DEIJIYuwuzubbNfC473R0Aa1b2c3d4e5f60718..."
}
playerKey(plaintext):  cafd9a4acf8a8490ea07e8253c549090
ffmpeg -decryption_key cafd9a4acf8a8490ea07e8253c549090 -i <file>.rlk -c copy out.mp4
```

Convert a `.rlk` to MP4:

```sh
benshu-client video -course 3 -index 1 -phone 13443586709 -pass '...' \
  | grep -oE '^playerKey\(plaintext\):\s+\S+' | awk '{print $2}' \
  | xargs -I{} ffmpeg -decryption_key {} -i video.rlk -c copy video.mp4
```

Reuse a session without re-logging in (pass the session key hex printed
at login time):

```sh
$ benshu-client video -course 3 -index 1 -token f08bfb44-... -sk dcda99647288cd0ca3925a45e7078e85
```

Convert a `.xpdf` ebook to PDF (course id comes from the file header; the
course's ebookKey is fetched and decrypted with the session key):

```sh
$ benshu-client xpdf -file "课件1.xpdf" -phone 13443586709 -pass '...'
login ok: token=f08bfb44-... (sessionKeyHex=dcda99647288cd0ca3925a45e7078e85)
course:
{
  "id": 3,
  "courseName": "示例课程",
  "ebookKey": "otbBjWojFV8TXaVGlAxhZUCJJLbwCY36wVuUx0CBwacX=...",
  ...
}
ebookKey(plaintext, course key): cafd9a4acf8a8490ea07e8253c549090
xpdf -> pdf: "课件1.pdf" (1234567 bytes, course 3)
```

Report playback progress:

```sh
$ benshu-client report -course 3 -index 1 -sec 60 -student 1180 -token f08bfb44-...
report_watch: 保存成功
```

Offline self-check (no network):

```sh
$ benshu-client selfcheck
```

## Notes

- **One session per account at a time**: logging in with a new session
  invalidates the previous one (the server kicks older `satoken`s). Don't
  run the player and this client against the same account simultaneously;
  use `-token` to reuse a session instead.
- **`-token` alone cannot decrypt**: the playerKey/ebookKey envelopes are
  encrypted with a per-login session key. Use `-phone/-pass`, or `-token`
  together with `-sk <sessionKeyHex>` from the login output.
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
