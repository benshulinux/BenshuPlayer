// Command BenshuPlayer is a clean-room, open-source client for the
// BenshuPlayer course server protocol.
//
// It implements ONLY the client-server protocol layer (login, course
// listing, video metadata, playback reporting). It contains no vendor
// code and no DRM bypass: playerKey decryption is exposed so owners of
// purchased content can use it, matching the interoperability use case.
//
// Subcommands:
//
//	BenshuPlayer login  -phone <phone> -pass <pass> [-server <url>]
//	BenshuPlayer courses -student <id> [-token <satoken>] [-server <url>]
//	BenshuPlayer course -id <id> [-token <satoken> | -phone <phone> -pass <pass>] [-server <url>]
//	BenshuPlayer video  -course <id> -index <n> [-token <satoken> | -phone <phone> -pass <pass>] [-server <url>]
//	BenshuPlayer report -course <id> -index <n> -sec <s> [-student <id>] [-token <satoken>] [-server <url>]
//	BenshuPlayer video  -course <id> -index <n> [-url <uri>]   (cache lookup, no credentials; server on miss with -phone -pass)
//	BenshuPlayer xpdf  -file <book.xpdf> [-course <id>] [-out <book.pdf>] [-url <uri>]   (cache first, server on miss)
//	BenshuPlayer selfcheck          (offline crypto self-test)
//
// When `video`/`course` run with -phone/-pass they log in in-process and
// print the DECRYPTED playerKey (the 32-hex CENC content key that ffmpeg
// takes as -decryption_key) / course key. With -token only, the envelopes
// are shown as ciphertext (the session key is per-login and unknown).
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"benshuplayer/internal/api"
	"benshuplayer/internal/crypto"
	"benshuplayer/internal/gistcache"
	"benshuplayer/internal/machineid"
	"benshuplayer/internal/protocol"
	"benshuplayer/internal/xpdf"
)

const usage = `benshuplayer — clean-room BenshuPlayer protocol client

Usage:
  BenshuPlayer login   -phone <phone> -pass <pass> [-server <url>]     # prints token + sessionKeyHex
  BenshuPlayer courses -student <id> -token <satoken> [-server <url>]
  BenshuPlayer course  -id <id> -token <satoken> [-sk <hex>] [-server <url>]
  BenshuPlayer video   -course <id> -index <n> [-url <uri>]            # cache lookup, no credentials
                       [-token <satoken> [-sk <hex>]] [-server <url>]
  BenshuPlayer xpdf    -file <book.xpdf> [-course <id>] [-out <book.pdf>] [-url <uri>]
                       [-token <satoken> [-sk <hex>]] [-server <url>]
  BenshuPlayer locate  -file <video.rlk> [-url <uri>]                  # filename -> candidate rlk/{course}/{index} rows
  BenshuPlayer report  -course <id> -index <n> -sec <s> [-student <id>] [-token <satoken>] [-server <url>]
  BenshuPlayer selfcheck

Flags:
  -server    server base URL (default https://benshulinux.org:8443)
  -machineid machine id (default: derived from /etc/machine-id)
  -url       cache source: http(s) URL or local JSON file (same format; built-in default when published)
  -token     satoken from BenshuPlayer login (all commands except login)
  -sk        sessionKeyHex from BenshuPlayer login — required to decrypt playerKey/ebookKey
             envelopes on the server path (cache hits never need it)
  -student   student id (default: parsed from login response)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "login":
		err = cmdLogin(args)
	case "courses":
		err = cmdCourses(args)
	case "course":
		err = cmdCourse(args)
	case "video":
		err = cmdVideo(args)
	case "xpdf":
		err = cmdXpdf(args)
	case "report":
		err = cmdReport(args)
	case "locate":
		err = cmdLocate(args)
	case "selfcheck":
		err = cmdSelfcheck()
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// newClient builds a client for the given server, deriving the machineId
// from the local system unless one is supplied explicitly.
func newClient(server, machineID string) (*api.Client, error) {
	if machineID == "" {
		mid, err := machineid.LinuxMachineID()
		if err != nil {
			return nil, err
		}
		machineID = mid
	}
	return api.NewTestClient(server, machineID), nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	phone := fs.String("phone", "", "phone number")
	pass := fs.String("pass", "", "password")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	fs.Parse(args)

	if *phone == "" || *pass == "" {
		return fmt.Errorf("-phone and -pass are required")
	}
	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	data, err := c.Login(*phone, *pass)
	if err != nil {
		return err
	}
	dumpJSON("login response", data)
	fmt.Printf("token:  %s\n", data.TokenValue)
	fmt.Printf("sessionKeyHex: %s\n", c.SessionKeyHex())
	// stock-client post-login behavior: get/courses, then get_screen_record
	if courses, err := c.Courses(data.ID); err == nil {
		fmt.Printf("courses: %d\n", len(courses))
	}
	if cfg, err := c.ScreenRecord(); err == nil {
		fmt.Printf("screen_record config: %d entries\n", len(cfg))
	}
	return nil
}

func cmdCourses(args []string) error {
	fs := flag.NewFlagSet("courses", flag.ExitOnError)
	student := fs.Int("student", 0, "student id")
	token := fs.String("token", "", "satoken")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	fs.Parse(args)

	if *student == 0 {
		return fmt.Errorf("-student is required")
	}
	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	c.Token = *token
	courses, err := c.Courses(*student)
	if err != nil {
		return err
	}
	dumpJSON("courses", courses)
	return nil
}

func cmdCourse(args []string) error {
	fs := flag.NewFlagSet("course", flag.ExitOnError)
	id := fs.Int("id", 0, "course id")
	token := fs.String("token", "", "satoken from BenshuPlayer login")
	skhex := fs.String("sk", "", "session key hex from BenshuPlayer login (enables ebookKey decryption)")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	fs.Parse(args)

	if *id == 0 {
		return fmt.Errorf("-id is required")
	}
	if *token == "" {
		return fmt.Errorf("-token is required (run `BenshuPlayer login -phone ... -pass ...` first)")
	}
	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	c.Token = *token
	if *skhex != "" {
		raw, err := hex.DecodeString(*skhex)
		if err != nil || len(raw) != 16 {
			return fmt.Errorf("-sk must be 32 hex chars (16 bytes)")
		}
		c.SessionKeyRaw = raw
	}
	cd, err := c.Course(*id)
	if err != nil {
		return err
	}
	dumpJSON("course", cd)
	if cd.EBookKey != "" {
		if len(c.SessionKeyRaw) != 16 {
			fmt.Println("ebookKey present but no -sk — rerun with -sk <sessionKeyHex from login>")
		} else {
			key, err := protocol.DecryptEBookKey(cd.EBookKey, c.SessionKeyHex())
			if err != nil {
				fmt.Println("ebookKey decrypt:", err)
			} else {
				fmt.Printf("ebookKey(plaintext, course key): %s\n", key)
			}
		}
	}
	return nil
}

// cmdLocate maps a local .rlk filename back to candidate
// rlk/{course}/{index} cache rows by substring match on the server-side
// display name (the same semantics the stock player uses).
func cmdLocate(args []string) error {
	fs := flag.NewFlagSet("locate", flag.ExitOnError)
	file := fs.String("file", "", "local .rlk file path or filename")
	url := fs.String("url", gistcache.DefaultURL, "cache source: http(s) URL or local JSON file path")
	fs.Parse(args)

	if *file == "" {
		return fmt.Errorf("-file is required")
	}
	name := filepath.Base(*file)
	matches, err := gistcache.FindByName(*url, name)
	if err != nil {
		return err
	}
	if len(matches) == 0 {
		return fmt.Errorf("no cache row whose name contains %q", name)
	}
	for _, m := range matches {
		fmt.Printf("%s  (%s)\n", m.KeyPath, m.Entry.Name)
	}
	return nil
}

func cmdVideo(args []string) error {
	fs := flag.NewFlagSet("video", flag.ExitOnError)
	course := fs.Int("course", 0, "course id")
	index := fs.Int("index", 0, "video index (1-based)")
	token := fs.String("token", "", "satoken from BenshuPlayer login")
	skhex := fs.String("sk", "", "session key hex from BenshuPlayer login (enables playerKey decryption)")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	url := fs.String("url", gistcache.DefaultURL, "cache source: http(s) URL or local JSON file path")
	fs.Parse(args)

	if *course == 0 || *index == 0 {
		return fmt.Errorf("-course and -index are required")
	}

	// Path 1: gist cache lookup by (course, index) — no credentials.
	e, gerr := gistcache.Lookup(*url, fmt.Sprintf("rlk/%d/%d", *course, *index))
	if gerr == nil && e != nil && e.Key != "" {
		fmt.Printf("cache hit: course %d index %d (%s)\n", *course, *index, e.Name)
		printRlkKeys("", []string{e.Key})
		return nil
	}
	if *token == "" {
		if gerr == nil {
			return fmt.Errorf("cache miss — server path needs -token (run `BenshuPlayer login -phone ... -pass ...` first)")
		}
		return fmt.Errorf("cache lookup failed (%v) — server path needs -token", gerr)
	}

	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	c.Token = *token
	if *skhex != "" {
		raw, err := hex.DecodeString(*skhex)
		if err != nil || len(raw) != 16 {
			return fmt.Errorf("-sk must be 32 hex chars (16 bytes)")
		}
		c.SessionKeyRaw = raw
	}
	v, err := c.Video(*course, *index)
	if err != nil {
		return err
	}
	dumpJSON("video", v)
	if len(c.SessionKeyRaw) == 16 {
		if v.PlayerKey == "" {
			fmt.Println("playerKey: empty (free/preview video — stock player plays it with no key)")
		} else {
			key, err := c.PlayerKey(v)
			if err != nil {
				return err
			}
			if len(key) != 32 {
				return fmt.Errorf("decrypted playerKey has unexpected length %d (want 32 hex chars)", len(key))
			}
			fmt.Printf("playerKey(plaintext):  %s\n", key)
			fmt.Printf("ffmpeg -decryption_key %s -i <file>.rlk -c copy out.mp4\n", key)
		}
	} else {
		fmt.Println("note: no -sk given — playerKey envelope received but cannot be decrypted")
	}
	return nil
}

// printRlkKeys prints cache candidates and the ffmpeg usage line.
func printRlkKeys(tag string, keys []string) {
	fmt.Printf("%s\n", tag)
	for i, k := range keys {
		if len(keys) > 1 {
			fmt.Printf("playerKey(plaintext):  %s  (candidate %d/%d — try each, verify frames)\n", k, i+1, len(keys))
		} else {
			fmt.Printf("playerKey(plaintext):  %s\n", k)
		}
	}
	fmt.Printf("ffmpeg -decryption_key %s -i <file>.rlk -c copy out.mp4\n", keys[0])
}

// cmdXpdf converts a .xpdf ebook to PDF. The course id comes from the
// container header. Key resolution: gist cache (xpdf/course/<id>, no
// credentials) first; on miss, get/course/{id} on the server with an
// in-process login.
func cmdXpdf(args []string) error {
	fs := flag.NewFlagSet("xpdf", flag.ExitOnError)
	file := fs.String("file", "", "input .xpdf file")
	out := fs.String("out", "", "output .pdf path (default: input with .pdf suffix)")
	course := fs.Int("course", 0, "course id override (default: from the .xpdf header)")
	token := fs.String("token", "", "satoken from BenshuPlayer login")
	skhex := fs.String("sk", "", "session key hex from BenshuPlayer login (enables ebookKey decryption)")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	url := fs.String("url", gistcache.DefaultURL, "cache source: http(s) URL or local JSON file path")
	fs.Parse(args)

	if *file == "" {
		return fmt.Errorf("-file is required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	h, err := xpdf.ParseHeader(raw)
	if err != nil {
		return err
	}
	if *course != 0 {
		h.CourseID = uint64(*course)
	}

	// Path 1: gist cache lookup by course id (no credentials needed).
	e, gerr := gistcache.Lookup(*url, fmt.Sprintf("xpdf/course/%d", h.CourseID))
	if gerr == nil && e != nil && e.Key != "" {
		fmt.Printf("cache hit: xpdf/course/%d (%s)\n", h.CourseID, e.Name)
		return writePDF(*file, *out, e.Key, raw, h)
	}
	if *token == "" {
		if gerr == nil {
			return fmt.Errorf("cache miss — server path needs -token (run `BenshuPlayer login -phone ... -pass ...` first)")
		}
		return fmt.Errorf("cache lookup failed (%v) — server path needs -token", gerr)
	}

	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	c.Token = *token
	if *skhex != "" {
		raw, err := hex.DecodeString(*skhex)
		if err != nil || len(raw) != 16 {
			return fmt.Errorf("-sk must be 32 hex chars (16 bytes)")
		}
		c.SessionKeyRaw = raw
	}
	cd, err := c.Course(int(h.CourseID))
	if err != nil {
		return err
	}
	dumpJSON("course", cd)
	if cd.EBookKey == "" {
		return fmt.Errorf("course %d returned no ebookKey", h.CourseID)
	}
	if len(c.SessionKeyRaw) != 16 {
		return fmt.Errorf("no -sk given — ebookKey envelope received but cannot be decrypted")
	}
	ckey, err := protocol.DecryptEBookKey(cd.EBookKey, c.SessionKeyHex())
	if err != nil {
		return fmt.Errorf("ebookKey decrypt: %w", err)
	}
	if len(ckey) != 32 {
		return fmt.Errorf("decrypted ebookKey has unexpected length %d (want 32 hex chars)", len(ckey))
	}
	fmt.Printf("ebookKey(plaintext, course key): %s\n", ckey)
	return writePDF(*file, *out, string(ckey), raw, h)
}

// writePDF derives the per-file key and decrypts the xpdf body.
func writePDF(inPath, outPath, courseKey string, raw []byte, h xpdf.Header) error {
	key := xpdf.FileKey(courseKey)
	pt, err := xpdf.DecryptBody(key, raw[xpdf.HeaderLen:], h)
	if err != nil {
		return err
	}
	if outPath == "" {
		outPath = strings.TrimSuffix(inPath, filepath.Ext(inPath)) + ".pdf"
	}
	if err := os.WriteFile(outPath, pt, 0o644); err != nil {
		return err
	}
	fmt.Printf("xpdf -> pdf: %s (%d bytes, course %d)\n", outPath, len(pt), h.CourseID)
	return nil
}

func cmdReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	course := fs.Int("course", 0, "course id")
	student := fs.Int("student", 0, "student id")
	index := fs.Int("index", 0, "video index")
	sec := fs.Int("sec", 0, "watch seconds")
	token := fs.String("token", "", "satoken")
	server := fs.String("server", protocol.DefaultServerURL, "server base URL")
	machineid := fs.String("machineid", "", "machine id (default: derived from /etc/machine-id)")
	fs.Parse(args)

	if *course == 0 || *student == 0 || *index == 0 {
		return fmt.Errorf("-course -student -index are required")
	}
	c, err := newClient(*server, *machineid)
	if err != nil {
		return err
	}
	c.Token = *token
	if err := c.ReportWatch(*course, *student, *index, *sec); err != nil {
		return err
	}
	fmt.Println("report_watch: ok")
	return nil
}

func cmdSelfcheck() error {
	fmt.Println("crypto self-check:")
	fmt.Printf("  universal key = %s (expect 98e32d...303954)\n",
		cryptoHex(crypto.UniversalKey())[:32])
	return nil
}

func cryptoHex(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xf]
	}
	return string(out)
}

// dumpJSON prints a server-returned struct as indented JSON, exactly as
// received (encrypted fields stay ciphertext).
func dumpJSON(label string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fmt.Printf("%s: <json error: %v>\n", label, err)
		return
	}
	fmt.Printf("%s:\n%s\n", label, b)
}
