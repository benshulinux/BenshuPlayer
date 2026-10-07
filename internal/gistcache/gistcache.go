// Package gistcache queries the key cache published as a single JSON
// file. The source is a URI: an http(s) URL (e.g. a gist raw endpoint)
// or a local file path — both carry the identical JSON, so local files
// and the published gist are interchangeable. The JSON maps cache keys
// to candidate key lists, e.g.
//
//	{
//	  "rlk/<courseId>/<videoIndex>": ["32hex", ...],
//	  "xpdf/course/<courseId>": ["32hex", ...]
//	}
//
// Lookups never require credentials. The file is small (a few hundred
// KB), so it is fetched once and reused for the process lifetime.
package gistcache

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// DefaultURL is the default cache source. Filled in once the gist is
// published; override per-invocation with -url.
const DefaultURL = ""

// browserUA satisfies the raw-github signature check on some paths.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var client = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		ForceAttemptHTTP2: false,
		Proxy:             http.ProxyFromEnvironment, // Go 1.26: nil Proxy does NOT fall back to env
	},
}

type cache struct {
	entries map[string][]string
}

var loaded *cache

// Lookup returns the candidate keys for keyPath, or nil when the cache
// has no such entry. A fetch failure is returned as an error so callers
// can fall back to the server path.
func Lookup(source, keyPath string) ([]string, error) {
	if source == "" {
		return nil, fmt.Errorf("gistcache: no cache URL configured")
	}
	if loaded == nil {
		entries, err := fetch(source)
		if err != nil {
			return nil, err
		}
		loaded = &cache{entries: entries}
	}
	return loaded.entries[strings.Trim(keyPath, "/")], nil
}

// fetch reads the JSON table from an http(s) URI or a local file.
func fetch(source string) (map[string][]string, error) {
	var data []byte
	var err error
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		data, err = fetchHTTP(source)
	} else {
		data, err = os.ReadFile(strings.TrimPrefix(source, "file://"))
	}
	if err != nil {
		return nil, err
	}
	var entries map[string][]string
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("gistcache: bad payload: %w", err)
	}
	return entries, nil
}

func fetchHTTP(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gistcache: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("gistcache: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}
