// Package gistcache queries the key cache published as a single JSON
// file. The source is a URI: an http(s) URL (e.g. a gist raw endpoint)
// or a local file path — both carry the identical JSON, so local files
// and the published gist are interchangeable. The JSON maps cache keys
// to entries carrying the server-side display name and the key, e.g.
//
//	{
//	  "rlk/<courseId>/<videoIndex>": {"name": "sample-video.mp4", "key": "32hex"},
//	  "xpdf/course/<courseId>":     {"name": "Sample Course", "key": "32hex"}
//	}
//
// The legacy value shape (a bare list of candidate keys) is still
// parsed: the first element is used as the key.
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
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// DefaultURL is the default cache source: the key cache published as a
// secret gist on the project's GitHub account. Override per-invocation
// with -url (http(s) URL or local file path).
const DefaultURL = "https://gist.githubusercontent.com/benshulinux/0b5921f4d04ea6904e3d7ac96eb8e327/raw/kv_dump.json"

// browserUA satisfies the raw-github signature check on some paths.
const browserUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var client = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		ForceAttemptHTTP2: false,
		Proxy:             http.ProxyFromEnvironment, // Go 1.26: nil Proxy does NOT fall back to env
	},
}

// Entry is one cache row: the key itself plus the server-side display
// name, so a filename can be matched back to its course/index.
type Entry struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// Match pairs an Entry with its cache key path.
type Match struct {
	KeyPath string
	Entry   Entry
}

type cache struct {
	entries map[string]Entry
}

var loaded *cache

// Lookup returns the cache entry for keyPath, or (nil, nil) when the
// cache has no such entry. A fetch failure is returned as an error so
// callers can fall back to the server path.
func Lookup(source, keyPath string) (*Entry, error) {
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
	e, ok := loaded.entries[strings.Trim(keyPath, "/")]
	if !ok {
		return nil, nil
	}
	return &e, nil
}

// FindByName returns every cache row whose server-side display name
// stem is a substring of the given local filename stem (the same
// matching direction the stock player uses: a local name like
// "preview-extra-intro" hits the server row "extra-intro").
// Results are ordered by descending match length, so the closest row
// comes first. An empty result means the filename is not representable
// in the cache.
func FindByName(source, filename string) ([]Match, error) {
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
	stem := strings.TrimSuffix(filepath.Base(filename), filepath.Ext(filename))
	if stem == "" {
		return nil, fmt.Errorf("gistcache: empty filename stem")
	}
	var out []Match
	for k, e := range loaded.entries {
		serverStem := strings.TrimSuffix(e.Name, filepath.Ext(e.Name))
		if serverStem != "" && strings.Contains(stem, serverStem) {
			out = append(out, Match{KeyPath: k, Entry: e})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		li := len(strings.TrimSuffix(out[i].Entry.Name, filepath.Ext(out[i].Entry.Name)))
		lj := len(strings.TrimSuffix(out[j].Entry.Name, filepath.Ext(out[j].Entry.Name)))
		return li > lj
	})
	return out, nil
}

// fetch reads the JSON table from an http(s) URI or a local file.
func fetch(source string) (map[string]Entry, error) {
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
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("gistcache: bad payload: %w", err)
	}
	entries := make(map[string]Entry, len(raw))
	for k, v := range raw {
		var e Entry
		if err := json.Unmarshal(v, &e); err != nil || (e.Key == "" && e.Name == "") {
			// legacy shape: a bare list of candidate keys
			var keys []string
			if err := json.Unmarshal(v, &keys); err != nil {
				return nil, fmt.Errorf("gistcache: bad entry %q: %w", k, err)
			}
			if len(keys) > 0 {
				e = Entry{Key: keys[0]}
			}
		}
		entries[k] = e
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
