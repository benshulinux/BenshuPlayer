// Package mock is a local replay server for the BenshuPlayer protocol,
// used only by tests. It serves the exact response bodies captured from
// the user's own logged-in session (MITM sandbox captures), so the API
// client can be integration-tested fully offline.
package mock

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Fixture is the raw JSON of one capture file.
type Fixture struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	ReqBody     string            `json:"req_body"`
	RespBody    string            `json:"resp_body"`
	ReqHeaders  map[string]string `json:"req_headers"`
	RespHeaders map[string]string `json:"resp_headers"`
	Status      int               `json:"status"`
}

// Server replays fixtures keyed by "METHOD path".
type Server struct {
	mu          sync.Mutex
	fixtures    map[string][]Fixture
	seen        []string          // ordered request log "METHOD path"
	lastBodies  map[string]string // path -> last req body
	lastHeaders map[string]map[string]string
}

// NewServer builds an empty replay server.
func NewServer() *Server {
	return &Server{
		fixtures:    map[string][]Fixture{},
		lastBodies:  map[string]string{},
		lastHeaders: map[string]map[string]string{},
	}
}

// Add registers one fixture (dedup key = method + path).
func (s *Server) Add(f Fixture) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToUpper(f.Method) + " " + f.Path
	s.fixtures[key] = append(s.fixtures[key], f)
}

// AddCapture parses a capture JSON file and registers it.
func (s *Server) AddCapture(raw []byte) error {
	var f Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	s.Add(f)
	return nil
}

// Requests returns the ordered request log.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.seen))
	copy(out, s.seen)
	return out
}

// LastBody returns the body of the last request to path.
func (s *Server) LastBody(path string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastBodies[path]
}

// LastHeaders returns the headers of the last request to path.
func (s *Server) LastHeaders(path string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastHeaders[path]
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.seen = append(s.seen, r.Method+" "+r.URL.Path)
	body, _ := io.ReadAll(r.Body)
	s.lastBodies[r.URL.Path] = string(body)
	hdrs := map[string]string{}
	for k, v := range r.Header {
		hdrs[k] = strings.Join(v, "; ")
	}
	s.lastHeaders[r.URL.Path] = hdrs
	s.mu.Unlock()

	key := strings.ToUpper(r.Method) + " " + r.RequestURI
	s.mu.Lock()
	list := s.fixtures[key]
	if len(list) == 0 {
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"code":500,"msg":"mock: no fixture for %s","data":null}`, r.URL.Path)
		return
	}
	f := list[0]
	s.mu.Unlock()

	for k, v := range f.RespHeaders {
		if !strings.EqualFold(k, "Content-Length") && !strings.EqualFold(k, "Transfer-Encoding") {
			w.Header().Set(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.Status)
	fmt.Fprint(w, f.RespBody)
}
