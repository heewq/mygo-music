package netproxy

import (
	"net/http"
	"net/url"
	"testing"
)

// Parse takes a proxy as people type it, and turns down what isn't one.
func TestParse(t *testing.T) {
	good := map[string]string{
		"127.0.0.1:7890":               "http://127.0.0.1:7890",
		" http://127.0.0.1:7890/ ":     "http://127.0.0.1:7890",
		"SOCKS5://localhost:1080":      "socks5://localhost:1080",
		"socks5h://u:p@proxy.lan:1080": "socks5h://u:p@proxy.lan:1080",
		"https://proxy.example.com":    "https://proxy.example.com",
		"http://[::1]:8080":            "http://[::1]:8080",
	}
	for in, want := range good {
		u, err := Parse(in)
		if err != nil {
			t.Errorf("Parse(%q): %v", in, err)
			continue
		}
		if u.String() != want {
			t.Errorf("Parse(%q) = %q, want %q", in, u, want)
		}
	}
	for _, in := range []string{"", "   ", "ftp://host:21", "http://:8080", "http://host:0", "http://host:99999", "http://host:port", "http://host:80/path", "http://host:80?x=1"} {
		if u, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) = %q, want an error", in, u)
		}
	}
}

// Each mode sends a request where it says, and a manual proxy lets this
// computer's addresses go direct.
func TestProxyFor(t *testing.T) {
	defer current.Store(current.Load())
	defer func(old func(*http.Request) (*url.URL, error)) { systemProxy = old }(systemProxy)
	systemProxy = func(*http.Request) (*url.URL, error) { return url.Parse("http://system.proxy:3128") }

	via := func(rawURL string) string {
		t.Helper()
		req, _ := http.NewRequest("GET", rawURL, nil)
		u, err := proxyFor(req)
		if err != nil {
			t.Fatal(err)
		}
		if u == nil {
			return ""
		}
		return u.String()
	}

	if err := Set(Manual, "socks5://127.0.0.1:1080"); err != nil {
		t.Fatal(err)
	}
	if got := via("https://music.example.com/a.mp3"); got != "socks5://127.0.0.1:1080" {
		t.Errorf("manual: via %q", got)
	}
	for _, local := range []string{"http://localhost:3000/", "http://127.0.0.1:8080/", "http://[::1]/", "http://app.localhost/"} {
		if got := via(local); got != "" {
			t.Errorf("manual: %s via %q, want direct", local, got)
		}
	}

	// A proxy that doesn't parse leaves the one before.
	if err := Set(Manual, "nope://"); err == nil {
		t.Error("Set took a proxy that doesn't parse")
	}
	if got := via("https://music.example.com/"); got != "socks5://127.0.0.1:1080" {
		t.Errorf("after a bad proxy: via %q", got)
	}

	Set(Direct, "")
	if got := via("https://music.example.com/"); got != "" {
		t.Errorf("direct: via %q", got)
	}

	Set(System, "socks5://127.0.0.1:1080")
	if got := via("https://music.example.com/"); got != "http://system.proxy:3128" {
		t.Errorf("system: via %q", got)
	}
}
