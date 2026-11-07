package netproxy

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// upstream is a proxy standing in for the listener's: whatever host it's
// asked for, it reaches target, and it notes what it was asked.
type upstream struct {
	target string // host:port it reaches
	mu     sync.Mutex
	asked  []string // "CONNECT host:port" or "GET url", with the auth sent
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	what := r.Method + " " + r.RequestURI
	if auth := r.Header.Get("Proxy-Authorization"); auth != "" {
		what += " " + auth
	}
	u.asked = append(u.asked, what)
	u.mu.Unlock()
	if r.Method != http.MethodConnect {
		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme, pr.Out.URL.Host = "http", u.target
			},
		}
		rp.ServeHTTP(w, r)
		return
	}
	conn, err := net.Dial("tcp", u.target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	client, buf, _ := w.(http.Hijacker).Hijack()
	client.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	go func() { io.Copy(conn, buf); conn.Close() }()
	io.Copy(client, conn)
	client.Close()
}

func (u *upstream) log() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.asked...)
}

// relayClient is a client that goes through the relay, as a web view does.
func relayClient(t *testing.T) *http.Client {
	t.Helper()
	addr, err := RelayAddr()
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(&url.URL{Scheme: "http", Host: addr}),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}
}

func get(t *testing.T, c *http.Client, u string) string {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.Status + " " + string(b)
}

// What a web view asks of the relay goes through the proxy set by hand, with
// its password, and straight out once the listener says no proxy.
func TestRelayFollowsTheSettings(t *testing.T) {
	defer current.Store(current.Load())
	hello := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "hello "+r.Host) })
	site := httptest.NewTLSServer(hello)
	defer site.Close()
	plain := httptest.NewServer(hello)
	defer plain.Close()

	up := &upstream{target: strings.TrimPrefix(site.URL, "https://")}
	proxy := httptest.NewServer(up)
	defer proxy.Close()
	if err := Set(Manual, "http://me:secret@"+strings.TrimPrefix(proxy.URL, "http://")); err != nil {
		t.Fatal(err)
	}
	c := relayClient(t)

	// The host is made up: only the proxy can reach it.
	if got := get(t, c, "https://music.example/"); got != "200 OK hello music.example" {
		t.Errorf("through the proxy: %q", got)
	}
	up.target = strings.TrimPrefix(plain.URL, "http://")
	if got := get(t, c, "http://music.example/a"); got != "200 OK hello music.example" {
		t.Errorf("plain HTTP through the proxy: %q", got)
	}
	auth := "Basic bWU6c2VjcmV0" // me:secret
	want := []string{"CONNECT music.example:443 " + auth, "GET http://music.example/a " + auth}
	if got := up.log(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the proxy was asked:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	Set(Direct, "")
	c.CloseIdleConnections()
	if got := get(t, c, site.URL+"/"); !strings.HasPrefix(got, "200 OK hello 127.0.0.1") {
		t.Errorf("direct: %q", got)
	}
	if n := len(up.log()); n != 2 {
		t.Errorf("the proxy was asked %d times, want it left alone", n)
	}
}

// A proxy that turns the tunnel down shows as the relay's failure, rather
// than the page waiting.
func TestRelayReportsARefusingProxy(t *testing.T) {
	defer current.Store(current.Load())
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusForbidden)
	}))
	defer refusing.Close()
	if err := Set(Manual, refusing.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := relayClient(t).Get("https://music.example/"); err == nil {
		t.Error("the request went through a proxy that refused it")
	}
}

// Programs started get the relay as every proxy they read, in place of the
// environment's, and go direct to this computer.
func TestWithRelay(t *testing.T) {
	env := []string{"PATH=/bin", "HTTPS_PROXY=http://old:1", "http_proxy=http://old:1", "HOME=/home/me"}
	got := strings.Join(withRelay(env, "http://127.0.0.1:5000", false), "\n")
	want := strings.Join([]string{
		"PATH=/bin", "HOME=/home/me",
		"http_proxy=http://127.0.0.1:5000", "HTTP_PROXY=http://127.0.0.1:5000",
		"https_proxy=http://127.0.0.1:5000", "HTTPS_PROXY=http://127.0.0.1:5000",
		"all_proxy=http://127.0.0.1:5000", "ALL_PROXY=http://127.0.0.1:5000",
		"no_proxy=localhost,127.0.0.1,::1", "NO_PROXY=localhost,127.0.0.1,::1",
	}, "\n")
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
	// Windows has one of each name, whatever its case.
	win := withRelay([]string{"Path=C:\\", "HTTPS_PROXY=http://old:1"}, "http://127.0.0.1:5000", true)
	if len(win) != 1+len(proxyVars) {
		t.Errorf("windows: %q", win)
	}
}
