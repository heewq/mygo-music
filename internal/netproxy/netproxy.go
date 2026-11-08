// Package netproxy sends the app's requests through the proxy the listener
// set by hand, straight out, or as the system's settings say.
//
// It takes over the Proxy of http.DefaultTransport, which every client of
// the app that doesn't make a transport of its own goes through
// (http.DefaultClient, and clients with no Transport set), and of MyGo's
// shared transport, which its updater goes through.
package netproxy

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"

	sysproxy "github.com/egoist/mygo/netproxy"
)

// The ways to reach the web.
const (
	// System goes through the proxy the system's settings name, or the
	// environment's HTTP_PROXY, HTTPS_PROXY and NO_PROXY where they're set.
	System = "system"
	// Direct goes through no proxy.
	Direct = "off"
	// Manual goes through the proxy set by hand, but for this computer.
	Manual = "manual"
)

// config is how requests go out now.
type config struct {
	mode  string
	proxy *url.URL // for Manual
}

// String says how requests go out, to compare two configs by.
func (c *config) String() string {
	if c.proxy == nil {
		return c.mode
	}
	return c.mode + " " + c.proxy.String()
}

var current atomic.Pointer[config]

// transports are those whose Proxy this package decides.
var transports []*http.Transport

func init() {
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transports = append(transports, t)
	}
	// MyGo's is shared, made once, and nothing has asked it for a request
	// before main starts.
	transports = append(transports, sysproxy.Transport())
	for _, t := range transports {
		t.Proxy = proxyFor
	}
}

// systemProxy answers the system's proxy for a request; tests replace it.
var systemProxy = sysproxy.Proxy

// proxyFor answers the proxy to send req through, nil for none.
func proxyFor(req *http.Request) (*url.URL, error) {
	c := current.Load()
	if c == nil {
		return systemProxy(req)
	}
	switch c.mode {
	case Direct:
		return nil, nil
	case Manual:
		if isLoopback(req.URL.Hostname()) {
			return nil, nil
		}
		return c.proxy, nil
	}
	return systemProxy(req)
}

// isLoopback reports whether host is this computer, which a proxy elsewhere
// can't reach as the app means it.
func isLoopback(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Parse reads a proxy as typed: scheme://[user:password@]host[:port], where
// the scheme is http, https, socks5 or socks5h, and http when left out.
func Parse(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("no proxy")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("not a proxy address")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil, errors.New("the scheme must be http, https, socks5 or socks5h")
	}
	if u.Hostname() == "" {
		return nil, errors.New("no host")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("not a port: " + p)
		}
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("a proxy is only a host and port")
	}
	u.Path = ""
	return u, nil
}

// Set has requests go out as mode says, through raw for Manual. An unknown
// mode is System. A Manual proxy that doesn't parse leaves what was set
// before, and says why.
func Set(mode, raw string) error {
	c := &config{mode: mode}
	switch mode {
	case Direct:
	case Manual:
		u, err := Parse(raw)
		if err != nil {
			return err
		}
		c.proxy = u
	default:
		c.mode = System
	}
	if old := current.Swap(c); old != nil && old.String() == c.String() {
		return nil
	}
	// What's kept open went the old way; a request from now on goes the new.
	for _, t := range transports {
		t.CloseIdleConnections()
	}
	return nil
}
