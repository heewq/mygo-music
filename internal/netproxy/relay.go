package netproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// Web views take a proxy only as they're made, or as their browser starts
// (WebView2), and know nothing of the app's settings. The relay is a proxy
// on this computer for them: it sends what they ask on as the app's own
// requests go now, so a change of the settings reaches them as well.

var relay struct {
	once sync.Once
	addr string
	err  error
}

// Overridden reports whether the listener chose how to reach the web,
// rather than following the system, which web views do on their own.
func Overridden() bool {
	c := current.Load()
	return c != nil && c.mode != System
}

// RelayAddr starts the relay, the first time, and answers its host:port,
// on the loopback address. It runs until the app quits.
func RelayAddr() (string, error) {
	relay.once.Do(func() {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			relay.err = err
			return
		}
		relay.addr = ln.Addr().String()
		srv := &http.Server{Handler: relayHandler(), ReadHeaderTimeout: 30 * time.Second}
		go srv.Serve(ln)
	})
	return relay.addr, relay.err
}

// relayHandler is the relay: CONNECT opens a tunnel, as for HTTPS and
// WebSockets, and a request for an absolute http:// URL is sent on.
func relayHandler() http.Handler {
	forward := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL = r.In.URL
			r.Out.Host = r.In.Host
		},
		Transport: http.DefaultTransport,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodConnect:
			tunnel(w, r)
		case r.URL.IsAbs() && r.URL.Host != "":
			forward.ServeHTTP(w, r)
		default:
			http.Error(w, "this is a proxy", http.StatusBadRequest)
		}
	})
}

// tunnel joins the one asking to the host:port it asked for.
func tunnel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	upstream, err := dialVia(ctx, r.Host)
	cancel()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "can't tunnel", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		// What the client sent with its CONNECT may be in buf already.
		io.Copy(upstream, buf)
		closeWrite(upstream)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		closeWrite(client)
		done <- struct{}{}
	}()
	<-done
	<-done
	client.Close()
	upstream.Close()
}

// closeWrite tells the other end nothing more comes, where the connection
// can say it while it still reads.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// dialVia connects to addr, host:port, the way the app's requests go now.
func dialVia(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// The scheme decides which proxy the environment or the system
	// names: a tunnel is most often for TLS.
	scheme := "https"
	if port == "80" {
		scheme = "http"
	}
	p, err := proxyFor(&http.Request{URL: &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, port)}})
	if err != nil {
		return nil, err
	}
	direct := &net.Dialer{}
	if p == nil {
		return direct.DialContext(ctx, "tcp", addr)
	}
	switch p.Scheme {
	case "socks5", "socks5h":
		d, err := xproxy.FromURL(p, direct)
		if err != nil {
			return nil, err
		}
		if cd, ok := d.(xproxy.ContextDialer); ok {
			return cd.DialContext(ctx, "tcp", addr)
		}
		return d.Dial("tcp", addr)
	case "http", "https":
		return connectVia(ctx, direct, p, addr)
	}
	return nil, fmt.Errorf("can't go through a %s proxy", p.Scheme)
}

// connectVia asks an HTTP or HTTPS proxy for a tunnel to addr.
func connectVia(ctx context.Context, d *net.Dialer, p *url.URL, addr string) (net.Conn, error) {
	proxyAddr := p.Host
	if p.Port() == "" {
		port := "80"
		if p.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(p.Hostname(), port)
	}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if p.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: p.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if u := p.User; u != nil {
		pass, _ := u.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(u.Username()+":"+pass)))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		conn.Close()
		return nil, errors.New("the proxy said " + res.Status)
	}
	conn.SetDeadline(time.Time{})
	return &bufferedConn{conn, br}, nil
}

// bufferedConn reads first what was read past the proxy's answer.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite closes the writing half of a TCP connection under it.
func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}
