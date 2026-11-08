package app

import (
	"log"
	"os"
	"sync"

	"github.com/egoist/mygo"

	"mygo-music/internal/netproxy"
)

// webView2Args is read by WebView2 as its browser starts, once for the
// app, with the first web view.
const webView2Args = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"

var relayArgs sync.Once

// beforeSignInPage has WebView2's browser go through the relay, which
// follows the settings as they change, whatever they are: the browser
// takes its proxy only as it starts. It must come before the first web view.
func beforeSignInPage() {
	relayArgs.Do(func() {
		addr, err := netproxy.RelayAddr()
		if err != nil {
			log.Printf("sign-in page: not through the proxy: %v", err)
			return
		}
		args := "--proxy-server=http://" + addr
		if old := os.Getenv(webView2Args); old != "" {
			args = old + " " + args
		}
		os.Setenv(webView2Args, args)
	})
}

// proxySignInPage has nothing to do here: the browser has its proxy.
func proxySignInPage(*mygo.Window) {}
