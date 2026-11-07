package netproxy

import (
	"os"
	"runtime"
	"strings"
)

// proxyVars are the variables programs take their proxy from: curl's,
// ffmpeg's (http_proxy, for https too), Python's and yt-dlp's.
var proxyVars = []string{"http_proxy", "https_proxy", "all_proxy", "no_proxy"}

// Environ answers the environment a program the app starts runs with to
// reach the web as the app does: the app's own, with the proxy variables
// naming the relay, which goes the way the settings say, through a SOCKS
// proxy or one with a password too, which programs such as ffmpeg can't.
// Following the system, it answers nil: the app's environment as it is.
func Environ() ([]string, error) {
	if !Overridden() {
		return nil, nil
	}
	addr, err := RelayAddr()
	if err != nil {
		return nil, err
	}
	return withRelay(os.Environ(), "http://"+addr, runtime.GOOS == "windows"), nil
}

// withRelay is env with the proxy variables set to relay, and to go direct
// to this computer. Windows's names are the same in any case, so there each
// is set once.
func withRelay(env []string, relay string, windows bool) []string {
	out := make([]string, 0, len(env)+2*len(proxyVars))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if !isProxyVar(name) {
			out = append(out, kv)
		}
	}
	for _, name := range proxyVars {
		value := relay
		if name == "no_proxy" {
			value = "localhost,127.0.0.1,::1"
		}
		out = append(out, name+"="+value)
		if !windows {
			out = append(out, strings.ToUpper(name)+"="+value)
		}
	}
	return out
}

func isProxyVar(name string) bool {
	for _, v := range proxyVars {
		if strings.EqualFold(name, v) {
			return true
		}
	}
	return false
}
