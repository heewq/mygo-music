package app

import (
	"errors"
	"log"
	"net"
	"sync"

	"github.com/ebitengine/purego"
	"github.com/ebitengine/purego/objc"
	"github.com/egoist/mygo"

	"mygo-music/internal/netproxy"
)

// beforeSignInPage has nothing to do here: a page's proxy is its store's.
func beforeSignInPage() {}

// proxySignInPage points the store of a sign-in page's web view at the
// relay, before the page loads anything, when the listener chose how the
// app reaches the web; following the system, WebKit does on its own. It
// takes macOS 14, the first with the store's proxyConfigurations.
func proxySignInPage(win *mygo.Window) {
	if !netproxy.Overridden() {
		return
	}
	addr, err := netproxy.RelayAddr()
	if err == nil {
		mygo.RunOnMain(func() { err = pointAtRelay(objc.ID(win.NativeHandle()), addr) })
	}
	if err != nil {
		log.Printf("sign-in page: not through the proxy: %v", err)
	}
}

// network are the functions of Network.framework that make a proxy.
var network struct {
	once           sync.Once
	err            error
	endpointCreate func(host, port string) uintptr
	httpConnect    func(endpoint, tlsOptions uintptr) uintptr
	release        func(obj uintptr)
}

func loadNetwork() error {
	network.once.Do(func() {
		lib, err := purego.Dlopen("/System/Library/Frameworks/Network.framework/Network", purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			network.err = err
			return
		}
		for name, fn := range map[string]any{
			"nw_endpoint_create_host":             &network.endpointCreate,
			"nw_proxy_config_create_http_connect": &network.httpConnect,
			"nw_release":                          &network.release,
		} {
			if _, err := purego.Dlsym(lib, name); err != nil {
				network.err = err
				return
			}
			purego.RegisterLibFunc(fn, lib, name)
		}
	})
	return network.err
}

// pointAtRelay sets the proxy of the store of the web view in win to the
// relay at addr. Main thread only.
func pointAtRelay(win objc.ID, addr string) error {
	sel := objc.RegisterName
	web := findView(win.Send(sel("contentView")), objc.GetClass("WKWebView"))
	if web == 0 {
		return errors.New("no web view")
	}
	store := web.Send(sel("configuration")).Send(sel("websiteDataStore"))
	if store == 0 || !objc.Send[bool](store, sel("respondsToSelector:"), sel("setProxyConfigurations:")) {
		return errors.New("macOS 14 or newer is needed")
	}
	if err := loadNetwork(); err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	endpoint := network.endpointCreate(host, port)
	config := network.httpConnect(endpoint, 0)
	defer network.release(endpoint)
	defer network.release(config)
	list := objc.ID(objc.GetClass("NSArray")).Send(sel("arrayWithObject:"), config)
	store.Send(sel("setProxyConfigurations:"), list)
	return nil
}

// findView finds v, or the first view under it, of class cls.
func findView(v objc.ID, cls objc.Class) objc.ID {
	if v == 0 {
		return 0
	}
	if objc.Send[bool](v, objc.RegisterName("isKindOfClass:"), cls) {
		return v
	}
	subs := v.Send(objc.RegisterName("subviews"))
	for i := range objc.Send[uint](subs, objc.RegisterName("count")) {
		if found := findView(subs.Send(objc.RegisterName("objectAtIndex:"), i), cls); found != 0 {
			return found
		}
	}
	return 0
}
