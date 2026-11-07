//go:build !darwin && !windows

package app

import "github.com/egoist/mygo"

// WebKitGTK's pages follow the system's proxy.

func beforeSignInPage()            {}
func proxySignInPage(*mygo.Window) {}
