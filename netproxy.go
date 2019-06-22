// Package netproxy - network dialer with support HTTP/HTTPS/SOCKS5 proxy, timeout and forward-proxy.
// Fork of "golang.org/x/net/proxy" by biter with support HTTP/HTTPS/SOCKS5 proxy and timeout.
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package netproxy - network dialer with support HTTP/HTTPS/SOCKS5 proxy, timeout and forward-proxy.
package netproxy

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"
)

// A Dialer is a means to establish a connection.
type Dialer interface {
	// Dial connects to the given address via the proxy.
	Dial(network, addr string) (net.Conn, error)
}

// Auth contains authentication parameters that specific Dialers may require.
type Auth struct {
	User, Password string
}

// FromEnvironment returns the dialer specified by the proxy related variables in
// the environment.
func FromEnvironment() Dialer {
	allProxy := allProxyEnv.Get()
	if len(allProxy) == 0 {
		return Direct
	}

	proxyURL, err := url.Parse(allProxy)
	if err != nil {
		return Direct
	}

	timeoutString := timeoutEnv.Get()
	if len(timeoutString) == 0 {
		timeoutString = "1000"
	}
	timeout, err := strconv.Atoi(timeoutString)
	if err != nil {
		timeout = 1000
	}

	proxy, err := FromURL(proxyURL, Direct, time.Millisecond*time.Duration(timeout))
	if err != nil {
		return Direct
	}

	noProxy := noProxyEnv.Get()
	if len(noProxy) == 0 {
		return proxy
	}

	perHost := NewPerHost(proxy, Direct)
	perHost.AddFromString(noProxy)
	return perHost
}

// proxySchemes is a map from URL schemes to a function that creates a Dialer
// from a URL with such a scheme.
var proxySchemes map[string]func(*url.URL, Dialer, time.Duration) (Dialer, error)

// RegisterDialerType takes a URL scheme and a function to generate Dialers from
// a URL with that scheme and a forwarding Dialer. Registered schemes are used
// by FromURL.
func RegisterDialerType(scheme string, f func(*url.URL, Dialer, time.Duration) (Dialer, error)) {
	if proxySchemes == nil {
		proxySchemes = make(map[string]func(*url.URL, Dialer, time.Duration) (Dialer, error))
	}
	proxySchemes[scheme] = f
}

// FromURL returns a Dialer given a URL specification and an underlying
// Dialer for it to make network requests.
// Support HTTP/HTTPS/SOCKS5 proxy
func FromURL(u *url.URL, forward Dialer, timeout time.Duration) (Dialer, error) { // add by biter
	var auth *Auth
	if u.User != nil {
		auth = new(Auth)
		auth.User = u.User.Username()
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	switch u.Scheme {
	case "socks5":
		return SOCKS5("tcp", u.Host, auth, forward, timeout)
	case "http", "https":
		return HTTPProxyDialer("tcp", u.Host, auth, forward, timeout)
	}

	// If the scheme doesn't match any of the built-in schemes, see if it
	// was registered by another package.
	if proxySchemes != nil {
		if f, ok := proxySchemes[u.Scheme]; ok {
			return f(u, forward, timeout)
		}
	}

	return nil, errors.New("proxy: unknown scheme: " + u.Scheme)
}

var (
	allProxyEnv = &envOnce{
		names: []string{"ALL_PROXY", "all_proxy"},
	}
	noProxyEnv = &envOnce{
		names: []string{"NO_PROXY", "no_proxy"},
	}
	timeoutEnv = &envOnce{ // add by biter
		names: []string{"TIMEOUT", "timeout"},
	}
)

// envOnce looks up an environment variable (optionally by multiple
// names) once. It mitigates expensive lookups on some platforms
// (e.g. Windows).
// (Borrowed from net/http/transport.go)
type envOnce struct {
	names []string
	once  sync.Once
	val   string
}

func (e *envOnce) Get() string {
	e.once.Do(e.init)
	return e.val
}

func (e *envOnce) init() {
	for _, n := range e.names {
		e.val = os.Getenv(n)
		if e.val != "" {
			return
		}
	}
}

// reset is used by tests
func (e *envOnce) reset() {
	e.once = sync.Once{}
	e.val = ""
}
