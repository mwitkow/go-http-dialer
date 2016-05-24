// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

// Package http_dialer provides HTTP(S) CONNECT tunneling net.Dialer. It allows you to
// establish arbitrary TCP connections (as long as your proxy allows them) through a HTTP(S) CONNECT point.
package http_dialer

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type opt func(*HttpTunnel)

// New constructs an HttpTunnel to be used a net.Dial command.
// The first parameter is a proxy URL, for example https://foo.example.com:9090 will use foo.example.com as proxy on
// port 9090 using TLS for connectivity.
// Optional customization parameters are available, e.g.: WithTls, WithDialer, WithConnectionTimeout
func New(proxyUrl *url.URL, opts ...opt) *HttpTunnel {
	t := &HttpTunnel{
		parentDialer: &net.Dialer{},
	}
	t.parseProxyUrl(proxyUrl)
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// WithTls sets the tls.Config to be used (e.g. CA certs) when connecting to an HTTP proxy over TLS.
func WithTls(tlsConfig *tls.Config) opt {
	return func(t *HttpTunnel) {
		t.tlsConfig = tlsConfig
	}
}

// WithDialer allows the customization of the underlying net.Dialer used for establishing TCP connections to the proxy.
func WithDialer(dialer *net.Dialer) opt {
	return func(t *HttpTunnel) {
		t.parentDialer = dialer
	}
}

// WithConnectionTimeout customizes the underlying net.Dialer.Timeout.
func WithConnectionTimeout(timeout time.Duration) opt {
	return func(t *HttpTunnel) {
		t.parentDialer.Timeout = timeout
	}
}

type HttpTunnel struct {
	parentDialer *net.Dialer
	isTls        bool

	proxyAddr string
	// Customizeable TlsConfig to be used when connecting.
	tlsConfig *tls.Config
}

func (t *HttpTunnel) parseProxyUrl(proxyUrl *url.URL) {
	t.proxyAddr = proxyUrl.Host
	if strings.ToLower(proxyUrl.Scheme) == "https" {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":443"
		}
		t.isTls = true
	} else {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":8080"
		}
		t.isTls = false
	}
}

func (t *HttpTunnel) dialProxy() (net.Conn, error) {
	if !t.isTls {
		return t.parentDialer.Dial("tcp", t.proxyAddr)
	}
	return tls.DialWithDialer(t.parentDialer, "tcp", t.proxyAddr, t.tlsConfig)
}

func (t *HttpTunnel) Dial(network string, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("network type '%v' unsupported (only 'tcp')", network)
	}
	conn, err := t.dialProxy()
	if err != nil {
		return nil, fmt.Errorf("http_tunnel: failed dialing to proxy: %v", err)
	}
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address, // This is weird
		Header: make(http.Header),
	}
	// TODO(mwitkow): add Proxy-Authorization support.
	req.Write(conn)

	// TLS server will not speak until spoken to.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("http_tunnel: failed proxying %d: %s", resp.StatusCode, resp.Status)
	}
	return conn, nil
}
