// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/mwitkow/go-http-dialer"
	"github.com/mwitkow/go-http-dialer/test/testproto"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func TestDialerIntegrationTestSuite(t *testing.T) {
	suite.Run(t, &DialerIntegrationTestSuite{})
}

type DialerIntegrationTestSuite struct {
	suite.Suite

	grpcListener    net.Listener
	tlsGrpcListener net.Listener

	grpcServer        *grpc.Server
	httpProxy         *goproxy.ProxyHttpServer
	httpProxyListener net.Listener
	tlsProxyListener  net.Listener

	ctx context.Context
}

func (s *DialerIntegrationTestSuite) SetupSuite() {
	var err error

	// non TLS server
	s.grpcListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for grpcListener")
	server := grpc.NewServer()
	mwitkow_testproto.RegisterTestServiceServer(server, &mwitkow_testproto.TestService{})
	go func() {
		s.T().Logf("starting grpc.Server at: %v", s.grpcListener.Addr().String())
		server.Serve(s.grpcListener)
	}()

	// TLS server
	s.tlsGrpcListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for grpcListener")
	server = grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTlsConfig())))
	mwitkow_testproto.RegisterTestServiceServer(server, &mwitkow_testproto.TestService{})
	go func() {
		s.T().Logf("starting grpc.Server TLS at: %v", s.tlsGrpcListener.Addr().String())
		server.Serve(s.tlsGrpcListener)
	}()

	s.httpProxyListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for httpProxyListener")
	s.httpProxy = goproxy.NewProxyHttpServer()
	s.httpProxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		fmt.Printf("Got CONNECT Host: %v, URL: %v ReqHost: %v\n", host, ctx.Req.URL.String(), ctx.Req.Host)
		return goproxy.OkConnect, host
	}))
	go func() {
		s.T().Logf("starting http.Proxy at: %v", s.httpProxyListener.Addr().String())
		http.Serve(s.httpProxyListener, s.httpProxy)
	}()

	s.tlsProxyListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for tlsProxyListener")
	go func() {
		s.T().Logf("starting tls http.Proxy at: %v", s.tlsProxyListener.Addr().String())
		tlsListener := tls.NewListener(s.tlsProxyListener, serverTlsConfig())
		http.Serve(tlsListener, s.httpProxy)
	}()
}

func (s *DialerIntegrationTestSuite) TearDownSuite() {
	if s.grpcListener != nil {
		s.T().Logf("stopped grpc.Server at: %v", s.grpcListener.Addr().String())
		s.grpcListener.Close()
	}
	if s.httpProxyListener != nil {
		s.httpProxyListener.Close()
		s.T().Logf("stopped httpProxy at: %v", s.httpProxyListener.Addr().String())
		s.httpProxyListener.Close()
	}
	if s.tlsProxyListener != nil {
		s.tlsProxyListener.Close()
		s.T().Logf("stopped tls httpProxy at: %v", s.tlsProxyListener.Addr().String())
		s.tlsProxyListener.Close()
	}
	if s.tlsGrpcListener != nil {
		s.T().Logf("stopped tls grpc.Server at: %v", s.grpcListener.Addr().String())
		s.tlsGrpcListener.Close()
	}
}

func (s *DialerIntegrationTestSuite) SetupTest() {
	// Make all RPC calls last at most 2 sec, meaning all async issues or deadlock will not kill tests.
	s.ctx, _ = context.WithTimeout(context.TODO(), 2*time.Second)
}

func (s *DialerIntegrationTestSuite) grpcAddr() string {
	return s.grpcListener.Addr().String()
}

func (s *DialerIntegrationTestSuite) grpcTlsAddr() string {
	return s.tlsGrpcListener.Addr().String()
}

func (s *DialerIntegrationTestSuite) proxyUrl() *url.URL {
	u, err := url.Parse("http://" + s.httpProxyListener.Addr().String())
	require.NoError(s.T(), err, "failed parsing httpProxyListener into URL")
	return u
}

func (s *DialerIntegrationTestSuite) proxyTlsUrl() *url.URL {
	u, err := url.Parse("https://" + s.tlsProxyListener.Addr().String())
	require.NoError(s.T(), err, "failed parsing tlsProxyListener into URL")
	return u
}

func (s *DialerIntegrationTestSuite) Test_DialDirectly() {
	client, err := grpc.Dial(s.grpcAddr(), grpc.WithInsecure(), grpc.WithBlock(), grpc.WithTimeout(2*time.Second))
	require.NoError(s.T(), err, "must not error on client Dial")
	testClient := mwitkow_testproto.NewTestServiceClient(client)
	_, err = testClient.PingEmpty(s.ctx, &mwitkow_testproto.Empty{})
	require.NoError(s.T(), err, "empty call must succeed")
}

func (s *DialerIntegrationTestSuite) Test_NoTls_NoTls() {
	dialer := http_dialer.New(s.proxyUrl())
	client, err := grpc.Dial(
		s.grpcAddr(),
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(2*time.Second),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) { return dialer.Dial("tcp", addr) }))
	require.NoError(s.T(), err, "must not error on client Dial")
	testClient := mwitkow_testproto.NewTestServiceClient(client)
	_, err = testClient.PingEmpty(s.ctx, &mwitkow_testproto.Empty{})
	require.NoError(s.T(), err, "empty call must succeed")
}

func (s *DialerIntegrationTestSuite) Test_ProxyTls_NoTls() {
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()))
	client, err := grpc.Dial(
		s.grpcAddr(),
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(2*time.Second),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) { return dialer.Dial("tcp", addr) }))
	require.NoError(s.T(), err, "must not error on client Dial")
	testClient := mwitkow_testproto.NewTestServiceClient(client)
	_, err = testClient.PingEmpty(s.ctx, &mwitkow_testproto.Empty{})
	require.NoError(s.T(), err, "empty call must succeed")
}

func (s *DialerIntegrationTestSuite) Test_ProxyTls_Tls() {
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()))
	client, err := grpc.Dial(
		s.grpcTlsAddr(),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTlsConfig())),
		grpc.WithBlock(),
		grpc.WithTimeout(2*time.Second),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) { return dialer.Dial("tcp", addr) }))
	require.NoError(s.T(), err, "must not error on client Dial")
	testClient := mwitkow_testproto.NewTestServiceClient(client)
	_, err = testClient.PingEmpty(s.ctx, &mwitkow_testproto.Empty{})
	require.NoError(s.T(), err, "empty call must succeed")
}

func serverTlsConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("testdata/server1.pem", "testdata/server1.key")
	if err != nil {
		panic(fmt.Sprintf("failed reading serverTlsConfig: %v", err))
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func clientTlsConfig() *tls.Config {
	b, err := ioutil.ReadFile("testdata/ca.pem")
	if err != nil {
		panic(fmt.Sprintf("failed reading clientTlsConfig: %v", err))
	}
	cp := x509.NewCertPool()
	if !cp.AppendCertsFromPEM(b) {
		panic(fmt.Sprintf("failed appending certs in clientTlsConfig: %v", err))
	}
	return &tls.Config{InsecureSkipVerify: true, RootCAs: cp}
}
