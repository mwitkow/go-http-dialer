// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package end2end_test

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

	"encoding/base64"

	"github.com/elazarl/goproxy"
	"github.com/mwitkow/go-http-dialer"
	"github.com/mwitkow/go-http-dialer/test/testproto"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type testAuthHandler func(resp http.ResponseWriter, req *http.Request) bool

func TestDialerIntegrationTestSuite(t *testing.T) {
	suite.Run(t, &DialerIntegrationTestSuite{})
}

var (
	expectedUser       = "john"
	expectedPassword   = "bonjovi"
	withBasicProxyAuth = http_dialer.WithProxyAuth(http_dialer.AuthBasic(expectedUser, expectedPassword))
)

// expectBasicProxyAuth implements a basic auth check.
func expectBasicProxyAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		expected := base64.StdEncoding.EncodeToString([]byte(expectedUser + ":" + expectedPassword))
		if req.Header.Get("Proxy-Authorization") != "Basic "+expected {
			resp.Header().Set("Proxy-Authenticate", `Basic realm="foobar"`)
			resp.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		handler(resp, req)
	}
}

type DialerIntegrationTestSuite struct {
	suite.Suite

	grpcListener    net.Listener
	tlsGrpcListener net.Listener

	grpcServer        *grpc.Server
	authHandler       testAuthHandler
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
	noTlsServer := grpc.NewServer()
	mwitkow_testproto.RegisterTestServiceServer(noTlsServer, &mwitkow_testproto.TestService{})
	s.T().Logf("starting grpc.Server at: %v", s.grpcListener.Addr().String())
	go func() {
		noTlsServer.Serve(s.grpcListener)
	}()

	// TLS server
	s.tlsGrpcListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for grpcListener")
	tlsServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTlsConfig())))
	mwitkow_testproto.RegisterTestServiceServer(tlsServer, &mwitkow_testproto.TestService{})
	s.T().Logf("starting grpc.Server TLS at: %v", s.tlsGrpcListener.Addr().String())
	go func() {
		tlsServer.Serve(s.tlsGrpcListener)
	}()

	s.httpProxyListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for httpProxyListener")
	s.httpProxy = goproxy.NewProxyHttpServer()
	s.httpProxy.OnRequest().HandleConnect(goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		fmt.Printf("Got CONNECT Host: %v, URL: %v ReqHost: %v\n", host, ctx.Req.URL.String(), ctx.Req.Host)
		return goproxy.OkConnect, host
	}))
	s.T().Logf("starting http.Proxy at: %v", s.httpProxyListener.Addr().String())
	go func() {
		http.Serve(s.httpProxyListener, expectBasicProxyAuth(s.httpProxy.ServeHTTP))
	}()

	s.tlsProxyListener, err = net.Listen("tcp", "127.0.0.1:0")
	require.NoError(s.T(), err, "must be able to allocate a port for tlsProxyListener")
	s.T().Logf("starting tls http.Proxy at: %v", s.tlsProxyListener.Addr().String())
	go func() {
		tlsListener := tls.NewListener(s.tlsProxyListener, serverTlsConfig())
		http.Serve(tlsListener, expectBasicProxyAuth(s.httpProxy.ServeHTTP))
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
	dialer := http_dialer.New(s.proxyUrl(), withBasicProxyAuth)
	s.grpcCallAndAssert(false, dialer)
}

func (s *DialerIntegrationTestSuite) Test_ProxyTls_NoTls() {
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()), withBasicProxyAuth)
	s.grpcCallAndAssert(false, dialer)
}

func (s *DialerIntegrationTestSuite) Test_ProxyTls_Tls() {
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()), withBasicProxyAuth)
	s.grpcCallAndAssert(true, dialer)
}

func (s *DialerIntegrationTestSuite) Test_SupportsAuthChallenge_WithNoInitialHeader() {
	yoloBasicAuth := &yoloBasicAuthWithoutInitialHeaders{
		username:             expectedUser,
		password:             expectedPassword,
		initialHeaderContent: "", // empty string causes no Proxy-Authenticate to be sent
	}
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()), http_dialer.WithProxyAuth(yoloBasicAuth))
	s.grpcCallAndAssert(true, dialer)
}

func (s *DialerIntegrationTestSuite) Test_SupportsAuthChallenge_WithBadInitialHeader() {
	yoloBasicAuth := &yoloBasicAuthWithoutInitialHeaders{
		username:             expectedUser,
		password:             expectedPassword,
		initialHeaderContent: "BadValue", // initial bad value will cause a reauthencite that will succeed.
	}
	dialer := http_dialer.New(s.proxyTlsUrl(), http_dialer.WithTls(clientTlsConfig()), http_dialer.WithProxyAuth(yoloBasicAuth))
	s.grpcCallAndAssert(true, dialer)
}

func (s *DialerIntegrationTestSuite) grpcCallAndAssert(isGrpcTls bool, dialer *http_dialer.HttpTunnel) {
	opts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTimeout(2 * time.Second),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) { return dialer.Dial("tcp", addr) }),
	}
	addr := s.grpcAddr()
	if isGrpcTls {
		addr = s.grpcTlsAddr()
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(clientTlsConfig())))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}
	client, err := grpc.Dial(addr, opts...)
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

type yoloBasicAuthWithoutInitialHeaders struct {
	username             string
	password             string
	initialHeaderContent string
}

func (b *yoloBasicAuthWithoutInitialHeaders) Type() string {
	return "Basic"
}

func (b *yoloBasicAuthWithoutInitialHeaders) InitialResponse() string {
	return b.initialHeaderContent
}

func (b *yoloBasicAuthWithoutInitialHeaders) ChallengeResponse(challenge string) string {
	resp := b.username + ":" + b.password
	return base64.StdEncoding.EncodeToString([]byte(resp))
}
