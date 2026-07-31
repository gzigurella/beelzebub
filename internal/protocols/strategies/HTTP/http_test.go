package HTTP

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		require.NoError(t, err)
		nets = append(nets, n)
	}
	return nets
}

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func TestBuildHTTPResponse_Basic(t *testing.T) {
	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}

	cmd := parser.Command{
		Handler:    "Hello World",
		StatusCode: 200,
		Headers:    []string{"X-Test: value"},
	}

	req := httptest.NewRequest("GET", "http://localhost/", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if resp.Body != "Hello World" {
		t.Errorf("expected body 'Hello World', got %q", resp.Body)
	}
}

func TestBuildHTTPResponse_WithStatusCode(t *testing.T) {
	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}

	cmd := parser.Command{
		Handler:    "Not Found",
		StatusCode: 404,
		Headers:    []string{},
	}

	req := httptest.NewRequest("GET", "http://localhost/test", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resp.Body != "Not Found" {
		t.Errorf("expected body 'Not Found', got %q", resp.Body)
	}
}

func TestTraceRequest(t *testing.T) {
	tr := &mockTracer{}

	cmd := parser.Command{Name: "test"}
	req := httptest.NewRequest("GET", "/path", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	req.Header.Set("User-Agent", "test-agent")

	traceRequest(req, tr, cmd, "test honeypot", "body content", mustCIDRs(t, "10.0.0.0/8"))

	if len(tr.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(tr.events))
	}
	e := tr.events[0]
	if e.RequestURI != "/path" {
		t.Errorf("expected URI /path, got %s", e.RequestURI)
	}
	if e.SourceIp != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", e.SourceIp)
	}
}

func TestTraceRequest_TLS(t *testing.T) {
	tr := &mockTracer{}
	cmd := parser.Command{Name: "test"}
	req := httptest.NewRequest("GET", "https://localhost/secure", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.TLS = &tls.ConnectionState{ServerName: "example.com"}

	traceRequest(req, tr, cmd, "tls test", "", nil)

	if len(tr.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(tr.events))
	}
	if tr.events[0].TLSServerName != "example.com" {
		t.Errorf("expected TLS server name 'example.com', got %s", tr.events[0].TLSServerName)
	}
}

func TestSetResponseHeaders(t *testing.T) {
	w := httptest.NewRecorder()
	setResponseHeaders(w, []string{"X-Custom:value1", "X-Other:value2"}, 201)

	if w.Code != 201 {
		t.Errorf("expected status 201, got %d", w.Code)
	}
	if w.Header().Get("X-Custom") != "value1" {
		t.Errorf("expected X-Custom header 'value1', got %s", w.Header().Get("X-Custom"))
	}
}

func TestSetResponseHeaders_NoStatusCode(t *testing.T) {
	w := httptest.NewRecorder()
	setResponseHeaders(w, nil, 0)

	// StatusText(0) returns empty string, so WriteHeader should not be called
	if w.Code != 200 {
		t.Errorf("expected default status 200, got %d", w.Code)
	}
}

func TestRealClientAddr_NoTrustedProxies(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	host, port := realClientAddr(req, nil)
	if host != "10.0.0.1" {
		t.Errorf("expected host 10.0.0.1, got %s", host)
	}
	if port != "12345" {
		t.Errorf("expected port 12345, got %s", port)
	}
}

func TestRealClientAddr_WithTrustedProxy(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1")

	host, port := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	if host != "8.8.8.8" {
		t.Errorf("expected host 8.8.8.8, got %s", host)
	}
	if port != "" {
		t.Errorf("expected empty port, got %s", port)
	}
}

func TestRealClientAddr_TrustedProxyAllTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"

	host, _ := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	// All proxies trusted, so fall back to RemoteAddr
	if host != "10.0.0.1" {
		t.Errorf("expected host 10.0.0.1, got %s", host)
	}
}

func TestRealClientAddr_BadRemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "not-a-valid-addr"

	host, _ := realClientAddr(req, nil)
	if host != "not-a-valid-addr" {
		t.Errorf("expected host 'not-a-valid-addr', got %s", host)
	}
}

func TestIPInNets(t *testing.T) {
	nets := mustCIDRs(t, "10.0.0.0/8", "192.168.0.0/16")

	if !ipInNets(net.ParseIP("10.1.2.3"), nets) {
		t.Error("expected 10.1.2.3 to be in 10.0.0.0/8")
	}
	if !ipInNets(net.ParseIP("192.168.1.1"), nets) {
		t.Error("expected 192.168.1.1 to be in 192.168.0.0/16")
	}
	if ipInNets(net.ParseIP("8.8.8.8"), nets) {
		t.Error("expected 8.8.8.8 to NOT be in any trusted nets")
	}
}

func TestMapHeaderToString(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("X-Custom", "value")

	result := mapHeaderToString(headers)
	if !strings.Contains(result, "Content-Type") || !strings.Contains(result, "application/json") {
		t.Errorf("expected header Content-Type in output, got %s", result)
	}
}

func TestMapCookiesToString(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: "session", Value: "abc123"},
	}
	result := mapCookiesToString(cookies)
	if !strings.Contains(result, "session=abc123") {
		t.Errorf("expected session cookie in output, got %s", result)
	}
}

func TestHTTPStrategy_Init_Valid(t *testing.T) {
	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test HTTP",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.Len(t, strategy.servers, 1)
}

func TestHTTPStrategy_Init_WithTLS(t *testing.T) {
	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test HTTPS",
		TLSKeyPath:  "/nonexistent/key.pem",
		TLSCertPath: "/nonexistent/cert.pem",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestHTTPStrategy_StopAll(t *testing.T) {
	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test HTTP",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Len(t, strategy.servers, 1)

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.servers)
}

func TestHTTPStrategy_StopAll_Empty(t *testing.T) {
	strategy := &HTTPStrategy{}
	assert.NoError(t, strategy.StopAll())
}

func TestHTTPStrategy_Init_WithCommands_Matching(t *testing.T) {
	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	rex, err := regexp.Compile("/test")
	require.NoError(t, err)

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test HTTP with commands",
		Commands: []parser.Command{
			{
				Regex:      rex,
				Handler:    "test response",
				StatusCode: 200,
				Name:       "test-command",
			},
		},
	}

	err = strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestHTTPStrategy_Init_FallbackCommand(t *testing.T) {
	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("fallback"))
	})

	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: mux,
	}
	strategy.servers = map[string]*http.Server{"test:0": srv}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test HTTP",
		FallbackCommand: parser.Command{
			Handler:    "not found",
			StatusCode: 404,
			Name:       "fallback",
		},
	}

	_ = strategy.Init(servConf, mt)
}

func TestRealClientAddr_XRealIP(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-Ip", "8.8.8.8")

	host, _ := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	assert.Equal(t, "8.8.8.8", host)
}

func TestRealClientAddr_XRealIPTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Real-Ip", "10.0.0.2")

	host, _ := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	assert.Equal(t, "10.0.0.1", host)
}

type failOnCloseListener struct {
	net.Listener
	closeErr error
}

func (f *failOnCloseListener) Close() error {
	f.Listener.Close()
	return f.closeErr
}

func TestHTTPStrategy_StopAll_ShutdownError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failL := &failOnCloseListener{Listener: l, closeErr: errors.New("simulated close error")}

	srv := &http.Server{Handler: http.NewServeMux()}
	go srv.Serve(failL)
	time.Sleep(50 * time.Millisecond)

	strategy := &HTTPStrategy{}
	strategy.servers = map[string]*http.Server{"test:0": srv}

	err = strategy.StopAll()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated close error")
	assert.Nil(t, strategy.servers)
}

func TestHTTPStrategy_Stop_ShutdownError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failL := &failOnCloseListener{Listener: l, closeErr: errors.New("simulated close error")}

	srv := &http.Server{Handler: http.NewServeMux()}
	go srv.Serve(failL)
	time.Sleep(50 * time.Millisecond)

	strategy := &HTTPStrategy{}
	strategy.servers = map[string]*http.Server{"test:0": srv}

	servConf := parser.BeelzebubServiceConfiguration{Address: "test:0"}
	err = strategy.Stop(servConf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated close error")
	// On error, Stop returns immediately without deleting from map
	assert.Len(t, strategy.servers, 1)
}

func TestHTTPStrategy_Stop_ServerNotFound(t *testing.T) {
	strategy := &HTTPStrategy{}
	strategy.servers = map[string]*http.Server{"other:0": {}}

	err := strategy.Stop(parser.BeelzebubServiceConfiguration{Address: "test:0"})
	assert.NoError(t, err)
}

func TestHTTPStrategy_StopAll_ServerNotFound(t *testing.T) {
	strategy := &HTTPStrategy{}
	err := strategy.StopAll()
	assert.NoError(t, err)
}

func TestHTTPStrategy_Init_OverwriteExisting(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address: fmt.Sprintf("127.0.0.1:%d", port),
	}

	// First init creates the server
	err = strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.Len(t, strategy.servers, 1)

	// Second init with same address overwrites
	err = strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.Len(t, strategy.servers, 1)

	err = strategy.StopAll()
	assert.NoError(t, err)
}

type testCommandPlugin struct{}

func (p *testCommandPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "http-test-cmd"}
}

func (p *testCommandPlugin) Execute(_ context.Context, req plugin.CommandRequest) (string, error) {
	return "plugin-output", nil
}

type testHTTPPlugin struct{}

func (p *testHTTPPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "http-test-http"}
}

func (p *testHTTPPlugin) HandleHTTP(r *http.Request) plugin.HTTPResponse {
	return plugin.HTTPResponse{
		StatusCode:  201,
		Body:        "http-plugin-body",
		Headers:     map[string]string{"X-Custom": "value"},
		ContentType: "text/plain",
	}
}

type testCommandPluginError struct{}

func (p *testCommandPluginError) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "http-test-cmd-err"}
}

func (p *testCommandPluginError) Execute(_ context.Context, req plugin.CommandRequest) (string, error) {
	return "", errors.New("simulated execute error")
}

func TestBuildHTTPResponse_PluginCommand(t *testing.T) {
	plugin.Register(&testCommandPlugin{})

	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	cmd := parser.Command{Plugin: "http-test-cmd"}
	req := httptest.NewRequest("GET", "http://localhost/", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	assert.NoError(t, err)
	assert.Equal(t, "plugin-output", resp.Body)
}

func TestBuildHTTPResponse_PluginCommandError(t *testing.T) {
	plugin.Register(&testCommandPluginError{})

	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	cmd := parser.Command{Plugin: "http-test-cmd-err"}
	req := httptest.NewRequest("GET", "http://localhost/", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	assert.Error(t, err)
	assert.Contains(t, resp.Body, "404 Not Found")
}

func TestBuildHTTPResponse_HTTPPlugin(t *testing.T) {
	plugin.Register(&testHTTPPlugin{})

	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	cmd := parser.Command{Plugin: "http-test-http"}
	req := httptest.NewRequest("GET", "http://localhost/", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	assert.NoError(t, err)
	assert.Equal(t, "http-plugin-body", resp.Body)
	assert.Equal(t, 201, resp.StatusCode)
}

func TestBuildHTTPResponse_UnknownPlugin(t *testing.T) {
	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}

	cmd := parser.Command{
		Plugin:     "nonexistent-plugin",
		Handler:    "fallback",
		StatusCode: 200,
	}

	req := httptest.NewRequest("GET", "http://localhost/", nil)

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	assert.NoError(t, err)
	assert.Equal(t, "fallback", resp.Body)
}

type errReader struct{}

func (r *errReader) Read(p []byte) (int, error) {
	return 0, errors.New("simulated read error")
}

func TestBuildHTTPResponse_BodyReadError(t *testing.T) {
	tr := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{}
	cmd := parser.Command{Handler: "fallback-body", StatusCode: 200}
	req := httptest.NewRequest("POST", "http://localhost/", io.NopCloser(&errReader{}))

	resp, err := buildHTTPResponse(servConf, tr, cmd, req)
	assert.NoError(t, err)
	assert.Equal(t, "fallback-body", resp.Body)
}

func TestRealClientAddr_XFFEmptyParts(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "8.8.8.8, , 10.0.0.1")

	host, port := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	assert.Equal(t, "8.8.8.8", host)
	assert.Equal(t, "", port)
}

func TestRealClientAddr_XFFAllTrustedFallbackToXRI(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	// XFF entries are all trusted
	req.Header.Set("X-Forwarded-For", "10.0.0.2, 10.0.0.1")
	// XRI is also trusted
	req.Header.Set("X-Real-Ip", "10.0.0.3")

	host, port := realClientAddr(req, mustCIDRs(t, "10.0.0.0/8"))
	assert.Equal(t, "10.0.0.1", host)
	assert.Equal(t, "12345", port)
}

func TestHTTPStrategy_HandleRequest_StaticResponse(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()

	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	rex := regexp.MustCompile("^/test$")
	servConf := parser.BeelzebubServiceConfiguration{
		Address:     addr,
		Description: "test HTTP",
		Commands: []parser.Command{
			{Regex: rex, Handler: "test response", StatusCode: 200, Name: "test-cmd"},
		},
	}

	err = strategy.Init(servConf, mt)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://%s/test", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "test response", string(body))
	assert.Equal(t, 200, resp.StatusCode)

	strategy.StopAll()
}

func TestHTTPStrategy_HandleRequest_Fallback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	l.Close()

	strategy := &HTTPStrategy{}
	mt := &mockTracer{}

	rex := regexp.MustCompile("^/test$")
	servConf := parser.BeelzebubServiceConfiguration{
		Address:     addr,
		Description: "test HTTP",
		Commands: []parser.Command{
			{Regex: rex, Handler: "test response", StatusCode: 200},
		},
		FallbackCommand: parser.Command{
			Handler: "not found", StatusCode: 404, Name: "fallback",
		},
	}

	err = strategy.Init(servConf, mt)
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://%s/unknown", addr))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "not found", string(body))
	assert.Equal(t, 404, resp.StatusCode)

	strategy.StopAll()
}
