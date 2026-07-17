package TCP

import (
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
)

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func newStrategyWithSessions() *TCPStrategy {
	return &TCPStrategy{Sessions: historystore.NewHistoryStore()}
}

func TestHandleTCPConnection_NoCommands_Legacy(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		Commands:               []parser.Command{},
	}
	strategy := newStrategyWithSessions()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConnection(server, servConf, mt, strategy)
	}()

	client.Write([]byte("hello world"))
	client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for connection handler")
	}

	assert.GreaterOrEqual(t, len(mt.events), 1)
	assert.Equal(t, tracer.Stateless.String(), mt.events[0].Status)
}

func TestHandleTCPConnection_WithBanner(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		Banner:                 "Welcome to TCP honeypot",
	}
	strategy := newStrategyWithSessions()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConnection(server, servConf, mt, strategy)
	}()

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read banner: %v", err)
	}

	banner := strings.TrimSpace(string(buf[:n]))
	assert.Equal(t, "Welcome to TCP honeypot", banner)

	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for connection handler")
	}
}

func TestHandleTCPConnection_WithCommands(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	rex, _ := regexp.Compile("ping")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		Commands: []parser.Command{
			{
				Regex:   rex,
				Handler: "pong",
				Name:    "ping-command",
			},
		},
	}
	strategy := newStrategyWithSessions()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConnection(server, servConf, mt, strategy)
	}()

	client.Write([]byte("ping\n"))
	time.Sleep(100 * time.Millisecond)

	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	assert.Equal(t, "pong", strings.TrimSpace(string(buf[:n])))

	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for connection handler")
	}
}

func TestHandleTCPConnection_NonUTF8Bytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
	}
	strategy := newStrategyWithSessions()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConnection(server, servConf, mt, strategy)
	}()

	client.Write([]byte{0xff, 0xfe, 0x00, 0x01})
	client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for connection handler")
	}

	assert.GreaterOrEqual(t, len(mt.events), 1)
	if len(mt.events) > 0 {
		assert.NotEmpty(t, mt.events[0].CommandRaw)
	}
}

func TestTCPStrategy_Init_InvalidAddress(t *testing.T) {
	strategy := newStrategyWithSessions()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "invalid-address-no-port",
		Description: "test",
	}

	err := strategy.Init(servConf, mt)
	assert.Error(t, err)
}

func TestTCPStrategy_StopAll(t *testing.T) {
	strategy := newStrategyWithSessions()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Len(t, strategy.listeners, 1)

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.listeners)
}

func TestTCPStrategy_StopAll_Empty(t *testing.T) {
	strategy := newStrategyWithSessions()
	assert.NoError(t, strategy.StopAll())
}

func TestTCPStrategy_StopAll_AcceptsReturnsClosed(t *testing.T) {
	strategy := newStrategyWithSessions()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Len(t, strategy.listeners, 1)

	// Stop all, which closes the listener
	assert.NoError(t, strategy.StopAll())

	// The accept loop should exit cleanly (net.ErrClosed)
	time.Sleep(50 * time.Millisecond)
}

func TestTCPStrategy_StopAll_AlreadyClosed(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	listener.Close()

	strategy := newStrategyWithSessions()
	strategy.listeners = append(strategy.listeners, listener)

	// Close on an already-closed listener returns an error now
	err := strategy.StopAll()
	assert.Error(t, err)
	assert.Nil(t, strategy.listeners)
}

func TestHexEscapeNonPrintable(t *testing.T) {
	tests := []struct {
		input    []byte
		expected string
	}{
		{[]byte("hello"), "hello"},
		{[]byte{0x00, 0x01, 0x02}, `\x00\x01\x02`},
		{[]byte("test\x00end"), "test\\x00end"},
		{[]byte{0x7f}, `\x7f`},
		{[]byte{0x5c}, `\x5c`}, // backslash
	}
	for _, tt := range tests {
		result := hexEscapeNonPrintable(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

func TestHandleTCPConnection_Deadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 1,
		Commands:               []parser.Command{},
	}
	strategy := newStrategyWithSessions()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTCPConnection(server, servConf, mt, strategy)
	}()

	// Don't write anything, let the deadline expire
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for deadline")
	}
}
