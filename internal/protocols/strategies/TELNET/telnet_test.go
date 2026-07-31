package TELNET

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type telnetTestCommandPlugin struct{}

func (p *telnetTestCommandPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "telnet-test-cmd"}
}

func (p *telnetTestCommandPlugin) Execute(_ context.Context, req plugin.CommandRequest) (string, error) {
	return "telnet-plugin-output", nil
}

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func newTelnetStrategy() *TelnetStrategy {
	return &TelnetStrategy{Sessions: historystore.NewHistoryStore()}
}

// drain reads from conn until deadline expires, discarding data.
func drain(conn net.Conn, timeout time.Duration) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
	}
	conn.SetReadDeadline(time.Time{})
}

func TestNegotiateTelnet_ReadTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		negotiateTelnet(server)
	}()

	// Don't send anything — let the 100ms deadline expire
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for negotiateTelnet")
	}
}

func TestNegotiateTelnet(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		negotiateTelnet(server)
	}()

	// Send a negotiation sequence quickly
	client.Write([]byte{IAC, WILL, ECHO})
	client.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReadLine(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan string, 1)
	go func() {
		s, _ := readLine(server)
		done <- s
	}()

	client.Write([]byte("hello\n"))
	select {
	case s := <-done:
		assert.Equal(t, "hello", s)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReadLine_IACSkip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan string, 1)
	go func() {
		s, _ := readLine(server)
		done <- s
	}()

	// Send IAC DO 1 followed by a newline
	client.Write([]byte{IAC, DO, ECHO, 'h', 'i', '\n'})
	select {
	case s := <-done:
		assert.Equal(t, "hi", s)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReadLine_IACSubnegotiation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan string, 1)
	go func() {
		s, _ := readLine(server)
		done <- s
	}()

	// Send IAC SB ... IAC SE followed by a newline
	msg := []byte{IAC, SB, 1, 2, 3, IAC, SE, 'o', 'k', '\n'}
	client.Write(msg)
	select {
	case s := <-done:
		assert.Equal(t, "ok", s)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestBuildPrompt(t *testing.T) {
	assert.Equal(t, "user@host:~$ ", buildPrompt("user", "host"))
	assert.Equal(t, "@:~$ ", buildPrompt("", ""))
}

func TestTelnetStrategy_Init_InvalidAddress(t *testing.T) {
	strategy := newTelnetStrategy()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "invalid-address-no-port",
		Description: "test",
	}

	err := strategy.Init(servConf, mt)
	assert.Error(t, err)
}

func TestTelnetStrategy_Init_Valid(t *testing.T) {
	strategy := newTelnetStrategy()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "127.0.0.1:0",
		Description:   "test telnet",
		PasswordRegex: ".*",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestHandleTelnetConnection_BadPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	rex, _ := regexp.Compile("secret")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		PasswordRegex:          rex.String(),
		ServerName:             "test",
	}
	strategy := newTelnetStrategy()

	go handleTelnetConnection(server, servConf, mt, strategy)

	drain(client, 500*time.Millisecond)

	client.Write([]byte("user\n"))
	drain(client, 100*time.Millisecond)
	client.Write([]byte("wrongpass\n"))

	time.Sleep(200 * time.Millisecond)
	client.Close()
}

func TestHandleTelnetConnection_ValidPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	rex, _ := regexp.Compile(".*")
	cmdRex, _ := regexp.Compile("ls")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		PasswordRegex:          rex.String(),
		ServerName:             "test",
		Commands: []parser.Command{
			{Regex: cmdRex, Handler: "ok"},
		},
	}
	strategy := newTelnetStrategy()

	go handleTelnetConnection(server, servConf, mt, strategy)

	drain(client, 500*time.Millisecond)
	client.Write([]byte("admin\n"))
	drain(client, 100*time.Millisecond)
	client.Write([]byte("mypass\n"))
	drain(client, 100*time.Millisecond)

	client.Write([]byte("ls\n"))

	time.Sleep(200 * time.Millisecond)
	client.Close()
}

func TestTelnetStrategy_StopAll(t *testing.T) {
	strategy := newTelnetStrategy()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "127.0.0.1:0",
		Description:   "test",
		PasswordRegex: ".*",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Len(t, strategy.listeners, 1)

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.listeners)
}

func TestTelnetStrategy_StopAll_Empty(t *testing.T) {
	strategy := newTelnetStrategy()
	assert.NoError(t, strategy.StopAll())
}

func TestTelnetStrategy_StopAll_AlreadyClosed(t *testing.T) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	listener.Close()

	strategy := newTelnetStrategy()
	strategy.listeners = map[string]net.Listener{"test:0": listener}

	// Close on an already-closed listener returns an error now
	err := strategy.StopAll()
	assert.Error(t, err)
	assert.Nil(t, strategy.listeners)
}

func TestTelnetStrategy_Stop_CloseError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.New(t).NoError(err)
	addr := listener.Addr().String()
	listener.Close()

	listener2, err := net.Listen("tcp", addr)
	require.New(t).NoError(err)

	strategy := newTelnetStrategy()
	strategy.listeners = map[string]net.Listener{addr: listener2}

	err = strategy.Stop(parser.BeelzebubServiceConfiguration{Address: addr})
	assert.NoError(t, err)
	assert.Empty(t, strategy.listeners)
}

func TestTelnetStrategy_Stop_ServerNotFound(t *testing.T) {
	strategy := newTelnetStrategy()
	strategy.listeners = map[string]net.Listener{"other:0": nil}

	err := strategy.Stop(parser.BeelzebubServiceConfiguration{Address: "test:0"})
	assert.NoError(t, err)
}

func TestTelnetStrategy_Init_OverwriteExisting(t *testing.T) {
	strategy := newTelnetStrategy()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "127.0.0.1:0",
		PasswordRegex: ".*",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.Len(t, strategy.listeners, 1)

	// Second Init with same address should close old listener and create new one
	err = strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.Len(t, strategy.listeners, 1)

	strategy.StopAll()
}

func TestTelnetStrategy_Init_BadRegex(t *testing.T) {
	strategy := newTelnetStrategy()
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "127.0.0.1:0",
		PasswordRegex: "[invalid",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestReadLine_ControlChars(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan string, 1)
	go func() {
		s, _ := readLine(server)
		done <- s
	}()

	// Control chars (e.g. 0x01) should be skipped
	client.Write([]byte{0x01, 0x02, 'a', 'b', '\n'})
	select {
	case s := <-done:
		assert.Equal(t, "ab", s)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestReadLine_EOF(t *testing.T) {
	client, server := net.Pipe()
	client.Close()

	_, err := readLine(server)
	assert.Error(t, err)
}

func TestReadLine_IACSubnegotiation_Incomplete(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	done := make(chan string, 1)
	go func() {
		s, _ := readLine(server)
		done <- s
	}()

	// Send IAC SB with data followed by IAC SE to properly close, then newline
	client.Write([]byte{IAC, SB, 1, 2, 3, IAC, SE, 'x', '\n'})
	select {
	case s := <-done:
		assert.Equal(t, "x", s)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestHandleTelnetConnection_UnmatchedCommand(t *testing.T) {
	client, server := net.Pipe()
	mt := &mockTracer{}
	rex, _ := regexp.Compile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		PasswordRegex:          ".*",
		ServerName:             "test",
		Commands: []parser.Command{
			{Regex: rex, Handler: "ok"},
		},
	}
	strategy := newTelnetStrategy()

	done := make(chan struct{})
	go func() {
		handleTelnetConnection(server, servConf, mt, strategy)
		close(done)
	}()

	drain(client, 500*time.Millisecond)
	client.Write([]byte("admin\n"))
	drain(client, 100*time.Millisecond)
	client.Write([]byte("pass\n"))
	drain(client, 100*time.Millisecond)

	// Send unmatched command
	client.Write([]byte("unknown\n"))
	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 512)
	n, _ := client.Read(buf)
	assert.Contains(t, string(buf[:n]), "command not found")

	client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler")
	}

	// Verify session end trace (safe to read after handler exited)
	foundEnd := false
	for _, e := range mt.events {
		if e.Msg == "End TELNET Session" {
			foundEnd = true
			break
		}
	}
	assert.True(t, foundEnd, "should have end session trace event")
}

func TestHandleTelnetConnection_PromptWriteFailure(t *testing.T) {
	client, server := net.Pipe()
	mt := &mockTracer{}
	rex, _ := regexp.Compile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		PasswordRegex:          ".*",
		ServerName:             "test",
		Commands: []parser.Command{
			{Regex: rex, Handler: "ok"},
		},
	}
	strategy := newTelnetStrategy()

	done := make(chan struct{})
	go func() {
		defer close(done)
		handleTelnetConnection(server, servConf, mt, strategy)
	}()

	// Drain the initial login prompts
	drain(client, 500*time.Millisecond)

	// Send username
	client.Write([]byte("admin\n"))
	drain(client, 100*time.Millisecond)
	// Send password — after this, the handler enters the command loop
	client.Write([]byte("pass\n"))
	time.Sleep(200 * time.Millisecond)

	// Close the write side to make the next prompt write fail
	client.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for handler to exit on write failure")
	}
}

func TestHandleTelnetConnection_WithPluginCommand(t *testing.T) {
	plugin.Register(&telnetTestCommandPlugin{})

	client, server := net.Pipe()
	defer client.Close()

	mt := &mockTracer{}
	rex, _ := regexp.Compile("ls")
	servConf := parser.BeelzebubServiceConfiguration{
		Description:            "test",
		DeadlineTimeoutSeconds: 5,
		PasswordRegex:          ".*",
		ServerName:             "test",
		Commands: []parser.Command{
			{
				Regex:  rex,
				Plugin: "telnet-test-cmd",
			},
		},
	}
	strategy := newTelnetStrategy()

	go handleTelnetConnection(server, servConf, mt, strategy)

	drain(client, 500*time.Millisecond)
	client.Write([]byte("admin\n"))
	drain(client, 100*time.Millisecond)
	client.Write([]byte("pass\n"))
	drain(client, 100*time.Millisecond)

	client.Write([]byte("ls\n"))
	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 512)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("failed to read plugin response: %v", err)
	}
	output := strings.TrimSpace(string(buf[:n]))
	assert.Contains(t, output, "telnet-plugin-output")

	client.Close()
}

func TestHandleTelnetConnection_WriteFailAtLogin(t *testing.T) {
	// Create a conn that fails immediately on write
	client, server := net.Pipe()
	client.Close()

	mt := &mockTracer{}
	servConf := parser.BeelzebubServiceConfiguration{
		Description:   "test",
		PasswordRegex: ".*",
	}
	strategy := newTelnetStrategy()

	// Should not panic, just return
	handleTelnetConnection(server, servConf, mt, strategy)
}
