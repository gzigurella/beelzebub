package SSH

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"
	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type sshTestCommandPlugin struct{}

func (p *sshTestCommandPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "ssh-test-cmd"}
}

func (p *sshTestCommandPlugin) Execute(_ context.Context, req plugin.CommandRequest) (string, error) {
	return "ssh-plugin-output", nil
}

type sshTestCommandPluginError struct{}

func (p *sshTestCommandPluginError) Metadata() plugin.Metadata {
	return plugin.Metadata{Name: "ssh-test-cmd-err"}
}

func (p *sshTestCommandPluginError) Execute(_ context.Context, req plugin.CommandRequest) (string, error) {
	return "", fmt.Errorf("simulated error")
}

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func TestBuildPrompt(t *testing.T) {
	tests := []struct {
		user       string
		serverName string
		expected   string
	}{
		{"root", "ubuntu", "root@ubuntu:~$ "},
		{"admin", "debian", "admin@debian:~$ "},
		{"", "", "@:~$ "},
		{"user", "", "user@:~$ "},
		{"", "server", "@server:~$ "},
	}
	for _, tt := range tests {
		t.Run(tt.user+"@"+tt.serverName, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildPrompt(tt.user, tt.serverName))
		})
	}
}

func TestSSHStrategy_Init_ValidAddress(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		Description:            "test SSH",
		DeadlineTimeoutSeconds: 2,
		PasswordRegex:          ".*",
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
	assert.NotNil(t, strategy.Sessions)
}

func TestSSHStrategy_Init_ReusesExistingSessions(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		DeadlineTimeoutSeconds: 1,
		PasswordRegex:          ".*",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.NotNil(t, strategy.Sessions)

	original := strategy.Sessions

	// A second Init must reuse the same Sessions store, not replace it.
	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Same(t, original, strategy.Sessions)
}

func TestSSHStrategy_Init_InvalidAddress(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:       "invalid-address-no-port",
		PasswordRegex: ".*",
	}

	// SSH runs the listener asynchronously; Init itself should not return an error.
	assert.NoError(t, strategy.Init(servConf, mt))
}

func TestSSHStrategy_StopAll(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		Description:            "test SSH",
		DeadlineTimeoutSeconds: 2,
		PasswordRegex:          ".*",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Equal(t, 1, len(strategy.servers))

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.servers)
}

func TestSSHStrategy_StopAll_Empty(t *testing.T) {
	strategy := &SSHStrategy{}
	assert.NoError(t, strategy.StopAll())
}

func TestSSHStrategy_StopAll_MultipleInits(t *testing.T) {
	strategy := &SSHStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:                "127.0.0.1:0",
		Description:            "test SSH",
		DeadlineTimeoutSeconds: 1,
		PasswordRegex:          ".*",
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Equal(t, 1, len(strategy.servers))

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.servers)

	// Verify servers can be restarted after StopAll
	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Equal(t, 1, len(strategy.servers))

	time.Sleep(100 * time.Millisecond)
	assert.NoError(t, strategy.StopAll())
}

type failOnCloseListener struct {
	net.Listener
	closeErr error
}

func (f *failOnCloseListener) Close() error {
	f.Listener.Close()
	return f.closeErr
}

type mockSession struct {
	rawCmd   string
	user     string
	remoteAddr string
	environ  []string
	writeBuf []byte
	readBuf  []byte
}

func (m *mockSession) Write(p []byte) (int, error) {
	m.writeBuf = append(m.writeBuf, p...)
	return len(p), nil
}

func (m *mockSession) Read(p []byte) (int, error) {
	if len(m.readBuf) == 0 {
		return 0, fmt.Errorf("EOF")
	}
	n := copy(p, m.readBuf)
	m.readBuf = m.readBuf[n:]
	return n, nil
}

func (m *mockSession) User() string                    { return m.user }
func (m *mockSession) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 2222} }
func (m *mockSession) Environ() []string                { return m.environ }
func (m *mockSession) RawCommand() string              { return m.rawCmd }
func (m *mockSession) Exit(code int) error              { return nil }
func (m *mockSession) Command() []string                { return nil }
func (m *mockSession) Subsystem() string                { return "" }
func (m *mockSession) PublicKey() ssh.PublicKey          { return nil }
func (m *mockSession) Context() ssh.Context              { return &mockContext{user: m.user} }
func (m *mockSession) Permissions() ssh.Permissions      { return ssh.Permissions{} }
func (m *mockSession) Pty() (ssh.Pty, <-chan ssh.Window, bool) { return ssh.Pty{}, nil, false }
func (m *mockSession) Signer() ssh.Signer                { return nil }
func (m *mockSession) Close() error                       { return nil }
func (m *mockSession) CloseWrite() error                  { return nil }
func (m *mockSession) Break(chan<- bool)                  {}
func (m *mockSession) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 22} }
func (m *mockSession) Lock()                               {}
func (m *mockSession) Unlock()                             {}
func (m *mockSession) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (m *mockSession) Stderr() io.ReadWriter              { return nil }
func (m *mockSession) Signals(ch chan<- ssh.Signal)       {}

type mockContext struct {
	user string
}

func (m *mockContext) User() string                    { return m.user }
func (m *mockContext) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 2222} }
func (m *mockContext) Environ() []string                { return nil }
func (m *mockContext) Permissions() *ssh.Permissions     { return nil }
func (m *mockContext) SetValue(k, v interface{})         {}
func (m *mockContext) ClientVersion() string             { return "SSH-2.0-test" }
func (m *mockContext) ServerVersion() string             { return "SSH-2.0-beelzebub" }
func (m *mockContext) Deadline() (time.Time, bool)       { return time.Time{}, false }
func (m *mockContext) Done() <-chan struct{}              { return nil }
func (m *mockContext) Err() error                         { return nil }
func (m *mockContext) Value(key interface{}) interface{}  { return nil }
func (m *mockContext) LocalAddr() net.Addr                { return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 22} }
func (m *mockContext) SessionID() string                  { return "test-session-id" }
func (m *mockContext) Lock()                               {}
func (m *mockContext) Unlock()                             {}

func TestHandleSession_RawCommand(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		Commands: []parser.Command{
			{Regex: rex, Handler: "bin  boot  dev", Name: "ls-cmd"},
		},
	}
	sess := &mockSession{rawCmd: "ls", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	assert.Contains(t, string(sess.writeBuf), "bin")
	assert.GreaterOrEqual(t, len(mt.events), 1)
	assert.Equal(t, "SSH Raw Command", mt.events[0].Msg)
}

func TestHandleSession_RawCommand_NotFound(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		ServerName:  "test-server",
		Commands: []parser.Command{
			{Regex: rex, Handler: "bin  boot", Name: "ls-cmd"},
		},
	}
	sess := &mockSession{rawCmd: "unknown", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	// Should fall through to terminal session
	assert.GreaterOrEqual(t, len(mt.events), 2)
	assert.Equal(t, "New SSH Terminal Session", mt.events[0].Msg)
}

func TestHandleSession_RawCommand_WithExit(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^exit$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		ServerName:  "test-server",
		Commands: []parser.Command{
			{Regex: rex, Handler: "", Name: "exit-cmd"},
		},
	}
	sess := &mockSession{rawCmd: "exit", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	assert.GreaterOrEqual(t, len(mt.events), 1)
	assert.Equal(t, "SSH Raw Command", mt.events[0].Msg)
}

func TestHandlePassword_Match(t *testing.T) {
	mt := &mockTracer{}
	ctx := &mockContext{user: "root"}
	servConf := parser.BeelzebubServiceConfiguration{
		PasswordRegex: "^root|admin$",
	}

	result := handlePassword(ctx, "root", servConf, mt)
	assert.True(t, result)

	assert.GreaterOrEqual(t, len(mt.events), 1)
	assert.Equal(t, "New SSH Login Attempt", mt.events[0].Msg)
}

func TestHandlePassword_NoMatch(t *testing.T) {
	mt := &mockTracer{}
	ctx := &mockContext{user: "root"}
	servConf := parser.BeelzebubServiceConfiguration{
		PasswordRegex: "^admin$",
	}

	result := handlePassword(ctx, "wrongpass", servConf, mt)
	assert.False(t, result)
}

func TestHandlePassword_InvalidRegex(t *testing.T) {
	mt := &mockTracer{}
	ctx := &mockContext{user: "root"}
	servConf := parser.BeelzebubServiceConfiguration{
		PasswordRegex: "[invalid",
	}

	result := handlePassword(ctx, "test", servConf, mt)
	assert.False(t, result)
}

func TestHandleSession_PluginCommand(t *testing.T) {
	plugin.Register(&sshTestCommandPlugin{})

	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^ping$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		Commands: []parser.Command{
			{Regex: rex, Plugin: "ssh-test-cmd", Name: "ping-cmd"},
		},
	}
	sess := &mockSession{rawCmd: "ping", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	assert.Contains(t, string(sess.writeBuf), "ssh-plugin-output")
	assert.GreaterOrEqual(t, len(mt.events), 1)
}

func TestHandleSession_PluginCommandError(t *testing.T) {
	plugin.Register(&sshTestCommandPluginError{})

	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^fail$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		Commands: []parser.Command{
			{Regex: rex, Plugin: "ssh-test-cmd-err", Name: "fail-cmd"},
		},
	}
	sess := &mockSession{rawCmd: "fail", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	assert.Contains(t, string(sess.writeBuf), "command not found")
}

func TestHandleSession_TerminalCommand(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		ServerName:  "test-server",
		Commands: []parser.Command{
			{Regex: rex, Handler: "bin  boot", Name: "ls-cmd"},
		},
	}
	sess := &mockSession{
		rawCmd:  "",
		user:    "root",
		readBuf: []byte("ls\nexit\n"),
	}

	handleSession(sess, servConf, mt, sessions)

	// Should have terminal interaction and end session events
	foundInteraction := false
	foundEnd := false
	for _, e := range mt.events {
		if e.Msg == "SSH Terminal Session Interaction" {
			foundInteraction = true
		}
		if e.Msg == "End SSH Session" {
			foundEnd = true
		}
	}
	assert.True(t, foundInteraction, "should have terminal interaction event")
	assert.True(t, foundEnd, "should have end session event")
}

func TestHandleSession_TerminalUnknownCommand(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	rex := regexp.MustCompile("^ls$")
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		ServerName:  "test-server",
		Commands: []parser.Command{
			{Regex: rex, Handler: "bin", Name: "ls-cmd"},
		},
	}
	sess := &mockSession{
		rawCmd:  "",
		user:    "root",
		readBuf: []byte("unknown\nexit\n"),
	}

	handleSession(sess, servConf, mt, sessions)

	// Unknown command just loops back, no interaction event
	foundInteraction := false
	for _, e := range mt.events {
		if e.Msg == "SSH Terminal Session Interaction" {
			foundInteraction = true
			break
		}
	}
	assert.False(t, foundInteraction, "should NOT have interaction event for unknown command")
}

func TestHandleSession_EndSession(t *testing.T) {
	mt := &mockTracer{}
	sessions := historystore.NewHistoryStore()
	servConf := parser.BeelzebubServiceConfiguration{
		Description: "test",
		ServerName:  "test-server",
	}
	sess := &mockSession{rawCmd: "", user: "root"}

	handleSession(sess, servConf, mt, sessions)

	// No raw command → enters terminal loop → Read returns EOF → exits → end session trace
	foundEnd := false
	for _, e := range mt.events {
		if e.Msg == "End SSH Session" {
			foundEnd = true
			break
		}
	}
	assert.True(t, foundEnd, "should emit End SSH Session event")
}

func TestSSHStrategy_Stop_ServerNotFound(t *testing.T) {
	strategy := &SSHStrategy{}
	strategy.servers = map[string]*ssh.Server{"other:0": nil}

	err := strategy.Stop(parser.BeelzebubServiceConfiguration{Address: "test:0"})
	assert.NoError(t, err)
}

func TestSSHStrategy_StopAll_ShutdownError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failL := &failOnCloseListener{Listener: l, closeErr: errors.New("simulated close error")}

	server := &ssh.Server{
		Handler: ssh.Handler(func(s ssh.Session) {}),
	}
	go func() {
		server.Serve(failL)
	}()
	time.Sleep(50 * time.Millisecond)

	strategy := &SSHStrategy{}
	strategy.servers = map[string]*ssh.Server{"test:0": server}

	err = strategy.StopAll()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated close error")
	assert.Nil(t, strategy.servers)
}


