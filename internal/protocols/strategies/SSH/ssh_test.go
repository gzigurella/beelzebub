package SSH

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/gliderlabs/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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


