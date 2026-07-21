package MCP

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockTracer struct {
	events []tracer.Event
}

func (m *mockTracer) TraceEvent(event tracer.Event) {
	m.events = append(m.events, event)
}

func TestMCPStrategy_Init_NoTools(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server",
		Protocol:    "mcp",
		Tools:       []parser.Tool{},
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestMCPStrategy_Init_ToolWithNoParams(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server",
		Protocol:    "mcp",
		Tools: []parser.Tool{
			{
				Name:        "tool:no-params",
				Description: "A tool with no params",
				Params:      nil,
				Handler:     "response",
			},
		},
	}

	// Tool with no params should be skipped (logged as error) without panicking
	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestMCPStrategy_Init_ToolWithParams(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server",
		Protocol:    "mcp",
		Tools: []parser.Tool{
			{
				Name:        "greet",
				Description: "A greeting tool",
				Handler:     "Hello!",
				Params: []parser.Param{
					{
						Name:        "name",
						Description: "Name to greet",
					},
				},
			},
		},
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestMCPStrategy_Init_ToolWithAnnotations(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}
	readOnly := true

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server with annotations",
		Protocol:    "mcp",
		Tools: []parser.Tool{
			{
				Name:        "annotated-tool",
				Description: "An annotated tool",
				Handler:     "annotated response",
				Annotations: &parser.ToolAnnotations{
					Title:         "My Tool",
					ReadOnlyHint:  &readOnly,
					IdempotentHint: &readOnly,
				},
				Params: []parser.Param{
					{
						Name:        "input",
						Description: "Input param",
					},
				},
			},
		},
	}

	err := strategy.Init(servConf, mt)
	assert.NoError(t, err)
}

func TestMCPStrategy_StopAll(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server",
		Protocol:    "mcp",
		Tools:       []parser.Tool{},
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Len(t, strategy.servers, 1)

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.servers)
}

func TestMCPStrategy_StopAll_Empty(t *testing.T) {
	strategy := &MCPStrategy{}
	assert.NoError(t, strategy.StopAll())
}

func TestMCPStrategy_StopAll_MultipleInits(t *testing.T) {
	strategy := &MCPStrategy{}
	mt := &mockTracer{}

	servConf := parser.BeelzebubServiceConfiguration{
		Address:     "127.0.0.1:0",
		Description: "test MCP server",
		Protocol:    "mcp",
		Tools:       []parser.Tool{},
	}

	assert.NoError(t, strategy.Init(servConf, mt))
	assert.NoError(t, strategy.Init(servConf, mt))
	assert.Equal(t, 1, len(strategy.servers))

	assert.NoError(t, strategy.StopAll())
	assert.Nil(t, strategy.servers)
}

type failOnCloseListener struct {
	net.Listener
	closeErr error
}

func (f *failOnCloseListener) Close() error {
	f.Listener.Close()
	return f.closeErr
}

func TestMCPStrategy_StopAll_ShutdownError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failL := &failOnCloseListener{Listener: l, closeErr: errors.New("simulated close error")}

	rawSrv := &http.Server{Handler: http.NewServeMux()}
	go rawSrv.Serve(failL)
	time.Sleep(50 * time.Millisecond)

	mcpServer := server.NewMCPServer("test", "1.0.0")
	httpServer := server.NewStreamableHTTPServer(mcpServer,
		server.WithStreamableHTTPServer(rawSrv),
	)

	strategy := &MCPStrategy{}
	strategy.servers = map[string]*server.StreamableHTTPServer{"test:0": httpServer}

	err = strategy.StopAll()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated close error")
	assert.Nil(t, strategy.servers)
}

func TestMCPStrategy_Stop_ShutdownError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	failL := &failOnCloseListener{Listener: l, closeErr: errors.New("simulated close error")}

	rawSrv := &http.Server{Handler: http.NewServeMux()}
	go rawSrv.Serve(failL)
	time.Sleep(50 * time.Millisecond)

	mcpServer := server.NewMCPServer("test", "1.0.0")
	httpServer := server.NewStreamableHTTPServer(mcpServer,
		server.WithStreamableHTTPServer(rawSrv),
	)

	strategy := &MCPStrategy{}
	strategy.servers = map[string]*server.StreamableHTTPServer{"test:0": httpServer}

	err = strategy.Stop(parser.BeelzebubServiceConfiguration{Address: "test:0"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simulated close error")
	assert.Empty(t, strategy.servers)
}

func TestMCPStrategy_Stop_ServerNotFound(t *testing.T) {
	strategy := &MCPStrategy{}
	strategy.servers = map[string]*server.StreamableHTTPServer{"other:0": nil}

	err := strategy.Stop(parser.BeelzebubServiceConfiguration{Address: "test:0"})
	assert.NoError(t, err)
}
