package MCP

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	log "github.com/sirupsen/logrus"
)

type remoteAddrCtxKey struct{}

type MCPStrategy struct {
	servers map[string]*server.StreamableHTTPServer
}

func (mcpStrategy *MCPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if oldServer, ok := mcpStrategy.servers[servConf.Address]; ok {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		oldServer.Shutdown(ctx)
		cancel()
	}

	mcpServer := server.NewMCPServer(
		servConf.Description,
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	for _, toolConfig := range servConf.Tools {
		if toolConfig.Params == nil || len(toolConfig.Params) == 0 {
			log.Errorf("Tool %s has no parameters defined", toolConfig.Name)
			continue
		}

		opts := []mcp.ToolOption{
			mcp.WithDescription(toolConfig.Description),
		}

		if toolConfig.Annotations != nil {
			ann := toolConfig.Annotations
			if ann.Title != "" {
				opts = append(opts, mcp.WithTitleAnnotation(ann.Title))
			}
			if ann.ReadOnlyHint != nil {
				opts = append(opts, mcp.WithReadOnlyHintAnnotation(*ann.ReadOnlyHint))
			}
			if ann.DestructiveHint != nil {
				opts = append(opts, mcp.WithDestructiveHintAnnotation(*ann.DestructiveHint))
			}
			if ann.IdempotentHint != nil {
				opts = append(opts, mcp.WithIdempotentHintAnnotation(*ann.IdempotentHint))
			}
			if ann.OpenWorldHint != nil {
				opts = append(opts, mcp.WithOpenWorldHintAnnotation(*ann.OpenWorldHint))
			}
		}

		for _, param := range toolConfig.Params {
			opts = append(opts,
				mcp.WithString(
					param.Name,
					mcp.Required(),
					mcp.Description(param.Description),
				),
			)
		}

		tool := mcp.NewTool(toolConfig.Name, opts...)

		mcpServer.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			host, port, _ := net.SplitHostPort(ctx.Value(remoteAddrCtxKey{}).(string))

			tr.TraceEvent(tracer.Event{
				Msg:           "New MCP tool invocation",
				Protocol:      tracer.MCP.String(),
				Status:        tracer.Stateless.String(),
				RemoteAddr:    ctx.Value(remoteAddrCtxKey{}).(string),
				SourceIp:      host,
				SourcePort:    port,
				ID:            uuid.New().String(),
				Description:   servConf.Description,
				Command:       fmt.Sprintf("%s|%s", request.Params.Name, request.Params.Arguments),
				CommandOutput: toolConfig.Handler,
			})
			return mcp.NewToolResultText(toolConfig.Handler), nil
		})
	}

	httpServer := server.NewStreamableHTTPServer(
		mcpServer,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, remoteAddrCtxKey{}, r.RemoteAddr)
		}),
	)

	if mcpStrategy.servers == nil {
		mcpStrategy.servers = make(map[string]*server.StreamableHTTPServer)
	}
	mcpStrategy.servers[servConf.Address] = httpServer

	go func() {
		if err := httpServer.Start(servConf.Address); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				log.Debugf("MCP server on %s stopped: %s", servConf.Address, err.Error())
			} else {
				log.Errorf("Failed to start MCP server on %s: %v", servConf.Address, err)
			}
		}
	}()

	return nil
}

func (mcpStrategy *MCPStrategy) StopAll() error {
	var errs []error
	for _, srv := range mcpStrategy.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := srv.Shutdown(ctx); err != nil {
			log.Errorf("error shutting down MCP server: %s", err.Error())
			errs = append(errs, err)
		}
		cancel()
	}
	mcpStrategy.servers = nil
	if len(errs) > 0 {
		return fmt.Errorf("mcp stop errors: %w", errors.Join(errs...))
	}
	return nil
}

func (mcpStrategy *MCPStrategy) Stop(servConf parser.BeelzebubServiceConfiguration) error {
	srv, ok := mcpStrategy.servers[servConf.Address]
	if !ok {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Errorf("error shutting down MCP server on %s: %s", servConf.Address, err.Error())
		return err
	}
	delete(mcpStrategy.servers, servConf.Address)
	return nil
}
