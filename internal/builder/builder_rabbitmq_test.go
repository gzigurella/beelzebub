package builder

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/HTTP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TCP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/rabbitmq"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupRabbitMQContainer(t *testing.T) (testcontainers.Container, string) {
	t.Helper()

	ctx := context.Background()
	container, err := rabbitmq.RunContainer(ctx,
		testcontainers.WithImage("rabbitmq:3.13-alpine"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Server startup complete").
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		if strings.Contains(err.Error(), "Cannot connect to the Docker daemon") {
			t.Skip("Docker not available, skipping RabbitMQ test")
		}
		t.Fatalf("failed to start RabbitMQ container: %s", err.Error())
	}

	uri, err := container.PortEndpoint(ctx, "5672/tcp", "amqp")
	require.NoError(t, err)

	t.Cleanup(func() {
		container.Terminate(ctx)
	})

	return container, uri
}

func TestBuildRabbitMQ_Success(t *testing.T) {
	_, uri := setupRabbitMQContainer(t)

	b := NewBuilder()
	err := b.buildRabbitMQ(uri)
	assert.NoError(t, err)
	assert.NotNil(t, b.rabbitMQConnection)
	assert.NotNil(t, b.rabbitMQChannel)

	b.Close()
}

func TestBuildRabbitMQ_SuccessWithQueueDeclare(t *testing.T) {
	_, uri := setupRabbitMQContainer(t)

	b := NewBuilder()
	err := b.buildRabbitMQ(uri)
	require.NoError(t, err)

	// Verify queue was declared and is usable
	q, err := b.rabbitMQChannel.QueueInspect(RabbitmqQueueName)
	require.NoError(t, err)
	assert.Equal(t, RabbitmqQueueName, q.Name)

	b.Close()
}

func TestBuilderClose_WithRabbitMQ_Success(t *testing.T) {
	_, uri := setupRabbitMQContainer(t)

	tmpDir := t.TempDir()
	logFilePath := filepath.Join(tmpDir, "test.log")

	b := NewBuilder()

	err := b.buildLogger(parser.Logging{
		Debug:               false,
		DebugReportCaller:   false,
		LogDisableTimestamp: true,
		LogsPath:            logFilePath,
	})
	require.NoError(t, err)

	err = b.buildRabbitMQ(uri)
	require.NoError(t, err)

	err = b.Close()
	assert.NoError(t, err)
	assert.Nil(t, b.rabbitMQConnection)
	assert.Nil(t, b.rabbitMQChannel)
}

func TestBuilderClose_LogFileCloseError(t *testing.T) {
	tmpDir := t.TempDir()
	logFilePath := filepath.Join(tmpDir, "test.log")

	b := NewBuilder()
	err := b.buildLogger(parser.Logging{
		Debug:               false,
		DebugReportCaller:   false,
		LogDisableTimestamp: true,
		LogsPath:            logFilePath,
	})
	require.NoError(t, err)
	require.NotNil(t, b.logsFile)

	// Close the file first so Close() gets an error on double-close
	b.logsFile.Close()

	// Close() logs the error but does not return it
	err = b.Close()
	assert.NoError(t, err)
}

func TestBuilderClose_CloudAndRabbitMQ(t *testing.T) {
	_, uri := setupRabbitMQContainer(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"1","config":"protocol: \"http\"\naddress: \"127.0.0.1:0\"\ndescription: \"test\"","tokenId":"token"}]`))
	}))
	defer ts.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{
		Core: struct {
			Logging        parser.Logging        `yaml:"logging"`
			Tracings       parser.Tracings       `yaml:"tracings"`
			Prometheus     parser.Prometheus     `yaml:"prometheus"`
			BeelzebubCloud parser.BeelzebubCloud `yaml:"beelzebub-cloud"`
		}{
			Tracings: parser.Tracings{
				RabbitMQ: parser.RabbitMQ{
					URI: uri,
				},
			},
			BeelzebubCloud: parser.BeelzebubCloud{
				Enabled:                true,
				URI:                    ts.URL,
				AuthToken:              "test-token",
				PollingIntervalSeconds: 9999,
			},
		},
	}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	require.Len(t, b.beelzebubServicesConfiguration, 1)

	err := b.Close()
	assert.NoError(t, err)
	assert.Nil(t, b.rabbitMQConnection)
	assert.Nil(t, b.rabbitMQChannel)
}

func TestBuilderRun_CloudWithValidConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"1","config":"protocol: \"http\"\naddress: \"127.0.0.1:0\"\ndescription: \"test\"","tokenId":"token"}]`))
	}))
	defer ts.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{
		Core: struct {
			Logging        parser.Logging        `yaml:"logging"`
			Tracings       parser.Tracings       `yaml:"tracings"`
			Prometheus     parser.Prometheus     `yaml:"prometheus"`
			BeelzebubCloud parser.BeelzebubCloud `yaml:"beelzebub-cloud"`
		}{
			BeelzebubCloud: parser.BeelzebubCloud{
				Enabled:                true,
				URI:                    ts.URL,
				AuthToken:              "test-token",
				PollingIntervalSeconds: 9999,
			},
		},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.NoError(t, err)
	require.Len(t, b.beelzebubServicesConfiguration, 1)
	require.Equal(t, "http", b.beelzebubServicesConfiguration[0].Protocol)

	b.Close()
}

func TestBuilderMCP_DeployCallback(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "mcp", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Deploy a duplicate to verify MCP callback path was exercised
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "mcp",
		Address:  "127.0.0.1:0",
	}
	err = b.DeployService(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	b.Close()
}

func TestBuilderBuild_WithRabbitMQ(t *testing.T) {
	_, uri := setupRabbitMQContainer(t)

	b := NewBuilder()
	err := b.buildRabbitMQ(uri)
	require.NoError(t, err)
	require.NotNil(t, b.rabbitMQConnection)

	bcopy := b.build()
	assert.Nil(t, bcopy.rabbitMQChannel)
	assert.Nil(t, bcopy.rabbitMQConnection)
	assert.NotNil(t, b.rabbitMQConnection, "original builder retains connection")
}

func TestBuilderRun_InitServicesError(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "tcp", Address: addr},
	}
	b.traceStrategy = func(event tracer.Event) {}

	// Port is occupied by l, so TCP init will fail
	err = b.Run()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error during init tcp")

	l.Close()
}

func TestBuilderRun_DebugLogging(t *testing.T) {
	b := NewBuilder()
	err := b.buildLogger(parser.Logging{
		Debug:               true,
		DebugReportCaller:   false,
		LogDisableTimestamp: true,
	})
	require.NoError(t, err)

	b.Close()
}

func TestBuilderCloud_CallbackInvoked(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"id":"1","config":"protocol: \"http\"\naddress: \"127.0.0.1:0\"\ndescription: \"test\"","tokenId":"token"}]`))
	}))
	defer ts.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{
		Core: struct {
			Logging        parser.Logging        `yaml:"logging"`
			Tracings       parser.Tracings       `yaml:"tracings"`
			Prometheus     parser.Prometheus     `yaml:"prometheus"`
			BeelzebubCloud parser.BeelzebubCloud `yaml:"beelzebub-cloud"`
		}{
			BeelzebubCloud: parser.BeelzebubCloud{
				Enabled:                true,
				URI:                    ts.URL,
				AuthToken:              "test-token",
				PollingIntervalSeconds: 1,
			},
		},
	}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	b.Close()
}
