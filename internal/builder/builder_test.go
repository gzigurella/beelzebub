package builder

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/HTTP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TCP"
	_ "github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuilderClose_LogFile(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir := t.TempDir()
	logFilePath := tmpDir + "/test.log"

	// Create a builder instance
	builder := NewBuilder()

	// Build logger which opens a log file
	loggingConfig := parser.Logging{
		Debug:               false,
		DebugReportCaller:   false,
		LogDisableTimestamp: true,
		LogsPath:            logFilePath,
	}

	err := builder.buildLogger(loggingConfig)
	assert.NoError(t, err)
	assert.NotNil(t, builder.logsFile)

	// Verify the log file exists and is open
	fileInfo, err := os.Stat(logFilePath)
	assert.NoError(t, err)
	assert.NotNil(t, fileInfo)

	// Close the builder
	err = builder.Close()
	assert.NoError(t, err)

	// Verify the log file is closed by attempting to write to it
	// Writing to a closed file should return an error
	_, err = builder.logsFile.WriteString("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "file already closed")
}

func TestBuilderClose_NoLogFile(t *testing.T) {
	// Create a builder without opening a log file
	builder := NewBuilder()

	// Close should succeed even without a log file
	err := builder.Close()
	assert.NoError(t, err)
}

func TestBuilderClose_NilLogFile(t *testing.T) {
	// Create a builder with explicitly nil log file
	builder := &Builder{
		logsFile: nil,
	}

	// Close should succeed with nil log file
	err := builder.Close()
	assert.NoError(t, err)
}

func TestSetTraceStrategy(t *testing.T) {
	b := NewBuilder()
	strategy := func(event tracer.Event) {}
	b.setTraceStrategy(strategy)
	if b.traceStrategy == nil {
		t.Errorf("expected traceStrategy to be set")
	}
}

func TestBuildLogger_InvalidPath(t *testing.T) {
	b := NewBuilder()
	cfg := parser.Logging{
		LogsPath: filepath.Join("/", "invalid", "path", "that", "does", "not", "exist.log"),
	}

	err := b.buildLogger(cfg)
	if err == nil {
		t.Fatalf("expected error for invalid log path, got nil")
	}
}

func TestBuilderBuild(t *testing.T) {
	b1 := NewBuilder()
	b1.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b2 := b1.build()

	if b2 == nil {
		t.Fatalf("expected build to return a new builder")
	}
	if b2.beelzebubCoreConfigurations != b1.beelzebubCoreConfigurations {
		t.Errorf("expected configurations to be copied")
	}
}

func TestBuilderRun_Empty(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}

	// Set trace strategy to avoid nil pointer
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	if err != nil {
		t.Errorf("expected no error running empty builder, got %v", err)
	}

	// Give a little time for the prometheus goroutine (which will just exit immediately since prometheus config is empty)
	time.Sleep(10 * time.Millisecond)
}

func TestBuilderRun_AllProtocols(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}

	// Add one service configuration for each protocol to hit all switch branches
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
		{Protocol: "ssh", Address: "127.0.0.1:0"},
		{Protocol: "tcp", Address: "127.0.0.1:0"},
		{Protocol: "telnet", Address: "127.0.0.1:0"},
		{Protocol: "mcp", Address: "127.0.0.1:0"},
	}

	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	if err != nil {
		t.Errorf("expected no error running builder with protocols, got %v", err)
	}

	time.Sleep(100 * time.Millisecond) // Wait a bit to let go funcs run and cover lines inside
}

func TestBuilderRun_UnknownProtocol(t *testing.T) {
	// We cannot easily test unknown protocol because it calls log.Fatalf
	// which causes the test to exit.
}

func TestBuildRabbitMQ_InvalidURI(t *testing.T) {
	b := NewBuilder()
	err := b.buildRabbitMQ("invalid-uri")
	if err == nil {
		t.Errorf("expected error building RabbitMQ with invalid URI")
	}
}

func TestBuilderRun_Prometheus(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{
		Core: struct {
			Logging        parser.Logging        `yaml:"logging"`
			Tracings       parser.Tracings       `yaml:"tracings"`
			Prometheus     parser.Prometheus     `yaml:"prometheus"`
			BeelzebubCloud parser.BeelzebubCloud `yaml:"beelzebub-cloud"`
		}{
			Prometheus: parser.Prometheus{
				Path: "/metrics",
				Port: "127.0.0.1:0",
			},
		},
	}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	assert.NoError(t, err)
	assert.NotNil(t, b.prometheusServer)

	time.Sleep(50 * time.Millisecond)
}

func TestBuilderReload(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	newConfigs := []parser.BeelzebubServiceConfiguration{
		{Protocol: "tcp", Address: "127.0.0.1:0"},
	}

	err = b.Reload(newConfigs)
	assert.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	err = b.Close()
	assert.NoError(t, err)
}

func TestBuilderReload_WhenClosing(t *testing.T) {
	b := NewBuilder()
	b.closing.Store(true)

	err := b.Reload([]parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	})
	assert.NoError(t, err)
}

func TestBuilderReload_WithoutRun_ReturnsError(t *testing.T) {
	b := NewBuilder()

	err := b.Reload([]parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "reload called before Run()")
}

func TestBuilderReload_RollbackOnFailure(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Reload with invalid config that will fail Run().
	// TCP Init with a missing port causes net.Listen to error out.
	invalidConfigs := []parser.BeelzebubServiceConfiguration{
		{Protocol: "tcp", Address: "invalid-address-no-port"},
	}
	err = b.Reload(invalidConfigs)
	require.Error(t, err)                // should report the reload failure
	require.Contains(t, err.Error(), "reload failed, rolled back")

	// After rollback, old config should be running.
	// Close returns nil even though `closing` is already true
	// (set during the Reload → Close → rollback flow).
	err = b.Close()
	require.NoError(t, err)
}

func TestBuilderClose_Basic(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	err = b.Close()
	require.NoError(t, err)
}

func TestBuilderClose_WithBeelzebubCloud(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}
	// Set up a cloud instance to cover the Stop() path in Close()
	b.beelzebubCloud = plugins.InitBeelzebubCloud("http://localhost:9999", "test-token", nil, 0, nil)

	err := b.Run()
	require.NoError(t, err)
	time.Sleep(50 * time.Millisecond)

	// Close should stop the cloud instance
	err = b.Close()
	require.NoError(t, err)
	// Second call should be a no-op
	err = b.Close()
	require.NoError(t, err)
}

func TestBuilderClose_WithProtocols(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:0"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	assert.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	err = b.Close()
	assert.NoError(t, err)

	// Second close should be a no-op (atomic guard)
	err = b.Close()
	assert.NoError(t, err)
}

func TestBuilderReload_EndToEnd(t *testing.T) {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port1 := l1.Addr().(*net.TCPAddr).Port
	l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port2 := l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: fmt.Sprintf("127.0.0.1:%d", port1)},
	}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(200 * time.Millisecond)

	// Port1 should be open after Run
	conn1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port1), 2*time.Second)
	require.NoError(t, err, "port1 should be open after Run")
	conn1.Close()

	// Port2 should be closed before Reload
	_, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port2), 500*time.Millisecond)
	require.Error(t, err, "port2 should be closed before Reload")

	// Reload to port2
	newConfigs := []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: fmt.Sprintf("127.0.0.1:%d", port2)},
	}
	require.NoError(t, b.Reload(newConfigs))
	time.Sleep(200 * time.Millisecond)

	// Port1 should be closed after Reload
	_, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port1), 500*time.Millisecond)
	require.Error(t, err, "port1 should be closed after Reload")

	// Port2 should be open after Reload
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port2), 2*time.Second)
	require.NoError(t, err, "port2 should be open after Reload")
	conn2.Close()

	require.NoError(t, b.Close())
}

func TestBuilderReload_EndToEnd_WithReloadCh(t *testing.T) {
	l1, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port1 := l1.Addr().(*net.TCPAddr).Port
	l1.Close()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port2 := l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: fmt.Sprintf("127.0.0.1:%d", port1)},
	}
	b.traceStrategy = func(event tracer.Event) {}
	b.reloadCh = make(chan []parser.BeelzebubServiceConfiguration, 1)

	// Start the reload consumer manually (same as Run() does when cloud is enabled).
	consumerDone := make(chan struct{})
	go func() {
		for cfg := range b.reloadCh {
			if err := b.Reload(cfg); err != nil {
				t.Logf("reload from channel failed: %s", err.Error())
			}
		}
		// When Close() closes reloadCh, the loop exits.
		close(consumerDone)
	}()

	require.NoError(t, b.Run())
	time.Sleep(200 * time.Millisecond)

	// Port1 should be open after Run
	conn1, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port1), 2*time.Second)
	require.NoError(t, err, "port1 should be open after Run")
	conn1.Close()

	// Write new configs to reloadCh (simulating cloud config change).
	// Reload() internally calls Close() which closes reloadCh — the consumer
	// goroutine above exits. Run() will not recreate reloadCh because cloud
	// is not enabled, but the reload has already happened.
	newConfigs := []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: fmt.Sprintf("127.0.0.1:%d", port2)},
	}
	b.reloadCh <- newConfigs
	time.Sleep(300 * time.Millisecond)

	// Port1 should be closed after reload
	_, err = net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port1), 500*time.Millisecond)
	require.Error(t, err, "port1 should be closed after channel reload")

	// Port2 should be open after reload
	conn2, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port2), 2*time.Second)
	require.NoError(t, err, "port2 should be open after channel reload")
	conn2.Close()

	// Close already happened inside Reload(), second call is no-op.
	require.NoError(t, b.Close())

	// Consumer goroutine should have exited when reloadCh was closed by Close()
	select {
	case <-consumerDone:
	case <-time.After(time.Second):
		t.Fatal("consumer goroutine did not exit after channel closed")
	}
}

func TestBuilderRun_CloudError_EmptyConfig(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]"))
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
				Enabled: true,
				URI:     ts.URL,
				AuthToken: "test-token",
			},
		},
	}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no honeypots configuration found")

	b.Close()
}

func TestBuilderClose_WithPrometheus(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{
		Core: struct {
			Logging        parser.Logging        `yaml:"logging"`
			Tracings       parser.Tracings       `yaml:"tracings"`
			Prometheus     parser.Prometheus     `yaml:"prometheus"`
			BeelzebubCloud parser.BeelzebubCloud `yaml:"beelzebub-cloud"`
		}{
			Prometheus: parser.Prometheus{
				Path: "/metrics",
				Port: "127.0.0.1:0",
			},
		},
	}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}
	b.traceStrategy = func(event tracer.Event) {}

	err := b.Run()
	require.NoError(t, err)
	require.NotNil(t, b.prometheusServer)

	err = b.Close()
	require.NoError(t, err)
	require.Nil(t, b.prometheusServer)
}

func TestBuilderDeployService_Success(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:0",
	}
	err := b.DeployService(cfg)
	require.NoError(t, err)
	assert.Len(t, b.beelzebubServicesConfiguration, 1)

	b.Close()
}

func TestBuilderDeployService_Duplicate(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:8080"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:8080",
	}
	err := b.DeployService(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	b.Close()
}

func TestBuilderDeployService_UnknownProtocol(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "nonexistent",
		Address:  "127.0.0.1:9999",
	}
	err := b.DeployService(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	b.Close()
}

func TestBuilderDeployService_Closing(t *testing.T) {
	b := NewBuilder()
	b.closing.Store(true)

	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "http",
		Address:  "127.0.0.1:8080",
	}
	err := b.DeployService(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "builder is closing")
}

func TestBuilderDeployService_InitFailure(t *testing.T) {
	// Occupy a port so the deploy's Init fails
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	defer l.Close()

	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	// Use TCP protocol because Init is synchronous (net.Listen inside)
	// which returns the bind error immediately (unlike HTTP which is async)
	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "tcp",
		Address:  addr,
	}
	err = b.DeployService(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deploy")

	b.Close()
}

func TestBuilderDeployService_PreservesExistingConfigs(t *testing.T) {
	b := NewBuilder()
	b.beelzebubCoreConfigurations = &parser.BeelzebubCoreConfigurations{}
	b.beelzebubServicesConfiguration = []parser.BeelzebubServiceConfiguration{
		{Protocol: "http", Address: "127.0.0.1:8080"},
	}
	b.traceStrategy = func(event tracer.Event) {}

	require.NoError(t, b.Run())
	time.Sleep(50 * time.Millisecond)

	cfg := parser.BeelzebubServiceConfiguration{
		Protocol: "tcp",
		Address:  "127.0.0.1:9090",
	}
	err := b.DeployService(cfg)
	require.NoError(t, err)
	assert.Len(t, b.beelzebubServicesConfiguration, 2)

	b.Close()
}
