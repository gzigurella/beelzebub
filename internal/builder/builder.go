package builder

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/MCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TELNET"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/HTTP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/SSH"
	"github.com/beelzebub-labs/beelzebub/v3/internal/protocols/strategies/TCP"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	amqp "github.com/rabbitmq/amqp091-go"
	log "github.com/sirupsen/logrus"
)

const RabbitmqQueueName = "event"

type Builder struct {
	beelzebubServicesConfiguration []parser.BeelzebubServiceConfiguration
	beelzebubCoreConfigurations    *parser.BeelzebubCoreConfigurations
	traceStrategy                  tracer.Strategy
	rabbitMQChannel                *amqp.Channel
	rabbitMQConnection             *amqp.Connection
	logsFile                       *os.File
	startedServices                []plugin.ServicePlugin
	servicesCancel                 context.CancelFunc

	protocolManager *protocols.ProtocolManager
	prometheusServer *http.Server
	beelzebubCloud  *plugins.BeelzebubCloud

	reloadMu  sync.Mutex
	reloadCh  chan []parser.BeelzebubServiceConfiguration
	closing   atomic.Bool
}

func (b *Builder) setTraceStrategy(traceStrategy tracer.Strategy) {
	b.traceStrategy = traceStrategy
}

func (b *Builder) buildLogger(configurations parser.Logging) error {
	output := io.Writer(os.Stdout)

	if configurations.LogsPath != "" {
		logsFile, err := os.OpenFile(configurations.LogsPath, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
		if err != nil {
			return err
		}
		output = io.MultiWriter(os.Stdout, logsFile)
		b.logsFile = logsFile
	}

	log.SetOutput(output)

	log.SetFormatter(&log.JSONFormatter{
		DisableTimestamp: configurations.LogDisableTimestamp,
	})
	log.SetReportCaller(configurations.DebugReportCaller)
	if configurations.Debug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	return nil
}

func (b *Builder) buildRabbitMQ(rabbitMQURI string) error {
	rabbitMQConnection, err := amqp.Dial(rabbitMQURI)
	if err != nil {
		return err
	}

	b.rabbitMQChannel, err = rabbitMQConnection.Channel()
	if err != nil {
		return err
	}

	if _, err = b.rabbitMQChannel.QueueDeclare(RabbitmqQueueName, false, false, false, false, nil); err != nil {
		return err
	}

	b.rabbitMQConnection = rabbitMQConnection
	return nil
}

func (b *Builder) Close() error {
	if !b.closing.CompareAndSwap(false, true) {
		return nil
	}

	// Stop the reload consumer goroutine. Reload() will re-create
	// reloadCh + consumer in Run() if cloud is still enabled.
	if b.reloadCh != nil {
		close(b.reloadCh)
		b.reloadCh = nil
	}

	if b.servicesCancel != nil {
		b.servicesCancel()
	}
	for _, svc := range b.startedServices {
		svc.Stop()
	}
	b.startedServices = nil
	b.servicesCancel = nil

	if b.protocolManager != nil {
		if err := b.protocolManager.StopAll(); err != nil {
			log.Errorf("error stopping protocol servers: %s", err.Error())
		}
	}

	if b.beelzebubCloud != nil {
		b.beelzebubCloud.Stop()
	}

	if b.prometheusServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := b.prometheusServer.Shutdown(ctx); err != nil {
			log.Errorf("error shutting down Prometheus server: %s", err.Error())
		}
		cancel()
		b.prometheusServer = nil
	}

	if b.logsFile != nil {
		if err := b.logsFile.Close(); err != nil {
			log.Errorf("error closing log file: %s", err.Error())
		}
	}

	if b.rabbitMQConnection != nil {
		if err := b.rabbitMQChannel.Close(); err != nil {
			return err
		}
		if err := b.rabbitMQConnection.Close(); err != nil {
			return err
		}
		b.rabbitMQChannel = nil
		b.rabbitMQConnection = nil
	}
	return nil
}

func (b *Builder) Run() error {
	fmt.Println(
		`
██████  ███████ ███████ ██      ███████ ███████ ██████  ██    ██ ██████  
██   ██ ██      ██      ██         ███  ██      ██   ██ ██    ██ ██   ██ 
██████  █████   █████   ██        ███   █████   ██████  ██    ██ ██████  
██   ██ ██      ██      ██       ███    ██      ██   ██ ██    ██ ██   ██ 
██████  ███████ ███████ ███████ ███████ ███████ ██████   ██████  ██████  
Deception runtime framework, happy hacking!`)

	// Init Prometheus openmetrics with explicit server and custom mux
	if (b.beelzebubCoreConfigurations.Core.Prometheus != parser.Prometheus{}) {
		if b.prometheusServer == nil {
			promMux := http.NewServeMux()
			promMux.Handle(b.beelzebubCoreConfigurations.Core.Prometheus.Path, promhttp.Handler())
			b.prometheusServer = &http.Server{
				Addr:    b.beelzebubCoreConfigurations.Core.Prometheus.Port,
				Handler: promMux,
			}
			go func() {
				if err := b.prometheusServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					log.Fatalf("Error init Prometheus: %s", err.Error())
				}
			}()
		}
	}

	// Start registered background service plugins.
	svcCtx, cancel := context.WithCancel(context.Background())
	b.servicesCancel = cancel
	for _, svc := range plugin.Services() {
		if err := svc.Start(svcCtx); err != nil {
			log.Errorf("Error starting service plugin %q, continuing without it: %s",
				svc.Metadata().Name, err.Error())
			continue
		}
		b.startedServices = append(b.startedServices, svc)
	}

	// Init Protocol strategies
	secureShellStrategy := &SSH.SSHStrategy{}
	hypertextTransferProtocolStrategy := &HTTP.HTTPStrategy{}
	transmissionControlProtocolStrategy := &TCP.TCPStrategy{}
	modelContextProtocolStrategy := &MCP.MCPStrategy{}
	telnetStrategy := &TELNET.TelnetStrategy{}

	b.protocolManager = protocols.InitProtocolManager(
		b.traceStrategy,
		secureShellStrategy,
		hypertextTransferProtocolStrategy,
		transmissionControlProtocolStrategy,
		modelContextProtocolStrategy,
		telnetStrategy,
	)

	if b.beelzebubCoreConfigurations.Core.BeelzebubCloud.Enabled {
		conf := b.beelzebubCoreConfigurations.Core.BeelzebubCloud

		if b.reloadCh == nil {
			b.reloadCh = make(chan []parser.BeelzebubServiceConfiguration, 1)

			go func() {
				for cfg := range b.reloadCh {
					if err := b.Reload(cfg); err != nil {
						log.Errorf("hot-reload failed: %s", err.Error())
					}
				}
			}()
		}

		cloud := plugins.InitBeelzebubCloud(conf.URI, conf.AuthToken, func(newConfigs []parser.BeelzebubServiceConfiguration, hash string) {
			// Don't enqueue if the builder is shutting down — reloadCh
			// may be closed by Close() and writing to a closed chan panics.
			if b.closing.Load() {
				return
			}
			select {
			case b.reloadCh <- newConfigs:
			default:
			}
		}, time.Duration(conf.PollingIntervalSeconds)*time.Second, nil)

		b.beelzebubCloud = cloud

		if honeypotsConfiguration, _, err := cloud.GetHoneypotsConfigurations(); err != nil {
			return err
		} else {
			if len(honeypotsConfiguration) == 0 {
				return errors.New("no honeypots configuration found")
			}
			b.beelzebubServicesConfiguration = honeypotsConfiguration
		}
	}

	for _, beelzebubServiceConfiguration := range b.beelzebubServicesConfiguration {
		var strategy protocols.ServiceStrategy
		switch beelzebubServiceConfiguration.Protocol {
		case "http":
			strategy = hypertextTransferProtocolStrategy
		case "ssh":
			strategy = secureShellStrategy
		case "tcp":
			strategy = transmissionControlProtocolStrategy
		case "mcp":
			strategy = modelContextProtocolStrategy
		case "telnet":
			strategy = telnetStrategy
		default:
			log.Fatalf("protocol %s not managed", beelzebubServiceConfiguration.Protocol)
		}

		if err := b.protocolManager.InitService(beelzebubServiceConfiguration, strategy); err != nil {
			return fmt.Errorf("error during init protocol: %s, %s", beelzebubServiceConfiguration.Protocol, err.Error())
		}
	}

	return nil
}

func (b *Builder) Reload(newConfigs []parser.BeelzebubServiceConfiguration) error {
	b.reloadMu.Lock()
	defer b.reloadMu.Unlock()

	if b.closing.Load() {
		log.Warn("reload skipped: builder is closing")
		return nil
	}

	log.Info("Hot-reloading configurations...")

	oldConfigs := b.beelzebubServicesConfiguration

	b.Close()

	b.beelzebubServicesConfiguration = newConfigs
	b.protocolManager = nil

	// Re-establish broker connections if they were configured
	if b.beelzebubCoreConfigurations != nil && b.beelzebubCoreConfigurations.Core.Tracings.RabbitMQ.Enabled {
		if err := b.buildRabbitMQ(b.beelzebubCoreConfigurations.Core.Tracings.RabbitMQ.URI); err != nil {
			return fmt.Errorf("re-establishing RabbitMQ after reload: %w", err)
		}
	}

	if err := b.Run(); err != nil {
		log.Errorf("reload failed with new configs: %s; attempting rollback", err.Error())
		b.beelzebubServicesConfiguration = oldConfigs
		b.protocolManager = nil
		if rbErr := b.Run(); rbErr != nil {
			log.Fatalf("reload rollback also failed: %s", rbErr.Error())
		}
		b.closing.Store(false)
		return fmt.Errorf("reload failed, rolled back to previous configs: %w", err)
	}

	b.closing.Store(false)
	return nil
}

// build returns a degraded Builder for the initial startup phase.
// Only the configuration and tracing fields survive; the caller should
// use the original Builder (not the build copy) for Reload / Close.
func (b *Builder) build() *Builder {
	return &Builder{
		beelzebubServicesConfiguration: b.beelzebubServicesConfiguration,
		traceStrategy:                  b.traceStrategy,
		beelzebubCoreConfigurations:    b.beelzebubCoreConfigurations,
		prometheusServer:               b.prometheusServer,
	}
}

func NewBuilder() *Builder {
	return &Builder{}
}
