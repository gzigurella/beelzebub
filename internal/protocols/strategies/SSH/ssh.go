package SSH

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/historystore"
	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/gliderlabs/ssh"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/term"
)

type SSHStrategy struct {
	Sessions          *historystore.HistoryStore
	servers           []*ssh.Server
	cleanerOnce       sync.Once
}

func (sshStrategy *SSHStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	if sshStrategy.Sessions == nil {
		sshStrategy.Sessions = historystore.NewHistoryStore()
	}
	sshStrategy.cleanerOnce.Do(func() {
		go sshStrategy.Sessions.HistoryCleaner()
	})

	server := &ssh.Server{
		Addr:        servConf.Address,
		MaxTimeout:  time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
		IdleTimeout: time.Duration(servConf.DeadlineTimeoutSeconds) * time.Second,
		Version:     servConf.ServerVersion,
		Handler: func(sess ssh.Session) {
			uuidSession := uuid.New()

			host, port, _ := net.SplitHostPort(sess.RemoteAddr().String())
			sessionKey := "SSH" + host + sess.User()

			if sess.RawCommand() != "" {
				var histories []plugins.Message
				if sshStrategy.Sessions.HasKey(sessionKey) {
					histories = sshStrategy.Sessions.Query(sessionKey)
				}
				for _, command := range servConf.Commands {
					if command.Regex.MatchString(sess.RawCommand()) {
						commandOutput := command.Handler
						if command.Plugin != "" {
							if cp, ok := plugin.GetCommand(command.Plugin); ok {
								output, err := cp.Execute(context.Background(), plugin.CommandRequest{
									Command:  sess.RawCommand(),
									ClientIP: host,
									Protocol: "ssh",
									History:  plugins.MessagesToPlugin(histories),
									Config:   plugins.ConfigFromServiceConf(servConf),
								})
								if err != nil {
									log.Errorf("plugin %q execute error: %s", command.Plugin, err.Error())
									commandOutput = "command not found"
								} else {
									commandOutput = output
								}
							} else {
								log.Warnf("unknown plugin %q, skipping", command.Plugin)
							}
						}
						var newEntries []plugins.Message
						newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: sess.RawCommand()})
						newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
						sshStrategy.Sessions.Append(sessionKey, newEntries...)

						sess.Write(append([]byte(commandOutput), '\n'))

						tr.TraceEvent(tracer.Event{
							Msg:           "SSH Raw Command",
							Protocol:      tracer.SSH.String(),
							RemoteAddr:    sess.RemoteAddr().String(),
							SourceIp:      host,
							SourcePort:    port,
							Status:        tracer.Start.String(),
							ID:            uuidSession.String(),
							Environ:       strings.Join(sess.Environ(), ","),
							User:          sess.User(),
							Description:   servConf.Description,
							Command:       sess.RawCommand(),
							CommandOutput: commandOutput,
							Handler:       command.Name,
						})
						return
					}
				}
			}

			tr.TraceEvent(tracer.Event{
				Msg:         "New SSH Terminal Session",
				Protocol:    tracer.SSH.String(),
				RemoteAddr:  sess.RemoteAddr().String(),
				SourceIp:    host,
				SourcePort:  port,
				Status:      tracer.Start.String(),
				ID:          uuidSession.String(),
				Environ:     strings.Join(sess.Environ(), ","),
				User:        sess.User(),
				Description: servConf.Description,
			})

			terminal := term.NewTerminal(sess, buildPrompt(sess.User(), servConf.ServerName))
			var histories []plugins.Message
			if sshStrategy.Sessions.HasKey(sessionKey) {
				histories = sshStrategy.Sessions.Query(sessionKey)
			}

			for {
				commandInput, err := terminal.ReadLine()
				if err != nil {
					break
				}
				if commandInput == "exit" {
					break
				}
				for _, command := range servConf.Commands {
					if command.Regex.MatchString(commandInput) {
						commandOutput := command.Handler
						if command.Plugin != "" {
							if cp, ok := plugin.GetCommand(command.Plugin); ok {
								output, err := cp.Execute(context.Background(), plugin.CommandRequest{
									Command:  commandInput,
									ClientIP: host,
									Protocol: "ssh",
									History:  plugins.MessagesToPlugin(histories),
									Config:   plugins.ConfigFromServiceConf(servConf),
								})
								if err != nil {
									log.Errorf("plugin %q execute error: %s", command.Plugin, err.Error())
									commandOutput = "command not found"
								} else {
									commandOutput = output
								}
							} else {
								log.Warnf("unknown plugin %q, skipping", command.Plugin)
							}
						}
						var newEntries []plugins.Message
						newEntries = append(newEntries, plugins.Message{Role: plugins.USER.String(), Content: commandInput})
						newEntries = append(newEntries, plugins.Message{Role: plugins.ASSISTANT.String(), Content: commandOutput})
						sshStrategy.Sessions.Append(sessionKey, newEntries...)
						histories = append(histories, newEntries...)

						terminal.Write(append([]byte(commandOutput), '\n'))

						tr.TraceEvent(tracer.Event{
							Msg:           "SSH Terminal Session Interaction",
							RemoteAddr:    sess.RemoteAddr().String(),
							SourceIp:      host,
							SourcePort:    port,
							Status:        tracer.Interaction.String(),
							Command:       commandInput,
							CommandOutput: commandOutput,
							ID:            uuidSession.String(),
							Protocol:      tracer.SSH.String(),
							Description:   servConf.Description,
							Handler:       command.Name,
						})
						break
					}
				}
			}

			tr.TraceEvent(tracer.Event{
				Msg:      "End SSH Session",
				Status:   tracer.End.String(),
				ID:       uuidSession.String(),
				Protocol: tracer.SSH.String(),
			})
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			host, port, _ := net.SplitHostPort(ctx.RemoteAddr().String())

			tr.TraceEvent(tracer.Event{
				Msg:         "New SSH Login Attempt",
				Protocol:    tracer.SSH.String(),
				Status:      tracer.Stateless.String(),
				User:        ctx.User(),
				Password:    password,
				Client:      ctx.ClientVersion(),
				RemoteAddr:  ctx.RemoteAddr().String(),
				SourceIp:    host,
				SourcePort:  port,
				ID:          uuid.New().String(),
				Description: servConf.Description,
			})
			matched, err := regexp.MatchString(servConf.PasswordRegex, password)
			if err != nil {
				log.Errorf("error regex: %s, %s", servConf.PasswordRegex, err.Error())
				return false
			}
			return matched
		},
	}

	sshStrategy.servers = append(sshStrategy.servers, server)

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			if errors.Is(err, ssh.ErrServerClosed) {
				log.Debugf("SSH server on %s stopped: %s", servConf.Address, err.Error())
			} else {
				log.Errorf("error during init SSH Protocol: %s", err.Error())
			}
		}
	}()
	return nil
}

func (sshStrategy *SSHStrategy) StopAll() error {
	if sshStrategy.Sessions != nil {
		sshStrategy.Sessions.Close()
	}
	sshStrategy.cleanerOnce = sync.Once{}

	var errs []error
	for _, server := range sshStrategy.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := server.Shutdown(ctx); err != nil {
			log.Errorf("error shutting down SSH server: %s", err.Error())
			errs = append(errs, err)
		}
		cancel()
	}
	sshStrategy.servers = nil
	if len(errs) > 0 {
		return fmt.Errorf("ssh stop errors: %w", errors.Join(errs...))
	}
	return nil
}

func buildPrompt(user string, serverName string) string {
	return fmt.Sprintf("%s@%s:~$ ", user, serverName)
}
