package HTTP

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/plugins"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/beelzebub-labs/beelzebub/v3/pkg/plugin"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type HTTPStrategy struct {
	servers []*http.Server
}

type httpResponse struct {
	StatusCode int
	Headers    []string
	Body       string
}

func (httpStrategy *HTTPStrategy) Init(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer) error {
	serverMux := http.NewServeMux()

	serverMux.HandleFunc("/", func(responseWriter http.ResponseWriter, request *http.Request) {
		var matched bool
		var resp httpResponse
		var err error
		for _, command := range servConf.Commands {
			var err error
			matched = command.Regex.MatchString(request.RequestURI)
			if matched {
				resp, err = buildHTTPResponse(servConf, tr, command, request)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					resp.StatusCode = 500
					resp.Body = "500 Internal Server Error"
				}
				break
			}
		}
		if !matched {
			command := servConf.FallbackCommand
			if command.Handler != "" || command.Plugin != "" {
				resp, err = buildHTTPResponse(servConf, tr, command, request)
				if err != nil {
					log.Errorf("error building http response: %s: %v", request.RequestURI, err)
					resp.StatusCode = 500
					resp.Body = "500 Internal Server Error"
				}
			}
		}
		setResponseHeaders(responseWriter, resp.Headers, resp.StatusCode)
		fmt.Fprint(responseWriter, resp.Body)

	})

	srv := &http.Server{
		Addr:    servConf.Address,
		Handler: serverMux,
	}

	httpStrategy.servers = append(httpStrategy.servers, srv)

	go func() {
		var err error
		if servConf.TLSKeyPath != "" && servConf.TLSCertPath != "" {
			err = srv.ListenAndServeTLS(servConf.TLSCertPath, servConf.TLSKeyPath)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Errorf("error during init HTTP Protocol: %v", err)
			return
		}
	}()

	log.WithFields(log.Fields{
		"port":     servConf.Address,
		"commands": len(servConf.Commands),
	}).Infof("Init service: %s", servConf.Description)
	return nil
}

func (httpStrategy *HTTPStrategy) StopAll() error {
	var errs []error
	for _, srv := range httpStrategy.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := srv.Shutdown(ctx); err != nil {
			log.Errorf("error shutting down HTTP server: %s", err.Error())
			errs = append(errs, err)
		}
		cancel()
	}
	httpStrategy.servers = nil
	if len(errs) > 0 {
		return fmt.Errorf("http stop errors: %w", errors.Join(errs...))
	}
	return nil
}

func buildHTTPResponse(servConf parser.BeelzebubServiceConfiguration, tr tracer.Tracer, command parser.Command, request *http.Request) (httpResponse, error) {
	resp := httpResponse{
		Body:       command.Handler,
		Headers:    command.Headers,
		StatusCode: command.StatusCode,
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(request.Body, 1024*1024))
	body := ""
	if err == nil {
		body = string(bodyBytes)
	}
	traceRequest(request, tr, command, servConf.Description, body, servConf.TrustedProxiesNets)

	if command.Plugin != "" {
		host, _ := realClientAddr(request, servConf.TrustedProxiesNets)

		if cp, ok := plugin.GetCommand(command.Plugin); ok {
			cmd := fmt.Sprintf("Method: %s, RequestURI: %s, Body: %s", request.Method, request.RequestURI, body)
			output, err := cp.Execute(context.Background(), plugin.CommandRequest{
				Command:  cmd,
				ClientIP: host,
				Protocol: "http",
				Config:   plugins.ConfigFromServiceConf(servConf),
			})
			if err != nil {
				resp.Body = "404 Not Found!"
				return resp, fmt.Errorf("plugin %q execute error: %w", command.Plugin, err)
			}
			resp.Body = output
		} else if hp, ok := plugin.GetHTTP(command.Plugin); ok {
			if command.Plugin == plugins.MazePluginName {
				maze := &plugins.MazeHoneypot{
					ServerVersion: servConf.ServerVersion,
					ServerName:    servConf.ServerName,
				}
				mazeResp := maze.HandleRequest(request)
				resp.StatusCode = mazeResp.StatusCode
				resp.Body = mazeResp.Body
				for k, v := range mazeResp.Headers {
					resp.Headers = append(resp.Headers, fmt.Sprintf("%s: %s", k, v))
				}
				resp.Headers = append(resp.Headers, fmt.Sprintf("Content-Type: %s", mazeResp.ContentType))
			} else {
				httpResp := hp.HandleHTTP(request)
				resp.StatusCode = httpResp.StatusCode
				resp.Body = httpResp.Body
				resp.Headers = append(resp.Headers, fmt.Sprintf("Content-Type: %s", httpResp.ContentType))
				for k, v := range httpResp.Headers {
					resp.Headers = append(resp.Headers, fmt.Sprintf("%s: %s", k, v))
				}
			}
		} else {
			log.Warnf("unknown plugin %q, skipping", command.Plugin)
		}
	}

	return resp, nil
}

func traceRequest(request *http.Request, tr tracer.Tracer, command parser.Command, HoneypotDescription, body string, trustedProxies []*net.IPNet) {
	host, port := realClientAddr(request, trustedProxies)

	remoteAddr := host
	if port != "" {
		remoteAddr = net.JoinHostPort(host, port)
	}
	event := tracer.Event{
		Msg:             "HTTP New request",
		RequestURI:      request.RequestURI,
		Protocol:        tracer.HTTP.String(),
		HTTPMethod:      request.Method,
		Body:            body,
		HostHTTPRequest: request.Host,
		UserAgent:       request.UserAgent(),
		Cookies:         mapCookiesToString(request.Cookies()),
		Headers:         mapHeaderToString(request.Header),
		HeadersMap:      request.Header,
		Status:          tracer.Stateless.String(),
		RemoteAddr:      remoteAddr,
		SourceIp:        host,
		SourcePort:      port,
		ID:              uuid.New().String(),
		Description:     HoneypotDescription,
		Handler:         command.Name,
	}
	if request.TLS != nil {
		event.Msg = "HTTPS New Request"
		event.TLSServerName = request.TLS.ServerName
	}
	tr.TraceEvent(event)
}

// realClientAddr returns the host and port of the real client.
//
// The immediate TCP peer (request.RemoteAddr) is the only non-spoofable source
// of identity: it is set by Go's net/http server from the socket peer address.
// X-Forwarded-For and X-Real-IP are application-level headers and trivially
// forgeable when the honeypot is reachable directly from the Internet.
//
// Algorithm:
//   - If trustedProxies is empty OR the immediate peer is not in trustedProxies,
//     headers are ignored entirely and the peer address is returned. This
//     protects deployments where beelzebub is exposed directly: an attacker
//     setting "X-Forwarded-For: 8.8.8.8" cannot make us log 8.8.8.8.
//   - If the peer is a trusted proxy, X-Forwarded-For is parsed right-to-left
//     and the first entry that is NOT itself a trusted hop is treated as the
//     real client. This neutralizes XFF poisoning, where a client sends a
//     pre-filled XFF and the trusted proxy appends the real peer to it
//     ("spoofed, real-peer"): walking from the right skips the trusted hops
//     until the legitimate client IP appears.
//   - If XFF is empty or contains only trusted hops, X-Real-IP is consulted as
//     a single-hop fallback. If it too is missing or trusted, the peer
//     address is returned.
//
// The returned port mirrors the peer's port; XFF/X-Real-IP do not carry port
// information, so when the address comes from a header the port is empty.
func realClientAddr(r *http.Request, trustedProxies []*net.IPNet) (host, port string) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
		port = ""
	}
	if len(trustedProxies) == 0 {
		return host, port
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil || !ipInNets(peerIP, trustedProxies) {
		return host, port
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(parts[i])
			if candidate == "" {
				continue
			}
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !ipInNets(ip, trustedProxies) {
				return candidate, ""
			}
		}
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil && !ipInNets(ip, trustedProxies) {
			return xri, ""
		}
	}
	return host, port
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func mapHeaderToString(headers http.Header) string {
	headersString := ""

	for key := range headers {
		for _, values := range headers[key] {
			headersString += fmt.Sprintf("[Key: %s, values: %s],", key, values)
		}
	}

	return headersString
}

func mapCookiesToString(cookies []*http.Cookie) string {
	cookiesString := ""

	for _, cookie := range cookies {
		cookiesString += cookie.String()
	}

	return cookiesString
}

func setResponseHeaders(responseWriter http.ResponseWriter, headers []string, statusCode int) {
	for _, headerStr := range headers {
		keyValue := strings.Split(headerStr, ":")
		if len(keyValue) > 1 {
			responseWriter.Header().Add(keyValue[0], keyValue[1])
		}
	}
	if len(http.StatusText(statusCode)) > 0 {
		responseWriter.WriteHeader(statusCode)
	}
}
