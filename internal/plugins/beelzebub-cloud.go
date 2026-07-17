package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/parser"
	"github.com/beelzebub-labs/beelzebub/v3/internal/tracer"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type OnConfigChanged func(newConfigs []parser.BeelzebubServiceConfiguration, hash string)

type EventDTO struct {
	DateTime        string
	RemoteAddr      string
	Protocol        string
	Command         string
	CommandOutput   string
	Status          string
	Msg             string
	ID              string
	Environ         string
	User            string
	Password        string
	Client          string
	Headers         string
	HeadersMap      map[string][]string
	Cookies         string
	UserAgent       string
	HostHTTPRequest string
	Body            string
	HTTPMethod      string
	RequestURI      string
	Description     string
	SourceIp        string
	SourcePort      string
	TLSServerName   string
}

type BeelzebubCloud struct {
	URI             string
	AuthToken       string
	client          *resty.Client
	PollingInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	onChange        OnConfigChanged
}

type HoneypotConfigResponseDTO struct {
	ID            string `json:"id"`
	Config        string `json:"config"`
	TokenID       string `json:"tokenId"`
	LastUpdatedOn string `json:"lastUpdatedOn"`
}

func InitBeelzebubCloud(uri, authToken string, onChange OnConfigChanged, pollingInterval time.Duration, client *resty.Client) *BeelzebubCloud {
	ctx, cancel := context.WithCancel(context.Background())
	if pollingInterval <= 0 {
		pollingInterval = 15 * time.Second
	}
	if client == nil {
		client = resty.New()
	}
	beelzebubCloud := &BeelzebubCloud{
		URI:             uri,
		AuthToken:       authToken,
		client:          client,
		PollingInterval: pollingInterval,
		ctx:             ctx,
		cancel:          cancel,
		onChange:        onChange,
	}
	if onChange != nil {
		go func() {
			if err := beelzebubCloud.verifyConfigurationsChanged(); err != nil {
				log.Fatalf("Error verify configurations changed: %s", err.Error())
			}
		}()
	}
	return beelzebubCloud
}

func (beelzebubCloud *BeelzebubCloud) SendEvent(event tracer.Event) (bool, error) {
	eventDTO, err := beelzebubCloud.mapToEventDTO(event)
	if err != nil {
		return false, err
	}

	requestJson, err := json.Marshal(eventDTO)
	if err != nil {
		return false, err
	}

	if beelzebubCloud.AuthToken == "" {
		return false, errors.New("authToken is empty")
	}

	response, err := beelzebubCloud.client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(requestJson).
		SetHeader("Authorization", beelzebubCloud.AuthToken).
		SetResult(&tracer.Event{}).
		Post(fmt.Sprintf("%s/events", beelzebubCloud.URI))

	log.Debug(response)

	if err != nil {
		return false, err
	}

	return response.StatusCode() == 200, nil
}

func (beelzebubCloud *BeelzebubCloud) GetHoneypotsConfigurations() ([]parser.BeelzebubServiceConfiguration, string, error) {
	if beelzebubCloud.AuthToken == "" {
		return nil, "", errors.New("authToken is empty")
	}

	response, err := beelzebubCloud.client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", beelzebubCloud.AuthToken).
		SetResult([]HoneypotConfigResponseDTO{}).
		Get(fmt.Sprintf("%s/honeypots", beelzebubCloud.URI))

	if err != nil {
		return nil, "", err
	}

	if response.StatusCode() != 200 {
		return nil, "", errors.New(fmt.Sprintf("Response code: %v, error: %s", response.StatusCode(), string(response.Body())))
	}

	var honeypotsConfig []HoneypotConfigResponseDTO

	if err = json.Unmarshal(response.Body(), &honeypotsConfig); err != nil {
		return nil, "", fmt.Errorf("failed to parse honeypots response: %w, body: %s", err, string(response.Body()))
	}

	var servicesConfiguration = make([]parser.BeelzebubServiceConfiguration, 0)
	var localHashBuilder strings.Builder

	for _, honeypotConfig := range honeypotsConfig {
		var honeypotsConfig parser.BeelzebubServiceConfiguration

		if err = yaml.Unmarshal([]byte(honeypotConfig.Config), &honeypotsConfig); err != nil {
			return nil, "", err
		}
		if err := honeypotsConfig.CompileCommandRegex(); err != nil {
			return nil, "", fmt.Errorf("unable to load service config from cloud: invalid regex: %v", err)
		}
		if err := honeypotsConfig.CompileTrustedProxies(); err != nil {
			return nil, "", fmt.Errorf("unable to load service config from cloud: TrustedProxies %v", err)
		}
		servicesConfiguration = append(servicesConfiguration, honeypotsConfig)

		if hashCode, err := honeypotsConfig.HashCode(); err != nil {
			return nil, "", err
		} else {
			localHashBuilder.WriteString(hashCode)
		}

	}

	return servicesConfiguration, localHashBuilder.String(), nil
}

func (beelzebubCloud *BeelzebubCloud) Stop() {
	beelzebubCloud.cancel()
}

func (beelzebubCloud *BeelzebubCloud) checkConfigurationsChanged(lastHash string) (configs []parser.BeelzebubServiceConfiguration, newHash string, changed bool, err error) {
	configs, configurationsHash, err := beelzebubCloud.GetHoneypotsConfigurations()
	if err != nil {
		return nil, "", false, err
	}
	return configs, configurationsHash, lastHash != "" && lastHash != configurationsHash, nil
}

func (beelzebubCloud *BeelzebubCloud) verifyConfigurationsChanged() error {
	var lastHash = ""
	for {
		select {
		case <-beelzebubCloud.ctx.Done():
			return nil
		default:
		}

		configs, newHash, changed, err := beelzebubCloud.checkConfigurationsChanged(lastHash)
		if err != nil {
			return err
		}
		if changed {
			log.Debug("Configurations changed.")
			if beelzebubCloud.onChange != nil {
				beelzebubCloud.onChange(configs, newHash)
			}
		}
		lastHash = newHash
		select {
		case <-time.After(beelzebubCloud.PollingInterval):
		case <-beelzebubCloud.ctx.Done():
			return nil
		}
	}
}

func (beelzebubCloud *BeelzebubCloud) mapToEventDTO(event tracer.Event) (EventDTO, error) {
	eventDTO := EventDTO{
		DateTime:        event.DateTime,
		RemoteAddr:      event.RemoteAddr,
		Protocol:        event.Protocol,
		Command:         event.Command,
		CommandOutput:   event.CommandOutput,
		Status:          event.Status,
		Msg:             event.Msg,
		ID:              event.ID,
		Environ:         event.Environ,
		User:            event.User,
		Password:        event.Password,
		Client:          event.Client,
		Cookies:         event.Cookies,
		UserAgent:       event.UserAgent,
		HostHTTPRequest: event.HostHTTPRequest,
		Body:            event.Body,
		HTTPMethod:      event.HTTPMethod,
		RequestURI:      event.RequestURI,
		Description:     event.Description,
		SourceIp:        event.SourceIp,
		SourcePort:      event.SourcePort,
		TLSServerName:   event.TLSServerName,
	}

	if len(event.Headers) > 0 {
		headersJSON, err := json.Marshal(event.Headers)
		if err != nil {
			return EventDTO{}, fmt.Errorf("failed to marshal headers: %w", err)
		}
		eventDTO.Headers = string(headersJSON)
	}

	return eventDTO, nil
}
