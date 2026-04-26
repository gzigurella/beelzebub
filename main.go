package main

import (
	"errors"
	"flag"
	"os"
	"runtime/debug"

	"github.com/mariocandela/beelzebub/v3/builder"
	"github.com/mariocandela/beelzebub/v3/parser"

	log "github.com/sirupsen/logrus"
)

func main() {
	var (
		quit                            = make(chan struct{})
		configurationsCorePath          string
		configurationsServicesDirectory string
		memLimitMiB                     int
		validate                        bool
	)

	flag.StringVar(&configurationsCorePath, "confCore", "./configurations/beelzebub.yaml", "Provide the path of configurations core")
	flag.StringVar(&configurationsServicesDirectory, "confServices", "./configurations/services/", "Directory config services")
	flag.IntVar(&memLimitMiB, "memLimitMiB", 100, "Process Memory in MiB (default 100, set to -1 to use system default)")
	flag.BoolVar(&validate, "validate", false, "Validate configurations without starting the daemon")
	flag.Parse()

	if memLimitMiB > 0 {
		// SetMemoryLimit takes an int64 value for the number of bytes.
		// bytes value = MiB value * 1024 * 1024
		debug.SetMemoryLimit(int64(memLimitMiB * 1024 * 1024))
	}

	configurationsParser := parser.Init(configurationsCorePath, configurationsServicesDirectory)

	if validate {
		services, parseIssues, err := configurationsParser.ReadConfigurationsServicesForValidation()
		if err != nil {
			log.Fatalf("Error during validation: %s", err)
		}
		serviceResult := parser.Validate(services, parseIssues)

		coreConfigurations, err := configurationsParser.ReadConfigurationsCore()
		if err != nil {
			coreConfigurations = &parser.BeelzebubCoreConfigurations{}
		}
		coreResult := parser.ValidateCore(coreConfigurations)

		combined := parser.ValidateResult{
			Results:       append(serviceResult.Results, coreResult.Results...),
			TotalErrors:   serviceResult.TotalErrors + coreResult.TotalErrors,
			TotalWarnings: serviceResult.TotalWarnings + coreResult.TotalWarnings,
		}
		combined.Print()
		os.Exit(combined.ExitCode())
	}

	coreConfigurations, err := configurationsParser.ReadConfigurationsCore()
	failOnError(err, "Error during ReadConfigurationsCore: ")

	beelzebubServicesConfiguration, err := configurationsParser.ReadConfigurationsServices()
	failOnError(err, "Error during ReadConfigurationsServices: ")

	if len(beelzebubServicesConfiguration) == 0 && !coreConfigurations.Core.BeelzebubCloud.Enabled {
		failOnError(errors.New("no services configured: provide a services directory, set BEELZEBUB_SERVICES_CONFIG, or enable beelzebub-cloud"), "Error during ReadConfigurationsServices: ")
	}

	beelzebubBuilder := builder.NewBuilder()

	director := builder.NewDirector(beelzebubBuilder)

	beelzebubBuilder, err = director.BuildBeelzebub(coreConfigurations, beelzebubServicesConfiguration)
	failOnError(err, "Error during BuildBeelzebub: ")

	err = beelzebubBuilder.Run()
	failOnError(err, "Error during run beelzebub core: ")

	defer beelzebubBuilder.Close()

	<-quit
}

func failOnError(err error, msg string) {
	if err != nil {
		log.Fatalf("%s: %s", msg, err)
	}
}
