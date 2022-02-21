package main

import (
	"flag"
	"os"

	vaultlogin "github.com/jamesandariese/hashistack-node-bootstrapper/internal/cmd/vault-tls-bootstrap"
	"github.com/rs/zerolog"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.InfoLevel).
		Output(zerolog.ConsoleWriter{Out: os.Stderr})

	p, flagSet := vaultlogin.NewProgram()

	var verbose bool
	var debug bool
	var trace bool
	var quiet bool
	var silent bool

	flagSet.BoolVar(&verbose, "verbose", false, "Verbose logging")
	flagSet.BoolVar(&verbose, "v", false, "Verbose logging")
	flagSet.BoolVar(&debug, "debug", false, "Debug level logging")
	flagSet.BoolVar(&trace, "trace", false, "Trace level logging")
	flagSet.BoolVar(&quiet, "quiet", false, "Log warnings and errors only")
	flagSet.BoolVar(&silent, "silent", false, "No logs and only show cubbyhole token at end")

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(2)
		}
		logger.Error().Msg("couldn't parse args " + err.Error())
		os.Exit(2)
	}

	if verbose {
		logger = logger.Level(zerolog.DebugLevel)
	}
	if debug {
		logger = logger.Level(zerolog.DebugLevel).With().Caller().Logger()
	}
	if trace {
		logger = logger.Level(zerolog.TraceLevel).With().Caller().Logger()
	}
	if quiet {
		logger = logger.Level(zerolog.WarnLevel)
	}
	if silent {
		logger = zerolog.Nop()
	}

	p.SetLogger(logger)

	os.Exit(p.RunCLI())
}
