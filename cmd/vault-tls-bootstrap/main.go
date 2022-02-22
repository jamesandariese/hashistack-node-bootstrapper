package main

import (
	"flag"
	"os"

	vaultlogin "github.com/jamesandariese/hashistack-node-bootstrapper/internal/cmd/vault-tls-bootstrap"
	zerolog_cli "github.com/jamesandariese/zerolog_cli_adapter"
	"github.com/rs/zerolog"
)

func main() {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger().Level(zerolog.InfoLevel).
		Output(zerolog.ConsoleWriter{Out: os.Stderr})

	p, flagSet := vaultlogin.NewProgram()

	lg := zerolog_cli.NewLoggerGenerator(logger)
	lg.UpdateFlagSet(flagSet)

	if err := flagSet.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			os.Exit(2)
		}
		logger.Error().Msg("couldn't parse args " + err.Error())
		os.Exit(2)
	}

	p.SetLogger(lg.Logger())

	os.Exit(p.RunCLI())
}
