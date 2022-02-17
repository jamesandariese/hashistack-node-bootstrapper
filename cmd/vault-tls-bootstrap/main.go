package main

import (
	"os"

	vaultlogin "github.com/jamesandariese/hashistack-node-bootstrapper/internal/cmd/vault-tls-bootstrap"
)

func main() {
	os.Exit(vaultlogin.RunCLI(os.Args))
}
