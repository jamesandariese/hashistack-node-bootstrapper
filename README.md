# `hashistack-node-bootstrapper`

Bootstrapping utilities for a hashistack.

## Commands

### `vault-tls-bootstrap`

Usage: `vault-tls-bootstrap NODENAME`

Creates a token for `NODENAME.node.dc1.consul` with SAN for `client.dc1.consul`.

* uses your existing vault token (must vault login previously) -> token0
* creates and tests a cubbyhole token -> `cubby`
* downloads a TLS cert from vault -> `cert1`
* logs into vault with `cert1` -> `token1`
* creates a cert with `token1` -> `cert2`
* logs in with `cert2` -> `token2`
* creates another cert with `token2` -> `cert3`
* pushes `cert3` into `cubby` at `cubbyhole/cert`
* prints `cubby`

#### Install

go install github.com/jamesandariese/hashistack-node-bootstrapper/cmd/vault-tls-bootstrap@latest
