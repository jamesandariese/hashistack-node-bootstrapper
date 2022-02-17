Bootstrapping utilities for a hashistack.

### Commands

* `vault-tls-bootstrap` -- downloads a TLS cert from vault, logs in with it, creates a cert with the new login, logs in with that, creates another cert with the newest login, and pushes the final cert into a cubbyhole token at cubbyhole/cert.  Prints the cubbyhole token.
