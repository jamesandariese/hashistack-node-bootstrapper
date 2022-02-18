.PHONY: all always-build

all: README.md version/version.go build/vault-tls-bootstrap

README.md: README.md.tmpl always-build
	gomplate < README.md.tmpl > README.md

version/version.go: version/version.go.tmpl always-build
	gomplate < version/version.go.tmpl > version/version.go

dist-clean:
	rm -f README.md

prepare-release: prepare-release-preflight prepare-release-do-it
prepare-release-preflight:
	@echo $(RELEASE_VERSION) | grep . || (echo "need a RELEASE_VERSION set to prepare a release.  don't use this target directly"; exit 1)
prepare-release-do-it: dist-clean README.md version/version.go
	git add README.md
	git add version/version.go

enable-hooks:
	git config --local core.hooksPath .githooks

GOMOD=$(shell go list -m)
build/vault-tls-bootstrap: version/version.go
	go build -o build/vault-tls-bootstrap $(GOMOD)/cmd/vault-tls-bootstrap 

