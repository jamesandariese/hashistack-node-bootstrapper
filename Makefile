.PHONY: all always-build

all: README.md

README.md: README.md.tmpl always-build
	gomplate < README.md.tmpl > README.md

dist-clean:
	rm -f README.md

prepare-release: prepare-release-preflight prepare-release-do-it
prepare-release-preflight:
	@echo $(RELEASE_VERSION) | grep . || (echo "need a RELEASE_VERSION set to prepare a release.  don't use this target directly"; exit 1)
prepare-release-do-it: dist-clean README.md
	git add README.md

enable-hooks:
	git config --local core.hooksPath .githooks
