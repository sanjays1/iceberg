# =================================================================
#
# Work of the U.S. Department of Defense, Defense Digital Service.
# Released as open source under the MIT License.  See LICENSE file.
#
# =================================================================

ifdef GOPATH
GCFLAGS=-trimpath=$(shell printenv GOPATH)/src
else
GCFLAGS=-trimpath=$(shell go env GOPATH)/src
endif

STATIC_LDFLAGS=-linkmode external -extldflags -static

ICEBERG_LDFLAGS=-X main.gitBranch=$(shell git branch | grep \* | cut -d ' ' -f2) -X main.gitCommit=$(shell git rev-list -1 HEAD)

ifndef DEST
DEST=bin
endif

.PHONY: help

help:  ## Print the help documentation
	@grep -E '^[a-zA-Z0-9_-\]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

#
# Dependencies
#

deps_go:  ## Install Go dependencies
	go get -d -t ./...

.PHONY: deps_go_test
deps_go_test: ## Download Go dependencies for tests
	go get golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow # download shadow
	go install golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow # install shadow
	go get -u github.com/kisielk/errcheck # download and install errcheck
	go get -u github.com/client9/misspell/cmd/misspell # download and install misspell
	go get -u github.com/gordonklaus/ineffassign # download and install ineffassign
	go get -u honnef.co/go/tools/cmd/staticcheck # download and instal staticcheck
	go get -u golang.org/x/tools/cmd/goimports # download and install goimports

deps_arm:  ## Install dependencies to cross-compile to ARM
	# ARMv7
	apt-get install -y libc6-armel-cross libc6-dev-armel-cross binutils-arm-linux-gnueabi libncurses5-dev gcc-arm-linux-gnueabi g++-arm-linux-gnueabi
  # ARMv8
	apt-get install gcc-aarch64-linux-gnu g++-aarch64-linux-gnu

#
# Go building, formatting, testing, and installing
#

fmt:  ## Format Go source code
	go fmt $$(go list ./... )

.PHONY: imports
imports: bin/goimports ## Update imports in Go source code
	# If missing, install goimports with: go get golang.org/x/tools/cmd/goimports
	bin/goimports -w -local github.com/deptofdefense/iceberg,github.com/deptofdefense $$(find . -iname '*.go')

vet: ## Vet Go source code
	go vet $$(go list ./...)

tidy: ## Tidy Go source code
	go mod tidy

.PHONY: test_go
test_go: bin/errcheck bin/ineffassign bin/staticcheck ## Run Go tests
	bash scripts/test.sh

.PHONY: test_cli
test_cli: ## Run CLI tests
	bash scripts/test-cli.sh

install:  ## Install iceberg CLI on current platform
	go install -gcflags="$(GCFLAGS)" -ldflags="$(LDFLAGS) $(iceberg_LDFLAGS)" github.com/deptofdefense/iceberg/cmd/iceberg

#
# Command line Programs
#

bin/goimports:
	go build -o bin/goimports golang.org/x/tools/cmd/goimports

bin/errcheck:
	go build -o bin/errcheck github.com/kisielk/errcheck

bin/ineffassign:
	go build -o bin/ineffassign github.com/gordonklaus/ineffassign

bin/staticcheck:
	go build -o bin/staticcheck honnef.co/go/tools/cmd/staticcheck

bin/shadow:
	go build -o bin/shadow golang.org/x/tools/go/analysis/passes/shadow/cmd/shadow

bin/iceberg: ## Build iceberg CLI for Darwin / amd64
	go build -o bin/iceberg -gcflags="$(GCFLAGS)" -ldflags="$(LDFLAGS) $(ICEBERG_LDFLAGS)" github.com/deptofdefense/iceberg/cmd/iceberg

bin_linux/iceberg: ## Build iceberg CLI for Linux / amd64
	GOOS=linux GOARCH=amd64 go build -o bin_linux/iceberg -gcflags="$(GCFLAGS)" -ldflags="$(ICEBERG_LDFLAGS)" github.com/deptofdefense/iceberg/cmd/iceberg

bin_darwin_static/iceberg: ## Build iceberg CLI for Darwin / amd64
	GOOS=darwin GOARCH=amd64 go build -o bin_darwin_static/iceberg -gcflags="$(GCFLAGS)" -ldflags="$(STATIC_LDFLAGS) $(ICEBERG_LDFLAGS)" github.com/deptofdefense/iceberg/cmd/iceberg

bin_linux_static/iceberg: ## Build iceberg CLI for Linux / amd64
	GOOS=linux GOARCH=amd64 go build -o bin_linux_static/iceberg -gcflags="$(GCFLAGS)" -ldflags="$(STATIC_LDFLAGS) $(ICEBERG_LDFLAGS)" github.com/deptofdefense/iceberg/cmd/iceberg

build: bin/iceberg

#
# Docker
#

docker_build:
	docker build -f Dockerfile --tag iceberg:latest .

#
# Certificate Targets
#

temp/server.crt:
	mkdir -p temp
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout temp/server.key -out temp/server.crt


## Clean

clean:  ## Clean artifacts
	rm -fr bin
