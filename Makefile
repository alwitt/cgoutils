BASE_DIR = $(realpath .)
SHELL = bash

all: lint

.PHONY: lint
lint: .prepare ## Lint the files
	@go mod tidy
	@golint ./...
	@golangci-lint run ./...

.PHONY: fix
fix: .prepare ## Lint and fix vialoations
	@go mod tidy
	@golangci-lint run --fix ./...

.PHONY: test
test: .prepare ## Run unittests
	go test --count 1 -v -timeout 300s -short ./...

.PHONY: one-test
one-test: .prepare ## Run one unittest
	go test --count 1 -v -timeout 30s -run ^$(FILTER) github.com/alwitt/cgoutils/...

.PHONY: prep-cfssl
prep-cfssl: .prepare ## Prepare CA certficate for use by development cfssl
	mkdir -vp tmp/test_ca
	cfssl genkey -initca docker/cfssl_ca.csr.json | tee tmp/test_ca/new_ca.json
	cat tmp/test_ca/new_ca.json | jq '.cert' -r | tee docker/test_ca.pem
	cat tmp/test_ca/new_ca.json | jq '.key' -r | tee docker/test_ca_key.pem

.PHONY: up
up: ## Prepare the docker stack
	@docker compose -f docker/docker-compose.yaml --project-directory $(BASE_DIR) up -d

.PHONY: down
down: ## Take down docker stack
	@docker compose -f docker/docker-compose.yaml --project-directory $(BASE_DIR) down

.PHONY: cicd-support
cicd-support: ## Build CICD support docker image
	@docker build -t "alwitt/cicd-support:cgoutils" -f docker/Dockerfile.cicd-support .

.prepare: ## Prepare the project for local development
	@pip3 install --user pre-commit
	@pre-commit install
	@pre-commit install-hooks
	@GO111MODULE=on go install github.com/go-critic/go-critic/cmd/gocritic@v0.5.4
	@touch .prepare

help: ## Display this help screen
	@grep -h -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
