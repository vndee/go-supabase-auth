.PHONY: test lint coverage integration-test clean help

GOCMD=go
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
GOLINT=golangci-lint
GOFMT=$(GOCMD) fmt
GOMOD=$(GOCMD) mod
GOBUILD=$(GOCMD) build
GOCOVER=$(GOCMD) tool cover
GOLDFLAGS=-ldflags "-s -w"

help:
	@echo "Available targets:"
	@echo "  test            - Run unit tests"
	@echo "  lint            - Run linter"
	@echo "  coverage        - Generate test coverage report"
	@echo "  integration-test - Run integration tests (requires SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)"
	@echo "  clean           - Clean up build artifacts"
	@echo "  tidy            - Run go mod tidy"
	@echo "  fmt             - Format code"

test:
	$(GOTEST) -v ./...

lint:
	$(GOVET) ./...
	$(GOLINT) run ./...

fmt:
	$(GOFMT) ./...

coverage:
	$(GOTEST) -coverprofile=coverage.raw.out ./auth/...
	# Filter out mock and testing packages
	cat coverage.raw.out | grep -v "/mock/" | grep -v "/testing/" > coverage.out
	$(GOCOVER) -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

coverage-core:
	$(GOTEST) -coverprofile=coverage.raw.out ./auth/...
	# Only include core files (exclude mocks, examples, tests)
	cat coverage.raw.out | grep -v "/mock/" | grep -v "/testing/" | grep -v "_test.go" > coverage.out
	$(GOCOVER) -func=coverage.out
	$(GOCOVER) -html=coverage.out -o coverage.html
	@echo "Core package coverage report generated: coverage.html"

integration-test:
	SUPABASE_INTEGRATION_TEST=true $(GOTEST) -v -run TestIntegration ./...

tidy:
	$(GOMOD) tidy

clean:
	rm -f coverage.out
	rm -f coverage.html