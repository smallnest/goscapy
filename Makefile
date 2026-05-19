.PHONY: all build test test-verbose test-race test-cover test-cover-html bench lint fmt vet tidy clean check help

# Default target
all: build

# --- Build ---
build:
	go build ./...

# --- Test ---
test:
	go test ./...

test-verbose:
	go test -v ./...

test-race:
	go test -race ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

test-cover-html: test-cover
	go tool cover -html=coverage.out -o coverage.html
	@echo "coverage.html generated"

bench:
	go test -bench=. -benchmem ./...

# --- Code Quality ---
lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
	goimports -w .

vet:
	go vet ./...

tidy:
	go mod tidy

# --- Utilities ---
clean:
	rm -f coverage.out coverage.html

check: fmt vet lint test
	@echo "All checks passed"

# --- Help ---
help:
	@echo "Available targets:"
	@echo "  build            Build all packages"
	@echo "  test             Run all tests"
	@echo "  test-verbose     Run tests with verbose output"
	@echo "  test-race        Run tests with race detector"
	@echo "  test-cover       Run tests with coverage profile"
	@echo "  test-cover-html  Generate HTML coverage report"
	@echo "  bench            Run benchmarks"
	@echo "  lint             Run golangci-lint"
	@echo "  fmt              Format code (gofmt + goimports)"
	@echo "  vet              Run go vet"
	@echo "  tidy             Run go mod tidy"
	@echo "  clean            Clean build artifacts"
	@echo "  check            Run fmt, vet, lint, and test"