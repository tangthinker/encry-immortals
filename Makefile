GO ?= go
BIN := bin/eimmortal
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
DIST ?= dist

.PHONY: all build test test-race vet fmt golden fuzz crash-test scale-test release-snapshot clean

all: build

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/eimmortal

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w ./cmd ./internal ./tools

# Golden vectors: regenerating requires an explicit wire-version bump (12.3).
golden:
	$(GO) test ./internal/... -run 'TestGolden' -count=1

# Crash injection matrix (12.2): builds a -tags testhooks binary and runs K1-K8.
crash-test:
	$(GO) test ./internal/pipeline -run TestCrashInjectionMatrix -v

# Chain-load scaling measurement (feeds the checkpoint decision, Q7).
scale-test:
	EIMMORTAL_SCALE_TEST=1 $(GO) test ./internal/journal -run TestChainLoadScaling -v

# Fuzz targets (12.4). Each target runs FUZZTIME (default 60s).
fuzz:
	$(GO) test ./internal/wire -run '^$' -fuzz 'FuzzSliceEnvelope' -fuzztime ${FUZZTIME:-60s}

# Local release archives, same script as the tag-triggered GitHub workflow.
release-snapshot:
	./scripts/release-build.sh "$(VERSION)" "$(DIST)"

clean:
	rm -rf bin dist coverage.out