GO ?= go
BIN := bin/apex

.PHONY: all build test test-race vet fmt golden fuzz clean

all: build

build:
	$(GO) build -trimpath -o $(BIN) ./cmd/apex

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

# Fuzz targets (12.4). Each target runs FUZZTIME (default 60s).
fuzz:
	$(GO) test ./internal/wire -run '^$' -fuzz 'FuzzSliceEnvelope' -fuzztime ${FUZZTIME:-60s}

clean:
	rm -rf bin coverage.out