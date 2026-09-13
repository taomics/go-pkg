SRC := $(shell find . -name '*.go')

export GOEXPERIMENT := jsonv2

.PHONY: lint test test-unit cov cov-unit

lint:
	golangci-lint run --config ../.golangci.yml --fix

# Run all tests, including live network integration tests (requires internet)
test:
	go test -race -cover -tags=integration ./...

# Run only offline-safe local unit tests (fast, no external traffic)
test-unit:
	go test -race -cover ./...

# View coverage of all tests, including integration tests
cov: coverage.out
	go tool cover -func=coverage.out

# View coverage of offline-safe unit tests only
cov-unit: coverage-unit.out
	go tool cover -func=coverage-unit.out

coverage.out: $(SRC)
	go test -tags=integration -coverprofile=coverage.out .

coverage-unit.out: $(SRC)
	go test -coverprofile=coverage-unit.out .
