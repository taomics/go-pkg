SRC := $(shell find . -name '*.go')

lint:
	golangci-lint run --config ../.golangci.yml --fix

test:
	go test -race -cover ./...

cov: coverage.out
	go tool cover -func=coverage.out

coverage.out: $(SRC)
	go test -coverprofile=coverage.out .
