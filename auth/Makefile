SRC := $(shell find . -name '*.go')

export GOEXPERIMENT := jsonv2

all: lint test

lint:
	golangci-lint run --config ../.golangci.yml

test:
	go test -v ./...

cov: coverage.out
	go tool cover -func=coverage.out

coverage.out: $(SRC)
	go test -coverprofile=coverage.out .
