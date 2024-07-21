all: lint test

lint:
	golangci-lint run --config ../.golangci.yml

test:
	go test -v ./...
