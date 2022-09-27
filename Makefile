#!/usr/bin/make -f

export CGO_ENABLED=0
export GO111MODULE=on

OUTPUT=bin/main

default: lint test build

# Run all lint checking with exit codes for CI.
lint:
	golint -set_exit_status `go list ./... | grep -v /vendor/`

# Run go fmt against code
fmt:
	go fmt ./...

# Run tests with coverage reporting.
test:
	go test -cover ./...

build:
	GOOS=linux go build -o ${OUTPUT} main.go

# https://docs.aws.amazon.com/lambda/latest/dg/golang-package.html
package: build
	zip -j function.zip ${OUTPUT}

.PHONY: *