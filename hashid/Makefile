.PHONY: clean vendor upgrade-dependencies build test run

BINARY_NAME=hashID

clean:
	go clean
	rm bin/${BINARY_NAME}

vendor:
	go mod vendor

upgrade-dependencies:
	go get -u
	go mod tidy

test:
	go test -v ./...

build:
	go build -o bin/${BINARY_NAME} main.go

run:
	bin/${BINARY_NAME} -h
