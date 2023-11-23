.PHONY: clean vendor upgrade-dependencies build test run

BINARY_NAME=hashID

clean:
	cd hashid && go clean && rm bin/${BINARY_NAME}

vendor:
	cd hashid && go mod vendor

upgrade-dependencies:
	cd hashid && go get -u && go mod tidy

test:
	cd hashid && go test -v ./...

build:
	cd hashid && go build -o bin/${BINARY_NAME} main.go

run:
	bin/${BINARY_NAME} -h
