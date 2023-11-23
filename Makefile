.PHONY: clean vendor upgrade-dependencies build run

BINARY_NAME=hashID

clean:
	cd hashID && go clean && rm bin/${BINARY_NAME}

vendor:
	cd hashID && go mod vendor

upgrade-dependencies:
	cd hashID && go get -u && go mod tidy

build:
	cd hashID && go build -o ../bin/${BINARY_NAME} main.go

run:
	bin/${BINARY_NAME} -h
