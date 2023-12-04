BUILD_DIR = bin
BINARY_NAME=hashID
VERSION= $(shell git describe --tags --always)

.PHONY: clean
clean:
	go clean
	rm -f ${BUILD_DIR}/${BINARY_NAME}-*

.PHONY: vendor
vendor:
	go mod vendor

.PHONY: updep
updep:
	go get -u
	go mod tidy

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: build
build:
	mkdir -p ${BUILD_DIR}
	GOOS=linux GOARCH=amd64 go build -o ${BUILD_DIR}/${BINARY_NAME}-${VERSION}-amd64-linux cmd/hashid/main.go
	GOOS=linux GOARCH=arm64 go build -o ${BUILD_DIR}/${BINARY_NAME}-${VERSION}-arm64-linux cmd/hashid/main.go
	GOOS=darwin GOARCH=amd64 go build -o ${BUILD_DIR}/${BINARY_NAME}-${VERSION}-amd64-darwin cmd/hashid/main.go
	GOOS=windows GOARCH=amd64 go build -o ${BUILD_DIR}/${BINARY_NAME}-${VERSION}-amd64.exe cmd/hashid/main.go

