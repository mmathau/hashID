BINARY_NAME=hashID

build:
	go build -o bin/${BINARY_NAME} main.go

run:
	bin/${BINARY_NAME} -h

clean:
	go clean
	rm bin/${BINARY_NAME}
