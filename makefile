BINARY_NAME=privmess

# Choose the Go compiler
GOBUILD=go build

all: build

build: 
	$(GOBUILD) -o $(BINARY_NAME) -v
clean: 
	go clean
	rm -f $(BINARY_NAME)

run: build
	./$(BINARY_NAME)

test: 
	go test -v ./...
