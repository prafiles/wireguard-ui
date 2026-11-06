BINARY_NAME := wireguard-ui

.PHONY: all build test cover clean

all: build

build:
	go build -o $(BINARY_NAME) .

# Run the unit test suite with per-package coverage.
test:
	go test ./emailer/... ./handler/... ./model/... ./router/... ./store/... ./util/... -cover

# Same, but also writes coverage.out (view with: go tool cover -html=coverage.out).
cover:
	go test ./emailer/... ./handler/... ./model/... ./router/... ./store/... ./util/... -coverprofile=coverage.out
	go tool cover -func=coverage.out | tail -1

clean:
	rm -f $(BINARY_NAME) coverage.out
