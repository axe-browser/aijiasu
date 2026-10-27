.PHONY: all build test check clean

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o aijiasu-native ./cmd/aijiasu-native
	@if [ "$$(go env GOOS)" = "darwin" ]; then codesign --force --sign - aijiasu-native && codesign --verify --strict aijiasu-native; fi
	@echo "编译完成: ./aijiasu-native"

test: check

check:
	go mod verify
	go vet ./...
	go test -race -p 1 -timeout 180s ./...
	python3 -m unittest discover -s tools -p 'test_*.py'

clean:
	rm -f aijiasu-native
