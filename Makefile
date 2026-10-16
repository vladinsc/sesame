.PHONY: build test vet lint demo images tidy

BINARIES := sesame-broker sesame-egress sesame-keygen

build:
	@for b in $(BINARIES); do go build -o bin/$$b ./cmd/$$b; done

test:
	go test ./...

vet:
	go vet ./...

tidy:
	go mod tidy

demo:
	bash examples/local/demo.sh

images:
	@for b in sesame-broker sesame-egress; do \
		docker build --build-arg CMD=$$b -t $$b:dev . ; \
	done
