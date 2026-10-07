BINARY  := benshu-client
PREFIX  ?= /usr/local
GO      ?= go

.PHONY: all build test selfcheck vet fmt clean install

all: build

build:
	$(GO) build -o $(BINARY) ./cmd/benshu-client

test:
	$(GO) test ./...

selfcheck:
	$(GO) run ./cmd/benshu-client selfcheck

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -f $(BINARY)

install: build
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY)
