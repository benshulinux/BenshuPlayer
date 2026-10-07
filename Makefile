BINARY   := BenshuPlayer
XPDFBIN  := xpdf2pdf
PREFIX   ?= /usr/local
GO       ?= go

.PHONY: all build test selfcheck vet fmt clean install uninstall

all: build

build: $(BINARY) $(XPDFBIN)

$(BINARY):
	$(GO) build -o $(BINARY) ./cmd/benshuplayer

$(XPDFBIN):
	$(GO) build -o $(XPDFBIN) ./cmd/xpdf2pdf

test:
	$(GO) test ./...

selfcheck:
	$(GO) run ./cmd/benshuplayer selfcheck

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

clean:
	rm -f $(BINARY) $(XPDFBIN)

install: build
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)
	install -m 0755 $(XPDFBIN) $(PREFIX)/bin/$(XPDFBIN)

uninstall:
	rm -f $(PREFIX)/bin/$(BINARY) $(PREFIX)/bin/$(XPDFBIN)
