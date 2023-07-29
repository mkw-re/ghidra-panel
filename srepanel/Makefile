GO?=go
GO_SOURCES:=$(shell find . -name '*.go')

.PHONY: build
build: srepanel

srepanel: $(GO_SOURCES) go.mod go.sum
	$(GO) build -o $@ .

.PHONY: clean
clean:
	rm -f srepanel
