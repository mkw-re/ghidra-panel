GO?=go
GO_SOURCES:=$(shell find . -type f -not -path './srepanel')

.PHONY: build
build: srepanel

srepanel: $(GO_SOURCES) go.mod go.sum
	$(GO) build -o $@ .

.PHONY: clean
clean:
	rm -f srepanel
