GO?=go

GO_SOURCES:=$(shell find . -name '*.go')

.PHONY: build
build: srepanel

srepanel: $(GO_SOURCES) go.mod go.sum
	$(GO) build -o $@ ./cmd/srepanel

.PHONY: jaas
jaas:
	$(MAKE) -C jaas build

test.db: srepanel
	rm -f test.db
	./srepanel -db $@ -init
	./srepanel set-password -db $@ -user-id 42 -user richard -pass richard

.ONESHELL:
.PHONY: integration
integration:
	$(MAKE) -C jaas integration
