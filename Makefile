.PHONY: build
build:
	$(MAKE) -C srepanel build

.PHONY: dev
dev: build
	srepanel/srepanel -config test_config.json

.PHONY: jaas
jaas:
	$(MAKE) -C jaas build

test.db: build
	rm -f test.db
	srepanel/srepanel -db $@ -init
	srepanel/srepanel set-password -db $@ -user-id 42 -user richard -pass richard

.ONESHELL:
.PHONY: integration
integration:
	$(MAKE) -C jaas integration

clean:
	$(MAKE) -C jaas clean
	$(MAKE) -C srepanel clean
	#rm -f ghidra_panel.secrets.json
	rm -f test.db
