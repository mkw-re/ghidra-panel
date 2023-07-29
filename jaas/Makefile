MAVEN?=mvn
SQLITE?=sqlite3

.PHONY: build
build:
	$(MAVEN) package

../test.db:
	$(MAKE) -C .. test.db

.PHONY: integration
integration: ../test.db
	SAMPLE_USER=richard SAMPLE_PASS=richard $(MAVEN) \
 	  -Dexec.mainClass=re.mkw.srejaas.SampleAcn \
 	  -Dexec.classpathScope=test test-compile \
 	  -Djava.security.auth.login.config=test.conf exec:java

.PHONY: clean
clean:
	#$(MAVEN) clean
	rm -rf target
