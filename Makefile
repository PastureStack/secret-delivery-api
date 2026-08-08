.PHONY: build test validate integration-test package verify-artifact ci clean

build:
	./scripts/build

test:
	./scripts/test

validate:
	./scripts/validate

integration-test: build
	./scripts/integration-test

package: build
	./scripts/package

verify-artifact: package
	./scripts/verify-artifact

ci:
	./scripts/ci

clean:
	rm -rf bin dist
