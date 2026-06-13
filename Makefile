.PHONY: build run-scan

build:
	cargo build --bin mvis
	codesign --force --sign - --entitlements mvis.entitlements --timestamp=none target/debug/mvis

run-scan:
	$(MAKE) build
	sudo target/debug/mvis scan $(PROCESS) $(MODE)
