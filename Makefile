PREFIX ?= /usr/local
MANDIR ?= $(PREFIX)/share/man/man1

.PHONY: build build-release run-scan install uninstall

build:
	cargo build --bin mvis
	codesign --force --sign - --entitlements mvis.entitlements --timestamp=none target/debug/mvis

build-release:
	cargo build --release --bin mvis

run-scan:
	$(MAKE) build
	sudo target/debug/mvis scan $(PROCESS) $(MODE)

install:
	@test -f target/release/mvis || { echo "error: run 'make build-release' first"; exit 1; }
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 target/release/mvis $(DESTDIR)$(PREFIX)/bin/mvis
	install -d $(DESTDIR)$(MANDIR)
	install -m 644 doc/mvis.1 $(DESTDIR)$(MANDIR)/mvis.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/mvis
	rm -f $(DESTDIR)$(MANDIR)/mvis.1
