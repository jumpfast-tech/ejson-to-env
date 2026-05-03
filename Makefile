PREFIX ?= /usr/local
BINDIR  = $(PREFIX)/bin
SCRIPT  = ejson-to-env.sh
TARGET  = $(BINDIR)/ejson-to-env

.PHONY: install uninstall

install:
	install -d $(BINDIR)
	install -m 755 $(SCRIPT) $(TARGET)
	@echo "Installed: $(TARGET)"

uninstall:
	rm -f $(TARGET)
	@echo "Removed: $(TARGET)"
