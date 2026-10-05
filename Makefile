CC ?= gcc
CFLAGS ?= -std=c11 -Wextra -Wall -g -O0 -Werror
CPPFLAGS ?=
LDFLAGS ?=

.PHONY: all clean help

all: aes aes_whitener

aes: aes.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

aes_whitener: aes_whitener.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

aes_encrypt: aes_encrypt.c tables.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f aes aes_whitener aes_encrypt tables.h whitener wb_aes whitened.h *.o traces.txt dfa_*.csv dfa_fail_*.log
	rm -rf __pycache__

help:
	@echo "Available Makefile targets:"
	@echo "  all          Build standard AES and the white-box table generator"
	@echo "  aes          Build standard AES-128 reference binary"
	@echo "  aes_whitener Build white-box lookup table generator"
	@echo "  aes_encrypt  Build white-box AES encryption binary (requires tables.h)"
	@echo "  clean        Remove compiled binaries, generated headers, and test logs"
	@echo "  help         Display this help message"
