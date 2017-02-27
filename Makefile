EMACS_ROOT ?= ../..

UNAME_S=$(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	EMACS ?= /Applications/Emacs.app/Contents/MacOS/Emacs
	# homebrew OpenSSL
	OPENSSL_CFLAGS =  -I/usr/local/opt/openssl/include
	OPENSSL_LDFLAGS = -L/usr/local/opt/openssl/lib
else
	EMACS ?= emacs
	OPENSSL_CFLAGS =
	OPENSSL_LDFLAGS =
endif

CC      = gcc
LD      = gcc
CPPFLAGS = -I$(EMACS_ROOT)/src $(OPENSSL_CFLAGS)
CFLAGS = -std=gnu99 -ggdb3 -Wall -fPIC $(CPPFLAGS)
LDFLAGS = $(OPENSSL_LDFLAGS)
CIPHER_LIBS=$(shell pkg-config --libs openssl)

.PHONY : test

all: cipher-core.so

cipher-core.so: cipher-core.o
	$(LD) -shared $(LDFLAGS) -o $@ $^ $(CIPHER_LIBS)

cipher-core.o: cipher-core.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f cipher-core.so cipher-core.o

test:
	$(EMACS) -Q -batch -L . $(LOADPATH) \
		-l test/test.el \
		-f ert-run-tests-batch-and-exit
