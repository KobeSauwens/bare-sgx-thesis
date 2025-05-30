# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk
HACL_STAR_DIR=dist/portable-gcc-compatible/
#HACL_STAR =$(HACL_STAR_DIR)

CRYPTO_LDFLAGS := $(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libs)

ifeq ($(LVI_MITIGATION), ControlFlow)
    ifeq ($(LVI_MITIGATION_BINDIR),)
        $(error LVI_MITIGATION_BINDIR is not set)
    endif
    # Only run once.
    ifeq (,$(findstring $(LVI_MITIGATION_BINDIR),$(CC)))
        CC := $(LVI_MITIGATION_BINDIR)/$(CC)
    endif
    COMPILER := $(COMPILER)-lvi-cfg
    CRYPTO_LDFLAGS := $(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}libslvicfg)
endif

ifeq ($(OE_CRYPTO_LIB),openssl_3)
  CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --variable=${OE_CRYPTO_LIB}flags) -Os
else
  CFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --cflags) -Idist/portable-gcc-compatible/ \
	-Idist/karamel/include -Idist/karamel/krmllib/dist/minimal -Os
endif
LDFLAGS=$(shell pkg-config oeenclave-$(COMPILER) --libs) -L$(HACL_STAR_DIR) -levercrypt
INCDIR=$(shell pkg-config oeenclave-$(COMPILER) --variable=includedir)

all:
	$(MAKE) build
	$(MAKE) keys
	$(MAKE) sign

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../oe_crypto_app.edl --trusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 enc.c -o enc.o
	$(CC) -g -c $(CFLAGS) -DOE_API_VERSION=2 oe_crypto_app_t.c -o oe_crypto_app_t.o
	$(CC) -o enclave oe_crypto_app_t.o enc.o $(LDFLAGS) $(CRYPTO_LDFLAGS)

sign:
	oesign sign -e enclave -c oe_crypto_app.conf -k private.pem

clean:
	rm -f enc.o enclave enclave.signed private.pem public.pem oe_crypto_app_t.o oe_crypto_app_t.h oe_crypto_app_t.c oe_crypto_app_args.h

keys:
	openssl genrsa -out private.pem -3 3072
	openssl rsa -in private.pem -pubout -out public.pem
