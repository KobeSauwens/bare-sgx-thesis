# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

LIBSGXSTEP_DIR=../../../
LIBSGXSTEP=$(LIBSGXSTEP_DIR)/libsgxstep

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags) -I$(LIBSGXSTEP_DIR)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs) -pthread -L$(LIBSGXSTEP) -lelf 
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../oe_crypto_app.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) oe_crypto_app_u.c
	$(CC) -o oe_crypto_app_host oe_crypto_app_u.o host.o $(LDFLAGS)

clean:
	rm -f oe_crypto_app_host host.o oe_crypto_app_u.o oe_crypto_app_u.c oe_crypto_app_u.h oe_crypto_app_args.h
