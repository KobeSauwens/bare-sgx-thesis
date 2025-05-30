LIBSGXSTEP_DIR		= ../../external/sgx-step
LIBSGXSTEP			= $(LIBSGXSTEP_DIR)/libsgxstep
-include $(LIBSGXSTEP)/Makefile.config
LIBSGXSTEP_SILEN 	= 1

BARESGX         = ../../urts/
ENCLAVE         = enclave_crypto/

SUBDIRS         = $(ENCLAVE) $(BARESGX) $(LIBSGXSTEP)

CC              := gcc
LD              := gcc
INCLUDE         := -I$(BARESGX)/include/ -I$(LIBSGXSTEP_DIR) -I../../trts/bare-trts/
CFLAGS          := -Wall  -g -fPIC $(CFLAGS) -Os
LDFLAGS         := -z noexecstack -lbaresgx-urts -lsgx-step -L$(BARESGX) -L$(LIBSGXSTEP) -lcrypto -lelf

SOURCES         = $(shell ls *.c)
OBJECTS         = $(SOURCES:.c=.o) $(ENCLAVE)test_encl_u.o
OUTPUT          = app

BUILDDIRS       = $(SUBDIRS:%=build-%)
CLEANDIRS       = $(SUBDIRS:%=clean-%)

all: $(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT) 

%.o : %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INCLUDE) -c $< -o $@

$(BUILDDIRS):
	$(MAKE) -C $(@:build-%=%)

$(CLEANDIRS):
	$(MAKE) clean -C $(@:clean-%=%)

clean: $(CLEANDIRS)
	rm -f $(OBJECTS) $(OUTPUT)
