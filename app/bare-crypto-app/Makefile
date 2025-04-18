BARESGX         = ../../urts
ENCLAVE         = enclave

SUBDIRS         = $(ENCLAVE) $(BARESGX)

CC              := gcc
LD              := gcc
EDGER		:= sgx_edger8r
INCLUDE         := -I$(BARESGX)/include/ -I./enclave
CFLAGS          := -Wall -Werror -g -fPIC $(CFLAGS)
LDFLAGS         := -z noexecstack -lbaresgx-urts -L$(BARESGX) -lcrypto 

SOURCES         = $(shell ls *.c)
OBJECTS         = $(SOURCES:.c=.o)
OUTPUT          = app

BUILDDIRS       = $(SUBDIRS:%=build-%)
CLEANDIRS       = $(SUBDIRS:%=clean-%)

PRIVATE_KEY       = private_key.pem
PUBLIC_KEY        = public_key.pem

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


