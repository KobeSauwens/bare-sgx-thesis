BARESGX         = ../../urts
ENCLAVE         = enclave
HACL_STAR   	:= ../../external/hacl-star
TRTS			:= ../../trts

SUBDIRS         = $(ENCLAVE) $(BARESGX) 
CC              := gcc
LD              := gcc
EDGER			:= sgx_edger8r
INCLUDE         += -I$(BARESGX)/include/ -I../../trts/bare-trts/ #VRAGEN AAN JO#-I./enclave -I $(HACL_STAR)/dist/karamel/include/ -I $(HACL_STAR)/dist/karamel/krmllib/dist/minimal/
CFLAGS          := -Wall -g -fPIC $(CFLAGS) 
LDFLAGS         := -z noexecstack -lbaresgx-urts -L$(BARESGX) -lcrypto #-L $(HACL_STAR)/dist/portable-gcc-compatible/ -levercrypt

SOURCES         = $(shell ls *.c)
OBJECTS         = $(SOURCES:.c=.o) enclave/test_encl_u.o
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