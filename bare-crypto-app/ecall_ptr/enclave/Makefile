.PHONY: all clean

ENCLAVE     := test_encl
ENCLAVE_EDL := test_encl.edl
EDGER		:= sgx_edger8r


CFLAGS  += -Wall -static-pie -nostdlib -ffreestanding -fPIE \
	       -fno-stack-protector -mrdrnd $(INCLUDES)
LDFLAGS := -z noexecstack -Wl,-T,test_encl.lds,--build-id=none

encl.elf: test_encl_bootstrap.S test_encl.c test_encl_t.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.elf *.o

edger: $(ENCLAVE).edl
	#echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL)