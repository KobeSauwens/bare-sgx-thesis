.PHONY: all clean

ENCLAVE     := test_encl
ENCLAVE_EDL := test_encl.edl
EDGER		:= sgx_edger8r


INCLUDE         := -I./hacl-c/
LDFLAGS         := -z noexecstack -lbaresgx-urts -L$(BARESGX) -lcrypto -lhacl
CFLAGS  += -Wall -static-pie -nostdlib -ffreestanding -fPIE -D_FORTIFY_SOURCE=0\
	       -fno-stack-protector -mrdrnd $(INCLUDES) -Os
LDFLAGS := -z noexecstack -Wl,-T,test_encl.lds,--build-id=none

encl.elf: test_encl_bootstrap.S test_encl.c hacl-hmac.o 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.elf *.o



hacl-hmac.o: hacl-c/Hacl_HMAC_SHA2_256.c
	$(CC) -c $(CFLAGS) -o $@ $<

edger: $(ENCLAVE).edl test_encl.c
	#echo "$(INDENT)[GEN]" $(EDGER) $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL)
