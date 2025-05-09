.PHONY: all clean edger

ENCLAVE     := test_encl
ENCLAVE_EDL := test_encl.edl
EDGER       := sgx_edger8r
HACL_STAR   := .#../../../external/hacl-star
KLIBC       := ../../../trts/klibc-2.0.14/usr
TRTS        := ../../../trts

INCLUDES := -I $(HACL_STAR)/dist/portable-gcc-compatible/ \
			-I $(HACL_STAR)/dist/karamel/krmllib/dist/minimal \
			-I $(HACL_STAR)/dist/karamel/include/
# Optional KLIBC includes (uncomment if needed)
#INCLUDES += -I $(KLIBC)/include/ \
#            -I $(KLIBC)/include/bits64/ \
#            -I $(KLIBC)/include/arch/x86_64/

CFLAGS := -Wall -static-pie -nostdlib -ffreestanding -fPIE -D_FORTIFY_SOURCE=0\
          -fno-stack-protector -mrdrnd -Os $(INCLUDES) -fno-builtin

LDFLAGS := -z noexecstack  -nostdlib -nodefaultlibs \
           -Wl,-T,test_encl.lds,--build-id=none \
           -L $(HACL_STAR)/dist/portable-gcc-compatible/ -levercrypt
# Optional HACL lib path
#LDFLAGS += -L $(HACL_STAR)/dist/karamel/lib/
#-L $(KLIBC)/klibc

all: encl.elf

encl.elf: heap_2.o test_encl_bootstrap.S test_encl.c bare_trts.o test_encl_t.o 
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f *.elf *.o

edger: $(ENCLAVE_EDL)
	$(EDGER) $(ENCLAVE_EDL)

heap_2.o: $(TRTS)/FreeRTOS/heap_2.c $(TRTS)/FreeRTOS/FreeRTOSConfig.h
	$(CC) $(CFLAGS) -c $< -o $@

bare_trts.o: $(TRTS)/bare-trts/bare_trts.c
	$(CC) $(CFLAGS) -c $< -o $@

test_encl_t.o: test_encl_t.c
	$(CC) $(CFLAGS) -c $< -o $@

#
#hacl-hmac.o: hacl-c/Hacl_HMAC_SHA2_256.c$(HACL_STAR)/dist/portable-gcc-compatible/Lib_RandomBuffer_System.o 
#	$(CC) $(CFLAGS) -c $< -o $@
