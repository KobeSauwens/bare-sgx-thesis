/* utility headers */
#include "../../external/sgx-step/libsgxstep/debug.h"
#include <time.h> // For timing
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#include <string.h>
#include "../../external/sgx-step/libsgxstep/cpu.h"
#include "../../external/sgx-step/libsgxstep/sched.h"
#include "../../external/sgx-step/libsgxstep/enclave.h"
#include "../../external/sgx-step/libsgxstep/pt.h"
#include "../../external/sgx-step/libsgxstep/apic.h"
#include "../../external/sgx-step/libsgxstep/cache.h"
#include "../../external/sgx-step/libsgxstep/elf_parser.h"
#include <sys/mman.h>
/* SGX untrusted runtime */
#include <sgx_urts.h>
#include "./Enclave_crypto/encl_u.h"
//#include "return_Enclave/encl_u.h"

#define DIGEST_LEN      32
#define KEY_LEN_AEAD    32
#define KEY_LEN_HMAC    16
#define MAC_LEN         16
#define KEY_LEN_AES     16
#define NONCE_LEN       12
#define TAG_LEN 32  // 256 bits

#define NUM_SAMPLES     1000
#define DELAY           1
#define ITERATIONS      100000
#define DEBUG           0
#define ENCLAVE_DBG     1
#define ENCLAVE_PATH            "Enclave_crypto/encl.so"
#define DIGEST_LEN 32  // 256 bits

uint64_t diff[NUM_SAMPLES];
void *encl_page = NULL;
uint64_t *pte_encl = 0;
int step_cnt = 0;

void print_args(
    sgx_enclave_id_t eid,
    int* allowed,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* mac,
    const uint8_t* m, size_t mlen,
    const uint8_t* aad, size_t aadlen,
    const uint8_t* nonce, size_t noncelen
) {
    printf("=== ChaCha20-Poly1305 Enclave Call Arguments ===\n");
    printf("Enclave ID:\t\t0x%lx\n", eid);
    printf("Allowed flag addr:\t%p\n\n", (void*)allowed);

    printf("Plaintext [len: %zu]:\t", mlen);
    for (size_t i = 0; i < mlen; i++) printf("%02x ", m[i]);
    printf("\n");

    printf("AAD [len: %zu]:\t\t", aadlen);
    for (size_t i = 0; i < aadlen; i++) printf("%02x ", aad[i]);
    printf("\n");

    printf("Nonce [len: %zu]:\t", noncelen);
    for (size_t i = 0; i < noncelen; i++) printf("%02x ", nonce[i]);
    printf("\n");

    printf("Ciphertext [len: %zu]:\t", ciphertext_len);
    for (size_t i = 0; i < ciphertext_len; i++) printf("%02x ", ciphertext[i]);
    printf("\n");

    printf("MAC [len: 16]:\t\t");
    for (size_t i = 0; i < 16; i++) printf("%02x ", mac[i]);
    printf("\n");
}

/* define untrusted OCALL functions here */
void aep_cb_func(void)
{
    #if DEBUG
    	uint64_t erip = edbgrd_erip() - (uint64_t)get_enclave_base();
    	info("^^ enclave RIP=%#lx; ACCESSED=%lu", erip, ACCESSED(*pte_encl));
    #endif
}

void handle_fault(int signo, siginfo_t * si, void  *ctx)
{
    ucontext_t *uc = (ucontext_t *) ctx;

    switch ( signo )
    {
      case SIGSEGV:
        info("caught SIGSEGV; restoring trigger page access rights");
    	*pte_encl = MARK_EXECUTABLE(*pte_encl);

        sgx_step_do_trap = 1;
	break;

      case SIGTRAP:
        #if DEBUG
            info("Caught single-step trap (RIP=%p)\n", si->si_addr);
        #endif

        if (si->si_addr == sgx_get_aep())
            step_cnt++;

        /* ensure RFLAGS.TF is clear to disable debug single-stepping */
        uc->uc_mcontext.gregs[REG_EFL] &= ~0x100;
        break;

      default:
        info("Caught unknown signal '%d'", signo);
        abort();
    }

    // NOTE: return eventually continues at aep_cb_func and initiates
    // single-stepping mode.
    return;
}

void register_signal_handler(int signo)
{
    struct sigaction act, old_act;

    /* Specify #PF handler with signinfo arguments */
    memset(&act, 0, sizeof(sigaction));
    act.sa_sigaction = handle_fault;
    act.sa_flags = SA_RESTART | SA_SIGINFO;

    /* Block all signals while the signal is being handled */
    sigfillset(&act.sa_mask);
    ASSERT(!sigaction( signo, &act, &old_act ));
}

void ocall_print(const char *str)
{
    info("ocall_print: enclave says: '%s'", str);
}

void ocall_print_uint8_array(uint8_t *arr, size_t len) {
    printf("Print via ocall: \nsha256sum = ");
    for (size_t i = 0; i < len; i++) {
        printf("%02x ", arr[i]);
    }
    printf("\n\n");
}

char *read_from_user(void)
{
    char *buffer = NULL;
    int len; size_t size;

    printf("Enter super secret password ('q' to exit): ");
    if ((len=getline(&buffer, &size, stdin)) != -1)
    {
        /* get rid of the terminating newline character */
        buffer[len-1]='\0';
        printf("--> You entered: '%s'\n", buffer);
        return buffer;
    }
    else
    {
        printf("--> failure to read line\n");
        return NULL;
    }
}

sgx_enclave_id_t create_enclave(void)
{
    sgx_launch_token_t token = {0};
    int updated = 0;
    sgx_enclave_id_t eid = -1;

    info_event("Creating enclave...");
    SGX_ASSERT( sgx_create_enclave( ENCLAVE_PATH, /*debug=*/1,
                                    &token, &updated, &eid, NULL ) );

    return eid;
}

int compare(const void * a, const void * b) {
   return ( *(uint64_t*)a - *(uint64_t*)b );
}

    
int benchmark_timing() 
{
    sgx_enclave_id_t eid = create_enclave();
    char filename[100];
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(filename, sizeof(filename), "../../data/benchmark-sdk/timing/enclave_timing_return_%Y-%m-%d_%H-%M-%S.csv", timeinfo);

    // Allocate buffer for elapsed cycles
    uint64_t *cycles = malloc(ITERATIONS * sizeof(uint64_t));
    if (!cycles) {
        printf("Memory allocation failed\n");
        return 1;
    }
    
    int allowed = 0;
    uint8_t nonce[NONCE_LEN] = {0x0};


    char *aad = "TCB should be minimized!";
    uint32_t aadlen = strlen(aad);
   

    char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);
    uint8_t digest[TAG_LEN] = {0x0};
    
    char *m = "Bare-SGX rocks!";
    uint32_t mlen = strlen(m);
	
	uint8_t mac[MAC_LEN] = {0x0};
    
    uint8_t *ciphertext = malloc(mlen);
    uint8_t *decrypted = malloc(mlen);

    if (ciphertext == NULL || decrypted == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    int result = prepare_system_for_benchmark(100);
    if (result == 0) {
        printf("System prepared successfully\n");
    } else {
        printf("Failed to prepare system\n");
    }

    // Perform benchmark and store results
    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        //ecall_return(eid);
        //encl_op_chacha20poly1305_enc(eid, &allowed, ciphertext, mac, m, mlen, aad, aadlen, nonce);
        //encl_op_chacha20poly1305_dec(eid, &allowed, ciphertext, mac, decrypted, mlen, aad, aadlen, nonce);
        //encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len);
        uint64_t start = rdtsc_begin();
        //ecall_return(eid);
        //encl_op_chacha20poly1305_enc(eid, &allowed, ciphertext, mac, m, mlen, aad, aadlen, nonce);
        //encl_op_chacha20poly1305_dec(eid, &allowed, ciphertext, mac, decrypted, mlen, aad, aadlen, nonce);
        //encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len);
        uint64_t end = rdtsc_end();

        cycles[i] = end - start;
    }

    print_args(eid, &allowed, ciphertext, mlen, mac, decrypted, mlen, aad, aadlen, nonce, NONCE_LEN);
    // Write all results to file after measurements
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        printf("Error opening file %s!\n", filename);
        free(cycles);
        return 1;
    }

    fprintf(fp, "Iteration,ElapsedCycles\n");
    for (uint32_t i = 0; i < ITERATIONS; ++i) {
        fprintf(fp, "%u,%lu\n", i, cycles[i]);
    }

    fclose(fp);
    free(cycles);
    printf("Data written to %s",filename);

    info_event("destroying SGX enclave");
    SGX_ASSERT(sgx_destroy_enclave(eid));

    info("all is well; exiting..");
    return 0;
}


int benchmark_instructions()
{

    /************************************************************************/


    info_event("loading sdk enclave");
    sgx_enclave_id_t eid = create_enclave();
    int allowed = 0;

    print_enclave_info();

    info("dry run");

    uint8_t nonce[NONCE_LEN] = {0x0};


    char *aad = "TCB should be minimized!";
    uint32_t aadlen = strlen(aad);
   

    char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);
    uint8_t digest[TAG_LEN] = {0x0};
    
    char *m = "Bare-SGX rocks!";
    uint32_t mlen = strlen(m);
	
	uint8_t mac[MAC_LEN] = {0x0};
    
    uint8_t *ciphertext = malloc(mlen);
    uint8_t *decrypted = malloc(mlen);

    if (ciphertext == NULL || decrypted == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    
    /* =========================== START SOLUTION ===========ENCLAVE              = Enclave================ */
    //SGX_ASSERT(ecall_get_secret(eid, &allowed, digest, (uint8_t*) message, message_len));
    //ecall_return(eid);
    //encl_op_chacha20poly1305_enc(eid, &allowed, ciphertext, mac, m, mlen, aad, aadlen, nonce);
    //encl_op_chacha20poly1305_dec(eid, &allowed, ciphertext, mac, decrypted, mlen, aad, aadlen, nonce);
    encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len);

    /************************************************************************/
    info_event("configuring attacker runtime");
    register_symbols(ENCLAVE_PATH);
    //print_symbols();
    register_aep_cb(aep_cb_func);
    register_signal_handler( SIGSEGV );
    //attacker_config_page_table();

    info("Offset: %i",get_symbol_offset("enclave_entry"));
    encl_page = get_symbol_offset("enclave_entry") + get_enclave_base();
    info("entry page at %p", encl_page);
    ASSERT(pte_encl = remap_page_table_level(encl_page, PTE));
    info("PTE remapped to pte_encl = %p",pte_encl);
    ASSERT(PRESENT(*pte_encl));
    print_pte(pte_encl);

    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);


    /* use hardware trap flag instead of timer aep_cb_funcIRQ */
    register_signal_handler( SIGTRAP );
    set_debug_optin();

    /************************************************************************/
    info_event("single-stepping DECRYPT sdk enclave");
     
    //ecall_return(eid);
    //encl_op_chacha20poly1305_enc(eid, &allowed, ciphertext, mac, m, mlen, aad, aadlen, nonce);
    //encl_op_chacha20poly1305_dec(eid, &allowed, ciphertext, mac, decrypted, mlen, aad, aadlen, nonce);
    //encl_op_hmac(eid, &allowed, digest, (uint8_t*) message, message_len);
    
    //SGX_ASSERT(ecall_get_secret(eid, &allowed, digest, (uint8_t*) message, message_len));
    info("enclave returned; step_cnt=%d\n", step_cnt);
    //print_args(eid, &allowed, ciphertext, mlen, mac, decrypted, mlen, aad, aadlen, nonce, NONCE_LEN);
    printf("hmac=");
    dump_hex(digest, DIGEST_LEN);

    return 0;
}


int main( int argc, char **argv )
{
    //benchmark_timing();
    benchmark_instructions();
	return 0;
}
