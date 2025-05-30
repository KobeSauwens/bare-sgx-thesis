/* MIT License
 *
 * Copyright (c) 2016-2022 INRIA, CMU and Microsoft Corporation
 * Copyright (c) 2022-2023 HACL* Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#ifndef __Hacl_Frodo1344_H
#define __Hacl_Frodo1344_H

#if defined(__cplusplus)
extern "C" {
#endif

#include <string.h>
#include "krml/internal/types.h"
#include "krml/lowstar_endianness.h"
#include "krml/internal/target.h"

/* SNIPPET_START: Hacl_Frodo1344_crypto_bytes */

extern uint32_t Hacl_Frodo1344_crypto_bytes;

/* SNIPPET_END: Hacl_Frodo1344_crypto_bytes */

/* SNIPPET_START: Hacl_Frodo1344_crypto_publickeybytes */

extern uint32_t Hacl_Frodo1344_crypto_publickeybytes;

/* SNIPPET_END: Hacl_Frodo1344_crypto_publickeybytes */

/* SNIPPET_START: Hacl_Frodo1344_crypto_secretkeybytes */

extern uint32_t Hacl_Frodo1344_crypto_secretkeybytes;

/* SNIPPET_END: Hacl_Frodo1344_crypto_secretkeybytes */

/* SNIPPET_START: Hacl_Frodo1344_crypto_ciphertextbytes */

extern uint32_t Hacl_Frodo1344_crypto_ciphertextbytes;

/* SNIPPET_END: Hacl_Frodo1344_crypto_ciphertextbytes */

/* SNIPPET_START: Hacl_Frodo1344_crypto_kem_keypair */

uint32_t Hacl_Frodo1344_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

/* SNIPPET_END: Hacl_Frodo1344_crypto_kem_keypair */

/* SNIPPET_START: Hacl_Frodo1344_crypto_kem_enc */

uint32_t Hacl_Frodo1344_crypto_kem_enc(uint8_t *ct, uint8_t *ss, uint8_t *pk);

/* SNIPPET_END: Hacl_Frodo1344_crypto_kem_enc */

/* SNIPPET_START: Hacl_Frodo1344_crypto_kem_dec */

uint32_t Hacl_Frodo1344_crypto_kem_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

/* SNIPPET_END: Hacl_Frodo1344_crypto_kem_dec */

#if defined(__cplusplus)
}
#endif

#define __Hacl_Frodo1344_H_DEFINED
#endif
