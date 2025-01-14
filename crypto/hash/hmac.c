/*
 * hmac.c
 *
 * implementation of hmac srtp_auth_type_t
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright(c) 2001-2017 Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "hmac.h"
#include "alloc.h"
#include "cipher_types.h"
#include "auth_test_cases.h"

/* the debug module for authentiation */

srtp_debug_module_t srtp_mod_hmac = {
    0,           /* debugging is off by default */
    "hmac sha-1" /* printable name for module   */
};

static srtp_err_status_t srtp_hmac_alloc(srtp_auth_t **a,
                                         size_t key_len,
                                         size_t out_len)
{
    extern const srtp_auth_type_t srtp_hmac;
    uint8_t *pointer;

    debug_print(srtp_mod_hmac, "allocating auth func with key length %zu",
                key_len);
    debug_print(srtp_mod_hmac, "                          tag length %zu",
                out_len);

    /*
     * check key length - note that we don't support keys larger
     * than 20 bytes yet
     */
    if (key_len > 20) {
        return srtp_err_status_bad_param;
    }

    /* check output length - should be less than 20 bytes */
    if (out_len > 20) {
        return srtp_err_status_bad_param;
    }

    /* allocate memory for auth and srtp_hmac_ctx_t structures */
    pointer = (uint8_t *)srtp_crypto_alloc(sizeof(srtp_hmac_ctx_t) +
                                           sizeof(srtp_auth_t));
    if (pointer == NULL) {
        return srtp_err_status_alloc_fail;
    }

    /* set pointers */
    *a = (srtp_auth_t *)pointer;
    (*a)->type = &srtp_hmac;
    (*a)->state = pointer + sizeof(srtp_auth_t);
    (*a)->out_len = out_len;
    (*a)->key_len = key_len;
    (*a)->prefix_len = 0;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_dealloc(srtp_auth_t *a)
{
    /* zeroize entire state*/
    octet_string_set_to_zero(a, sizeof(srtp_hmac_ctx_t) + sizeof(srtp_auth_t));

    /* free memory */
    srtp_crypto_free(a);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_init(void *statev,
                                        const uint8_t *key,
                                        size_t key_len)
{
    srtp_hmac_ctx_t *state = (srtp_hmac_ctx_t *)statev;
    uint8_t ipad[64];

    /*
     * check key length - note that we don't support keys larger
     * than 20 bytes yet
     */
    if (key_len > 20) {
        return srtp_err_status_bad_param;
    }

    /*
     * set values of ipad and opad by exoring the key into the
     * appropriate constant values
     */
    for (size_t i = 0; i < key_len; i++) {
        ipad[i] = key[i] ^ 0x36;
        state->opad[i] = key[i] ^ 0x5c;
    }
    /* set the rest of ipad, opad to constant values */
    for (size_t i = key_len; i < 64; i++) {
        ipad[i] = 0x36;
        ((uint8_t *)state->opad)[i] = 0x5c;
    }

    debug_print(srtp_mod_hmac, "ipad: %s",
                srtp_octet_string_hex_string(ipad, 64));

    /* initialize sha1 context */
    srtp_sha1_init(&state->init_ctx);

    /* hash ipad ^ key */
    srtp_sha1_update(&state->init_ctx, ipad, 64);
    memcpy(&state->ctx, &state->init_ctx, sizeof(srtp_sha1_ctx_t));

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_start(void *statev)
{
    srtp_hmac_ctx_t *state = (srtp_hmac_ctx_t *)statev;

    memcpy(&state->ctx, &state->init_ctx, sizeof(srtp_sha1_ctx_t));

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_update(void *statev,
                                          const uint8_t *message,
                                          size_t msg_octets)
{
    srtp_hmac_ctx_t *state = (srtp_hmac_ctx_t *)statev;

    debug_print(srtp_mod_hmac, "input: %s",
                srtp_octet_string_hex_string(message, msg_octets));

    /* hash message into sha1 context */
    srtp_sha1_update(&state->ctx, message, msg_octets);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_hmac_compute(void *statev,
                                           const uint8_t *message,
                                           size_t msg_octets,
                                           size_t tag_len,
                                           uint8_t *result)
{
    srtp_hmac_ctx_t *state = (srtp_hmac_ctx_t *)statev;
    uint32_t hash_value[5];
    uint32_t H[5];
    size_t i;

    /* check tag length, return error if we can't provide the value expected */
    if (tag_len > 20) {
        return srtp_err_status_bad_param;
    }

    /* hash message, copy output into H */
    srtp_hmac_update(state, message, msg_octets);
    srtp_sha1_final(&state->ctx, H);

    /*
     * note that we don't need to debug_print() the input, since the
     * function hmac_update() already did that for us
     */
    debug_print(srtp_mod_hmac, "intermediate state: %s",
                srtp_octet_string_hex_string((uint8_t *)H, 20));

    /* re-initialize hash context */
    srtp_sha1_init(&state->ctx);

    /* hash opad ^ key  */
    srtp_sha1_update(&state->ctx, (uint8_t *)state->opad, 64);

    /* hash the result of the inner hash */
    srtp_sha1_update(&state->ctx, (uint8_t *)H, 20);

    /* the result is returned in the array hash_value[] */
    srtp_sha1_final(&state->ctx, hash_value);

    /* copy hash_value to *result */
    for (i = 0; i < tag_len; i++) {
        result[i] = ((uint8_t *)hash_value)[i];
    }

    debug_print(srtp_mod_hmac, "output: %s",
                srtp_octet_string_hex_string((uint8_t *)hash_value, tag_len));

    return srtp_err_status_ok;
}

static const char srtp_hmac_description[] =
    "hmac sha-1 authentication function";

/*
 * srtp_auth_type_t hmac is the hmac metaobject
 */

const srtp_auth_type_t srtp_hmac = {
    srtp_hmac_alloc,        /* */
    srtp_hmac_dealloc,      /* */
    srtp_hmac_init,         /* */
    srtp_hmac_compute,      /* */
    srtp_hmac_update,       /* */
    srtp_hmac_start,        /* */
    srtp_hmac_description,  /* */
    &srtp_hmac_test_case_0, /* */
    SRTP_HMAC_SHA1          /* */
};
