#include "py/runtime.h"
#include "py/mpprint.h"
#include "memzero.h"
#include "../../../../crypto/shrincs/shrincs.h"
#include "sha2.h"

STATIC mp_obj_t mod_trezorcrypto_shrincs_expand_sk(mp_obj_t seckey_32) {
    mp_buffer_info_t buf_32;
    mp_get_buffer_raise(seckey_32, &buf_32, MP_BUFFER_READ);

    uint8_t sha512_buf[64];
    sha512_Raw((const uint8_t*)buf_32.buf, 32, sha512_buf);

    uint8_t adrs[32] = {0};

    SHA256_CTX hash_ctx;
    sha256_Init(&hash_ctx);

    sha256_add_to_ctx(&hash_ctx, sha512_buf + 2*N, N);
    // Add zeros
    sha256_add_to_ctx(&hash_ctx, adrs, 32);
    sha256_add_to_ctx(&hash_ctx, adrs, 16);
    
    uint8_t pk_sf[N]; 
    uxmss_root(sha512_buf, &hash_ctx, adrs, pk_sf);

    memzero(sha512_buf, sizeof(sha512_buf));

    return mp_obj_new_bytes(pk_sf, sizeof(pk_sf));
}
MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_shrincs_expand_sk_obj, mod_trezorcrypto_shrincs_expand_sk);

static void shrincs_mp_progress_cb(uint16_t value, void *userdata) {
    mp_obj_t reporter = *(mp_obj_t *)userdata;
    mp_call_function_1(reporter, mp_obj_new_int(value));
}

STATIC mp_obj_t mod_trezorcrypto_shrincs_sign_stateless(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t sk_buf;
    mp_get_buffer_raise(args[0], &sk_buf, MP_BUFFER_READ);

    if (sk_buf.len != (N * 6)) {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
    }

    const uint8_t *sk_ptr = (const uint8_t *)sk_buf.buf;

    SecretKey sk;
    memcpy(sk.seed,     sk_ptr,         N);
    memcpy(sk.prf,      sk_ptr + N,     N);
    memcpy(sk.sf,       sk_ptr + N * 2, N);
    memcpy(sk.sl,       sk_ptr + N * 3, N);
    memcpy(sk.pk.seed,  sk_ptr + N * 4, N);
    memcpy(sk.pk.root,  sk_ptr + N * 5, N);

    mp_buffer_info_t msg_buf;
    mp_get_buffer_raise(args[1], &msg_buf, MP_BUFFER_READ);

    shrincs_progress_cb cb = NULL;
    mp_obj_t reporter = MP_OBJ_NULL;
    if (n_args >= 3 && args[2] != mp_const_none) {
        reporter = args[2];
        cb = shrincs_mp_progress_cb;
    }

    uint8_t signature[SL_SIZE];
    if (!shrincs_sign_stateless((const uint8_t*)msg_buf.buf, msg_buf.len, &sk, signature, cb, reporter != MP_OBJ_NULL ? &reporter : NULL))
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Error while signing message"));
    }

    memzero(&sk, sizeof(sk));

    return mp_obj_new_bytes(signature, sizeof(signature));
}

MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_shrincs_sign_stateless_obj, 2, 3, mod_trezorcrypto_shrincs_sign_stateless);

STATIC mp_obj_t mod_trezorcrypto_shrincs_sign_stateful(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t sk_buf;
    mp_get_buffer_raise(args[0], &sk_buf, MP_BUFFER_READ);

    if (sk_buf.len != (N * 6)) {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
    }

    const uint8_t *sk_ptr = (const uint8_t *)sk_buf.buf;

    SecretKey sk;
    memcpy(sk.seed,     sk_ptr,         N);
    memcpy(sk.prf,      sk_ptr + N,     N);
    memcpy(sk.sf,       sk_ptr + N * 2, N);
    memcpy(sk.sl,       sk_ptr + N * 3, N);
    memcpy(sk.pk.seed,  sk_ptr + N * 4, N);
    memcpy(sk.pk.root,  sk_ptr + N * 5, N);

    mp_obj_t *state_items;
    size_t state_len;
    mp_obj_get_array(args[1], &state_len, &state_items);
    if (state_len != 2) {
        mp_raise_ValueError(MP_ERROR_TEXT("State must be a tuple: (q, valid)"));
    }

    mp_buffer_info_t msg_buf;
    mp_get_buffer_raise(args[2], &msg_buf, MP_BUFFER_READ);

    State state;
    state.q = mp_obj_get_int(state_items[0]);
    state.valid = mp_obj_get_int(state_items[1]);

    if ((state.q + 1) > HSF) {
        mp_raise_ValueError(MP_ERROR_TEXT("State q is too large"));
    }

    uint32_t swn = mp_obj_get_int(args[3]);

    shrincs_progress_cb cb = NULL;
    mp_obj_t reporter = MP_OBJ_NULL;
    if (n_args >= 4 && args[4] != mp_const_none) {
        reporter = args[4];
        cb = shrincs_mp_progress_cb;
    }

    uint8_t signature[N + WOTS_SIGN_LEN + (state.q + 1) * N]; // ???
    if (!shrincs_sign_stateful((const uint8_t*)msg_buf.buf, msg_buf.len, &sk, &state, signature, swn, cb, reporter != MP_OBJ_NULL ? &reporter : NULL))
    {
        mp_raise_ValueError(MP_ERROR_TEXT("Error while signing message"));
    }

    memzero(sk_buf.buf, sk_buf.len);
    memzero(&sk, sizeof(sk));

    mp_obj_t res_items[2];

    res_items[0] = mp_obj_new_bytes(signature, sizeof(signature));

    mp_obj_t new_state_items[2] = {
        mp_obj_new_int_from_uint(state.q),
        mp_obj_new_int_from_uint(state.valid)
    };
    res_items[1] = mp_obj_new_tuple(2, new_state_items);

    return mp_obj_new_tuple(2, res_items);
}

MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_shrincs_sign_stateful_obj, 4, 5, mod_trezorcrypto_shrincs_sign_stateful);