#include "py/runtime.h"
#include "py/mpprint.h"
#include "memzero.h"
#include "../../../../crypto/slh_dsa/slh_dsa.h"
#include "../../../../crypto/slh_dsa/slh_param.h"
#include "sha2.h"

static void slh_dsa_mp_progress_cb(uint16_t value, void *userdata) {
    mp_obj_t reporter = *(mp_obj_t *)userdata;
    mp_call_function_1(reporter, mp_obj_new_int(value));
}

STATIC mp_obj_t mod_trezorcrypto_slh_dsa_sign(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t sk_buf;
    mp_get_buffer_raise(args[0], &sk_buf, MP_BUFFER_READ);

    if (sk_buf.len != 64) {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid length of secret key"));
    }

    const uint8_t *sk_ptr = (const uint8_t *)sk_buf.buf;

    mp_buffer_info_t msg_buf;
    mp_get_buffer_raise(args[1], &msg_buf, MP_BUFFER_READ);

    bool is_standard = mp_obj_is_true(args[2]);

    slh_progress_cb cb = NULL;
    mp_obj_t reporter = MP_OBJ_NULL;
    if (n_args >= 3 && args[3] != mp_const_none) {
        reporter = args[3];
        cb = slh_dsa_mp_progress_cb;
    }

    slh_param_t prm;

    if (is_standard)
    { 
        prm = slh_dsa_sha2_128s;
    }
    else
    {
        memcpy(&prm, &slh_dsa_sha2_128s, sizeof(slh_param_t));
        prm.alg_id = "custom-slh-dsa";
        prm.h = 45;  
        prm.d = 5;  
        prm.hp = 9;
        prm.a = 13;   
        prm.k = 10;
        prm.lg_w = 4;
    }

    uint32_t sig_len = slh_sig_sz(&prm); 
    uint8_t signature[sig_len];
    slh_sign(signature, (const uint8_t*)msg_buf.buf, msg_buf.len, NULL, 0, sk_ptr, NULL, &prm, cb, &reporter);

    memzero(sk_buf.buf, sk_buf.len);

    return mp_obj_new_bytes(signature, sizeof(signature));
}

MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_slh_dsa_sign_obj, 3, 4, mod_trezorcrypto_slh_dsa_sign);

STATIC mp_obj_t mod_trezorcrypto_slh_dsa_gen_sk(mp_obj_t seckey_32, mp_obj_t is_standard_obj) {
    mp_buffer_info_t buf_32;
    mp_get_buffer_raise(seckey_32, &buf_32, MP_BUFFER_READ);

    if (buf_32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("Expected 32-byte seed"));
    }

    bool is_standard = mp_obj_is_true(is_standard_obj);

    uint8_t sha512_buf[64];
    sha512_Raw((const uint8_t*)buf_32.buf, 32, sha512_buf);

    slh_param_t prm;
    if (is_standard) {
        prm = slh_dsa_sha2_128s;
    } else {
        memcpy(&prm, &slh_dsa_sha2_128s, sizeof(slh_param_t));
        prm.alg_id = "custom-slh-dsa";
        prm.h = 45;
        prm.d = 5;
        prm.hp = 9;
        prm.a = 13;
        prm.k = 10;
        prm.lg_w = 4;
    }

    uint32_t n = prm.n;

    uint8_t sk[64];
    uint8_t pk[32];

    slh_keygen_internal(sk, pk,
        sha512_buf,
        sha512_buf + n,
        sha512_buf + 2 * n,
        &prm);

    memzero(sha512_buf, sizeof(sha512_buf));

    return mp_obj_new_bytes(sk, sizeof(sk));
}
MP_DEFINE_CONST_FUN_OBJ_2(mod_trezorcrypto_slh_dsa_gen_sk_obj, mod_trezorcrypto_slh_dsa_gen_sk);