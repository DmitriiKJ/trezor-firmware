#include "py/runtime.h"
#include "py/mpprint.h"
#include "memzero.h"
#include "../../../../crypto/xmss/xmss.h"
#include "../../../../crypto/xmss/xmss_core.h"
#include "../../../../crypto/xmss/params.h"
#include "sha2.h"

static void xmss_mp_progress_cb(uint32_t current, uint32_t total, void *userdata) {
    mp_obj_t reporter = *(mp_obj_t *)userdata;
    uint32_t value = (total > 0) ? (uint32_t)(((uint64_t)current * 1000) / total) : 0;
    mp_call_function_1(reporter, mp_obj_new_int((mp_int_t)value));
}

// xmss_keygen(seed_bytes, oid[, reporter]) -> (sk_bytes, pk_bytes)
// seed_bytes must be exactly 3*n bytes (n depends on OID)
STATIC mp_obj_t mod_trezorcrypto_xmss_keygen(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t buf_32;
    mp_get_buffer_raise(args[0], &buf_32, MP_BUFFER_READ);

    if (buf_32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("Expected 32-byte seed"));
    }

    uint8_t sha512_buf[64];
    sha512_Raw((const uint8_t*)buf_32.buf, 32, sha512_buf);

    uint32_t oid = (uint32_t)mp_obj_get_int(args[1]);

    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid XMSS OID"));
    }

    mp_obj_t reporter = (n_args >= 3) ? args[2] : MP_OBJ_NULL;

    xmss_progress_cb cb = NULL;
    if (reporter != MP_OBJ_NULL && mp_obj_is_callable(reporter)) {
        cb = xmss_mp_progress_cb;
    }

    // sk: OID(4) + index_bytes + SK_SEED + SK_PRF + root + PUB_SEED
    // pk: OID(4) + root + PUB_SEED
    size_t sk_total = XMSS_OID_LEN + (size_t)params.sk_bytes;
    size_t pk_total = XMSS_OID_LEN + (size_t)params.pk_bytes;

    uint8_t *sk = m_new(uint8_t, sk_total);
    uint8_t *pk = m_new(uint8_t, pk_total);

    for (unsigned int i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }

    xmssmt_core_seed_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN,
                              sha512_buf,
                              cb, cb ? &reporter : NULL);

    mp_obj_t sk_obj = mp_obj_new_bytes(sk, sk_total);
    mp_obj_t pk_obj = mp_obj_new_bytes(pk, pk_total);

    memzero(sk, sk_total);
    m_del(uint8_t, sk, sk_total);
    m_del(uint8_t, pk, pk_total);

    mp_obj_t items[2] = {sk_obj, pk_obj};
    return mp_obj_new_tuple(2, items);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_xmss_keygen_obj, 2, 3, mod_trezorcrypto_xmss_keygen);

// xmss_sign(sk_bytes, msg[, reporter]) -> (sig_bytes, updated_sk_bytes)
// xmss_sign modifies the SK index internally; returns updated SK copy
STATIC mp_obj_t mod_trezorcrypto_xmss_sign(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t sk_buf;
    mp_get_buffer_raise(args[0], &sk_buf, MP_BUFFER_READ);

    if (sk_buf.len < XMSS_OID_LEN) {
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid secret key"));
    }

    mp_buffer_info_t msg_buf;
    mp_get_buffer_raise(args[1], &msg_buf, MP_BUFFER_READ);

    mp_obj_t reporter = (n_args >= 3) ? args[2] : MP_OBJ_NULL;

    xmss_progress_cb cb = NULL;
    if (reporter != MP_OBJ_NULL && mp_obj_is_callable(reporter)) {
        cb = xmss_mp_progress_cb;
    }

    uint8_t *sk_copy = m_new(uint8_t, sk_buf.len);
    memcpy(sk_copy, sk_buf.buf, sk_buf.len);

    uint32_t oid = 0;
    for (int i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk_copy[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    xmss_params params;
    if (xmss_parse_oid(&params, oid) != 0) {
        m_del(uint8_t, sk_copy, sk_buf.len);
        mp_raise_ValueError(MP_ERROR_TEXT("Invalid OID in secret key"));
    }

    // xmss_sign returns sm = [sig || message]; call core directly to pass callback
    size_t sm_max = (size_t)params.sig_bytes + msg_buf.len;
    uint8_t *sm = m_new(uint8_t, sm_max);
    unsigned long long smlen = 0;

    // skip OID prefix when calling core (it expects sk without OID)
    int ret = xmss_core_sign(&params, sk_copy + XMSS_OID_LEN, sm, &smlen,
                             (const unsigned char *)msg_buf.buf, msg_buf.len,
                             cb, cb ? &reporter : NULL);

    if (ret != 0) {
        memzero(sk_copy, sk_buf.len);
        m_del(uint8_t, sk_copy, sk_buf.len);
        m_del(uint8_t, sm, sm_max);
        mp_raise_ValueError(MP_ERROR_TEXT("XMSS sign failed (key exhausted?)"));
    }

    size_t sig_len = (size_t)smlen - msg_buf.len;
    mp_obj_t sig_obj = mp_obj_new_bytes(sm, sig_len);
    mp_obj_t updated_sk_obj = mp_obj_new_bytes(sk_copy, sk_buf.len);

    memzero(sk_copy, sk_buf.len);
    m_del(uint8_t, sk_copy, sk_buf.len);
    m_del(uint8_t, sm, sm_max);

    mp_obj_t items[2] = {sig_obj, updated_sk_obj};
    return mp_obj_new_tuple(2, items);
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_xmss_sign_obj, 2, 3, mod_trezorcrypto_xmss_sign);
