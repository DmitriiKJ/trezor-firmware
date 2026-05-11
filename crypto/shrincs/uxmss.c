#include "uxmss.h"

void uxmss_treehash(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t level, uint8_t* out)
{
    uint8_t left[N];
    wots_pk_gen(sk_seed, hash_ctx, adrs, level + 1, 1, left);

    uint8_t right[N];
    if (level == HSF - 1)
    {
        wots_pk_gen(sk_seed, hash_ctx, adrs, HSF + 1, 1, right);
    }
    else
    {
        uxmss_treehash(sk_seed, hash_ctx, adrs, level + 1, right);
    }

    setTypeAndClear(adrs, SF_TREE);
    setTreeHeight(adrs, HSF - level);
    setTreeIndex(adrs, 0);

    SHA256_CTX ctx = *hash_ctx;

    sha256_add_to_ctx(&ctx, adrs, 32);
    sha256_add_to_ctx(&ctx, left, N);
    sha256_add_to_ctx(&ctx, right, N);

    sha256_finalize(&ctx, out);
}

void uxmss_root(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint8_t* out)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    uxmss_treehash(sk_seed, hash_ctx, adrs, 0, out);
}

void uxmss_auth_path(const uint8_t* sk_seed, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint8_t* out)
{
    // uint8_t auth[(q > HSF ? q - 1 : q) * N];

    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    
    uint8_t tmp[N];
    if (q <= HSF)
    {
        if (q == HSF) 
        {
            wots_pk_gen(sk_seed, hash_ctx, adrs, HSF + 1, 1, tmp);
            memcpy(out, tmp, N);
        }
        else
        {
            uxmss_treehash(sk_seed, hash_ctx, adrs, q, tmp);
            memcpy(out, tmp, N);
        }

        for (uint32_t i = 1; i < q; i++)
        {
            wots_pk_gen(sk_seed, hash_ctx, adrs, q - i, 1, tmp);
            memcpy(out + N*i, tmp, N);
        }
    }
    else {
        for (uint32_t i = 0; i < HSF; i++)
        {
            wots_pk_gen(sk_seed, hash_ctx, adrs, HSF - i, 1, tmp);
            memcpy(out + N*i, tmp, N);
        }
    }
}

void uxmss_pk_from_sig(const uint8_t* wots_sig, const uint8_t* auth, const uint8_t* message, uint32_t message_len, const uint8_t* pk_root, SHA256_CTX* hash_ctx, uint8_t* adrs, uint32_t q, uint8_t* out)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);
    wots_pk_from_sig(wots_sig, message, message_len, pk_root, hash_ctx, adrs, q, 1, 0, out);

    setTypeAndClear(adrs, SF_TREE);
    if (q <= HSF) 
    {
        setTreeHeight(adrs, HSF - (q - 1));
        setTreeIndex(adrs, 0);

        SHA256_CTX ctx = *hash_ctx;

        sha256_add_to_ctx(&ctx, adrs, 32);
        sha256_add_to_ctx(&ctx, out, N);
        sha256_add_to_ctx(&ctx, auth, N);

        sha256_finalize(&ctx, out);

        for (uint32_t i = 1; i < q; i++)
        {
            setTreeHeight(adrs, HSF - (q - 1 - i));
            setTreeIndex(adrs, 0);

            ctx = *hash_ctx;
            sha256_add_to_ctx(&ctx, adrs, 32);
            sha256_add_to_ctx(&ctx, auth + N*i, N);
            sha256_add_to_ctx(&ctx, out, N);

            sha256_finalize(&ctx, out);
        }
    }
    else 
    {
        for (uint32_t i = 0; i < HSF; i++)
        {
            setTreeHeight(adrs, i + 1);
            setTreeIndex(adrs, 0);

            SHA256_CTX ctx = *hash_ctx;

            sha256_add_to_ctx(&ctx, adrs, 32);
            sha256_add_to_ctx(&ctx, auth + N*i, N);
            sha256_add_to_ctx(&ctx, out, N);

            sha256_finalize(&ctx, out);
        }
    }
}

void uxmss_sign(const uint8_t* message, uint32_t message_len, const uint8_t* sk_seed, const uint8_t* sk_prf, const uint8_t* pk_seed, const uint8_t* pk_root, SHA256_CTX *hash_ctx, uint8_t* adrs, uint32_t q, uint8_t* out)
{
    setLayerAddress(adrs, 0);
    setTreeAddress(adrs, 0, 0);

    wots_sign(message, message_len, sk_seed, sk_prf, pk_seed, pk_root, hash_ctx, adrs, q, 1, 0, out);
    uxmss_auth_path(sk_seed, hash_ctx, adrs, q, out + WOTS_SIGN_LEN);
}
