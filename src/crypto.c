/*
 * Copyright © 2020-2021 by Academia Sinica
 *
 * This file is part of SKISSM.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SKISSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SKISSM.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "skissm/crypto.h"

#include <string.h>

#include "additions/curve_sigs.h"
#include "curve25519-donna.h"

#include "gcm.h"
#include "hkdf.h"
#include "md.h"
#include "platform.h"
#include "sha256.h"
#include "base64.h"

#include "kyber/src/ref/api.h"
#include "kyber/src/ref/kem.h"
#include "kyber/src/ref/params.h"
#include "kyber/src/ref/indcpa.h"
#include "kyber/src/ref/symmetric.h"

#include "sphincsplus/src/ref/params/params-sphincs-shake-256f.h"
#include "sphincsplus/src/ref/address.h"
#include "sphincsplus/src/ref/api.h"
#include "sphincsplus/src/ref/hash.h"
#include "sphincsplus/src/ref/fors.h"
#include "sphincsplus/src/ref/merkle.h"

#include "skissm/account.h"
#include "skissm/mem_util.h"

/** amount of random data required to create a Curve25519 keypair */
#define CURVE25519_RANDOM_LENGTH CURVE25519_KEY_LENGTH

#define AES256_FILE_AD "SKISSM ---> file encryption with AES256/GCM/Nopadding algorithm"
#define AES256_FILE_AD_LEN 64
#define AES256_FILE_KDF_INFO "FILE"

#define AES256_DATA_AD "SKISSM ---> data encryption with AES256/GCM/Nopadding algorithm"
#define AES256_DATA_AD_LEN 64

/** buffer length for file encryption/decryption */
#define FILE_ENCRYPTION_BUFFER_LENGTH 8192

static const uint8_t CURVE25519_BASEPOINT[32] = {9};

static crypto_param_t ecdh_x25519_aes256_gcm_sha256_param = {
    false,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    0,
    CURVE25519_KEY_LENGTH,
    CURVE25519_KEY_LENGTH,
    CURVE_SIGNATURE_LENGTH,
    SHA256_OUTPUT_LENGTH,
    AES256_KEY_LENGTH,
    AES256_IV_LENGTH,
    AES256_GCM_TAG_LENGTH
};

static crypto_param_t kyber1024_sphincsplus_aes256_gcm_sha256_param = {
    true,
    pqcrystals_kyber1024_PUBLICKEYBYTES,
    pqcrystals_kyber1024_SECRETKEYBYTES,
    pqcrystals_kyber1024_CIPHERTEXTBYTES,
    SPX_PK_BYTES,
    SPX_SK_BYTES,
    SPX_BYTES,  // 49856
    SHA256_OUTPUT_LENGTH,
    AES256_KEY_LENGTH,
    AES256_IV_LENGTH,
    AES256_GCM_TAG_LENGTH
};

static void crypto_curve25519_generate_private_key(uint8_t *private_key) {
    uint8_t random[CURVE25519_RANDOM_LENGTH];
    get_skissm_plugin()->common_handler.gen_rand(random, sizeof(random));

    random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    memcpy(private_key, random, CURVE25519_KEY_LENGTH);
}

crypto_param_t get_ecdh_x25519_aes256_gcm_sha256_param() {
    return ecdh_x25519_aes256_gcm_sha256_param;
}

crypto_param_t get_kyber1024_sphincsplus_aes256_gcm_sha256_param() {
    return kyber1024_sphincsplus_aes256_gcm_sha256_param;
}

void crypto_curve25519_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    crypto_curve25519_generate_private_key(priv_key->data);

    curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
}

void crypto_curve25519_signature_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    int result;

    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    priv_key->len = CURVE25519_KEY_LENGTH;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * CURVE25519_KEY_LENGTH);
    pub_key->len = CURVE25519_KEY_LENGTH;

    uint8_t msg[10] = {0};
    uint8_t signature[CURVE_SIGNATURE_LENGTH];

    while (true) {
        crypto_curve25519_generate_private_key(priv_key->data);

        curve25519_donna(pub_key->data, priv_key->data, CURVE25519_BASEPOINT);
        crypto_curve25519_sign(priv_key->data, msg, 10, signature);
        result = crypto_curve25519_verify(signature, pub_key->data, msg, 10);
        if (result != 0) {
            // verify failed, regenerate the key pair
            ssm_notify_log(BAD_SIGN_KEY, "crypto_curve25519_signature_generate_key_pair() verify failed, regenerate the key pair.");
        } else {
            // success
            break;
        }
        // TODO in case of long running
    }
}

void crypto_kyber1024_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * pqcrystals_kyber1024_SECRETKEYBYTES);
    priv_key->len = pqcrystals_kyber1024_SECRETKEYBYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * pqcrystals_kyber1024_PUBLICKEYBYTES);
    pub_key->len = pqcrystals_kyber1024_PUBLICKEYBYTES;

    size_t i;
    indcpa_keypair(pub_key->data, priv_key->data);
    for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
        (priv_key->data)[i + KYBER_INDCPA_SECRETKEYBYTES] = (pub_key->data)[i];
    hash_h(priv_key->data + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, pub_key->data, KYBER_PUBLICKEYBYTES);

    get_skissm_plugin()->common_handler.gen_rand(
        priv_key->data + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, KYBER_SYMBYTES
    );
}

void crypto_sphincsplus_shake256_generate_key_pair(
    ProtobufCBinaryData *pub_key, ProtobufCBinaryData *priv_key
) {
    priv_key->data = (uint8_t *)malloc(sizeof(uint8_t) * SPX_SK_BYTES);
    priv_key->len = SPX_SK_BYTES;

    pub_key->data = (uint8_t *)malloc(sizeof(uint8_t) * SPX_PK_BYTES);
    pub_key->len = SPX_PK_BYTES;

    unsigned char seed[CRYPTO_SEEDBYTES];
    get_skissm_plugin()->common_handler.gen_rand(seed, CRYPTO_SEEDBYTES);
    crypto_sign_seed_keypair(pub_key->data, priv_key->data, seed);
}

uint8_t *crypto_curve25519_dh(
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *their_key,
    uint8_t *shared_secret
) {
    curve25519_donna(shared_secret, our_key->data, their_key->data);
    return NULL;
}

uint8_t *crypto_kyber1024_shared_secret(
    const ProtobufCBinaryData *our_key,
    const ProtobufCBinaryData *their_key,
    uint8_t *shared_secret
) {
    if (our_key == NULL) {
        // Encapsulation
        uint8_t *ct = (uint8_t *)malloc(sizeof(uint8_t) * pqcrystals_kyber1024_CIPHERTEXTBYTES);
        uint8_t buf[2*KYBER_SYMBYTES];
        uint8_t kr[2*KYBER_SYMBYTES];
        get_skissm_plugin()->common_handler.gen_rand(buf, KYBER_SYMBYTES);
        hash_h(buf, buf, KYBER_SYMBYTES);
        hash_h(buf+KYBER_SYMBYTES, their_key->data, KYBER_PUBLICKEYBYTES);
        hash_g(kr, buf, 2*KYBER_SYMBYTES);
        indcpa_enc(ct, buf, their_key->data, kr+KYBER_SYMBYTES);
        hash_h(kr+KYBER_SYMBYTES, ct, KYBER_CIPHERTEXTBYTES);
        kdf(shared_secret, kr, 2*KYBER_SYMBYTES);
        return ct;
    } else {
        // Decapsulation
        crypto_kem_dec(shared_secret, their_key->data, our_key->data);
        return NULL;
    }
}

void crypto_curve25519_sign(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
) {
    uint8_t nonce[CURVE_SIGNATURE_LENGTH];
    get_skissm_plugin()->common_handler.gen_rand(nonce, sizeof(nonce));
    curve25519_sign(signature_out, private_key, msg, msg_len, nonce);
}

void crypto_sphincsplus_shake256_sign(
    uint8_t *private_key,
    uint8_t *msg, size_t msg_len,
    uint8_t *signature_out
) {
    spx_ctx ctx;

    const unsigned char *sk_prf = private_key + SPX_N;
    const unsigned char *pk = private_key + 2*SPX_N;

    unsigned char optrand[SPX_N];
    unsigned char mhash[SPX_FORS_MSG_BYTES];
    unsigned char root[SPX_N];
    uint32_t i;
    uint64_t tree;
    uint32_t idx_leaf;
    uint32_t wots_addr[8] = {0};
    uint32_t tree_addr[8] = {0};

    memcpy(ctx.sk_seed, private_key, SPX_N);
    memcpy(ctx.pub_seed, pk, SPX_N);

    /* This hook allows the hash function instantiation to do whatever
       preparation or computation it needs, based on the public seed. */
    initialize_hash_function(&ctx);

    set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    get_skissm_plugin()->common_handler.gen_rand(optrand, SPX_N);
    /* Compute the digest randomization value. */
    gen_message_random(signature_out, sk_prf, optrand, msg, msg_len, &ctx);

    /* Derive the message digest and leaf index from R, PK and M. */
    hash_message(mhash, &tree, &idx_leaf, signature_out, pk, msg, msg_len, &ctx);
    signature_out += SPX_N;

    set_tree_addr(wots_addr, tree);
    set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    fors_sign(signature_out, root, mhash, &ctx, wots_addr);
    signature_out += SPX_FORS_BYTES;

    for (i = 0; i < SPX_D; i++) {
        set_layer_addr(tree_addr, i);
        set_tree_addr(tree_addr, tree);

        copy_subtree_addr(wots_addr, tree_addr);
        set_keypair_addr(wots_addr, idx_leaf);

        merkle_sign(signature_out, root, &ctx, wots_addr, tree_addr, idx_leaf);
        signature_out += SPX_WOTS_BYTES + SPX_TREE_HEIGHT * SPX_N;

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT)-1));
        tree = tree >> SPX_TREE_HEIGHT;
    }
}

int crypto_curve25519_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
) {
    return curve25519_verify(signature_in, public_key, msg, msg_len);
}

int crypto_sphincsplus_shake256_verify(
    uint8_t *signature_in, uint8_t *public_key,
    uint8_t *msg, size_t msg_len
) {
    int result;
    result = crypto_sign_verify(signature_in, SPX_BYTES, msg, msg_len, public_key);
    return result;
}
//!
void crypto_aes_encrypt_gcm(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *ciphertext_data
) {
    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = ciphertext_data + plaintext_data_len;
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_IV_LENGTH, add, add_len, plaintext_data,
            ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);
}

size_t crypto_aes_decrypt_gcm(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t *aes_key, const uint8_t *iv,
    const uint8_t *add, size_t add_len,
    uint8_t *plaintext_data
) {
    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
        (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int key_len = AES256_KEY_LENGTH * 8;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            ciphertext_data_len - AES256_GCM_TAG_LENGTH, iv,
            AES256_IV_LENGTH, add, add_len, ciphertext_data,
            plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        return (ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    } else {
        return 0;
    }
}

size_t encrypt_aes_data(
    const uint8_t *plaintext_data, size_t plaintext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **ciphertext_data
) {
    size_t ciphertext_data_len = aes256_gcm_ciphertext_data_len(plaintext_data_len);
    *ciphertext_data = (uint8_t *)malloc(ciphertext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *tag_buf = *ciphertext_data + plaintext_data_len;
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, plaintext_data,
            *ciphertext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }

    mbedtls_gcm_free(&ctx);

    // done
    if (ret == 0) {
        return ciphertext_data_len;
    } else {
        free_mem((void **)ciphertext_data, ciphertext_data_len);
        *ciphertext_data = NULL;
        return 0;
    }
}

size_t decrypt_aes_data(
    const uint8_t *ciphertext_data, size_t ciphertext_data_len,
    const uint8_t aes_key[AES256_KEY_LENGTH],
    uint8_t **plaintext_data
) {
    size_t plaintext_data_len = aes256_gcm_plaintext_data_len(ciphertext_data_len);
    *plaintext_data = (uint8_t *)malloc(plaintext_data_len);

    mbedtls_gcm_context ctx;
    unsigned char *input_tag_buf =
        (unsigned char *)(ciphertext_data + ciphertext_data_len - AES256_GCM_TAG_LENGTH);
    unsigned char tag_buf[AES256_GCM_TAG_LENGTH];
    int ret;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_DATA_AD_LEN] = AES256_DATA_AD;

    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_DECRYPT,
            plaintext_data_len, iv,
            AES256_DATA_IV_LENGTH, AD, AES256_DATA_AD_LEN, ciphertext_data,
            *plaintext_data, AES256_GCM_TAG_LENGTH, tag_buf
        );
    }
    mbedtls_gcm_free(&ctx);

    // verify tag in "constant-time"
    int diff = 0, i;
    for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
        diff |= input_tag_buf[i] ^ tag_buf[i];
    if (diff == 0) {
        return plaintext_data_len;
    } else {
        return 0;
    }
}

int encrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r");
    outfile = fopen(out_file_path, "w");

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_plaintext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_plaintext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    int times = size / max_plaintext_size;
    int rest = size % max_plaintext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_ENCRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == 0) {
        int i;
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_plaintext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_plaintext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_plaintext_size, outfile);
        }
    }
    if (ret == 0) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == 0) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int decrypt_aes_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t aes_key[AES256_KEY_LENGTH]
) {
    FILE *infile, *outfile;
    infile = fopen(in_file_path, "r+");
    outfile = fopen(out_file_path, "w");

    int key_len = AES256_KEY_LENGTH * 8;
    uint8_t AD[AES256_FILE_AD_LEN] = AES256_FILE_AD;

    fseek(infile, 0, SEEK_END);
    long size = ftell(infile);
    fseek(infile, 0, SEEK_SET);

    int max_ciphertext_size = FILE_ENCRYPTION_BUFFER_LENGTH;
    unsigned char in_buffer[max_ciphertext_size];
    unsigned char out_buffer[FILE_ENCRYPTION_BUFFER_LENGTH];

    int times = (size - AES256_GCM_TAG_LENGTH) / max_ciphertext_size;
    int rest = (size - AES256_GCM_TAG_LENGTH) % max_ciphertext_size;

    mbedtls_gcm_context ctx;
    mbedtls_cipher_id_t cipher = MBEDTLS_CIPHER_ID_AES;
    int ret;
    int i;
    mbedtls_gcm_init(&ctx);
    ret = mbedtls_gcm_setkey(&ctx, cipher, aes_key, key_len);
    if (ret == 0) {
        uint8_t iv[AES256_DATA_IV_LENGTH] = {0};
        ret = mbedtls_gcm_starts(&ctx, MBEDTLS_GCM_DECRYPT, iv, AES256_DATA_IV_LENGTH, AD, AES256_FILE_AD_LEN);
    }

    if (ret == 0) {
        for (i = 0; i < times; i++) {
            fread(in_buffer, sizeof(char), max_ciphertext_size, infile);
            if ((ret = mbedtls_gcm_update(&ctx, max_ciphertext_size, in_buffer, out_buffer)) != 0)
                break;
            fwrite(out_buffer, sizeof(char), max_ciphertext_size, outfile);
        }
    }
    if (ret == 0) {
        if (rest > 0) {
            fread(in_buffer, sizeof(char), rest, infile);
            if ((ret = mbedtls_gcm_update(&ctx, rest, in_buffer, out_buffer)) == 0) {
                fwrite(out_buffer, sizeof(char), rest, outfile);
            }
        }
    }

    if (ret == 0) {
        uint8_t tag[AES256_GCM_TAG_LENGTH];
        if ((ret = mbedtls_gcm_finish(&ctx, tag, AES256_GCM_TAG_LENGTH)) == 0) {
            // fwrite(tag, sizeof(char), AES256_GCM_TAG_LENGTH, outfile);
            // verify tag
            uint8_t input_tag[AES256_GCM_TAG_LENGTH];
            fread(input_tag, sizeof(uint8_t), AES256_GCM_TAG_LENGTH, infile);

            // verify tag in "constant-time"
            int diff = 0;
            for (i = 0; i < AES256_GCM_TAG_LENGTH; i++)
                diff |= input_tag[i] ^ tag[i];
            if (diff == 0) {
                ret = 0;
            } else {
                ret = -1;
            }
        }
    }

    mbedtls_gcm_free(&ctx);

    fclose(outfile);
    fclose(infile);

    return ret;
}

int encrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes encryption
    return encrypt_aes_file(in_file_path, out_file_path, aes_key);
}

int decrypt_file(
    const char *in_file_path, const char *out_file_path,
    const uint8_t *password,
    const size_t password_len
) {
    // prepare aes_key
    size_t salt_len = 0;
    uint8_t salt[salt_len];
    uint8_t aes_key[AES256_KEY_LENGTH];

    crypto_hkdf_sha256(
        password, password_len,
        salt, salt_len,
        (uint8_t *)AES256_FILE_KDF_INFO, sizeof(AES256_FILE_KDF_INFO) - 1,
        aes_key, AES256_KEY_LENGTH
    );

    // perform aes decryption
    return decrypt_aes_file(in_file_path, out_file_path, aes_key);
}

void crypto_hkdf_sha256(
    const uint8_t *input, size_t input_len,
    const uint8_t *salt, size_t salt_len,
    const uint8_t *info, size_t info_len, uint8_t *output,
    size_t output_len
) {
    const mbedtls_md_info_t *sha256_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_hkdf(sha256_info, salt, salt_len, input, input_len, info, info_len, output, output_len);
}

void crypto_hmac_sha256(
    const uint8_t *key, size_t key_len,
    const uint8_t *input, size_t input_len,
    uint8_t *output
) {
    mbedtls_md_context_t ctx;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 1);
    mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key, key_len);
    mbedtls_md_hmac_update(&ctx, (const unsigned char *)input, input_len);
    mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);
}

void crypto_sha256(const uint8_t *msg, size_t msg_len, uint8_t *hash_out) {
    int buflen, ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    ret = mbedtls_sha256_update_ret(&ctx, msg, msg_len);
    ret = mbedtls_sha256_finish_ret(&ctx, hash_out);

    mbedtls_sha256_free(&ctx);
}

char *crypto_base64_encode(const uint8_t *msg, size_t msg_len) {
    size_t len = 4 * ((msg_len + 2) / 3) + 1;
    char *output = (char *)malloc(sizeof(char) * len);
    mbedtls_base64_encode((unsigned char *)output, len, &len, (const unsigned char *)msg, msg_len);
    return output;
}

char *crypto_base64_decode(const uint8_t *base64_data, size_t base64_data_len) {
    int pad = base64_data_len > 0 && (base64_data_len % 4 || base64_data[base64_data_len - 1] == '=');
    size_t len = ((len + 3) / 4 - pad) * 4 + 1;
    char* output = (char*)malloc(sizeof(char) * len);
    mbedtls_base64_decode((unsigned char*)output, len, &len, (const unsigned char *)base64_data, base64_data_len);
    return output;
}
