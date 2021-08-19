#include "cipher.h"

#include <stdbool.h>
#include <string.h>

#include "crypto.h"

static inline size_t aes256_gcm_ciphertext_len(size_t plaintext_length) {
  return plaintext_length + AES256_GCM_TAG_LENGTH;
}

static inline size_t aes256_gcm_plaintext_len(size_t ciphertext_len) {
  return ciphertext_len - AES256_GCM_TAG_LENGTH;
}

static size_t aes256_gcm_encrypt(const uint8_t *ad, const uint8_t *aes_key,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t **ciphertext) {
  uint8_t *iv = (uint8_t *)aes_key + AES256_KEY_LENGTH;
  size_t ciphertext_len = aes256_gcm_ciphertext_len(plaintext_len);
  *ciphertext = (uint8_t *)malloc(ciphertext_len);
  crypto_aes_encrypt_gcm(plaintext, plaintext_len, aes_key, iv, ad, AD_LENGTH,
                         *ciphertext);
  return ciphertext_len;
}

static size_t aes256_gcm_decrypt(const uint8_t *ad, const uint8_t *aes_key,
                                 const uint8_t *ciphertext,
                                 size_t ciphertext_len, uint8_t **plaintext) {
  uint8_t *iv = (uint8_t *)aes_key + AES256_KEY_LENGTH;
  size_t plaintext_len = aes256_gcm_plaintext_len(ciphertext_len);
  *plaintext = (uint8_t *)malloc(plaintext_len);
  return crypto_aes_decrypt_gcm(ciphertext, ciphertext_len, aes_key, iv, ad,
                                AD_LENGTH, *plaintext);
}

const struct cipher_suits E2EE_ECDH_X25519_AES256_GCM_SHA256 = {
    crypto_curve25519_generate_private_key,
    crypto_curve25519_generate_public_key,
    crypto_curve25519_generate_key_pair,
    crypto_curve25519_dh,
    aes256_gcm_encrypt,
    aes256_gcm_decrypt,
    crypto_curve25519_sign,
    crypto_curve25519_verify,
    crypto_hkdf_sha256,
    crypto_hmac_sha256,
    crypto_sha256
};