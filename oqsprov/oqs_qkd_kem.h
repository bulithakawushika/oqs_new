/*
 * oqs_qkd_kem.h - QKD+PQC+Classical Hybrid KEM Header
 * DECLARATIONS ONLY - No implementations should be in this file
 */
#ifndef OQS_QKD_KEM_H
#define OQS_QKD_KEM_H

#include <stdint.h>
#include <stddef.h>
#include <oqs/oqs.h>

#ifdef __cplusplus
extern "C" {
#endif

// Supported hybrid algorithms
#define QKD_ALG_QKD_MLKEM768_X25519     "qkd_mlkem768_x25519"
#define QKD_ALG_QKD_MLKEM1024_P384      "qkd_mlkem1024_p384" 
#define QKD_ALG_QKD_MLKEM768_P256       "qkd_mlkem768_p256"

// Key and ciphertext lengths (maximum across all variants)
#define QKD_HYB_MAX_PUBLICKEY_LENGTH    1280    // Max across all combinations
#define QKD_HYB_MAX_SECRETKEY_LENGTH    2464    // Max across all combinations
#define QKD_HYB_MAX_CIPHERTEXT_LENGTH   1120    // Max across all combinations
#define QKD_HYB_SHARED_SECRET_LENGTH    32      // Always 256 bits

// Error codes
#define QKD_HYB_SUCCESS                 0
#define QKD_HYB_ERROR_INVALID_PARAM    -1
#define QKD_HYB_ERROR_MEMORY           -2
#define QKD_HYB_ERROR_QKD_FAILED       -3
#define QKD_HYB_ERROR_CLASSICAL_FAILED -4
#define QKD_HYB_ERROR_PQ_FAILED        -5
#define QKD_HYB_ERROR_COMBINE_FAILED   -6

// TLS integration constants
#define OQS_QKD_MLKEM768_X25519_CODEPOINT   0x2FF0  // Private use range
#define OQS_QKD_MLKEM1024_P384_CODEPOINT    0x2FF1  // Private use range
#define OQS_QKD_MLKEM768_P256_CODEPOINT     0x2FF2  // Private use range

/* FUNCTION DECLARATIONS ONLY - Implementations go in .c files */

/**
 * Generate hybrid key pair
 */
int oqs_qkd_hyb_keygen(uint8_t *pk, uint8_t *sk, const char *alg_name);

/**
 * Encapsulate shared secret
 */
int oqs_qkd_hyb_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const char *alg_name);

/**
 * Decapsulate shared secret
 */
int oqs_qkd_hyb_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk, const char *alg_name);

/**
 * Get algorithm parameters
 */
int oqs_qkd_hyb_get_params(const char *alg_name, size_t *pk_len, size_t *sk_len, 
                           size_t *ct_len, size_t *ss_len);

/**
 * Check if algorithm is supported
 */
int oqs_qkd_hyb_is_supported(const char *alg_name);

#ifdef __cplusplus
}
#endif

#endif // OQS_QKD_KEM_H