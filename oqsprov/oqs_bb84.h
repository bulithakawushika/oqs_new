/*
 * oqs_bb84.h - BB84 QKD Header for OQS Provider
 * 
 * Header file for BB84 quantum key distribution implementation
 */

#ifndef OQS_BB84_H
#define OQS_BB84_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// BB84 configuration constants
#define BB84_DEFAULT_INITIAL_BITS   1024
#define BB84_MIN_KEY_LENGTH         16      // Minimum 128-bit key
#define BB84_MAX_KEY_LENGTH         256     // Maximum 2048-bit key
#define BB84_ERROR_THRESHOLD        0.11    // QBER threshold for eavesdropper detection

// BB84 context structure
typedef struct OQS_BB84_CTX {
    // Raw protocol data
    uint8_t *alice_bits;        // Alice's random bits
    uint8_t *alice_bases;       // Alice's random bases
    uint8_t *bob_bases;         // Bob's random bases  
    uint8_t *bob_bits;          // Bob's measurement results
    
    // Processed key data
    uint8_t *sifted_key;        // Final sifted key
    size_t key_length;          // Length of sifted key (bytes)
    size_t initial_length;      // Initial number of bits
    
    // Protocol status
    int eavesdropper_detected;  // 1 if eavesdropper detected, 0 otherwise
    double error_rate;          // Quantum bit error rate
    
    // Configuration
    double noise_level;         // Simulated channel noise
    int enable_error_correction; // Enable error correction/reconciliation
    int enable_privacy_amplification; // Enable privacy amplification
} OQS_BB84_CTX;

// BB84 function declarations

/**
 * Create new BB84 context
 * @param initial_bits Number of initial bits for the protocol
 * @return Pointer to BB84 context or NULL on failure
 */
OQS_BB84_CTX* oqs_bb84_new(size_t initial_bits);

/**
 * Generate QKD key using BB84 protocol
 * @param ctx BB84 context
 * @return 0 on success, -1 on failure
 */
int oqs_bb84_generate_key(OQS_BB84_CTX *ctx);

/**
 * Get the generated key
 * @param ctx BB84 context
 * @param key Buffer to store the key
 * @param key_len Pointer to buffer size (input) and actual key length (output)
 * @return 0 on success, -1 on failure
 */
int oqs_bb84_get_key(OQS_BB84_CTX *ctx, uint8_t *key, size_t *key_len);

/**
 * Check if eavesdropper was detected
 * @param ctx BB84 context
 * @return 1 if detected, 0 if not, -1 on error
 */
int oqs_bb84_eavesdropper_detected(OQS_BB84_CTX *ctx);

/**
 * Free BB84 context
 * @param ctx BB84 context to free
 */
void oqs_bb84_free(OQS_BB84_CTX *ctx);

/**
 * Set noise level for simulation
 * @param ctx BB84 context
 * @param noise_level Noise level (0.0 to 1.0)
 * @return 0 on success, -1 on failure
 */
int oqs_bb84_set_noise(OQS_BB84_CTX *ctx, double noise_level);

/**
 * Enable/disable error correction
 * @param ctx BB84 context
 * @param enable 1 to enable, 0 to disable
 * @return 0 on success, -1 on failure
 */
int oqs_bb84_set_error_correction(OQS_BB84_CTX *ctx, int enable);

/**
 * Get error rate from last protocol run
 * @param ctx BB84 context
 * @return Error rate (0.0 to 1.0) or -1.0 on error
 */
double oqs_bb84_get_error_rate(OQS_BB84_CTX *ctx);

// Error codes
#define BB84_SUCCESS                0
#define BB84_ERROR_INVALID_PARAM   -1
#define BB84_ERROR_MEMORY          -2
#define BB84_ERROR_EAVESDROPPER    -3
#define BB84_ERROR_HIGH_ERROR_RATE -4
#define BB84_ERROR_PYTHON          -5

#ifdef __cplusplus
}
#endif

#endif // OQS_BB84_H